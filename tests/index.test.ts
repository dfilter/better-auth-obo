import type { InternalAdapter } from "better-auth";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it, vi } from "vitest";
import {
  getOboToken,
  oboPlugin,
  type GetOboTokenParams,
  type OboPluginOptions,
  type OboResult,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Shared Microsoft social provider config (used in fallback tests)
// ---------------------------------------------------------------------------

const MS_SOCIAL_CONFIG = {
  clientId: "ms-social-client-id",
  clientSecret: "ms-social-client-secret",
  tenantId: "ms-social-tenant-id",
};

// ---------------------------------------------------------------------------
// Shared plugin config
// ---------------------------------------------------------------------------

const PLUGIN_OPTIONS = {
  defaultConfig: {
    authority: "https://login.microsoftonline.com/test-tenant",
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
  },
  applications: {
    graph: { scopes: ["https://graph.microsoft.com/.default"] },
    "my-api": { scopes: ["api://my-api/.default"] },
  },
} satisfies OboPluginOptions;

const MOCK_OBO_RESPONSE = {
  token_type: "Bearer" as const,
  scope: "https://graph.microsoft.com/.default",
  expires_in: 3600,
  ext_expires_in: 3600,
  access_token: "obo-access-token-xyz",
  refresh_token: "obo-refresh-token-abc",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function buildAuth() {
  const { auth, signInWithTestUser } = await getTestInstance({
    plugins: [oboPlugin(PLUGIN_OPTIONS)],
    disableTestUser: false,
  });
  return { auth, signInWithTestUser };
}

function mockFetchSuccess(overrides?: Partial<typeof MOCK_OBO_RESPONSE>) {
  return vi.fn(async () =>
    new Response(JSON.stringify({ ...MOCK_OBO_RESPONSE, ...overrides }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
}

async function seedMicrosoftAccount(
  adapter: InternalAdapter,
  userId: string,
  accessToken = "ms-access-token",
) {
  return adapter.createAccount({
    userId,
    providerId: "microsoft",
    accountId: "ms-account-id",
    accessToken,
    accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
  });
}

// ---------------------------------------------------------------------------
// Tests: oboPlugin()
// ---------------------------------------------------------------------------

describe("oboPlugin", () => {
  it("returns a valid BetterAuthPlugin with the correct id", () => {
    const plugin = oboPlugin(PLUGIN_OPTIONS);
    expect(plugin.id).toBe("obo-plugin");
    expect(plugin.options).toBe(PLUGIN_OPTIONS);
  });
});

// ---------------------------------------------------------------------------
// Tests: GetOboTokenParams type
// ---------------------------------------------------------------------------

describe("GetOboTokenParams type", () => {
  it("is exported and can be used to annotate params objects", () => {
    // This is a compile-time test — if the type doesn't exist the import fails.
    const params: GetOboTokenParams<typeof PLUGIN_OPTIONS["applications"]> = {
      userId: "user-123",
      applicationName: "graph", // typed as "graph" | "my-api"
    };
    expect(params.applicationName).toBe("graph");
  });
});

// ---------------------------------------------------------------------------
// Tests: getOboToken() — config resolution
// ---------------------------------------------------------------------------

describe("getOboToken — config resolution", () => {
  it("returns success: false for an unknown application name", async () => {
    const { auth } = await buildAuth();
    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: "any-user-id",
      applicationName: "nonexistent-app",
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain("Unknown application");
    expect(result.error).toContain("nonexistent-app");
  });

  it("derives the authority from tenantId when authority is omitted", async () => {
    const optionsWithTenantId = {
      defaultConfig: {
        tenantId: "my-tenant-id",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
      },
      applications: {
        graph: { scopes: ["https://graph.microsoft.com/.default"] },
      },
    } satisfies OboPluginOptions;

    const { auth, signInWithTestUser } = await getTestInstance({
      plugins: [oboPlugin(optionsWithTenantId)],
    });
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    let capturedUrl: string | undefined;
    const mockFetch = vi.fn(async (url: string | URL | Request) => {
      capturedUrl = url.toString();
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    await getOboToken(auth, optionsWithTenantId, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(capturedUrl).toBe(
      "https://login.microsoftonline.com/my-tenant-id/oauth2/v2.0/token",
    );
  });

  it("standalone helper returns success: false when no authority or tenantId can be resolved", async () => {
    const badOptions: OboPluginOptions = {
      defaultConfig: {
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
      },
      applications: {
        graph: { scopes: ["https://graph.microsoft.com/.default"] },
      },
    };
    const { auth } = await buildAuth();
    const result = await getOboToken(auth, badOptions, {
      userId: "any-user",
      applicationName: "graph",
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain("authority");
  });

  it("uses defaultConfig clientId for all applications and varies only scope", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    const bodies: URLSearchParams[] = [];
    const mockFetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      bodies.push(init?.body as URLSearchParams);
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });
    // Expire the cache so the second app also makes an HTTP call
    const cachedGraph = await ctx.internalAdapter.findAccountByProviderId(user.id, "obo-graph");
    await ctx.internalAdapter.updateAccount(cachedGraph!.id, {
      accessTokenExpiresAt: new Date(Date.now() - 1_000),
    });
    await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "my-api",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(bodies[0]?.get("client_id")).toBe("test-client-id");
    expect(bodies[1]?.get("client_id")).toBe("test-client-id");
    expect(bodies[0]?.get("scope")).toBe("https://graph.microsoft.com/.default");
    expect(bodies[1]?.get("scope")).toBe("api://my-api/.default");
  });
});

// ---------------------------------------------------------------------------
// Tests: getOboToken() — missing Microsoft account
// ---------------------------------------------------------------------------

describe("getOboToken — missing Microsoft account", () => {
  it("returns success: false when the user has no Microsoft account", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("No Microsoft access token found");
    expect(result.error).toContain(user.id);
  });

  it("returns success: false when the Microsoft account has no access token", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      // accessToken intentionally omitted
    });

    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("No Microsoft access token found");
  });
});

// ---------------------------------------------------------------------------
// Tests: getOboToken() — successful token exchange
// ---------------------------------------------------------------------------

describe("getOboToken — successful token exchange", () => {
  it("calls the Microsoft token endpoint with all required OBO parameters", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    let capturedUrl: string | undefined;
    let capturedBody: URLSearchParams | undefined;
    const mockFetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedBody = init?.body as URLSearchParams;
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(result.success).toBe(true);
    expect(capturedUrl).toBe(
      "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
    );
    expect(capturedBody?.get("grant_type")).toBe(
      "urn:ietf:params:oauth:grant-type:jwt-bearer",
    );
    expect(capturedBody?.get("assertion")).toBe("ms-access-token");
    expect(capturedBody?.get("requested_token_use")).toBe("on_behalf_of");
    expect(capturedBody?.get("client_id")).toBe("test-client-id");
    expect(capturedBody?.get("client_secret")).toBe("test-client-secret");
    expect(capturedBody?.get("scope")).toBe("https://graph.microsoft.com/.default");
  });

  it("returns an Account-shaped data object on success", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetchSuccess() },
    });

    expect(result.success).toBe(true);
    if (!result.success) return;

    // data is an Account-shaped object
    expect(result.data.accessToken).toBe("obo-access-token-xyz");
    expect(result.data.refreshToken).toBe("obo-refresh-token-abc");
    expect(result.data.scope).toBe("https://graph.microsoft.com/.default");
    expect(result.data.accessTokenExpiresAt).toBeInstanceOf(Date);
    expect(result.data.providerId).toBe("obo-graph");
    expect(result.data.userId).toBe(user.id);
    expect(typeof result.data.id).toBe("string");
  });

  it("discriminated union: data is null when success is false", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
    });

    // TypeScript narrows correctly: in the false branch data must be null
    expect(result.success).toBe(false);
    if (!result.success) {
      // data is typed as null here — this assertion proves the runtime shape
      expect(result.data).toBeNull();
      expect(typeof result.error).toBe("string");
    }
  });

  it("returns success: false when the Microsoft token endpoint returns an error", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    const mockFetch = vi.fn(async () =>
      new Response(
        JSON.stringify({
          error: "invalid_grant",
          error_description: "AADSTS70011: The provided value for 'scope' is not valid.",
        }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      ),
    );

    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("OBO token exchange failed");
  });
});

// ---------------------------------------------------------------------------
// Tests: getOboToken() — token caching
// ---------------------------------------------------------------------------

describe("getOboToken — token caching", () => {
  it("caches the OBO token as a synthetic account row after a successful exchange", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetchSuccess() },
    });

    const cachedAccount = await ctx.internalAdapter.findAccountByProviderId(
      user.id,
      "obo-graph",
    );
    expect(cachedAccount).not.toBeNull();
    expect(cachedAccount?.accessToken).toBe("obo-access-token-xyz");
    expect(cachedAccount?.refreshToken).toBe("obo-refresh-token-abc");
    expect(cachedAccount?.accessTokenExpiresAt).toBeInstanceOf(Date);
  });

  it("returns the cached account row on a second call without making an HTTP request", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    const mockFetch = mockFetchSuccess();

    // First call — performs the HTTP exchange
    await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Second call — served from cache, no new HTTP request
    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.accessToken).toBe("obo-access-token-xyz");
    }
  });

  it("re-exchanges when the cached OBO token is expired", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    // Seed an already-expired OBO cache entry
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "obo-graph",
      accountId: user.id,
      accessToken: "stale-obo-token",
      accessTokenExpiresAt: new Date(Date.now() - 1_000),
    });

    const mockFetch = mockFetchSuccess({ access_token: "fresh-obo-token-after-expiry" });

    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(result.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    if (result.success) {
      expect(result.data.accessToken).toBe("fresh-obo-token-after-expiry");
    }
  });

  it("does not serve a cached token that is within the 60-second expiry buffer", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    // Seed a cached entry that expires in 30 seconds (within the 60s buffer)
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "obo-graph",
      accountId: user.id,
      accessToken: "almost-expired-obo-token",
      accessTokenExpiresAt: new Date(Date.now() + 30_000),
    });

    const mockFetch = mockFetchSuccess({ access_token: "freshly-fetched-token" });

    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    if (result.success) {
      expect(result.data.accessToken).toBe("freshly-fetched-token");
    }
  });
});

// ---------------------------------------------------------------------------
// Tests: ctx.obo.getOboToken — via auth.$context
// ---------------------------------------------------------------------------

describe("ctx.obo.getOboToken — via auth.$context", () => {
  it("exposes ctx.obo on auth.$context after plugin registration", async () => {
    const { auth } = await buildAuth();
    const ctx = await auth.$context;
    expect(ctx.obo).toBeDefined();
    expect(typeof ctx.obo.getOboToken).toBe("function");
  });

  it("applicationName is narrowed to the plugin's application keys", async () => {
    // Compile-time test — the type of applicationName should be "graph" | "my-api"
    const { auth } = await buildAuth();
    const ctx = await auth.$context;
    // This should type-check: "graph" is a valid key
    const params: GetOboTokenParams<typeof PLUGIN_OPTIONS["applications"]> = {
      userId: "user-123",
      applicationName: "graph",
    };
    expect(params.applicationName).toBe("graph");
    // Confirm the function exists and accepts the params shape
    expect(typeof ctx.obo.getOboToken).toBe("function");
  });

  it("returns an Account-shaped result with options already bound", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    const result = await ctx.obo.getOboToken({
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetchSuccess() },
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.accessToken).toBe("obo-access-token-xyz");
      expect(result.data.providerId).toBe("obo-graph");
      expect(result.error).toBeNull();
    }
  });

  it("uses the same cache as the standalone helper", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    const mockFetch = mockFetchSuccess();

    // First call via the standalone helper — populates the cache
    await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Second call via ctx.obo — should hit the same cache
    const result = await ctx.obo.getOboToken({
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(mockFetch).toHaveBeenCalledTimes(1); // still 1
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.accessToken).toBe("obo-access-token-xyz");
    }
  });
});

// ---------------------------------------------------------------------------
// Tests: credential fallback from Microsoft social provider config
// ---------------------------------------------------------------------------

describe("credential fallback from Microsoft social provider", () => {
  it("reads clientId, clientSecret, and tenantId from the social provider when defaultConfig is omitted", async () => {
    const { auth, signInWithTestUser } = await getTestInstance({
      socialProviders: { microsoft: MS_SOCIAL_CONFIG },
      plugins: [
        oboPlugin({
          applications: {
            graph: { scopes: ["https://graph.microsoft.com/.default"] },
          },
        }),
      ],
    });
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    let capturedUrl: string | undefined;
    let capturedBody: URLSearchParams | undefined;
    const mockFetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedBody = init?.body as URLSearchParams;
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    const result = await ctx.obo.getOboToken({
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(result.success).toBe(true);
    expect(capturedBody?.get("client_id")).toBe("ms-social-client-id");
    expect(capturedBody?.get("client_secret")).toBe("ms-social-client-secret");
    expect(capturedUrl).toContain("ms-social-tenant-id");
  });

  it("defaultConfig fields take precedence over the social provider config", async () => {
    const { auth, signInWithTestUser } = await getTestInstance({
      socialProviders: { microsoft: MS_SOCIAL_CONFIG },
      plugins: [
        oboPlugin({
          defaultConfig: { tenantId: "override-tenant-id" },
          applications: {
            graph: { scopes: ["https://graph.microsoft.com/.default"] },
          },
        }),
      ],
    });
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    let capturedUrl: string | undefined;
    let capturedBody: URLSearchParams | undefined;
    const mockFetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedBody = init?.body as URLSearchParams;
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    await ctx.obo.getOboToken({
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(capturedUrl).toContain("override-tenant-id");
    expect(capturedUrl).not.toContain("ms-social-tenant-id");
    expect(capturedBody?.get("client_id")).toBe("ms-social-client-id");
    expect(capturedBody?.get("client_secret")).toBe("ms-social-client-secret");
  });

  it("warns when tenantId is explicitly set to 'common'", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    await getTestInstance({
      socialProviders: {
        microsoft: {
          clientId: "ms-client-id",
          clientSecret: "ms-client-secret",
          tenantId: "common",
        },
      },
      plugins: [
        oboPlugin({
          applications: {
            graph: { scopes: ["https://graph.microsoft.com/.default"] },
          },
        }),
      ],
    });

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("common"));
    warnSpy.mockRestore();
  });

  it("plugin init throws at startup when no credentials can be resolved", async () => {
    await expect(
      getTestInstance({
        plugins: [
          oboPlugin({
            applications: {
              graph: { scopes: ["https://graph.microsoft.com/.default"] },
            },
          }),
        ],
      }),
    ).rejects.toThrow("Missing required credentials");
  });
});

// ---------------------------------------------------------------------------
// OboResult type — exported type test
// ---------------------------------------------------------------------------

describe("OboResult exported type", () => {
  it("can be used to annotate variables", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    // Annotate explicitly to confirm the type is exported correctly
    const result: OboResult = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
    });

    expect(result.success).toBe(false); // no microsoft account seeded
    expect(result.data).toBeNull();
  });
});

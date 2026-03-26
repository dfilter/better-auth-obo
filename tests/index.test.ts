import type { InternalAdapter } from "better-auth";
import { getTestInstance } from "better-auth/test";
import { afterEach, describe, expect, it, vi } from "vitest";
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

/**
 * Stub globalThis.fetch to return a mock OBO response.
 * Used for auth.api.getOboToken tests — the endpoint goes through Better Auth's
 * toAuthEndpoints wrapper which calls betterFetch → globalThis.fetch internally.
 */
function stubFetch(overrides?: Partial<typeof MOCK_OBO_RESPONSE>) {
  const mockFn = vi.fn(async (_url: string | URL | Request, _init?: RequestInit) =>
    new Response(JSON.stringify({ ...MOCK_OBO_RESPONSE, ...overrides }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
  vi.stubGlobal("fetch", mockFn);
  return mockFn;
}

function stubFetchError(body: object, status = 400) {
  const mockFn = vi.fn(async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
  );
  vi.stubGlobal("fetch", mockFn);
  return mockFn;
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

afterEach(() => {
  vi.unstubAllGlobals();
});

// ---------------------------------------------------------------------------
// Tests: oboPlugin()
// ---------------------------------------------------------------------------

describe("oboPlugin", () => {
  it("returns a valid BetterAuthPlugin with the correct id", () => {
    const plugin = oboPlugin(PLUGIN_OPTIONS);
    expect(plugin.id).toBe("obo-plugin");
    expect(plugin.options).toBe(PLUGIN_OPTIONS);
  });

  it("exposes getOboToken on auth.api", async () => {
    const { auth } = await buildAuth();
    expect(typeof auth.api.getOboToken).toBe("function");
  });
});

// ---------------------------------------------------------------------------
// Tests: exported types
// ---------------------------------------------------------------------------

describe("exported types", () => {
  it("GetOboTokenParams can be used to annotate params objects", () => {
    const params: GetOboTokenParams<typeof PLUGIN_OPTIONS["applications"]> = {
      userId: "user-123",
      applicationName: "graph", // typed as "graph" | "my-api"
    };
    expect(params.applicationName).toBe("graph");
  });

  it("OboResult can be used to annotate return values", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const result: OboResult = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });
    expect(result.success).toBe(false); // no microsoft account seeded
  });
});

// ---------------------------------------------------------------------------
// Tests: auth.api.getOboToken — config resolution
// ---------------------------------------------------------------------------

describe("auth.api.getOboToken — config resolution", () => {
  it("returns success: false for an unknown application name", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "nonexistent-app" },
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
    vi.stubGlobal("fetch", vi.fn(async (url: string | URL | Request) => {
      capturedUrl = url.toString();
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }));

    await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(capturedUrl).toBe(
      "https://login.microsoftonline.com/my-tenant-id/oauth2/v2.0/token",
    );
  });

  it("uses defaultConfig clientId for all applications and varies only scope", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    const bodies: URLSearchParams[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      bodies.push(init?.body as URLSearchParams);
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }));

    await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });
    // Expire the graph cache so the my-api call also hits the token endpoint
    const cachedGraph = await ctx.internalAdapter.findAccountByProviderId(user.id, "obo-graph");
    await ctx.internalAdapter.updateAccount(cachedGraph!.id, {
      accessTokenExpiresAt: new Date(Date.now() - 1_000),
    });
    await auth.api.getOboToken({ body: { userId: user.id, applicationName: "my-api" } });

    expect(bodies[0]?.get("client_id")).toBe("test-client-id");
    expect(bodies[1]?.get("client_id")).toBe("test-client-id");
    expect(bodies[0]?.get("scope")).toBe("https://graph.microsoft.com/.default");
    expect(bodies[1]?.get("scope")).toBe("api://my-api/.default");
  });
});

// ---------------------------------------------------------------------------
// Tests: auth.api.getOboToken — missing Microsoft account
// ---------------------------------------------------------------------------

describe("auth.api.getOboToken — missing Microsoft account", () => {
  it("returns success: false when the user has no Microsoft account", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
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

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("No Microsoft access token found");
  });
});

// ---------------------------------------------------------------------------
// Tests: auth.api.getOboToken — successful token exchange
// ---------------------------------------------------------------------------

describe("auth.api.getOboToken — successful token exchange", () => {
  it("calls the Microsoft token endpoint with all required OBO parameters", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    let capturedUrl: string | undefined;
    let capturedBody: URLSearchParams | undefined;
    vi.stubGlobal("fetch", vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedBody = init?.body as URLSearchParams;
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }));

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
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
    stubFetch();

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(result.success).toBe(true);
    if (!result.success) return;

    expect(result.data.accessToken).toBe("obo-access-token-xyz");
    expect(result.data.refreshToken).toBe("obo-refresh-token-abc");
    expect(result.data.scope).toBe("https://graph.microsoft.com/.default");
    expect(result.data.accessTokenExpiresAt).toBeInstanceOf(Date);
    expect(result.data.providerId).toBe("obo-graph");
    expect(result.data.userId).toBe(user.id);
    expect(typeof result.data.id).toBe("string");
    expect(result.error).toBeNull();
  });

  it("discriminated union: data is null and error is a string when success is false", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.data).toBeNull();
      expect(typeof result.error).toBe("string");
    }
  });

  it("returns success: false when the Microsoft token endpoint returns an error", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);
    stubFetchError({
      error: "invalid_grant",
      error_description: "AADSTS70011: The provided value for 'scope' is not valid.",
    });

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("OBO token exchange failed");
  });
});

// ---------------------------------------------------------------------------
// Tests: auth.api.getOboToken — token caching
// ---------------------------------------------------------------------------

describe("auth.api.getOboToken — token caching", () => {
  it("caches the OBO token as a synthetic account row after a successful exchange", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);
    stubFetch();

    await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });

    const cachedAccount = await ctx.internalAdapter.findAccountByProviderId(
      user.id,
      "obo-graph",
    );
    expect(cachedAccount).not.toBeNull();
    expect(cachedAccount?.accessToken).toBe("obo-access-token-xyz");
    expect(cachedAccount?.refreshToken).toBe("obo-refresh-token-abc");
    expect(cachedAccount?.accessTokenExpiresAt).toBeInstanceOf(Date);
  });

  it("returns the cached account row on a second call without a new HTTP request", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);
    const mockFetch = stubFetch();

    await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });
    expect(mockFetch).toHaveBeenCalledTimes(1);

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(mockFetch).toHaveBeenCalledTimes(1); // still 1
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

    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "obo-graph",
      accountId: user.id,
      accessToken: "stale-obo-token",
      accessTokenExpiresAt: new Date(Date.now() - 1_000),
    });

    const mockFetch = stubFetch({ access_token: "fresh-obo-token-after-expiry" });

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
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

    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "obo-graph",
      accountId: user.id,
      accessToken: "almost-expired-obo-token",
      accessTokenExpiresAt: new Date(Date.now() + 30_000),
    });

    const mockFetch = stubFetch({ access_token: "freshly-fetched-token" });

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    if (result.success) {
      expect(result.data.accessToken).toBe("freshly-fetched-token");
    }
  });
});

// ---------------------------------------------------------------------------
// Tests: standalone getOboToken helper
// ---------------------------------------------------------------------------

describe("standalone getOboToken helper", () => {
  it("returns success: false when no authority or tenantId can be resolved", async () => {
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

  it("performs an OBO exchange with explicit credentials via fetchOptions", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const result = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.accessToken).toBe("obo-access-token-xyz");
    }
  });

  it("shares the cache with auth.api.getOboToken", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

    // First call via standalone helper — populates the cache
    const standaloneMock = vi.fn(async () =>
      new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: standaloneMock as never },
    });
    expect(standaloneMock).toHaveBeenCalledTimes(1);

    // Second call via auth.api — should hit the same DB cache, no HTTP
    const apiFetchMock = stubFetch();
    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(apiFetchMock).not.toHaveBeenCalled();
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
    vi.stubGlobal("fetch", vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedBody = init?.body as URLSearchParams;
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }));

    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
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
    vi.stubGlobal("fetch", vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = url.toString();
      capturedBody = init?.body as URLSearchParams;
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }));

    await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });

    expect(capturedUrl).toContain("override-tenant-id");
    expect(capturedUrl).not.toContain("ms-social-tenant-id");
    expect(capturedBody?.get("client_id")).toBe("ms-social-client-id");
    expect(capturedBody?.get("client_secret")).toBe("ms-social-client-secret");
  });

  it("warns when tenantId is explicitly set to 'common'", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const { auth, signInWithTestUser } = await getTestInstance({
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
    // Trigger credential resolution via the endpoint
    const { user } = await signInWithTestUser();
    await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("common"));
    warnSpy.mockRestore();
  });

  it("returns success: false when no credentials can be resolved at all", async () => {
    const { auth, signInWithTestUser } = await getTestInstance({
      plugins: [
        oboPlugin({
          applications: {
            graph: { scopes: ["https://graph.microsoft.com/.default"] },
          },
        }),
      ],
    });
    const { user } = await signInWithTestUser();

    // With the endpoint approach, credential errors surface as OboResult errors
    // rather than throwing at startup.
    const result = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain("Missing required credentials");
  });
});

import type { InternalAdapter } from "better-auth";
import { isAPIError } from "better-auth/api";
import { getTestInstance } from "better-auth/test";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getOboToken,
  OBO_ERROR_CODES,
  oboPlugin,
  type GetOboTokenParams,
  type MicrosoftOBOError,
  type OboPluginOptions,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Shared config
// ---------------------------------------------------------------------------

const MS_SOCIAL_CONFIG = {
  clientId: "ms-social-client-id",
  clientSecret: "ms-social-client-secret",
  tenantId: "ms-social-tenant-id",
};

const PLUGIN_OPTIONS = {
  defaultConfig: {
    authority: "https://login.microsoftonline.com/test-tenant",
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
  },
  applications: {
    graph: { scope: ["https://graph.microsoft.com/.default"] },
    "my-api": { scope: ["api://my-api/.default"] },
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

function stubFetch(overrides?: Partial<typeof MOCK_OBO_RESPONSE>) {
  const mockFn = vi.fn(async () =>
    new Response(JSON.stringify({ ...MOCK_OBO_RESPONSE, ...overrides }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }),
  );
  vi.stubGlobal("fetch", mockFn);
  return mockFn;
}

function stubFetchError(body: Partial<MicrosoftOBOError>, status = 400) {
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

/** Assert that a promise rejects with an APIError matching status and code. */
async function expectAPIError(
  fn: Promise<unknown>,
  status: string,
  code: string,
) {
  try {
    await fn;
    expect.fail("Expected APIError to be thrown");
  } catch (e) {
    expect(isAPIError(e)).toBe(true);
    if (isAPIError(e)) {
      expect(e.status).toBe(status);
      expect(e.body?.code).toBe(code);
    }
  }
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

  it("registers OBO_ERROR_CODES on the plugin as $ERROR_CODES", () => {
    const plugin = oboPlugin(PLUGIN_OPTIONS);
    expect(plugin.$ERROR_CODES).toBe(OBO_ERROR_CODES);
    expect(plugin.$ERROR_CODES.UNKNOWN_APPLICATION.code).toBe("UNKNOWN_APPLICATION");
    expect(plugin.$ERROR_CODES.MICROSOFT_ACCOUNT_NOT_FOUND.code).toBe(
      "MICROSOFT_ACCOUNT_NOT_FOUND",
    );
    expect(plugin.$ERROR_CODES.OBO_EXCHANGE_FAILED.code).toBe("OBO_EXCHANGE_FAILED");
    expect(plugin.$ERROR_CODES.MISSING_CREDENTIALS.code).toBe("MISSING_CREDENTIALS");
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
      applicationName: "graph",
    };
    expect(params.applicationName).toBe("graph");
  });

  it("MicrosoftOBOError is exported for inspecting e.body on OBO_EXCHANGE_FAILED errors", () => {
    const err: MicrosoftOBOError = {
      error: "invalid_grant",
      error_description: "AADSTS65001: consent required",
      error_codes: [65001],
      trace_id: "trace-abc",
      correlation_id: "corr-def",
    };
    expect(err.error).toBe("invalid_grant");
  });

  it("OBO_ERROR_CODES has the correct shape from defineErrorCodes", () => {
    expect(typeof OBO_ERROR_CODES.UNKNOWN_APPLICATION.code).toBe("string");
    expect(typeof OBO_ERROR_CODES.UNKNOWN_APPLICATION.message).toBe("string");
    expect(typeof OBO_ERROR_CODES.UNKNOWN_APPLICATION.toString()).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// Tests: auth.api.getOboToken — config resolution errors
// ---------------------------------------------------------------------------

describe("auth.api.getOboToken — config resolution errors", () => {
  it("throws APIError BAD_REQUEST / UNKNOWN_APPLICATION for an unknown application name", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    await expectAPIError(
      auth.api.getOboToken({ body: { userId: user.id, applicationName: "nonexistent-app" } }),
      "BAD_REQUEST",
      "UNKNOWN_APPLICATION",
    );
  });

  it("includes the invalid name and available names in the error message", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    try {
      await auth.api.getOboToken({
        body: { userId: user.id, applicationName: "bad-app" },
      });
    } catch (e) {
      if (isAPIError(e)) {
        expect(e.body?.message).toContain("bad-app");
        expect(e.body?.message).toContain("graph");
        expect(e.body?.message).toContain("my-api");
      }
    }
  });

  it("throws APIError INTERNAL_SERVER_ERROR / MISSING_CREDENTIALS when no credentials can be resolved", async () => {
    const { auth, signInWithTestUser } = await getTestInstance({
      plugins: [
        oboPlugin({
          applications: {
            graph: { scope: ["https://graph.microsoft.com/.default"] },
          },
        }),
      ],
    });
    const { user } = await signInWithTestUser();

    await expectAPIError(
      auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } }),
      "INTERNAL_SERVER_ERROR",
      "MISSING_CREDENTIALS",
    );
  });

  it("derives the authority from tenantId when authority is omitted", async () => {
    const optionsWithTenantId = {
      defaultConfig: {
        tenantId: "my-tenant-id",
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
      },
      applications: {
        graph: { scope: ["https://graph.microsoft.com/.default"] },
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

    await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });

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
  it("throws APIError NOT_FOUND / MICROSOFT_ACCOUNT_NOT_FOUND when user has no Microsoft account", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    await expectAPIError(
      auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } }),
      "NOT_FOUND",
      "MICROSOFT_ACCOUNT_NOT_FOUND",
    );
  });

  it("includes the userId in the NOT_FOUND error message", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    try {
      await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });
    } catch (e) {
      if (isAPIError(e)) {
        expect(e.body?.message).toContain(user.id);
      }
    }
  });

  it("throws APIError NOT_FOUND when the Microsoft account has no access token", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
    });

    await expectAPIError(
      auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } }),
      "NOT_FOUND",
      "MICROSOFT_ACCOUNT_NOT_FOUND",
    );
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

    await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });

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

  it("returns an Account-shaped object on success", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);
    stubFetch();

    const account = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(account.accessToken).toBe("obo-access-token-xyz");
    expect(account.refreshToken).toBe("obo-refresh-token-abc");
    expect(account.scope).toBe("https://graph.microsoft.com/.default");
    expect(account.accessTokenExpiresAt).toBeInstanceOf(Date);
    expect(account.providerId).toBe("obo-graph");
    expect(account.userId).toBe(user.id);
    expect(typeof account.id).toBe("string");
  });

  it("throws APIError BAD_GATEWAY / OBO_EXCHANGE_FAILED when Entra ID returns an error", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);
    stubFetchError({
      error: "invalid_grant",
      error_description: "AADSTS70011: scope not valid",
      error_codes: [70011],
    });

    await expectAPIError(
      auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } }),
      "BAD_GATEWAY",
      "OBO_EXCHANGE_FAILED",
    );
  });

  it("spreads Entra ID error fields onto the APIError body", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);
    stubFetchError({
      error: "invalid_grant",
      error_description: "AADSTS65001: consent required",
      error_codes: [65001],
      trace_id: "trace-abc",
      correlation_id: "corr-def",
    });

    try {
      await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });
    } catch (e) {
      if (isAPIError(e)) {
        expect(e.body?.code).toBe("OBO_EXCHANGE_FAILED");
        expect(e.body?.error).toBe("invalid_grant");
        expect(e.body?.error_description).toContain("AADSTS65001");
        expect(e.body?.error_codes).toEqual([65001]);
        expect(e.body?.trace_id).toBe("trace-abc");
        expect(e.body?.correlation_id).toBe("corr-def");
      }
    }
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

    const cached = await ctx.internalAdapter.findAccountByProviderId(user.id, "obo-graph");
    expect(cached).not.toBeNull();
    expect(cached?.accessToken).toBe("obo-access-token-xyz");
    expect(cached?.refreshToken).toBe("obo-refresh-token-abc");
    expect(cached?.accessTokenExpiresAt).toBeInstanceOf(Date);
  });

  it("returns the cached account row on a second call without a new HTTP request", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);
    const mockFetch = stubFetch();

    await auth.api.getOboToken({ body: { userId: user.id, applicationName: "graph" } });
    expect(mockFetch).toHaveBeenCalledTimes(1);

    const account = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(account.accessToken).toBe("obo-access-token-xyz");
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

    const account = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(account.accessToken).toBe("fresh-obo-token-after-expiry");
  });

  it("does not serve a cached token within the 60-second expiry buffer", async () => {
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

    const account = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(account.accessToken).toBe("freshly-fetched-token");
  });
});

// ---------------------------------------------------------------------------
// Tests: standalone getOboToken helper
// ---------------------------------------------------------------------------

describe("standalone getOboToken helper", () => {
  it("throws BetterAuthError when no authority or tenantId can be resolved", async () => {
    const badOptions: OboPluginOptions = {
      defaultConfig: {
        clientId: "test-client-id",
        clientSecret: "test-client-secret",
      },
      applications: {
        graph: { scope: ["https://graph.microsoft.com/.default"] },
      },
    };
    const { auth } = await buildAuth();

    await expect(
      getOboToken(auth, badOptions, { userId: "any-user", applicationName: "graph" }),
    ).rejects.toThrow("authority");
  });

  it("returns an Account on success with explicit credentials via fetchOptions", async () => {
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

    const account = await getOboToken(auth, PLUGIN_OPTIONS, {
      userId: user.id,
      applicationName: "graph",
      fetchOptions: { customFetchImpl: mockFetch as never },
    });

    expect(account.accessToken).toBe("obo-access-token-xyz");
    expect(account.providerId).toBe("obo-graph");
  });

  it("shares the cache with auth.api.getOboToken", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();
    const ctx = await auth.$context;
    await seedMicrosoftAccount(ctx.internalAdapter, user.id);

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

    const apiFetchMock = stubFetch();
    const account = await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    });

    expect(apiFetchMock).not.toHaveBeenCalled();
    expect(account.accessToken).toBe("obo-access-token-xyz");
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
            graph: { scope: ["https://graph.microsoft.com/.default"] },
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
            graph: { scope: ["https://graph.microsoft.com/.default"] },
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
            graph: { scope: ["https://graph.microsoft.com/.default"] },
          },
        }),
      ],
    });
    const { user } = await signInWithTestUser();
    // Trigger lazy credential resolution (will warn then succeed with "common" as tenant)
    await auth.api.getOboToken({
      body: { userId: user.id, applicationName: "graph" },
    }).catch(() => {});

    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining("common"));
    warnSpy.mockRestore();
  });
});

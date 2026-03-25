import { getTestInstance } from "better-auth/test";
import { describe, expect, it, vi } from "vitest";
import {
  exchangeOboToken,
  oboPlugin,
  type OboPluginOptions,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Shared plugin config
// ---------------------------------------------------------------------------

const PLUGIN_OPTIONS: OboPluginOptions = {
  defaultConfig: {
    socialProvider: "microsoft",
    authority: "https://login.microsoftonline.com/test-tenant",
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
  },
  applications: {
    graph: { scopes: ["https://graph.microsoft.com/.default"] },
    "my-api": {
      scopes: ["api://my-api/.default"],
      // override clientId for this app
      clientId: "my-api-client-id",
    },
  },
};

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

/**
 * Build an Auth instance with the OBO plugin and a better-sqlite3 in-memory DB.
 * Returns the auth instance and the raw DB adapter for seeding test data.
 */
async function buildAuth() {
  const { auth, db, testUser, signInWithTestUser } = await getTestInstance({
    plugins: [oboPlugin(PLUGIN_OPTIONS)],
    disableTestUser: false,
  });
  return { auth, db, testUser, signInWithTestUser };
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
// Tests: exchangeOboToken() — config resolution
// ---------------------------------------------------------------------------

describe("exchangeOboToken — config resolution", () => {
  it("returns an error for an unknown application name", async () => {
    const { auth } = await buildAuth();
    const { data, error } = await exchangeOboToken(
      auth,
      PLUGIN_OPTIONS,
      "any-user-id",
      "nonexistent-app",
    );
    expect(data).toBeNull();
    expect(error).toContain("Unknown application");
    expect(error).toContain("nonexistent-app");
  });

  it("merges application config over defaultConfig", async () => {
    // Verify by inspecting the fetch call — the overridden clientId should appear.
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    // Seed a Microsoft account for the test user
    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

    let capturedBody: URLSearchParams | undefined;
    const mockFetch = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      capturedBody = init?.body as URLSearchParams;
      return new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });

    await exchangeOboToken(auth, PLUGIN_OPTIONS, user.id, "my-api", {
      customFetchImpl: mockFetch as never,
    });

    expect(capturedBody?.get("client_id")).toBe("my-api-client-id");
    expect(capturedBody?.get("scope")).toBe("api://my-api/.default");
  });
});

// ---------------------------------------------------------------------------
// Tests: exchangeOboToken() — missing Microsoft account
// ---------------------------------------------------------------------------

describe("exchangeOboToken — missing Microsoft account", () => {
  it("returns an error when the user has no Microsoft account", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const { data, error } = await exchangeOboToken(
      auth,
      PLUGIN_OPTIONS,
      user.id,
      "graph",
    );

    expect(data).toBeNull();
    expect(error).toContain("No Microsoft access token found");
    expect(error).toContain(user.id);
  });

  it("returns an error when the Microsoft account has no access token", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    // Create a Microsoft account row but with no accessToken
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      // accessToken intentionally omitted
    });

    const { data, error } = await exchangeOboToken(
      auth,
      PLUGIN_OPTIONS,
      user.id,
      "graph",
    );

    expect(data).toBeNull();
    expect(error).toContain("No Microsoft access token found");
  });
});

// ---------------------------------------------------------------------------
// Tests: exchangeOboToken() — successful token exchange
// ---------------------------------------------------------------------------

describe("exchangeOboToken — successful token exchange", () => {
  it("calls the Microsoft token endpoint with all required OBO parameters", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

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

    const { data, error } = await exchangeOboToken(
      auth,
      PLUGIN_OPTIONS,
      user.id,
      "graph",
      { customFetchImpl: mockFetch as never },
    );

    expect(error).toBeNull();
    expect(data).not.toBeNull();

    // Verify the token endpoint URL
    expect(capturedUrl).toBe(
      "https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token",
    );

    // Verify required OBO parameters are present in the request body
    expect(capturedBody?.get("grant_type")).toBe(
      "urn:ietf:params:oauth:grant-type:jwt-bearer",
    );
    expect(capturedBody?.get("assertion")).toBe("ms-access-token");
    expect(capturedBody?.get("requested_token_use")).toBe("on_behalf_of");
    expect(capturedBody?.get("client_id")).toBe("test-client-id");
    expect(capturedBody?.get("client_secret")).toBe("test-client-secret");
    expect(capturedBody?.get("scope")).toBe(
      "https://graph.microsoft.com/.default",
    );
  });

  it("returns the OBO token data from the Microsoft response", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const { data, error } = await exchangeOboToken(
      auth,
      PLUGIN_OPTIONS,
      user.id,
      "graph",
      { customFetchImpl: mockFetch as never },
    );

    expect(error).toBeNull();
    expect(data?.access_token).toBe("obo-access-token-xyz");
    expect(data?.token_type).toBe("Bearer");
    expect(data?.scope).toBe("https://graph.microsoft.com/.default");
    expect(data?.refresh_token).toBe("obo-refresh-token-abc");
  });

  it("returns an error when the Microsoft token endpoint returns an error", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

    const errorBody = {
      error: "invalid_grant",
      error_description:
        "AADSTS70011: The provided value for the input parameter 'scope' is not valid.",
    };

    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify(errorBody), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const { data, error } = await exchangeOboToken(
      auth,
      PLUGIN_OPTIONS,
      user.id,
      "graph",
      { customFetchImpl: mockFetch as never },
    );

    expect(data).toBeNull();
    expect(error).toContain("OBO token exchange failed");
  });
});

// ---------------------------------------------------------------------------
// Tests: exchangeOboToken() — token caching
// ---------------------------------------------------------------------------

describe("exchangeOboToken — token caching", () => {
  it("caches the OBO token as a synthetic account row after a successful exchange", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await exchangeOboToken(auth, PLUGIN_OPTIONS, user.id, "graph", {
      customFetchImpl: mockFetch as never,
    });

    // The OBO token should now be cached in the account table
    const cachedAccount = await ctx.internalAdapter.findAccountByProviderId(
      user.id,
      "obo-graph",
    );
    expect(cachedAccount).not.toBeNull();
    expect(cachedAccount?.accessToken).toBe("obo-access-token-xyz");
    expect(cachedAccount?.refreshToken).toBe("obo-refresh-token-abc");
    expect(cachedAccount?.accessTokenExpiresAt).toBeInstanceOf(Date);
  });

  it("returns the cached token on a second call without making an HTTP request", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    // First call — performs the HTTP exchange
    await exchangeOboToken(auth, PLUGIN_OPTIONS, user.id, "graph", {
      customFetchImpl: mockFetch as never,
    });
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Second call — should use the cache, NOT make another HTTP request
    const { data, error } = await exchangeOboToken(
      auth,
      PLUGIN_OPTIONS,
      user.id,
      "graph",
      { customFetchImpl: mockFetch as never },
    );

    expect(mockFetch).toHaveBeenCalledTimes(1); // still 1 — no new call
    expect(error).toBeNull();
    expect(data?.access_token).toBe("obo-access-token-xyz");
  });

  it("re-exchanges when the cached OBO token is expired", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

    // Seed an already-expired OBO cache entry
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "obo-graph",
      accountId: user.id,
      accessToken: "stale-obo-token",
      accessTokenExpiresAt: new Date(Date.now() - 1_000), // 1 second in the past
    });

    const freshResponse = {
      ...MOCK_OBO_RESPONSE,
      access_token: "fresh-obo-token-after-expiry",
    };
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify(freshResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const { data, error } = await exchangeOboToken(
      auth,
      PLUGIN_OPTIONS,
      user.id,
      "graph",
      { customFetchImpl: mockFetch as never },
    );

    expect(error).toBeNull();
    expect(mockFetch).toHaveBeenCalledTimes(1); // a fresh HTTP call was made
    expect(data?.access_token).toBe("fresh-obo-token-after-expiry");
  });

  it("does not serve a cached token that is within the 60-second expiry buffer", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

    // Seed a cached entry that expires in 30 seconds (within the 60s buffer)
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "obo-graph",
      accountId: user.id,
      accessToken: "almost-expired-obo-token",
      accessTokenExpiresAt: new Date(Date.now() + 30_000),
    });

    const freshResponse = {
      ...MOCK_OBO_RESPONSE,
      access_token: "freshly-fetched-token",
    };
    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify(freshResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const { data } = await exchangeOboToken(
      auth,
      PLUGIN_OPTIONS,
      user.id,
      "graph",
      { customFetchImpl: mockFetch as never },
    );

    // Should have made a fresh HTTP call, not used the near-expired cache
    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(data?.access_token).toBe("freshly-fetched-token");
  });
});

// ---------------------------------------------------------------------------
// Tests: ctx.obo.exchangeToken — via auth.$context
// ---------------------------------------------------------------------------

describe("ctx.obo.exchangeToken — via auth.$context", () => {
  it("exposes ctx.obo on auth.$context after plugin registration", async () => {
    const { auth } = await buildAuth();
    const ctx = await auth.$context;
    expect(ctx.obo).toBeDefined();
    expect(typeof ctx.obo.exchangeToken).toBe("function");
  });

  it("returns the OBO token with options already bound", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    // No pluginOptions argument — options are bound at plugin init time
    const { data, error } = await ctx.obo.exchangeToken(
      user.id,
      "graph",
      { customFetchImpl: mockFetch as never },
    );

    expect(error).toBeNull();
    expect(data?.access_token).toBe("obo-access-token-xyz");
    expect(data?.token_type).toBe("Bearer");
  });

  it("uses the same cache as the standalone helper", async () => {
    const { auth, signInWithTestUser } = await buildAuth();
    const { user } = await signInWithTestUser();

    const ctx = await auth.$context;
    await ctx.internalAdapter.createAccount({
      userId: user.id,
      providerId: "microsoft",
      accountId: "ms-account-id",
      accessToken: "ms-access-token",
      accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
    });

    const mockFetch = vi.fn(async () =>
      new Response(JSON.stringify(MOCK_OBO_RESPONSE), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    // First call via the standalone helper — populates the cache
    await exchangeOboToken(auth, PLUGIN_OPTIONS, user.id, "graph", {
      customFetchImpl: mockFetch as never,
    });
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Second call via ctx.obo — should hit the same cache, no new HTTP request
    const { data, error } = await ctx.obo.exchangeToken(
      user.id,
      "graph",
      { customFetchImpl: mockFetch as never },
    );

    expect(mockFetch).toHaveBeenCalledTimes(1); // still 1
    expect(error).toBeNull();
    expect(data?.access_token).toBe("obo-access-token-xyz");
  });
});

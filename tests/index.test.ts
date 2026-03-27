import { getTestInstance } from "better-auth/test";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { OBO_ERROR_CODES, oboPlugin } from "../src/index";

// ---------------------------------------------------------------------------
// Module mock — intercept $fetch created inside oboPlugin so we control the
// Microsoft Entra ID OBO token exchange without making real HTTP requests.
// ---------------------------------------------------------------------------

const mockOboFetch = vi.fn();

vi.mock("@better-fetch/fetch", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@better-fetch/fetch")>();
  return {
    ...actual,
    createFetch: vi.fn(() => mockOboFetch),
  };
});

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MS_CLIENT_ID = "test-client-id";
const MS_CLIENT_SECRET = "test-client-secret";
const MS_TENANT_ID = "test-tenant-id";

const APP_NAME = "myapp";
const APP_SCOPE = "api://myapp/.default";

// A well-formed successful OBO response from Entra ID.
const successfulOboResponse = {
  data: {
    token_type: "Bearer" as const,
    scope: APP_SCOPE,
    expires_in: 3600,
    ext_expires_in: 5200,
    access_token: "obo-access-token-value",
  },
  error: null,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type AuthContext = Awaited<ReturnType<(typeof import("better-auth"))["betterAuth"]["prototype"]["$context"]>>;

/** Seed a Microsoft account row for a user so getAccessToken can find it. */
async function seedMicrosoftAccount(
  ctx: AuthContext,
  userId: string,
  opts: { accessToken?: string; accessTokenExpiresAt?: Date } = {},
) {
  return ctx.internalAdapter.createAccount({
    accountId: userId,
    providerId: "microsoft",
    userId,
    accessToken: opts.accessToken ?? "ms-user-access-token",
    accessTokenExpiresAt:
      opts.accessTokenExpiresAt ?? new Date(Date.now() + 60 * 60 * 1000),
    scope: "openid profile",
  });
}

/** Seed a cached OBO account row for a user + application. */
async function seedOboAccount(
  ctx: AuthContext,
  userId: string,
  applicationName: string,
  opts: { accessToken?: string; accessTokenExpiresAt?: Date } = {},
) {
  return ctx.internalAdapter.createAccount({
    accountId: crypto.randomUUID(),
    providerId: `microsoft:${applicationName}`,
    userId,
    accessToken: opts.accessToken ?? "cached-obo-token",
    accessTokenExpiresAt:
      opts.accessTokenExpiresAt ?? new Date(Date.now() + 2 * 60 * 60 * 1000),
    scope: APP_SCOPE,
  });
}

/** Delete all accounts for a user. */
async function clearAccounts(ctx: AuthContext, userId: string) {
  const accounts = await ctx.internalAdapter.findAccounts(userId);
  for (const a of accounts) await ctx.internalAdapter.deleteAccount(a.id);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("oboPlugin", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let api: any;
  let ctx: AuthContext;
  let testUserId: string;

  beforeAll(async () => {
    const { auth } = await getTestInstance({
      socialProviders: {
        microsoft: {
          clientId: MS_CLIENT_ID,
          clientSecret: MS_CLIENT_SECRET,
          tenantId: MS_TENANT_ID,
        },
      },
      plugins: [
        oboPlugin({
          applications: {
            [APP_NAME]: { scope: [APP_SCOPE] },
            emptyApp: { scope: [] },
          },
        }),
      ],
    });

    // auth.api infers only HTTP-exposed endpoints; pathless endpoints exist at
    // runtime but are excluded from the TypeScript type, so we cast to any.
    api = auth.api;
    ctx = await auth.$context;

    const user = await ctx.internalAdapter.createUser({
      id: crypto.randomUUID(),
      email: "obo-test@example.com",
      name: "OBO Test User",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    testUserId = user.id;
  });

  beforeEach(() => {
    mockOboFetch.mockReset();
  });

  // -------------------------------------------------------------------------
  // 1. Unknown application
  // -------------------------------------------------------------------------
  it("throws UNKNOWN_APPLICATION for an unconfigured application name", async () => {
    await expect(
      api.getOboToken({ body: { userId: testUserId, applicationName: "nonexistent" } }),
    ).rejects.toMatchObject({
      body: { code: OBO_ERROR_CODES.UNKNOWN_APPLICATION.code },
    });
  });

  // -------------------------------------------------------------------------
  // 2. Empty scope array
  // -------------------------------------------------------------------------
  it("throws MISSING_APPLICATION_SCOPE when application scope is empty", async () => {
    await expect(
      api.getOboToken({ body: { userId: testUserId, applicationName: "emptyApp" } }),
    ).rejects.toMatchObject({
      body: { code: OBO_ERROR_CODES.MISSING_APPLICATION_SCOPE.code },
    });
  });

  // -------------------------------------------------------------------------
  // 3. Valid cached token — returned as-is, no HTTP call
  // -------------------------------------------------------------------------
  it("returns cached OBO account without calling Microsoft when token is fresh", async () => {
    await seedOboAccount(ctx, testUserId, APP_NAME, {
      accessToken: "cached-obo-token",
      accessTokenExpiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000),
    });

    const result = await api.getOboToken({
      body: { userId: testUserId, applicationName: APP_NAME },
    });

    expect(result?.accessToken).toBe("cached-obo-token");
    expect(mockOboFetch).not.toHaveBeenCalled();

    await clearAccounts(ctx, testUserId);
  });

  // -------------------------------------------------------------------------
  // 4. Token within 60s buffer → exchange triggered, account updated
  // -------------------------------------------------------------------------
  it("refreshes OBO token when cached token is within the 60s expiry buffer", async () => {
    await seedOboAccount(ctx, testUserId, APP_NAME, {
      accessToken: "expiring-obo-token",
      accessTokenExpiresAt: new Date(Date.now() + 30_000), // 30s — inside buffer
    });
    await seedMicrosoftAccount(ctx, testUserId);

    mockOboFetch.mockResolvedValueOnce(successfulOboResponse);

    const result = await api.getOboToken({
      body: { userId: testUserId, applicationName: APP_NAME },
    });

    expect(mockOboFetch).toHaveBeenCalledOnce();
    expect(result?.accessToken).toBe("obo-access-token-value");

    await clearAccounts(ctx, testUserId);
  });

  // -------------------------------------------------------------------------
  // 5. No cached account → new OBO exchange, account created
  // -------------------------------------------------------------------------
  it("creates a new OBO account when none exists for the user + application", async () => {
    await seedMicrosoftAccount(ctx, testUserId);

    mockOboFetch.mockResolvedValueOnce(successfulOboResponse);

    const result = await api.getOboToken({
      body: { userId: testUserId, applicationName: APP_NAME },
    });

    expect(mockOboFetch).toHaveBeenCalledOnce();
    expect(result?.accessToken).toBe("obo-access-token-value");
    expect(result?.providerId).toBe(`microsoft:${APP_NAME}`);
    expect(result?.userId).toBe(testUserId);

    await clearAccounts(ctx, testUserId);
  });

  // -------------------------------------------------------------------------
  // 6. No Microsoft account for the user → getAccessToken error propagates
  // -------------------------------------------------------------------------
  it("propagates an error when the user has no Microsoft account", async () => {
    await clearAccounts(ctx, testUserId);

    await expect(
      api.getOboToken({ body: { userId: testUserId, applicationName: APP_NAME } }),
    ).rejects.toThrow();

    expect(mockOboFetch).not.toHaveBeenCalled();
  });

  // -------------------------------------------------------------------------
  // 7. OBO exchange fails → OBO_EXCHANGE_FAILED
  // -------------------------------------------------------------------------
  it("throws OBO_EXCHANGE_FAILED when the Entra ID OBO exchange returns an error", async () => {
    await seedMicrosoftAccount(ctx, testUserId);

    mockOboFetch.mockResolvedValueOnce({
      data: null,
      error: {
        error: "invalid_grant",
        error_description:
          "AADSTS70011: The provided request must include a 'scope' input parameter.",
      },
    });

    await expect(
      api.getOboToken({ body: { userId: testUserId, applicationName: APP_NAME } }),
    ).rejects.toMatchObject({
      body: { code: OBO_ERROR_CODES.OBO_EXCHANGE_FAILED.code },
    });

    await clearAccounts(ctx, testUserId);
  });

  // -------------------------------------------------------------------------
  // 8. No Microsoft provider configured → MISSING_CREDENTIALS
  // -------------------------------------------------------------------------
  it("throws MISSING_CREDENTIALS when the Microsoft social provider is not configured", async () => {
    const { auth: authWithoutMs } = await getTestInstance({
      plugins: [
        oboPlugin({
          applications: { [APP_NAME]: { scope: [APP_SCOPE] } },
        }),
      ],
    });

    const ctxWithoutMs = await authWithoutMs.$context;
    const user = await ctxWithoutMs.internalAdapter.createUser({
      id: crypto.randomUUID(),
      email: "no-ms@example.com",
      name: "No MS User",
      emailVerified: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    await expect(
      (authWithoutMs.api as any).getOboToken({
        body: { userId: user.id, applicationName: APP_NAME },
      }),
    ).rejects.toMatchObject({
      body: { code: OBO_ERROR_CODES.MISSING_CREDENTIALS.code },
    });
  });

  // -------------------------------------------------------------------------
  // 9. accessTokenExpiresAt is computed correctly from expires_in
  // -------------------------------------------------------------------------
  it("sets accessTokenExpiresAt to approximately now + expires_in seconds", async () => {
    await seedMicrosoftAccount(ctx, testUserId);

    const expiresIn = 3600;
    const before = Date.now();

    mockOboFetch.mockResolvedValueOnce({
      data: {
        token_type: "Bearer" as const,
        scope: APP_SCOPE,
        expires_in: expiresIn,
        ext_expires_in: 5200,
        access_token: "fresh-obo-token",
      },
      error: null,
    });

    const result = await api.getOboToken({
      body: { userId: testUserId, applicationName: APP_NAME },
    });

    const after = Date.now();
    const expiresAtMs = result?.accessTokenExpiresAt?.getTime() ?? 0;

    expect(expiresAtMs).toBeGreaterThanOrEqual(before + expiresIn * 1000);
    expect(expiresAtMs).toBeLessThanOrEqual(after + expiresIn * 1000);

    await clearAccounts(ctx, testUserId);
  });
});

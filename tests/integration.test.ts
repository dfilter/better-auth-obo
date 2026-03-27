import { getTestInstance } from "better-auth/test";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { OBO_ERROR_CODES, oboPlugin } from "../src/index";

// ---------------------------------------------------------------------------
// Environment variables (loaded via --env-file=.env.test)
// ---------------------------------------------------------------------------

const ACCESS_TOKEN = process.env.VITE_ENTRA_ACCESS_TOKEN ?? "";
const CLIENT_ID = process.env.VITE_ENTRA_CLIENT_ID ?? "";
const CLIENT_SECRET = process.env.VITE_ENTRA_CLIENT_SECRET ?? "";
const TENANT_ID = process.env.VITE_ENTRA_TENANT_ID ?? "";
const OBO_SCOPE = process.env.VITE_ENTRA_OBO_SCOPE ?? "";

// ---------------------------------------------------------------------------
// Token expiry guard — decode the JWT payload without verifying the signature
// ---------------------------------------------------------------------------

function decodeJwtPayload(token: string): Record<string, unknown> {
  try {
    return JSON.parse(
      Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"),
    );
  } catch {
    return {};
  }
}

const jwtPayload = decodeJwtPayload(ACCESS_TOKEN);
const tokenExp = typeof jwtPayload.exp === "number" ? jwtPayload.exp : 0;
const tokenExpired = Date.now() > tokenExp * 1000;
const tokenExpiresAt = new Date(tokenExp * 1000);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type AuthContext = Awaited<
  ReturnType<(typeof import("better-auth"))["betterAuth"]["prototype"]["$context"]>
>;

async function clearAccounts(ctx: AuthContext, userId: string) {
  const accounts = await ctx.internalAdapter.findAccounts(userId);
  for (const a of accounts) await ctx.internalAdapter.deleteAccount(a.id);
}

// ---------------------------------------------------------------------------
// Integration tests
// Skip the entire suite if the access token in .env.test is expired.
// To refresh it, sign in to the app and copy a new VITE_ENTRA_ACCESS_TOKEN.
// ---------------------------------------------------------------------------

describe.skipIf(tokenExpired)(
  "oboPlugin integration (live Entra ID)",
  () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let api: any;
    let ctx: AuthContext;
    let testUserId: string;

    beforeAll(async () => {
      const { auth } = await getTestInstance({
        socialProviders: {
          microsoft: {
            clientId: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            tenantId: TENANT_ID,
          },
        },
        plugins: [
          oboPlugin({
            applications: {
              downstream: { scope: OBO_SCOPE.split(",") },
            },
          }),
        ],
      });

      api = auth.api;
      ctx = await auth.$context;

      const user = await ctx.internalAdapter.createUser({
        id: crypto.randomUUID(),
        email: "integration-test@example.com",
        name: "Integration Test User",
        emailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      testUserId = user.id;

      // Seed the user's Microsoft account using the real access token from
      // .env.test. accessTokenExpiresAt is set from the JWT exp claim so
      // getAccessToken won't try to refresh it (it's not expired yet).
      await ctx.internalAdapter.createAccount({
        accountId: testUserId,
        providerId: "microsoft",
        userId: testUserId,
        accessToken: ACCESS_TOKEN,
        accessTokenExpiresAt: tokenExpiresAt,
        scope: "access-as",
      });
    });

    afterEach(async () => {
      // Remove any OBO account rows created during the test, leaving the
      // seeded Microsoft account intact for subsequent tests.
      const accounts = await ctx.internalAdapter.findAccounts(testUserId);
      for (const a of accounts) {
        if (a.providerId !== "microsoft") {
          await ctx.internalAdapter.deleteAccount(a.id);
        }
      }
    });

    // -----------------------------------------------------------------------
    // 1. Happy path — real OBO exchange succeeds
    // -----------------------------------------------------------------------
    it("exchanges the user access token for an OBO token via Entra ID", async () => {
      const result = await api.getOboToken({
        body: { userId: testUserId, applicationName: "downstream" },
      });

      expect(result).toBeTruthy();
      expect(typeof result.accessToken).toBe("string");
      expect(result.accessToken.length).toBeGreaterThan(0);
      expect(result.providerId).toBe("microsoft:downstream");
      expect(result.userId).toBe(testUserId);
      expect(result.accessTokenExpiresAt).toBeInstanceOf(Date);
      expect(result.accessTokenExpiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    // -----------------------------------------------------------------------
    // 2. Cached token returned on second call — no second exchange
    // -----------------------------------------------------------------------
    it("returns the cached OBO token on subsequent calls without a new exchange", async () => {
      const first = await api.getOboToken({
        body: { userId: testUserId, applicationName: "downstream" },
      });

      const second = await api.getOboToken({
        body: { userId: testUserId, applicationName: "downstream" },
      });

      // Both calls must return the same access token — the second one was served
      // from the cache without hitting Entra ID again.
      expect(second.accessToken).toBe(first.accessToken);
      expect(second.accessTokenExpiresAt.getTime()).toBe(
        first.accessTokenExpiresAt.getTime(),
      );
    });

    // -----------------------------------------------------------------------
    // 3. Invalid access token → Entra rejects it → OBO_EXCHANGE_FAILED
    // -----------------------------------------------------------------------
    it("throws OBO_EXCHANGE_FAILED when the stored access token is invalid", async () => {
      // Create a separate user whose Microsoft account holds a bogus token.
      const badUser = await ctx.internalAdapter.createUser({
        id: crypto.randomUUID(),
        email: "bad-token@example.com",
        name: "Bad Token User",
        emailVerified: true,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      await ctx.internalAdapter.createAccount({
        accountId: badUser.id,
        providerId: "microsoft",
        userId: badUser.id,
        accessToken: "this-is-not-a-valid-token",
        accessTokenExpiresAt: new Date(Date.now() + 60 * 60 * 1000),
        scope: "access-as",
      });

      try {
        await expect(
          api.getOboToken({
            body: { userId: badUser.id, applicationName: "downstream" },
          }),
        ).rejects.toMatchObject({
          body: { code: OBO_ERROR_CODES.OBO_EXCHANGE_FAILED.code },
        });
      } finally {
        await clearAccounts(ctx, badUser.id);
        await ctx.internalAdapter.deleteUser(badUser.id);
      }
    });
  },
);

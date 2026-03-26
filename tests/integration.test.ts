/**
 * Integration tests for the OBO plugin against real Microsoft Entra ID endpoints.
 *
 * Run with:
 *   pnpm test:integration
 *
 * Requires a `.env.test` file with:
 *   VITE_ENTRA_CLIENT_ID      – middle-tier app client ID
 *   VITE_ENTRA_CLIENT_SECRET  – middle-tier app client secret
 *   VITE_ENTRA_TENANT_ID      – Azure AD tenant ID (must be specific, not "common")
 *   VITE_ENTRA_OBO_SCOPE      – comma-separated downstream scope
 *   VITE_ENTRA_ACCESS_TOKEN   – a valid delegated access token issued to VITE_ENTRA_CLIENT_ID
 *
 * All tests are skipped when any of the above variables are absent so that CI
 * without secrets does not fail.
 */

import { isAPIError } from "better-auth/api";
import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import { getOboToken, OBO_ERROR_CODES, oboPlugin, type OboPluginOptions } from "../src/index.js";

// ---------------------------------------------------------------------------
// Guard — skip everything when credentials are not available
// ---------------------------------------------------------------------------

const hasCredentials =
  !!process.env.VITE_ENTRA_CLIENT_ID &&
  !!process.env.VITE_ENTRA_CLIENT_SECRET &&
  !!process.env.VITE_ENTRA_TENANT_ID &&
  !!(process.env.VITE_ENTRA_OBO_SCOPE ?? process.env.VITE_ENTRA_OBO_SCOPES) &&
  !!process.env.VITE_ENTRA_ACCESS_TOKEN;

const oboScope = (process.env.VITE_ENTRA_OBO_SCOPE ?? process.env.VITE_ENTRA_OBO_SCOPES ?? "")
  .split(",")
  .filter(Boolean);

// ---------------------------------------------------------------------------
// Shared auth instance
// ---------------------------------------------------------------------------

async function buildIntegrationAuth() {
  const { auth, signInWithTestUser } = await getTestInstance({
    socialProviders: {
      microsoft: {
        clientId: process.env.VITE_ENTRA_CLIENT_ID!,
        clientSecret: process.env.VITE_ENTRA_CLIENT_SECRET!,
        tenantId: process.env.VITE_ENTRA_TENANT_ID!,
      },
    },
    plugins: [
      oboPlugin({
        applications: { downstream: { scope: oboScope } },
      }),
    ],
  });

  const { user } = await signInWithTestUser();
  const ctx = await auth.$context;

  await ctx.internalAdapter.createAccount({
    userId: user.id,
    providerId: "microsoft",
    accountId: user.id,
    accessToken: process.env.VITE_ENTRA_ACCESS_TOKEN!,
    accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
  });

  return { auth, ctx, user };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("OBO integration — real Entra ID token exchange", () => {
  it.skipIf(!hasCredentials)(
    "auth.api.getOboToken performs a successful OBO exchange and returns an Account",
    async () => {
      const { auth, user } = await buildIntegrationAuth();

      const account = await auth.api.getOboToken({
        body: { userId: user.id, applicationName: "downstream" },
      });

      expect(typeof account.accessToken).toBe("string");
      expect(account.accessToken!.length).toBeGreaterThan(0);
      expect(account.providerId).toBe("obo-downstream");
      expect(account.userId).toBe(user.id);
      expect(account.accessTokenExpiresAt).toBeInstanceOf(Date);
      expect(account.accessTokenExpiresAt!.getTime()).toBeGreaterThan(Date.now());
      const returnedScope = (account.scope ?? "").split(" ");
      const requestedScope = oboScope.flatMap((s) => s.split(" "));
      expect(returnedScope.some((s) => requestedScope.includes(s))).toBe(true);
    },
    30_000,
  );

  it.skipIf(!hasCredentials)(
    "OBO token is written to the account cache after exchange",
    async () => {
      const { auth, ctx, user } = await buildIntegrationAuth();

      await auth.api.getOboToken({
        body: { userId: user.id, applicationName: "downstream" },
      });

      const cached = await ctx.internalAdapter.findAccountByProviderId(
        user.id,
        "obo-downstream",
      );

      expect(cached).not.toBeNull();
      expect(typeof cached?.accessToken).toBe("string");
      expect(cached!.accessToken!.length).toBeGreaterThan(0);
      expect(cached?.accessTokenExpiresAt).toBeInstanceOf(Date);
      expect(cached!.accessTokenExpiresAt!.getTime()).toBeGreaterThan(Date.now());
    },
    30_000,
  );

  it.skipIf(!hasCredentials)(
    "second call returns the cached Account row without a new HTTP request",
    async () => {
      const { auth, user } = await buildIntegrationAuth();

      const first = await auth.api.getOboToken({
        body: { userId: user.id, applicationName: "downstream" },
      });

      const second = await auth.api.getOboToken({
        body: { userId: user.id, applicationName: "downstream" },
      });

      expect(second.id).toBe(first.id);
      expect(second.accessToken).toBe(first.accessToken);
    },
    30_000,
  );

  it.skipIf(!hasCredentials)(
    "standalone getOboToken with explicit defaultConfig performs a successful exchange",
    async () => {
      const { auth, signInWithTestUser } = await getTestInstance({
        plugins: [
          oboPlugin({
            defaultConfig: {
              clientId: process.env.VITE_ENTRA_CLIENT_ID!,
              clientSecret: process.env.VITE_ENTRA_CLIENT_SECRET!,
              tenantId: process.env.VITE_ENTRA_TENANT_ID!,
            },
            applications: { downstream: { scope: oboScope } },
          }),
        ],
      });
      const { user } = await signInWithTestUser();
      const ctx = await auth.$context;

      await ctx.internalAdapter.createAccount({
        userId: user.id,
        providerId: "microsoft",
        accountId: user.id,
        accessToken: process.env.VITE_ENTRA_ACCESS_TOKEN!,
        accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
      });

      const pluginOptions: OboPluginOptions = {
        defaultConfig: {
          clientId: process.env.VITE_ENTRA_CLIENT_ID!,
          clientSecret: process.env.VITE_ENTRA_CLIENT_SECRET!,
          tenantId: process.env.VITE_ENTRA_TENANT_ID!,
        },
        applications: { downstream: { scope: oboScope } },
      };

      const account = await getOboToken(auth, pluginOptions, {
        userId: user.id,
        applicationName: "downstream",
      });

      expect(typeof account.accessToken).toBe("string");
      expect(account.accessToken!.length).toBeGreaterThan(0);
      expect(account.providerId).toBe("obo-downstream");
    },
    30_000,
  );

  it.skipIf(!hasCredentials)(
    "throws APIError BAD_GATEWAY / OBO_EXCHANGE_FAILED with Entra ID error details when assertion is invalid",
    async () => {
      const { auth, signInWithTestUser } = await getTestInstance({
        socialProviders: {
          microsoft: {
            clientId: process.env.VITE_ENTRA_CLIENT_ID!,
            clientSecret: process.env.VITE_ENTRA_CLIENT_SECRET!,
            tenantId: process.env.VITE_ENTRA_TENANT_ID!,
          },
        },
        plugins: [
          oboPlugin({
            applications: { downstream: { scope: oboScope } },
          }),
        ],
      });
      const { user } = await signInWithTestUser();
      const ctx = await auth.$context;

      await ctx.internalAdapter.createAccount({
        userId: user.id,
        providerId: "microsoft",
        accountId: user.id,
        accessToken: "this-is-not-a-valid-token",
        accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
      });

      try {
        await auth.api.getOboToken({
          body: { userId: user.id, applicationName: "downstream" },
        });
        expect.fail("Expected APIError to be thrown");
      } catch (e) {
        expect(isAPIError(e)).toBe(true);
        if (isAPIError(e)) {
          expect(e.status).toBe("BAD_GATEWAY");
          expect(e.body?.code).toBe(OBO_ERROR_CODES.OBO_EXCHANGE_FAILED.code);
          // Entra ID error fields should be present on the body
          expect(typeof e.body?.error).toBe("string");
          expect(typeof e.body?.error_description).toBe("string");
        }
      }
    },
    30_000,
  );
});

/**
 * Integration tests for the OBO plugin against real Microsoft Entra ID endpoints.
 *
 * Run with:
 *   pnpm test:integration
 *
 * Requires a `.env` file with:
 *   VITE_ENTRA_CLIENT_ID      – middle-tier app client ID
 *   VITE_ENTRA_CLIENT_SECRET  – middle-tier app client secret
 *   VITE_ENTRA_TENANT_ID      – Azure AD tenant ID (must be specific, not "common")
 *   VITE_ENTRA_OBO_SCOPES     – comma-separated downstream scopes
 *   VITE_ENTRA_ACCESS_TOKEN   – a valid delegated access token issued to ENTRA_CLIENT_ID
 *
 * All tests are skipped when any of the above variables are absent so that CI
 * without secrets does not fail.
 */

import { getTestInstance } from "better-auth/test";
import { describe, expect, it } from "vitest";
import {
  exchangeOboToken,
  oboPlugin,
  type OboPluginOptions,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Guard — skip everything when credentials are not available
// ---------------------------------------------------------------------------

const hasCredentials =
  !!process.env.VITE_ENTRA_CLIENT_ID &&
  !!process.env.VITE_ENTRA_CLIENT_SECRET &&
  !!process.env.VITE_ENTRA_TENANT_ID &&
  !!process.env.VITE_ENTRA_OBO_SCOPES &&
  !!process.env.VITE_ENTRA_ACCESS_TOKEN;

const oboScopes = (process.env.VITE_ENTRA_OBO_SCOPES ?? "")
  .split(",")
  .filter(Boolean);

// ---------------------------------------------------------------------------
// Shared auth instance — credentials from the Microsoft social provider config
// so that the credential-fallback path is exercised end-to-end.
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
        // No defaultConfig — all credentials fall back to the social provider above
        applications: {
          downstream: { scopes: oboScopes },
        },
      }),
    ],
  });

  const { user } = await signInWithTestUser();
  const ctx = await auth.$context;

  // Seed a microsoft account row for the test user containing the real
  // access token. This mirrors what Better Auth stores after a real OAuth
  // sign-in via the Microsoft social provider.
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
    "ctx.obo.exchangeToken performs a successful OBO exchange",
    async () => {
      const { ctx, user } = await buildIntegrationAuth();

      const { data, error } = await ctx.obo.exchangeToken(
        user.id,
        "downstream",
      );

      expect(error).toBeNull();
      expect(data).not.toBeNull();
      expect(data?.token_type).toBe("Bearer");
      expect(typeof data?.access_token).toBe("string");
      expect(data!.access_token.length).toBeGreaterThan(0);
      expect(data?.expires_in).toBeGreaterThan(0);
      // The returned scope must contain at least one of the requested scopes
      const returnedScopes = data!.scope.split(" ");
      const requestedScopes = oboScopes.flatMap((s) => s.split(" "));
      expect(returnedScopes.some((s) => requestedScopes.includes(s))).toBe(
        true,
      );
    },
    30_000,
  );

  it.skipIf(!hasCredentials)(
    "OBO token is written to the account cache after exchange",
    async () => {
      const { ctx, user } = await buildIntegrationAuth();

      await ctx.obo.exchangeToken(user.id, "downstream");

      const cached = await ctx.internalAdapter.findAccountByProviderId(
        user.id,
        "obo-downstream",
      );

      expect(cached).not.toBeNull();
      expect(typeof cached?.accessToken).toBe("string");
      expect(cached!.accessToken!.length).toBeGreaterThan(0);
      expect(cached?.accessTokenExpiresAt).toBeInstanceOf(Date);
      expect(cached!.accessTokenExpiresAt!.getTime()).toBeGreaterThan(
        Date.now(),
      );
    },
    30_000,
  );

  it.skipIf(!hasCredentials)(
    "second call returns the cached token without a new HTTP request",
    async () => {
      const { ctx, user } = await buildIntegrationAuth();

      // First call — hits Entra ID, populates the cache
      const { data: first } = await ctx.obo.exchangeToken(
        user.id,
        "downstream",
      );
      expect(first).not.toBeNull();

      // Second call — must be served from cache; expires_in will be slightly
      // less because it is calculated from the stored accessTokenExpiresAt
      // rather than reset to a fresh 3600.
      const { data: second, error } = await ctx.obo.exchangeToken(
        user.id,
        "downstream",
      );

      expect(error).toBeNull();
      expect(second?.access_token).toBe(first?.access_token);
      // expires_in from cache is derived from time remaining, so it must be
      // ≤ the original (could be equal if the two calls happen in the same ms)
      expect(second!.expires_in).toBeLessThanOrEqual(first!.expires_in);
    },
    30_000,
  );

  it.skipIf(!hasCredentials)(
    "standalone exchangeOboToken with explicit defaultConfig performs a successful exchange",
    async () => {
      // This exercises the standalone path where credentials are supplied
      // explicitly in pluginOptions rather than via social provider fallback.
      const { auth, signInWithTestUser } = await getTestInstance({
        plugins: [
          oboPlugin({
            defaultConfig: {
              clientId: process.env.VITE_ENTRA_CLIENT_ID!,
              clientSecret: process.env.VITE_ENTRA_CLIENT_SECRET!,
              tenantId: process.env.VITE_ENTRA_TENANT_ID!,
            },
            applications: {
              downstream: { scopes: oboScopes },
            },
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
        applications: {
          downstream: { scopes: oboScopes },
        },
      };

      const { data, error } = await exchangeOboToken(
        auth,
        pluginOptions,
        user.id,
        "downstream",
      );

      expect(error).toBeNull();
      expect(data?.token_type).toBe("Bearer");
      expect(typeof data?.access_token).toBe("string");
      expect(data!.access_token.length).toBeGreaterThan(0);
    },
    30_000,
  );

  it.skipIf(!hasCredentials)(
    "returns a structured error when the assertion token is invalid",
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
            applications: {
              downstream: { scopes: oboScopes },
            },
          }),
        ],
      });
      const { user } = await signInWithTestUser();
      const ctx = await auth.$context;

      // Seed a microsoft account with a deliberately invalid access token
      await ctx.internalAdapter.createAccount({
        userId: user.id,
        providerId: "microsoft",
        accountId: user.id,
        accessToken: "this-is-not-a-valid-token",
        accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
      });

      const { data, error } = await ctx.obo.exchangeToken(
        user.id,
        "downstream",
      );

      expect(data).toBeNull();
      expect(error).not.toBeNull();
      expect(error).toContain("OBO token exchange failed");
    },
    30_000,
  );
});

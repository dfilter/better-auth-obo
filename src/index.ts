import { betterFetch, type BetterFetchOption } from "@better-fetch/fetch";
import type { Account, BetterAuthPlugin, InternalAdapter } from "better-auth";
import { APIError, BetterAuthError, defineErrorCodes } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import { z } from "zod";

/**
 * Minimal structural type for a Better Auth instance.
 * Using a structural type instead of the concrete `Auth<Options>` ensures
 * that `getOboToken` is compatible with any `Auth<Options>` regardless of
 * how narrowly TypeScript has inferred the `Options` type parameter.
 */
export type AuthLike = {
  $context: Promise<{ internalAdapter: InternalAdapter }>;
};

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/**
 * Machine-readable error codes for the OBO plugin.
 * These are registered on `auth.$ERROR_CODES` and included in the `code`
 * field of thrown `APIError` instances.
 *
 * @example
 * ```ts
 * import { isAPIError } from "better-auth/api";
 *
 * try {
 *   const account = await auth.api.getOboToken({ body: { userId, applicationName: "graph" } });
 * } catch (e) {
 *   if (isAPIError(e)) {
 *     switch (e.body.code) {
 *       case "MICROSOFT_ACCOUNT_NOT_FOUND": // user hasn't signed in via Microsoft
 *       case "OBO_EXCHANGE_FAILED":          // Entra ID rejected the exchange
 *       case "UNKNOWN_APPLICATION":          // applicationName not in plugin config
 *     }
 *   }
 * }
 * ```
 */
export const OBO_ERROR_CODES = defineErrorCodes({
  UNKNOWN_APPLICATION:
    "The requested application is not configured in oboPlugin",
  MISSING_APPLICATION_SCOPE:
    "The application config is missing required scope",
  MICROSOFT_ACCOUNT_NOT_FOUND:
    "No Microsoft access token found for this user — ensure the user signed in via the Microsoft social provider",
  OBO_EXCHANGE_FAILED:
    "The OBO token exchange with Microsoft Entra ID failed",
  MISSING_CREDENTIALS:
    "Required OBO credentials could not be resolved — provide them in oboPlugin({ defaultConfig }) or configure the Microsoft social provider",
});

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Configuration for the middle-tier application that performs the OBO exchange.
 *
 * All fields are optional — any that are omitted will be read from the
 * Microsoft social provider config already registered with Better Auth
 * (i.e. `socialProviders: { microsoft: { clientId, clientSecret, tenantId, authority } }`).
 *
 * Fields set here take precedence over the social provider config.
 *
 * Note on `authority` / `tenantId`: Microsoft explicitly recommends against
 * using `/common` or `/organizations` for OBO (especially with guest users).
 * The token endpoint must target the user's specific tenant. If your Microsoft
 * social provider is configured with `tenantId: "common"` (the default) you
 * must supply an explicit `tenantId` or `authority` here.
 */
type OboDefaultConfig = {
  /**
   * Token endpoint authority, e.g. `https://login.microsoftonline.com/my-tenant`.
   * Takes precedence over `tenantId`. Falls back to the social provider's
   * `authority` + `tenantId` if omitted.
   */
  authority?: string;
  /**
   * Convenience alternative to `authority`. Derives
   * `https://login.microsoftonline.com/<tenantId>`.
   * Falls back to the social provider's `tenantId` if omitted.
   */
  tenantId?: string;
  /**
   * Azure AD Application (client) ID of the middle-tier app.
   * Falls back to the social provider's `clientId` if omitted.
   */
  clientId?: string;
  /**
   * Azure AD client secret of the middle-tier app.
   * Falls back to the social provider's `clientSecret` if omitted.
   */
  clientSecret?: string;
};

/**
 * Per-downstream-application config.
 *
 * The only thing that varies between downstream applications is the set of
 * scope you want the OBO token to carry.
 */
type ApplicationConfig = {
  /** An optional stable identifier for this application entry. */
  id?: string;
  /**
   * Downstream API scope to request, e.g.
   * `["https://graph.microsoft.com/.default"]`.
   */
  scope: string[];
};

type ApplicationsConfig = {
  [applicationName: string]: ApplicationConfig;
};

/**
 * Options passed to `oboPlugin()`.
 *
 * Generic over `TApplications` so that `applicationName` in `GetOboTokenParams`
 * is narrowed to the exact keys of the `applications` object you provide.
 */
type OboPluginOptions<
  TApplications extends ApplicationsConfig = ApplicationsConfig,
> = {
  /**
   * Middle-tier application credentials and token endpoint overrides.
   * Any field omitted here is read from the Microsoft social provider config.
   * The entire `defaultConfig` object may be omitted if the social provider
   * config already contains all required fields with a specific (non-"common")
   * `tenantId`.
   */
  defaultConfig?: OboDefaultConfig;
  /**
   * Named downstream applications to exchange tokens for.
   * Keys become the valid values for `applicationName` in `GetOboTokenParams`.
   */
  applications: TApplications;
};

/**
 * Parameters for the standalone `getOboToken` helper.
 *
 * Generic over `TApplications` so `applicationName` is narrowed to the exact
 * keys of the `applications` object passed to `oboPlugin`.
 */
export type GetOboTokenParams<
  TApplications extends ApplicationsConfig = ApplicationsConfig,
> = {
  /** The Better Auth user ID to act on behalf of. */
  userId: string;
  /** A key from the `applications` config passed to `oboPlugin`. */
  applicationName: keyof TApplications & string;
  /** Optional `@better-fetch/fetch` overrides (e.g. custom fetch impl for tests). */
  fetchOptions?: BetterFetchOption;
};

/** Successful response from the Microsoft token endpoint — internal only. */
type MicrosoftOBOToken = {
  token_type: "Bearer";
  scope: string;
  expires_in: number;
  ext_expires_in: number;
  access_token: string;
  refresh_token?: string;
};

/**
 * The raw error response body returned by Microsoft Entra ID when an OBO
 * exchange fails. These fields are spread onto the thrown `APIError`'s body
 * alongside the standard `code` and `message` fields, so you can access them
 * from `e.body` after catching an `APIError` with code `"OBO_EXCHANGE_FAILED"`.
 */
export type MicrosoftOBOError = {
  error: string;
  error_description?: string;
  error_codes?: number[];
  timestamp?: string;
  trace_id?: string;
  correlation_id?: string;
};

/**
 * Fully resolved credentials — all fields required.
 * Built once per plugin instance (lazily on first endpoint call) by merging
 * `defaultConfig` over the Microsoft social provider config.
 */
type ResolvedCredentials = {
  authority: string;
  clientId: string;
  clientSecret: string;
};

/** Fully resolved per-call config — credentials + application scope. */
type ResolvedConfig = ResolvedCredentials & ApplicationConfig;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Minimal shape we read off the social provider's `options` object.
 * Typed loosely so we don't depend on the `MicrosoftOptions` import.
 */
type MicrosoftProviderOptions = {
  clientId?: string;
  clientSecret?: string;
  tenantId?: string;
  authority?: string;
};

/**
 * Resolve the OBO credentials by merging `defaultConfig` (explicit overrides)
 * over the Microsoft social provider config (fallback).
 *
 * Emits a console warning if the effective `tenantId` is `"common"` or
 * `"organizations"`, since Microsoft explicitly discourages those for OBO.
 *
 * Throws `BetterAuthError` if any required credential is missing — this is a
 * developer misconfiguration caught at init/first-call time, not a request failure.
 */
function resolveCredentials(
  defaultConfig: OboDefaultConfig | undefined,
  msProviderOptions: MicrosoftProviderOptions | undefined,
): ResolvedCredentials {
  const clientId = defaultConfig?.clientId ?? msProviderOptions?.clientId;
  const clientSecret =
    defaultConfig?.clientSecret ?? msProviderOptions?.clientSecret;

  // Authority resolution:
  //   1. explicit authority in defaultConfig
  //   2. explicit tenantId in defaultConfig → derive URL
  //   3. social provider authority + social provider tenantId → combine
  //   4. social provider tenantId alone → derive URL
  const effectiveTenantId =
    defaultConfig?.tenantId ?? msProviderOptions?.tenantId;
  const baseAuthority =
    defaultConfig?.authority ??
    (defaultConfig?.tenantId
      ? `https://login.microsoftonline.com/${defaultConfig.tenantId}`
      : msProviderOptions?.authority
        ? effectiveTenantId
          ? `${msProviderOptions.authority}/${effectiveTenantId}`
          : msProviderOptions.authority
        : effectiveTenantId
          ? `https://login.microsoftonline.com/${effectiveTenantId}`
          : undefined);

  const missing: string[] = [];
  if (!clientId) missing.push("clientId");
  if (!clientSecret) missing.push("clientSecret");
  if (!baseAuthority) missing.push("authority (or tenantId)");

  if (missing.length > 0) {
    throw new BetterAuthError(
      `${OBO_ERROR_CODES.MISSING_CREDENTIALS.message}. Missing: ${missing.join(", ")}.`,
    );
  }

  // Warn about multi-tenant endpoints — OBO requires a specific tenant.
  if (effectiveTenantId === "common" || effectiveTenantId === "organizations") {
    console.warn(
      `[obo-plugin] Warning: tenantId is "${effectiveTenantId}". ` +
        `Microsoft recommends using a specific tenant ID for OBO flows, ` +
        `especially with guest users. Set a specific tenantId or authority ` +
        `in oboPlugin({ defaultConfig }).`,
    );
  }

  return {
    authority: baseAuthority!,
    clientId: clientId!,
    clientSecret: clientSecret!,
  };
}

/**
 * Look up a per-application config and combine it with already-resolved
 * credentials to produce a fully resolved per-call config.
 *
 * Throws `APIError` (BAD_REQUEST) if the application name is unknown or
 * its scope list is empty — these are caller errors.
 */
function resolveConfig(
  credentials: ResolvedCredentials,
  pluginOptions: OboPluginOptions,
  applicationName: string,
): ResolvedConfig {
  const appConfig = pluginOptions.applications[applicationName];
  if (!appConfig) {
    throw APIError.from("BAD_REQUEST", {
      ...OBO_ERROR_CODES.UNKNOWN_APPLICATION,
      message:
        `${OBO_ERROR_CODES.UNKNOWN_APPLICATION.message}: "${applicationName}". ` +
        `Available applications: ${Object.keys(pluginOptions.applications).join(", ")}`,
    });
  }
  if (!appConfig.scope?.length) {
    throw APIError.from("BAD_REQUEST", {
      ...OBO_ERROR_CODES.MISSING_APPLICATION_SCOPE,
      message:
        `${OBO_ERROR_CODES.MISSING_APPLICATION_SCOPE.message}: "${applicationName}"`,
    });
  }
  return { ...credentials, ...appConfig };
}

/**
 * The `providerId` used when caching OBO tokens in the `account` table.
 * Using a namespaced value avoids any collisions with real social providers.
 */
function oboProviderId(applicationName: string): string {
  return `obo-${applicationName}`;
}

/**
 * Perform the Microsoft OBO token exchange HTTP call.
 */
function fetchOboToken(
  config: ResolvedConfig,
  assertion: string,
  fetchOptions?: BetterFetchOption,
): ReturnType<typeof betterFetch<MicrosoftOBOToken>> {
  const url = `${config.authority}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
    requested_token_use: "on_behalf_of",
    scope: config.scope.join(" "),
  });
  return betterFetch<MicrosoftOBOToken>(url, {
    ...fetchOptions,
    body,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    method: "POST",
  });
}

// ---------------------------------------------------------------------------
// Core implementation (private)
// ---------------------------------------------------------------------------

/**
 * Internal implementation of the OBO token exchange.
 * Accepts pre-resolved `credentials` and the raw `InternalAdapter` directly
 * so it can be called from both the plugin endpoint and the standalone helper.
 *
 * Throws `APIError` on all failure cases so that `auth.api` re-throws to the
 * caller and the standalone helper propagates the error naturally.
 */
async function _getOboToken<TApplications extends ApplicationsConfig>(
  adapter: InternalAdapter,
  credentials: ResolvedCredentials,
  pluginOptions: OboPluginOptions<TApplications>,
  params: GetOboTokenParams<TApplications>,
): Promise<Account> {
  const { userId, applicationName, fetchOptions } = params;

  // 1. Resolve per-application config (throws APIError BAD_REQUEST on invalid name/scope)
  const config = resolveConfig(credentials, pluginOptions, applicationName);

  const providerId = oboProviderId(applicationName);

  // 2. Check the OBO token cache (synthetic account row)
  const cachedAccount = await adapter.findAccountByProviderId(
    userId,
    providerId,
  );
  const now = Date.now();
  const bufferMs = 60_000; // 60-second expiry buffer

  if (
    cachedAccount?.accessToken &&
    cachedAccount.accessTokenExpiresAt &&
    cachedAccount.accessTokenExpiresAt.getTime() - now > bufferMs
  ) {
    return cachedAccount;
  }

  // 3. Look up the user's real Microsoft account to get the assertion token
  const accounts = await adapter.findAccounts(userId);
  const msAccount = accounts.find((a) => a.providerId === "microsoft");

  if (!msAccount?.accessToken) {
    throw APIError.from("NOT_FOUND", {
      ...OBO_ERROR_CODES.MICROSOFT_ACCOUNT_NOT_FOUND,
      message:
        `${OBO_ERROR_CODES.MICROSOFT_ACCOUNT_NOT_FOUND.message} (userId: "${userId}")`,
    });
  }

  // 4. Perform the OBO token exchange
  const { data: oboToken, error: fetchError } = await fetchOboToken(
    config,
    msAccount.accessToken,
    fetchOptions,
  );

  if (fetchError || !oboToken) {
    // Spread fetchError directly — it is typed as
    // { status: number; statusText: string } & MicrosoftOBOError | null,
    // so all Entra ID fields (error, error_description, error_codes, trace_id,
    // correlation_id) are included. Spreading null is a no-op.
    throw APIError.fromStatus("BAD_GATEWAY", {
      message: OBO_ERROR_CODES.OBO_EXCHANGE_FAILED.message,
      code: OBO_ERROR_CODES.OBO_EXCHANGE_FAILED.code,
      ...fetchError,
    });
  }

  // 5. Upsert the OBO token into the account table for caching.
  //    Both createAccount and updateAccount return the persisted Account row,
  //    which we return directly.
  const expiresAt = new Date(now + oboToken.expires_in * 1000);
  const tokenData = {
    accessToken: oboToken.access_token,
    accessTokenExpiresAt: expiresAt,
    scope: oboToken.scope,
    refreshToken: oboToken.refresh_token,
  };

  try {
    return cachedAccount
      ? await adapter.updateAccount(cachedAccount.id, tokenData)
      : await adapter.createAccount({
          userId,
          providerId,
          accountId: userId, // no real "accountId" for an OBO token — use userId
          ...tokenData,
        });
  } catch {
    // Caching failure is non-fatal — return a synthetic Account-shaped object
    // built from the exchange response so the caller still gets a usable token.
    return {
      id: cachedAccount?.id ?? "",
      createdAt: cachedAccount?.createdAt ?? new Date(now),
      updatedAt: new Date(now),
      providerId,
      accountId: userId,
      userId,
      ...tokenData,
    } satisfies Account;
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

/**
 * Better Auth server-side plugin for Microsoft On-Behalf-Of (OBO) token exchange.
 *
 * Reads `clientId`, `clientSecret`, `tenantId`, and `authority` from the
 * Microsoft social provider already configured in `betterAuth({ socialProviders })`
 * so you do not need to repeat them. Any field in `defaultConfig` takes
 * precedence over the social provider config.
 *
 * Exposes `auth.api.getOboToken({ body: { userId, applicationName } })` —
 * the idiomatic Better Auth server-side API pattern (same as `auth.api.banUser`,
 * `auth.api.createOrganization`, etc.). No HTTP request is made; Better Auth
 * calls the handler directly.
 *
 * On failure the endpoint throws an `APIError`. Catch it with `isAPIError` from
 * `better-auth/api` and inspect `e.body.code` against `OBO_ERROR_CODES` for
 * programmatic error handling.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { oboPlugin } from "better-auth-obo";
 * import { isAPIError } from "better-auth/api";
 *
 * export const auth = betterAuth({
 *   socialProviders: {
 *     microsoft: {
 *       clientId:     process.env.AZURE_CLIENT_ID!,
 *       clientSecret: process.env.AZURE_CLIENT_SECRET!,
 *       tenantId:     process.env.AZURE_TENANT_ID!,   // must be specific, not "common"
 *     },
 *   },
 *   plugins: [
 *     oboPlugin({
 *       applications: {
 *         graph:    { scope: ["https://graph.microsoft.com/.default"] },
 *         "my-api": { scope: ["api://my-api/.default"] },
 *       },
 *     }),
 *   ],
 * });
 *
 * // On your server:
 * try {
 *   const account = await auth.api.getOboToken({
 *     body: { userId, applicationName: "graph" },
 *   });
 *   account.accessToken // string | null | undefined
 * } catch (e) {
 *   if (isAPIError(e)) {
 *     console.error(e.body.code, e.body.message);
 *   }
 * }
 * ```
 */
export const oboPlugin = <TApplications extends ApplicationsConfig>(
  options: OboPluginOptions<TApplications>,
) => {
  // Credentials are resolved lazily on first endpoint call so that the social
  // provider config (from AuthContext) is available at that point. Once resolved
  // the result is cached for the lifetime of the plugin instance.
  let credentials: ResolvedCredentials | undefined;

  function getCredentials(ctx: {
    socialProviders: Array<{ id: string; options?: unknown }>;
  }): ResolvedCredentials {
    if (credentials) return credentials;
    const msProvider = ctx.socialProviders.find((p) => p.id === "microsoft");
    const msProviderOptions = msProvider?.options as
      | MicrosoftProviderOptions
      | undefined;
    // resolveCredentials throws BetterAuthError if credentials are missing.
    // We let it propagate so it surfaces as INTERNAL_SERVER_ERROR from the endpoint.
    credentials = resolveCredentials(options.defaultConfig, msProviderOptions);
    return credentials;
  }

  return {
    id: "obo-plugin",
    $ERROR_CODES: OBO_ERROR_CODES,
    options,

    endpoints: {
      /**
       * Get an OBO (On-Behalf-Of) token for the given user and downstream application.
       *
       * Called server-side via `auth.api.getOboToken({ body: { userId, applicationName } })`.
       * Better Auth invokes the handler directly without an HTTP request.
       *
       * Throws an `APIError` on failure — check `e.body.code` against `OBO_ERROR_CODES`
       * for programmatic handling. Returns the Better Auth `Account` row on success.
       */
      getOboToken: createAuthEndpoint(
        "/obo/get-token",
        {
          method: "POST",
          body: z.object({
            userId: z.string(),
            applicationName: z.string(),
          }),
          metadata: {
            openapi: {
              operationId: "getOboToken",
              summary: "Get an On-Behalf-Of token for a downstream application",
              description:
                "Exchanges the user's stored Microsoft access token for an OBO token " +
                "scoped to a named downstream application. Tokens are cached in the " +
                "account table and reused until within 60 seconds of expiry.",
              responses: {
                200: {
                  description: "The cached Better Auth Account row for the OBO token",
                  content: {
                    "application/json": {
                      schema: { $ref: "#/components/schemas/Account" },
                    },
                  },
                },
                400: { description: "Unknown application or missing scope" },
                404: { description: "User has no Microsoft access token" },
                502: { description: "Entra ID rejected the OBO exchange" },
              },
            },
          },
        },
        async (ctx) => {
          let resolvedCredentials: ResolvedCredentials;
          try {
            resolvedCredentials = getCredentials(ctx.context);
          } catch (err) {
            // BetterAuthError from resolveCredentials → surface as 500
            throw APIError.fromStatus("INTERNAL_SERVER_ERROR", {
              message: (err as Error).message,
              code: OBO_ERROR_CODES.MISSING_CREDENTIALS.code,
            });
          }
          return _getOboToken(
            ctx.context.internalAdapter,
            resolvedCredentials,
            options,
            {
              userId: ctx.body.userId,
              applicationName: ctx.body.applicationName,
            },
          );
        },
      ),
    },
  } satisfies BetterAuthPlugin;
};

// ---------------------------------------------------------------------------
// Standalone helper
// ---------------------------------------------------------------------------

/**
 * Get an OBO (On-Behalf-Of) token for the given user and downstream application.
 *
 * This is the standalone form of the helper — useful when you want to pass
 * credentials explicitly, pass a custom `fetchOptions` (e.g. in tests), or
 * avoid `auth.api` entirely. If you have registered `oboPlugin`, prefer
 * `auth.api.getOboToken({ body: { ... } })` instead — it is the idiomatic
 * Better Auth server-side call pattern.
 *
 * When called standalone, `pluginOptions.defaultConfig` must contain all
 * required credential fields (`clientId`, `clientSecret`, and `authority` or
 * `tenantId`) because there is no social provider context to fall back to.
 *
 * Throws `APIError` on request-time failures and `BetterAuthError` on
 * misconfiguration — both propagate to the caller without wrapping.
 *
 * @param auth          The Better Auth instance (from `betterAuth(...)`).
 * @param pluginOptions The same options object passed to `oboPlugin()`.
 * @param params        `{ userId, applicationName, fetchOptions? }`
 *
 * @returns The Better Auth `Account` row for the cached OBO token.
 * @throws  `BetterAuthError` if credentials are missing from `defaultConfig`.
 * @throws  `APIError` for request-time failures (BAD_REQUEST, NOT_FOUND, BAD_GATEWAY).
 */
export async function getOboToken(
  auth: AuthLike,
  pluginOptions: OboPluginOptions,
  params: GetOboTokenParams,
): Promise<Account> {
  // No social provider context available here — defaultConfig must be complete.
  // resolveCredentials throws BetterAuthError if anything is missing.
  const resolvedCredentials = resolveCredentials(
    pluginOptions.defaultConfig,
    undefined,
  );
  const ctx = await auth.$context;
  return _getOboToken(
    ctx.internalAdapter,
    resolvedCredentials,
    pluginOptions,
    params,
  );
}

// Re-export types so callers can annotate options and params
export type { OboPluginOptions };

import { betterFetch, type BetterFetchOption } from "@better-fetch/fetch";
import type { BetterAuthPlugin, InternalAdapter } from "better-auth";

/**
 * Minimal structural type for a Better Auth instance.
 * Using a structural type instead of the concrete `Auth<Options>` ensures
 * that `exchangeOboToken` is compatible with any `Auth<Options>` regardless
 * of how narrowly TypeScript has inferred the `Options` type parameter.
 */
export type AuthLike = {
  $context: Promise<{ internalAdapter: InternalAdapter }>;
};

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
 * scopes you want the OBO token to carry. Everything else (`clientId`,
 * `clientSecret`, `authority`) belongs to your middle-tier app and is
 * resolved once from `defaultConfig` or the Microsoft social provider config.
 */
type ApplicationConfig = {
  /** An optional stable identifier for this application entry. */
  id?: string;
  /**
   * Downstream API scopes to request, e.g.
   * `["https://graph.microsoft.com/.default"]`.
   */
  scopes: string[];
};

type ApplicationsConfig = {
  [applicationName: string]: ApplicationConfig;
};

/** Options passed to `oboPlugin()`. */
type OboPluginOptions = {
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
   * Keys are the `applicationName` strings passed to `exchangeOboToken`.
   */
  applications: ApplicationsConfig;
};

/** Successful response from the Microsoft token endpoint for an OBO exchange. */
type MicrosoftOBOToken = {
  token_type: "Bearer";
  scope: string;
  expires_in: number;
  ext_expires_in: number;
  access_token: string;
  refresh_token?: string;
};

/** Error response from the Microsoft token endpoint. */
type MicrosoftOBOError = {
  error: string;
  error_description?: string;
  error_codes?: number[];
  timestamp?: string;
  trace_id?: string;
  correlation_id?: string;
};

/**
 * Fully resolved credentials — all fields required.
 * Built at plugin init time by merging `defaultConfig` over the social
 * provider config, then reused for every `exchangeToken` call.
 */
type ResolvedCredentials = {
  authority: string;
  clientId: string;
  clientSecret: string;
};

/** Fully resolved per-call config — credentials + application scopes. */
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
 * Resolve the OBO credentials at plugin init time by merging `defaultConfig`
 * (explicit overrides) over the Microsoft social provider config (fallback).
 *
 * Emits a console warning if the effective `tenantId` is `"common"` or
 * `"organizations"`, since Microsoft explicitly discourages those for OBO.
 *
 * Throws if any required credential is missing after merging.
 */
function resolveCredentials(
  defaultConfig: OboDefaultConfig | undefined,
  msProviderOptions: MicrosoftProviderOptions | undefined,
): ResolvedCredentials {
  const clientId = defaultConfig?.clientId ?? msProviderOptions?.clientId;
  const clientSecret = defaultConfig?.clientSecret ?? msProviderOptions?.clientSecret;

  // Authority resolution:
  //   1. explicit authority in defaultConfig
  //   2. explicit tenantId in defaultConfig → derive URL
  //   3. social provider authority + social provider tenantId → combine
  //   4. social provider authority alone (may already include tenant path)
  const effectiveTenantId = defaultConfig?.tenantId ?? msProviderOptions?.tenantId;
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
    throw new Error(
      `[obo-plugin] Missing required credentials: ${missing.join(", ")}. ` +
        `Provide them in oboPlugin({ defaultConfig }) or ensure the Microsoft ` +
        `social provider is configured with these fields.`,
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
 */
function resolveConfig(
  credentials: ResolvedCredentials,
  pluginOptions: OboPluginOptions,
  applicationName: string,
): ResolvedConfig {
  const appConfig = pluginOptions.applications[applicationName];
  if (!appConfig) {
    throw new Error(
      `[obo-plugin] Unknown application "${applicationName}". ` +
        `Available applications: ${Object.keys(pluginOptions.applications).join(", ")}`,
    );
  }
  if (!appConfig.scopes?.length) {
    throw new Error(
      `[obo-plugin] Missing required scopes for application "${applicationName}".`,
    );
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
    scope: config.scopes.join(" "),
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
 * so it can be called both from the plugin's `init` hook (which resolved
 * credentials once at startup) and from the standalone helper.
 */
async function _exchangeOboToken(
  adapter: InternalAdapter,
  credentials: ResolvedCredentials,
  pluginOptions: OboPluginOptions,
  userId: string,
  applicationName: string,
  fetchOptions?: BetterFetchOption,
): Promise<{ data: MicrosoftOBOToken | null; error: string | null }> {
  // 1. Resolve per-application config
  let config: ResolvedConfig;
  try {
    config = resolveConfig(credentials, pluginOptions, applicationName);
  } catch (err) {
    return { data: null, error: (err as Error).message };
  }

  const providerId = oboProviderId(applicationName);

  // 2. Check the OBO token cache (synthetic account row)
  const cachedAccount = await adapter.findAccountByProviderId(userId, providerId);
  const now = Date.now();
  const bufferMs = 60_000; // 60-second expiry buffer

  if (
    cachedAccount?.accessToken &&
    cachedAccount.accessTokenExpiresAt &&
    cachedAccount.accessTokenExpiresAt.getTime() - now > bufferMs
  ) {
    // Valid cached token — reconstruct a MicrosoftOBOToken shape from stored fields
    return {
      data: {
        token_type: "Bearer",
        access_token: cachedAccount.accessToken,
        scope: cachedAccount.scope ?? config.scopes.join(" "),
        expires_in: Math.floor(
          (cachedAccount.accessTokenExpiresAt.getTime() - now) / 1000,
        ),
        ext_expires_in: Math.floor(
          (cachedAccount.accessTokenExpiresAt.getTime() - now) / 1000,
        ),
        ...(cachedAccount.refreshToken
          ? { refresh_token: cachedAccount.refreshToken }
          : {}),
      },
      error: null,
    };
  }

  // 3. Look up the user's real Microsoft account to get the assertion token
  const accounts = await adapter.findAccounts(userId);
  const msAccount = accounts.find((a) => a.providerId === "microsoft");

  if (!msAccount?.accessToken) {
    return {
      data: null,
      error:
        `[obo-plugin] No Microsoft access token found for user "${userId}". ` +
        `Ensure the user signed in via the Microsoft social provider.`,
    };
  }

  // 4. Perform the OBO token exchange
  const { data: oboToken, error: fetchError } = await fetchOboToken(
    config,
    msAccount.accessToken,
    fetchOptions,
  );

  if (fetchError || !oboToken) {
    const detail =
      fetchError instanceof Error
        ? fetchError.message
        : JSON.stringify(fetchError);
    return {
      data: null,
      error: `[obo-plugin] OBO token exchange failed: ${detail}`,
    };
  }

  // 5. Upsert the OBO token into the account table for caching
  const expiresAt = new Date(now + oboToken.expires_in * 1000);
  const tokenData = {
    accessToken: oboToken.access_token,
    accessTokenExpiresAt: expiresAt,
    scope: oboToken.scope,
    ...(oboToken.refresh_token ? { refreshToken: oboToken.refresh_token } : {}),
  };

  try {
    if (cachedAccount) {
      await adapter.updateAccount(cachedAccount.id, tokenData);
    } else {
      await adapter.createAccount({
        userId,
        providerId,
        accountId: userId, // no real "accountId" for an OBO token — use userId
        ...tokenData,
      });
    }
  } catch {
    // Caching failure is non-fatal — the token was still obtained successfully
  }

  return { data: oboToken, error: null };
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
 * Injects an `obo` helper onto `auth.$context` so you can call
 * `ctx.obo.exchangeToken(userId, applicationName)` directly without passing
 * credentials at the call site.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { oboPlugin } from "better-auth-obo";
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
 *       // defaultConfig can be omitted entirely when the social provider config
 *       // already has a specific tenantId.
 *       applications: {
 *         graph:    { scopes: ["https://graph.microsoft.com/.default"] },
 *         "my-api": { scopes: ["api://my-api/.default"] },
 *       },
 *     }),
 *   ],
 * });
 *
 * // On your server:
 * const ctx = await auth.$context;
 * const { data, error } = await ctx.obo.exchangeToken(userId, "graph");
 * ```
 */
export const oboPlugin = (options: OboPluginOptions) => {
  return {
    id: "obo-plugin",
    options,

    init(ctx) {
      // Find the Microsoft social provider and extract its options as fallback
      // credentials. The `options` field on the provider object contains the
      // raw config passed to `microsoft({ clientId, clientSecret, ... })`.
      const msProvider = ctx.socialProviders.find((p) => p.id === "microsoft");
      const msProviderOptions = msProvider?.options as MicrosoftProviderOptions | undefined;

      // Resolve credentials once at init time — throws early if anything is
      // missing so misconfiguration is caught at startup, not at request time.
      const credentials = resolveCredentials(options.defaultConfig, msProviderOptions);

      return {
        context: {
          obo: {
            /**
             * Exchange the user's stored Microsoft access token for an OBO token
             * scoped to a named downstream application.
             *
             * Credentials are already resolved — only `userId` and
             * `applicationName` (a key from `options.applications`) are needed.
             *
             * @param userId          Better Auth user ID to act on behalf of.
             * @param applicationName Key from `options.applications`.
             * @param fetchOptions    Optional `@better-fetch/fetch` overrides.
             */
            exchangeToken(
              userId: string,
              applicationName: string,
              fetchOptions?: BetterFetchOption,
            ): Promise<{ data: MicrosoftOBOToken | null; error: string | null }> {
              return _exchangeOboToken(
                ctx.internalAdapter,
                credentials,
                options,
                userId,
                applicationName,
                fetchOptions,
              );
            },
          },
        },
      };
    },
  } satisfies BetterAuthPlugin;
};

// ---------------------------------------------------------------------------
// Standalone helper
// ---------------------------------------------------------------------------

/**
 * Exchange the authenticated user's stored Microsoft access token for an OBO
 * (On-Behalf-Of) token scoped to a downstream application.
 *
 * This is the standalone form of the helper — useful when you want to pass
 * credentials explicitly or when you are not using `oboPlugin`. If you have
 * registered `oboPlugin`, prefer `(await auth.$context).obo.exchangeToken`
 * instead, which has credentials and options already bound.
 *
 * When called standalone, `pluginOptions.defaultConfig` must contain all
 * required credential fields (`clientId`, `clientSecret`, and `authority` or
 * `tenantId`) because there is no social provider context to fall back to.
 *
 * OBO tokens are **cached** in Better Auth's `account` table under a synthetic
 * `providerId` of `"obo-<applicationName>"`. A cached token is reused as long
 * as it expires more than 60 seconds in the future. Once expired, a fresh OBO
 * exchange is made automatically using the user's stored Microsoft access token.
 *
 * @param auth            The Better Auth instance (from `betterAuth(...)`).
 * @param pluginOptions   The same options object passed to `oboPlugin()`.
 * @param userId          The Better Auth user ID to exchange on behalf of.
 * @param applicationName A key from `pluginOptions.applications`.
 * @param fetchOptions    Optional `@better-fetch/fetch` options (e.g. for testing).
 *
 * @returns `{ data: MicrosoftOBOToken, error: null }` on success,
 *          `{ data: null, error: string }` on failure.
 */
export async function exchangeOboToken(
  auth: AuthLike,
  pluginOptions: OboPluginOptions,
  userId: string,
  applicationName: string,
  fetchOptions?: BetterFetchOption,
): Promise<{ data: MicrosoftOBOToken | null; error: string | null }> {
  let credentials: ResolvedCredentials;
  try {
    // No social provider context available here — defaultConfig must be complete.
    credentials = resolveCredentials(pluginOptions.defaultConfig, undefined);
  } catch (err) {
    return { data: null, error: (err as Error).message };
  }
  const ctx = await auth.$context;
  return _exchangeOboToken(ctx.internalAdapter, credentials, pluginOptions, userId, applicationName, fetchOptions);
}

// Re-export types so callers can type-narrow responses and annotate options
export type { MicrosoftOBOError, MicrosoftOBOToken, OboPluginOptions };

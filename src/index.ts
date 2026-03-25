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
 * These fields are fixed for your entire deployment:
 * - `clientId` / `clientSecret` identify *your* app registration in Entra ID.
 *   The OBO `assertion` token's `aud` claim must match `clientId` — they
 *   cannot differ between downstream applications.
 * - `authority` is the token endpoint for the user's tenant. In the OBO
 *   protocol the tenant is determined by the `tid` claim in the incoming
 *   assertion, not by which downstream API you are calling. Using `/common`
 *   or `/organizations` is explicitly discouraged by Microsoft (especially
 *   for guest users).
 * - `tenantId` is an optional convenience: if `authority` is omitted it is
 *   derived as `https://login.microsoftonline.com/<tenantId>`.
 */
type OboDefaultConfig = {
  /**
   * Token endpoint authority, e.g. `https://login.microsoftonline.com/my-tenant`.
   * Required unless `tenantId` is provided.
   */
  authority?: string;
  /**
   * Convenience alternative to `authority`. Used to derive
   * `https://login.microsoftonline.com/<tenantId>` when `authority` is absent.
   */
  tenantId?: string;
  /** Azure AD Application (client) ID of the *middle-tier* app. */
  clientId: string;
  /** Azure AD client secret of the *middle-tier* app. */
  clientSecret: string;
};

/**
 * Per-downstream-application config.
 *
 * The only thing that varies between downstream applications is the set of
 * scopes you want the OBO token to carry. Everything else (`clientId`,
 * `clientSecret`, `authority`) belongs to your middle-tier app and is
 * configured once in `defaultConfig`.
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
   * Middle-tier application credentials and token endpoint.
   * Shared across all downstream application exchanges.
   */
  defaultConfig: OboDefaultConfig;
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

/** Fully resolved config — `authority`, `clientId`, `clientSecret` and `scopes` guaranteed present. */
type ResolvedConfig = Omit<OboDefaultConfig, "authority"> & Required<Pick<OboDefaultConfig, "authority" | "clientId" | "clientSecret">> & ApplicationConfig;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Validate `defaultConfig` and merge it with a per-application entry,
 * returning a fully resolved config. Throws with a clear message on any
 * missing required field.
 */
function resolveConfig(
  options: OboPluginOptions,
  applicationName: string,
): ResolvedConfig {
  const appConfig = options.applications[applicationName];
  if (!appConfig) {
    throw new Error(
      `[obo-plugin] Unknown application "${applicationName}". ` +
        `Available applications: ${Object.keys(options.applications).join(", ")}`,
    );
  }

  // Derive authority from tenantId if authority is absent
  const authority =
    options.defaultConfig.authority ??
    (options.defaultConfig.tenantId
      ? `https://login.microsoftonline.com/${options.defaultConfig.tenantId}`
      : undefined);

  const missing: string[] = [];
  if (!authority) missing.push("authority (or tenantId)");
  if (!options.defaultConfig.clientId) missing.push("clientId");
  if (!options.defaultConfig.clientSecret) missing.push("clientSecret");
  if (!appConfig.scopes?.length) missing.push(`applications.${applicationName}.scopes`);

  if (missing.length > 0) {
    throw new Error(
      `[obo-plugin] Missing required config for application "${applicationName}": ${missing.join(", ")}`,
    );
  }

  return {
    ...options.defaultConfig,
    ...appConfig,
    authority: authority!,
  };
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
 *
 * @param config    Fully resolved config.
 * @param assertion The user's current Microsoft access token (the "incoming" token).
 * @param fetchOptions Optional `better-fetch` options (e.g. custom fetch impl for tests).
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
 * Accepts `InternalAdapter` directly so it can be called both from the public
 * standalone helper (which awaits `auth.$context`) and from the plugin's `init`
 * hook (which already holds the live `AuthContext`).
 */
async function _exchangeOboToken(
  adapter: InternalAdapter,
  pluginOptions: OboPluginOptions,
  userId: string,
  applicationName: string,
  fetchOptions?: BetterFetchOption,
): Promise<{ data: MicrosoftOBOToken | null; error: string | null }> {
  // 1. Resolve and validate config
  let config: ResolvedConfig;
  try {
    config = resolveConfig(pluginOptions, applicationName);
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
 * Registers the plugin and injects an `obo` helper object onto `auth.$context`
 * so you can call `ctx.obo.exchangeToken(userId, applicationName)` directly
 * after awaiting the context — no need to pass `pluginOptions` at the call site.
 *
 * The standalone `exchangeOboToken` export is also available for callers that
 * prefer to pass options explicitly or do not use the plugin system.
 *
 * @example
 * ```ts
 * import { betterAuth } from "better-auth";
 * import { oboPlugin } from "better-auth-obo";
 *
 * export const auth = betterAuth({
 *   plugins: [
 *     oboPlugin({
 *       defaultConfig: {
 *         authority: "https://login.microsoftonline.com/my-tenant-id",
 *         clientId: process.env.AZURE_CLIENT_ID!,
 *         clientSecret: process.env.AZURE_CLIENT_SECRET!,
 *       },
 *       applications: {
 *         graph:    { scopes: ["https://graph.microsoft.com/.default"] },
 *         "my-api": { scopes: ["api://my-api/.default"] },
 *       },
 *     }),
 *   ],
 * });
 *
 * // On your server — options already bound, no import of pluginOptions needed:
 * const ctx = await auth.$context;
 * const { data, error } = await ctx.obo.exchangeToken(userId, "graph");
 * ```
 */
export const oboPlugin = (options: OboPluginOptions) => {
  return {
    id: "obo-plugin",
    options,

    init(ctx) {
      return {
        context: {
          obo: {
            /**
             * Exchange the user's stored Microsoft access token for an OBO token
             * scoped to a named downstream application.
             *
             * The plugin options are already bound — only `userId` and
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
 * `pluginOptions` explicitly or when you are not using `oboPlugin`. If you
 * have registered `oboPlugin`, prefer `(await auth.$context).obo.exchangeToken`
 * instead, which has the options already bound.
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
  const ctx = await auth.$context;
  return _exchangeOboToken(ctx.internalAdapter, pluginOptions, userId, applicationName, fetchOptions);
}

// Re-export types so callers can type-narrow responses and annotate options
export type { MicrosoftOBOError, MicrosoftOBOToken, OboPluginOptions };

import { createFetch, createSchema } from "@better-fetch/fetch";
import type { Account, BetterAuthPlugin } from "better-auth";
import { APIError, defineErrorCodes } from "better-auth";
import { createAuthEndpoint, getAccessToken } from "better-auth/api";
import { z } from "zod";

// Server-only endpoint body — userId and applicationName are the only inputs
// needed; the plugin resolves all credentials from the auth config internally.
const bodySchema = z.object({
  userId: z.string(),
  applicationName: z.string(),
});

// Fields read from socialProviders.microsoft.options to construct the OBO
// request. scope is optional because the per-application scope (from
// OboPluginOptions) is used for the exchange, not the provider's login scope.
const msSocialProviderConfigSchema = z.object({
  clientId: z.string(),
  clientSecret: z.string(),
  tenantId: z.string(),
  scope: z.string().array().optional(),
});

// Shape of a successful Entra ID OBO token response.
const outputSchema = z.object({
  token_type: z.literal("Bearer"),
  scope: z.string(),
  expires_in: z.number(),
  ext_expires_in: z.number(),
  access_token: z.string(),
});

// Shape of an Entra ID error response — used by @better-fetch/fetch to
// deserialise errors so we can extract error_description for logging.
const defaultErrorSchema = z.object({
  error: z.string(),
  error_description: z.string().optional(),
  error_codes: z.number().array().optional(),
  timestamp: z.string().optional(),
  trace_id: z.string().optional(),
  correlation_id: z.string().optional(),
});

// Documents the fields sent to the Entra ID token endpoint. grant_type and
// requested_token_use are fixed values required by the OBO protocol spec
// (RFC 7523 / Entra ID OBO extension) — they are always these exact strings.
const inputSchema = z.object({
  client_id: z.string(),
  client_secret: z.string(),
  grant_type: z
    .literal("urn:ietf:params:oauth:grant-type:jwt-bearer")
    .default("urn:ietf:params:oauth:grant-type:jwt-bearer"),
  assertion: z.string(),
  requested_token_use: z.literal("on_behalf_of").default("on_behalf_of"),
  scope: z.string(),
});

/**
 * Machine-readable error codes for the OBO plugin.
 *
 * Registered on `auth.$ERROR_CODES` and exported so callers can do
 * programmatic error handling without matching on raw strings:
 *
 * ```ts
 * import { isAPIError } from "better-auth/api";
 * import { OBO_ERROR_CODES } from "better-auth-obo";
 *
 * catch (e) {
 *   if (isAPIError(e) && e.body.code === OBO_ERROR_CODES.OBO_EXCHANGE_FAILED.code) {
 *     // handle Entra ID rejection
 *   }
 * }
 * ```
 */
export const OBO_ERROR_CODES = defineErrorCodes({
  UNKNOWN_APPLICATION:
    "The requested application is not configured in oboPlugin",
  MISSING_APPLICATION_SCOPE: "The application config is missing required scope",
  MICROSOFT_ACCOUNT_NOT_FOUND:
    "No Microsoft access token found for this user — ensure the user signed in via the Microsoft social provider",
  OBO_EXCHANGE_FAILED: "The OBO token exchange with Microsoft Entra ID failed",
  MISSING_CREDENTIALS:
    "Required OBO credentials could not be resolved — provide them in oboPlugin({ defaultConfig }) or configure the Microsoft social provider",
});

/**
 * Configuration options for {@link oboPlugin}.
 */
export type OboPluginOptions = {
  /**
   * Named downstream applications that OBO tokens can be obtained for.
   *
   * Each key is an arbitrary name you choose (e.g. `"graph"`, `"my-api"`).
   * It becomes the `applicationName` value accepted by `getOboToken` and
   * the suffix of the synthetic `providerId` used to cache the token
   * (`"microsoft:<applicationName>"`).
   *
   * `scope` is the list of OAuth 2.0 scopes to request from Entra ID for
   * that downstream application — typically `["api://<app-id>/.default"]`.
   */
  applications: {
    [applicationName: string]: {
      scope: string[];
    };
  };
};

/**
 * Better Auth plugin that adds Microsoft Entra ID On-Behalf-Of (OBO) token
 * exchange to your server.
 *
 * Requires the built-in Microsoft social provider to be configured on the
 * same Better Auth instance — `clientId`, `clientSecret`, and `tenantId` are
 * read from that provider's options.
 *
 * Exposes a single server-only endpoint: `auth.api.getOboToken`.
 */
export const oboPlugin = (options: OboPluginOptions) => {
  const PROVIDER_ID = "microsoft";

  // Typed fetch instance for the Entra ID token endpoint. The schema
  // validates both the request body shape and the response, and the
  // defaultError schema deserialises Entra ID error responses.
  const $fetch = createFetch({
    defaultError: defaultErrorSchema,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    schema: createSchema({
      "@post/token": {
        input: inputSchema,
        output: outputSchema,
      },
    }),
  });

  return {
    id: "obo-plugin",
    $ERROR_CODES: OBO_ERROR_CODES,
    options,

    endpoints: {
      // Pathless endpoint — intentionally not registered on the HTTP router.
      // Call it server-side only via auth.api.getOboToken({ body: { ... } }).
      getOboToken: createAuthEndpoint(
        {
          method: "POST",
          body: bodySchema,
        },
        async (ctx) => {
          const {
            body: { applicationName, userId },
            context: { socialProviders, internalAdapter, adapter },
          } = ctx;

          // Validate the application name against plugin config before
          // touching the database — fail fast on misconfiguration.
          const appConfig = options.applications[applicationName];
          if (!appConfig) {
            throw APIError.from("BAD_REQUEST", {
              code: OBO_ERROR_CODES.UNKNOWN_APPLICATION.code,
              message: `${OBO_ERROR_CODES.UNKNOWN_APPLICATION.message}: ${applicationName}`,
            });
          }

          // scope is the space-separated string sent to Entra ID. Validate it
          // before any network or DB work.
          const scope = appConfig.scope.join(" ");
          if (!scope) {
            throw APIError.from("BAD_REQUEST", {
              code: OBO_ERROR_CODES.MISSING_APPLICATION_SCOPE.code,
              message: `${OBO_ERROR_CODES.MISSING_APPLICATION_SCOPE.message}: ${applicationName}`,
            });
          }

          // OBO tokens are cached as synthetic Better Auth account rows using
          // a providerId of "microsoft:<applicationName>". This keeps each
          // downstream application's token isolated per user, with no extra
          // database tables required.
          const applicationProviderId = `${PROVIDER_ID}:${applicationName}`;
          const applicationAccount = await adapter.findOne<Account>({
            model: "account",
            where: [
              {
                field: "providerId",
                value: applicationProviderId,
                operator: "eq",
                connector: "AND",
              },
              {
                field: "userId",
                value: userId,
                operator: "eq",
              },
            ],
          });

          // Serve from cache if the token has more than 60 seconds of
          // remaining lifetime. The 60-second buffer ensures the token won't
          // expire mid-request in a downstream API call.
          const now = Date.now();
          const bufferMs = 60_000;
          if (
            applicationAccount?.accessToken &&
            applicationAccount.accessTokenExpiresAt &&
            applicationAccount.accessTokenExpiresAt.getTime() - now > bufferMs
          ) {
            return applicationAccount;
          }

          // Resolve the Microsoft social provider config. This is done after
          // the cache check so we don't pay the lookup cost on cache hits.
          const msProvider = socialProviders.find(
            ({ id }) => id === PROVIDER_ID,
          );
          if (!msProvider?.options) {
            throw APIError.from("INTERNAL_SERVER_ERROR", {
              code: OBO_ERROR_CODES.MISSING_CREDENTIALS.code,
              message: OBO_ERROR_CODES.MISSING_CREDENTIALS.message,
            });
          }

          const { data: msConfig, error: msConfigError } =
            msSocialProviderConfigSchema.safeParse(msProvider.options);
          if (msConfigError) {
            throw APIError.from("INTERNAL_SERVER_ERROR", {
              code: OBO_ERROR_CODES.MISSING_CREDENTIALS.code,
              message: `${OBO_ERROR_CODES.MISSING_CREDENTIALS.message}: ${msConfigError.message}`,
            });
          }

          // Retrieve (and if necessary refresh) the user's Microsoft access
          // token via Better Auth's built-in getAccessToken endpoint. We call
          // it as a function by spreading ctx and overriding method + body —
          // the standard pattern for invoking one pathless endpoint from
          // inside another.
          const microsoftAccess = await getAccessToken({
            ...ctx,
            method: "POST",
            body: { providerId: PROVIDER_ID, userId },
            returnHeaders: false,
            returnStatus: false,
          });

          // POST to the Entra ID OBO token endpoint. The user's access token
          // becomes the assertion; Entra ID returns a new token scoped to the
          // downstream application.
          const tenantId = msConfig.tenantId;
          const { data: tokenResp, error: tokenError } = await $fetch(
            "@post/token",
            {
              baseURL: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0`,
              body: {
                client_id: msConfig.clientId,
                client_secret: msConfig.clientSecret,
                assertion: microsoftAccess.accessToken,
                scope,
                grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
                requested_token_use: "on_behalf_of",
              },
            },
          );
          if (tokenError) {
            throw APIError.from(
              "INTERNAL_SERVER_ERROR",
              OBO_ERROR_CODES.OBO_EXCHANGE_FAILED,
            );
          }

          const accessTokenExpiresAt = new Date(
            Date.now() + tokenResp.expires_in * 1000,
          );

          // Update the existing cache row if one exists, otherwise create a
          // new one. accountId on a new row is a random UUID — it is a
          // plugin-managed pseudo-account with no real OAuth provider identity.
          if (applicationAccount) {
            return await internalAdapter.updateAccount(applicationAccount.id, {
              accessToken: tokenResp.access_token,
              accessTokenExpiresAt,
              scope,
            });
          }

          return await internalAdapter.createAccount({
            accountId: crypto.randomUUID(),
            providerId: applicationProviderId,
            userId,
            accessToken: tokenResp.access_token,
            accessTokenExpiresAt,
            scope,
          });
        },
      ),
    },
  } satisfies BetterAuthPlugin;
};

import { createFetch, createSchema } from "@better-fetch/fetch";
import type { Account, BetterAuthPlugin } from "better-auth";
import { APIError, defineErrorCodes } from "better-auth";
import { createAuthEndpoint, getAccessToken } from "better-auth/api";
import { z } from "zod";

const bodySchema = z.object({
  userId: z.string(),
  applicationName: z.string(),
});

const msSocialProviderConfigSchema = z.object({
  clientId: z.string(),
  clientSecret: z.string(),
  tenantId: z.string(),
  scope: z.string().array().optional(),
});

const outputSchema = z.object({
  token_type: z.literal("Bearer"),
  scope: z.string(),
  expires_in: z.number(),
  ext_expires_in: z.number(),
  access_token: z.string(),
});

const defaultErrorSchema = z.object({
  error: z.string(),
  error_description: z.string().optional(),
  error_codes: z.number().array().optional(),
  timestamp: z.string().optional(),
  trace_id: z.string().optional(),
  correlation_id: z.string().optional(),
});

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

export type OboPluginOptions = {
  applications: {
    [applicationName: string]: {
      scope: string[];
    };
  };
};

export const oboPlugin = (options: OboPluginOptions) => {
  const PROVIDER_ID = "microsoft";

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

          // Validate the application is configured before doing any DB work.
          const appConfig = options.applications[applicationName];
          if (!appConfig) {
            throw APIError.from("BAD_REQUEST", {
              code: OBO_ERROR_CODES.UNKNOWN_APPLICATION.code,
              message: `${OBO_ERROR_CODES.UNKNOWN_APPLICATION.message}: ${applicationName}`,
            });
          }

          const scope = appConfig.scope.join(" ");
          if (!scope) {
            throw APIError.from("BAD_REQUEST", {
              code: OBO_ERROR_CODES.MISSING_APPLICATION_SCOPE.code,
              message: `${OBO_ERROR_CODES.MISSING_APPLICATION_SCOPE.message}: ${applicationName}`,
            });
          }

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

          const now = Date.now();
          const bufferMs = 60_000; // 60-second expiry buffer
          if (
            applicationAccount?.accessToken &&
            applicationAccount.accessTokenExpiresAt &&
            applicationAccount.accessTokenExpiresAt.getTime() - now > bufferMs
          ) {
            return applicationAccount;
          }

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

          const microsoftAccess = await getAccessToken({
            ...ctx,
            method: "POST",
            body: { providerId: PROVIDER_ID, userId },
            returnHeaders: false,
            returnStatus: false,
          });

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

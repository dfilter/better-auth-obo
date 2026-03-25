import { betterFetch, type BetterFetchOption } from "@better-fetch/fetch";
import type { BetterAuthPlugin } from "better-auth";

type BaseApplicationConfig = {
  socialProivder: "microsoft"; // add future providers here
  tenantId: string;
  clientId: string;
  clientSecret: string;
  authority: string;
};

type ApplicationConfig = Partial<BaseApplicationConfig> & {
  id?: string;
  scopes: string[];
};

type ApplicationsConfig = {
  [applicationName: string]: ApplicationConfig;
};

type OboPluginOptions = {
  defaultConfig: BaseApplicationConfig;
  applications: ApplicationsConfig;
};

type MicrosoftOBOToken = {
  token_type: "Bearer";
  scope: string;
  expires_in: number;
  ext_expires_in: number;
  access_token: string;
  refresh_token?: string;
};

const fetchOboToken = (
  config: ApplicationConfig & BaseApplicationConfig,
  betterFetchConfig: BetterFetchOption,
) => {
  switch (config.socialProivder) {
    case "microsoft": {
      const url = `${config.authority}/oauth2/v2.0/token`;
      const body = new URLSearchParams({
        client_id: config.clientId,
        client_secret: config.clientSecret,
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        scope: config.scopes.join(" "),
      });
      const headers = { "Content-Type": "application/x-www-form-urlencoded" };
      return betterFetch<MicrosoftOBOToken>(url, {
        ...betterFetchConfig,
        body,
        headers,
        method: "POST",
      });
    }
    default: {
      throw new Error("Not Implimented.");
    }
  }
};

export const oboPlugin = (options: OboPluginOptions) => {
  return {
    id: "obo-plugin",
    options,
  } satisfies BetterAuthPlugin;
};

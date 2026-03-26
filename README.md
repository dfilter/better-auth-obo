# better-auth-obo

A [Better Auth](https://better-auth.com) plugin that adds Microsoft Entra ID [On-Behalf-Of (OBO)](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow) token exchange to your server.

## What is OBO?

The On-Behalf-Of flow lets your API call downstream APIs **as the signed-in user**, without any additional user interaction. Your middle-tier API receives an access token from the client, exchanges it at the Entra ID token endpoint for a new token scoped to the downstream API, and uses that token to make the downstream call.

```
Client ──[token A]──► Your API ──[OBO exchange]──► Entra ID ──[token B]──► Downstream API
```

This plugin handles the exchange step. It reads the user's Microsoft access token that Better Auth already stores during sign-in, uses it as the OBO `assertion`, and returns a new token scoped to whichever downstream application you specify. Obtained tokens are cached in Better Auth's `account` table and reused until they are close to expiry.

> **Microsoft docs:** [OAuth 2.0 On-Behalf-Of flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow)

---

## Installation

```bash
npm install better-auth-obo
# or
pnpm add better-auth-obo
```

`better-auth` and `@better-fetch/fetch` are peer dependencies — they must be present in your project. `better-auth` almost certainly already is, and `@better-fetch/fetch` is included transitively by `better-auth` itself.

---

## Setup

Register `oboPlugin` alongside the Microsoft social provider in your `auth.ts`. The plugin reads `clientId`, `clientSecret`, and `tenantId` directly from the Microsoft social provider config — no duplication needed.

```ts
// auth.ts
import { betterAuth } from "better-auth";
import { oboPlugin } from "better-auth-obo";

export const auth = betterAuth({
  socialProviders: {
    microsoft: {
      clientId:     process.env.AZURE_CLIENT_ID!,
      clientSecret: process.env.AZURE_CLIENT_SECRET!,
      tenantId:     process.env.AZURE_TENANT_ID!,  // must be a specific tenant ID, not "common"
    },
  },
  plugins: [
    oboPlugin({
      applications: {
        // Each key is a name you choose; scopes are the downstream API's scopes.
        graph:    { scopes: ["https://graph.microsoft.com/.default"] },
        "my-api": { scopes: ["api://my-downstream-app-id/.default"] },
      },
    }),
  ],
});
```

> **Note:** `tenantId` must be a specific tenant GUID. Using `"common"` or `"organizations"` is not supported for OBO — Microsoft requires a tenant-specific token endpoint, especially for guest users. The plugin emits a warning at startup if a multi-tenant value is detected.

---

## Usage

### Via `auth.$context` (recommended)

The plugin injects an `obo` helper onto `auth.$context` at startup with credentials already bound. This is the cleanest call site — no credentials or options needed at the point of use.

`applicationName` is statically typed to the exact keys of the `applications` object you passed to `oboPlugin`, so typos are caught at compile time.

```ts
import { auth } from "./auth";

const ctx = await auth.$context;

// applicationName is typed as "graph" | "my-api" — typos are a compile error
const result = await ctx.obo.getOboToken({ userId, applicationName: "graph" });

if (!result.success) {
  console.error(result.error); // string
  return;
}

// result.data is a Better Auth Account object
// result.data.accessToken holds the OBO access token
await fetch("https://graph.microsoft.com/v1.0/me", {
  headers: { Authorization: `Bearer ${result.data.accessToken}` },
});
```

### Via the standalone helper

If you need to pass credentials explicitly — for example when writing tests or in a context where the plugin is not registered — use the exported `getOboToken` function directly. When using this form, `defaultConfig` must contain all required credential fields since there is no social provider context to fall back to.

```ts
import { getOboToken } from "better-auth-obo";
import { auth } from "./auth";

const pluginOptions = {
  defaultConfig: {
    clientId:     process.env.AZURE_CLIENT_ID!,
    clientSecret: process.env.AZURE_CLIENT_SECRET!,
    tenantId:     process.env.AZURE_TENANT_ID!,
  },
  applications: {
    "my-api": { scopes: ["api://my-downstream-app-id/.default"] },
  },
};

const result = await getOboToken(auth, pluginOptions, { userId, applicationName: "my-api" });
if (result.success) {
  console.log(result.data.accessToken);
}
```

---

## Configuration reference

### `oboPlugin(options)`

| Option | Type | Required | Description |
|---|---|---|---|
| `applications` | `Record<string, { scopes: string[], id?: string }>` | Yes | Named downstream applications. Each key becomes a valid `applicationName`. `scopes` are the downstream API scopes to request. |
| `defaultConfig` | `OboDefaultConfig` | No | Credential overrides. Any field omitted here is read from the Microsoft social provider config. The entire object may be omitted when the social provider already has a specific `tenantId`. |
| `defaultConfig.clientId` | `string` | No* | Middle-tier app client ID. Falls back to `socialProviders.microsoft.clientId`. |
| `defaultConfig.clientSecret` | `string` | No* | Middle-tier app client secret. Falls back to `socialProviders.microsoft.clientSecret`. |
| `defaultConfig.tenantId` | `string` | No* | Specific tenant ID. Used to derive the authority URL. Falls back to `socialProviders.microsoft.tenantId`. |
| `defaultConfig.authority` | `string` | No* | Full token endpoint authority, e.g. `https://login.microsoftonline.com/my-tenant`. Takes precedence over `tenantId`. Useful for sovereign clouds (Azure Government, Azure China). |

\* Required collectively — after merging `defaultConfig` with the social provider config, `clientId`, `clientSecret`, and either `authority` or `tenantId` must all be resolvable. The plugin throws at startup if any are missing.

### `ctx.obo.getOboToken(params)`

Accepts a single `GetOboTokenParams` object:

| Field | Type | Description |
|---|---|---|
| `userId` | `string` | The Better Auth user ID to act on behalf of. The user must have previously signed in via the Microsoft social provider. |
| `applicationName` | `keyof applications & string` | A key from `options.applications`. Typed to your exact application names — typos are compile errors. |
| `fetchOptions` | `BetterFetchOption` | Optional. Advanced fetch overrides (custom fetch implementation, timeouts, etc.). |

**Returns:** `Promise<OboResult>` — a discriminated union:

```ts
type OboResult =
  | { success: true;  data: Account; error: null   }
  | { success: false; data: null;    error: string };
```

On success (`result.success === true`), `result.data` is a Better Auth `Account` object containing the cached OBO token:

| Field | Type | Description |
|---|---|---|
| `accessToken` | `string \| null \| undefined` | The OBO access token for the downstream API. |
| `refreshToken` | `string \| null \| undefined` | Present when `offline_access` is in the requested scopes. |
| `scope` | `string \| null \| undefined` | Space-separated scopes granted by Entra ID. |
| `accessTokenExpiresAt` | `Date \| null \| undefined` | When the token expires. |
| `providerId` | `string` | Always `"obo-<applicationName>"`. |
| `userId` | `string` | The Better Auth user ID. |

On failure (`result.success === false`), `result.data` is `null` and `result.error` is a string describing the problem.

---

## Token caching

OBO tokens are cached automatically in Better Auth's existing `account` table using a synthetic `providerId` of `"obo-<applicationName>"`. This avoids extra database tables and works with any Better Auth database adapter.

**Cache behaviour:**

- A cached token is served as-is if it expires more than **60 seconds** in the future.
- A token within the 60-second buffer, or already expired, triggers a fresh OBO exchange using the user's stored Microsoft `accessToken` as the `assertion`.
- If the cache write fails (e.g. a transient DB error), the exchange result is still returned — caching failures are non-fatal.
- Each downstream application has its own cache entry per user, so tokens for `"graph"` and `"my-api"` are cached independently.

---

## Entra ID app registration requirements

For OBO to work, your middle-tier app registration in Entra ID must:

1. **Expose an API** — define at least one scope (e.g. `access-as`) under **Expose an API** in the app registration. The client app requests this scope when signing in, which makes your app the `aud` of the incoming token.
2. **Grant API permissions** — add delegated permissions for each downstream API your server needs to call (e.g. `User.Read` for Microsoft Graph, or custom scopes for your own APIs).
3. **Have admin consent** (or user consent) for those downstream permissions — this is what allows the OBO exchange to succeed without additional user interaction.

> See [Gaining consent for the middle-tier application](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow#gaining-consent-for-the-middle-tier-application) for details on the consent model.

---

## Testing

### Unit tests

Unit tests use an in-memory SQLite database and mock all HTTP calls. No credentials or network access needed.

```bash
pnpm test
```

### Integration tests

Integration tests make real HTTP requests to the Microsoft Entra ID token endpoint. They require a `.env.test` file in the project root:

```ini
VITE_ENTRA_CLIENT_ID=<your-middle-tier-app-client-id>
VITE_ENTRA_CLIENT_SECRET=<your-client-secret>
VITE_ENTRA_TENANT_ID=<your-tenant-id>
VITE_ENTRA_OBO_SCOPES=api://<downstream-app-id>/.default,offline_access
VITE_ENTRA_ACCESS_TOKEN=<a-valid-delegated-access-token>
```

| Variable | Description |
|---|---|
| `VITE_ENTRA_CLIENT_ID` | Client ID of the middle-tier app registration. |
| `VITE_ENTRA_CLIENT_SECRET` | Client secret of the middle-tier app registration. |
| `VITE_ENTRA_TENANT_ID` | Your Azure AD tenant ID (a specific GUID, not `"common"`). |
| `VITE_ENTRA_OBO_SCOPES` | Comma-separated scopes for the downstream application. |
| `VITE_ENTRA_ACCESS_TOKEN` | A valid delegated access token issued to `VITE_ENTRA_CLIENT_ID`. The `aud` claim must match the client ID. Obtain one via [MSAL](https://learn.microsoft.com/entra/msal/overview), [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer), or Postman. |

```bash
pnpm test:integration
```

Integration tests skip gracefully when any of the above variables are absent, so they will not cause CI pipelines to fail when secrets are not configured.

---

## Further reading

- [Microsoft identity platform — OAuth 2.0 On-Behalf-Of flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
- [On-behalf-of flows with MSAL.NET](https://learn.microsoft.com/entra/msal/dotnet/acquiring-tokens/web-apps-apis/on-behalf-of-flow) — covers tenant targeting, guest users, and MFA error handling
- [Better Auth — Microsoft social provider](https://www.better-auth.com/docs/authentication/social-login)
- [Better Auth — Writing plugins](https://www.better-auth.com/docs/concepts/plugins)

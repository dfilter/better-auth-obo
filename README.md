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
        // Each key is a name you choose; scope are the downstream API's scope.
        graph:    { scope: ["https://graph.microsoft.com/.default"] },
        "my-api": { scope: ["api://my-downstream-app-id/.default"] },
      },
    }),
  ],
});
```

> **Note:** `tenantId` must be a specific tenant GUID. Using `"common"` or `"organizations"` is not supported for OBO — Microsoft requires a tenant-specific token endpoint, especially for guest users. The plugin emits a warning at startup if a multi-tenant value is detected.

---

## Usage

This plugin is **server-only**. The endpoint is not registered on the HTTP router and cannot be called from a browser client. Call it from your server-side code (API route handlers, background jobs, etc.) via `auth.api`.

> **TypeScript note:** Because the endpoint has no URL path, it is intentionally excluded from the inferred type of `auth.api`. Cast to `any` or use a typed wrapper to call it.

On failure the endpoint throws an `APIError`. Catch it with `isAPIError` from `better-auth/api` and check `e.body.code` against `OBO_ERROR_CODES` for programmatic handling.

```ts
import { auth } from "./auth";
import { isAPIError } from "better-auth/api";

try {
  // Cast required — server-only endpoints are excluded from auth.api's
  // inferred TypeScript type but exist at runtime.
  const account = await (auth.api as any).getOboToken({
    body: { userId, applicationName: "graph" },
  });

  // account is a Better Auth Account object
  await fetch("https://graph.microsoft.com/v1.0/me", {
    headers: { Authorization: `Bearer ${account.accessToken}` },
  });
} catch (e) {
  if (isAPIError(e)) {
    // e.status:        "NOT_FOUND" | "BAD_REQUEST" | "INTERNAL_SERVER_ERROR"
    // e.body.code:     one of OBO_ERROR_CODES (e.g. "MICROSOFT_ACCOUNT_NOT_FOUND")
    // e.body.message:  human-readable description
    console.error(e.status, e.body?.code, e.body?.message);
  }
}
```

---

## Configuration reference

### `oboPlugin(options)`

| Option | Type | Required | Description |
|---|---|---|---|
| `applications` | `Record<string, { scope: string[] }>` | Yes | Named downstream applications. Each key becomes a valid `applicationName`. `scope` is the list of OAuth 2.0 scopes to request from Entra ID for that application — typically `["api://<app-id>/.default"]`. |

`clientId`, `clientSecret`, and `tenantId` are read directly from `socialProviders.microsoft` in your Better Auth config — no duplication required.

### `auth.api.getOboToken({ body: params })`

`body` accepts the following fields:

| Field | Type | Description |
|---|---|---|
| `userId` | `string` | The Better Auth user ID to act on behalf of. The user must have previously signed in via the Microsoft social provider. |
| `applicationName` | `string` | A key from `options.applications`. |

**Returns:** `Promise<Account>` — the Better Auth `Account` row for the cached OBO token:

| Field | Type | Description |
|---|---|---|
| `accessToken` | `string \| null \| undefined` | The OBO access token for the downstream API. |
| `scope` | `string \| null \| undefined` | Space-separated scopes granted by Entra ID. |
| `accessTokenExpiresAt` | `Date \| null \| undefined` | When the token expires. |
| `providerId` | `string` | Always `"microsoft:<applicationName>"`. |
| `userId` | `string` | The Better Auth user ID. |

**Throws:** `APIError` on failure. Check `e.status` and `e.body.code` against `OBO_ERROR_CODES`.

### `OBO_ERROR_CODES`

Machine-readable error codes registered on `auth.$ERROR_CODES`. Each value has `code` (string) and `message` (human-readable) fields.

| Code | HTTP status | Description |
|---|---|---|
| `UNKNOWN_APPLICATION` | 400 | `applicationName` not found in plugin config |
| `MISSING_APPLICATION_SCOPE` | 400 | Application config has an empty `scope` array |
| `MICROSOFT_ACCOUNT_NOT_FOUND` | 404 | User has no Microsoft `accessToken` stored |
| `OBO_EXCHANGE_FAILED` | 502 | Entra ID rejected the OBO exchange. Entra ID's `error`, `error_description`, `error_codes`, `trace_id`, and `correlation_id` are spread onto `e.body`. |
| `MISSING_CREDENTIALS` | 500 | Required credentials missing from both `defaultConfig` and the social provider config |

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
2. **Grant API permissions** — add delegated permissions for each downstream API your server needs to call (e.g. `User.Read` for Microsoft Graph, or custom scope for your own APIs).
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
VITE_ENTRA_OBO_SCOPE=api://<downstream-app-id>/.default,offline_access
VITE_ENTRA_ACCESS_TOKEN=<a-valid-delegated-access-token>
```

| Variable | Description |
|---|---|
| `VITE_ENTRA_CLIENT_ID` | Client ID of the middle-tier app registration. |
| `VITE_ENTRA_CLIENT_SECRET` | Client secret of the middle-tier app registration. |
| `VITE_ENTRA_TENANT_ID` | Your Azure AD tenant ID (a specific GUID, not `"common"`). |
| `VITE_ENTRA_OBO_SCOPE` | Comma-separated scope for the downstream application. |
| `VITE_ENTRA_ACCESS_TOKEN` | A valid delegated access token issued to `VITE_ENTRA_CLIENT_ID`. The `aud` claim must match the client ID. Obtain one via [MSAL](https://learn.microsoft.com/entra/msal/overview), [Graph Explorer](https://developer.microsoft.com/en-us/graph/graph-explorer), or Postman. |

```bash
pnpm test:integration
```

Integration tests skip gracefully when `VITE_ENTRA_ACCESS_TOKEN` is expired, so they will not cause CI pipeline failures when the token needs refreshing. To get a new token, sign in to your app with a Microsoft account and copy the access token issued to your middle-tier app registration.

---

## Further reading

- [Microsoft identity platform — OAuth 2.0 On-Behalf-Of flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-on-behalf-of-flow)
- [On-behalf-of flows with MSAL.NET](https://learn.microsoft.com/entra/msal/dotnet/acquiring-tokens/web-apps-apis/on-behalf-of-flow) — covers tenant targeting, guest users, and MFA error handling
- [Better Auth — Microsoft social provider](https://www.better-auth.com/docs/authentication/social-login)
- [Better Auth — Writing plugins](https://www.better-auth.com/docs/concepts/plugins)

---
name: ao-nextjs-ui
description: Rules for the Next.js App Router apps in web/ - Server Components, the BFF fetch to the Go API, Server Actions for mutations, session reading, and colocation. Use when creating or changing a TypeScript or TSX file under web/.
---

# Next.js rules

Three apps: `web/login-ui` (port 3000), `web/portal-ui` (3001), `web/console-ui`
(3002). Same rules for all three.

Load the `next-best-practices` skill before you write. Load `shadcn` when the work
is a UI component.

## Components

Server Components by default. Add `'use client'` only when the component needs real
interactivity: an event handler, a hook, or browser state.

Colocate. A component used by one route lives in that route folder. A component used
by three routes moves to `src/components`.

Import from the real path. A file that only re-exports other files is not needed.

## Reading data

Plain `fetch` inside a Server Component. The server reads the session cookie and
attaches the token before it calls the Go API. The browser never holds a token.

```tsx
export default async function Page() {
  const session = await getSession();
  const res = await fetch(`${process.env.GATEWAY_URL}/api/v1/admin/users`, {
    headers: { Authorization: `Bearer ${session.accessToken}` },
    cache: "no-store",
  });
  const { data, meta } = await res.json();
  return <UserTable rows={data} meta={meta} />;
}
```

Read the session on the server. A hook, a context provider, or a store holding auth
state puts it in the browser, where it does not belong.

The Go API answers in one envelope: `{code, status, message, data, meta?}`. Read
`data`, and read `meta` on a list.

## Mutations

Server Actions, submitted by a normal form:

```tsx
async function createUser(formData: FormData) {
  "use server";
  const session = await getSession();
  const res = await fetch(`${process.env.GATEWAY_URL}/api/v1/admin/users`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${session.accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username: formData.get("username") }),
  });
  if (!res.ok) {
    const { message, errors } = await res.json();
    return { message, errors };
  }
  revalidatePath("/users");
}
```

The client component sees a normal form submission. The server calls Go.

A `422` carries `errors` as `{field: message}`. Render those beside the fields.

Add a route handler only when the browser must call it directly: a webhook, an OIDC
callback, or a client component that already fetches from the browser. A route
handler that forwards a request the server could have made repeats what a Server
Action already does.

## Existing code

`console-ui` still uses `src/lib/console-api.ts` and proxy route handlers under
`src/app/api/admin`. That code is grandfathered. Write new code to the rules above,
and convert an old route when you are already changing it.

`portal-ui` reads and writes `/api/account/*` from client components, through
`src/lib/server/account-proxy.ts`. The proxy is what earns the route handlers: it
keeps the access token server-side, and it re-seals a session the gateway rotated.
Write a new account route the same way. A page that renders on the server uses a
Server Action instead.

Every route under `src/app/(console)` now reads its own first page on the server and
hands it to the view as `initial`. `src/lib/server/console-data.ts` holds the two
readers: `loadConsoleData` for the shell, and `serverRead` for one page. A view that
takes an `initial` seeds its state from it and skips exactly one mount fetch; every
move after that — a page, a sort, a search, a write — reads from the browser through
`console-api.ts`, which is what keeps the interactions working.

A new route follows the same shape. Do not add a route that renders a view with no
`initial` when the view fetches on mount: the page then arrives empty and fills in
after a round trip the server could have made.

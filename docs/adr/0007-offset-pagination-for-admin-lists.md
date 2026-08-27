# 0007 - Offset pagination for the admin lists

## Context

`console-ui` must show a pager: first, previous, the numbered pages, next, last. An
operator names a page and goes to it.

An earlier change, `paginate-admin-list-api`, built the opposite. It windowed every
growth-bearing admin list by keyset. Migration
`00033_page_keyset_indexes.sql` indexes seven tables over `(tenant_id, created_at,
id)` and states in its header why the index is required. `console-api.ts` answers
`Page<T>` with an opaque `nextCursor`. `store.tsx` appends rows on *Load more*, and
discards them when the ordering changes, because a cursor is only valid in the
ordering that minted it.

A keyset window has no page numbers. Page 7 has no address until an operator has
walked to page 6.

The `ao-go-api` skill prescribes offset. `middlewares.Paginate` and
`response.List` implement it today and answer `meta: {page, limit, total,
totalPages}`.

So three sources disagreed, and the page-number requirement decided between them.

## Decision

**The admin lists page by offset.** A list route that grows without bound mounts
`middlewares.Paginate` with its own sort allowlist and answers
`response.List(c, rows, total)`.

A bounded list answers whole and mounts no pager. The scopes, the mappers of one
scope, the keys, the memberships of one person, and the notification templates are
bounded by what a tenant configures, so a pager there would cost a round trip and
buy nothing.

**No new pagination package is built.** The middleware and the response helper
already exist, and the house skill already documents them.

**The console moves from cursors to page numbers.** `PageOpts.cursor` becomes
`page`. `Page<T>` carries `page` and `totalPages`. `LoadMore` becomes a pager.
`readPicker` is deleted. A picker reads one short page and narrows it with a
server-side search, so it never walks at all.

**The keyset indexes stay.** `ORDER BY created_at DESC, id DESC` with `LIMIT` and
`OFFSET` reads the same index. No migration changes, and none is reverted.

## Alternatives

- **Keep keyset and keep *Load more*.** It is correct under concurrent writes and
  it is already built. It cannot show a page number, and the page number is the
  requirement.
- **Keyset with a page number on top.** To reach page 7 the client walks pages 1 to
  6, so the jump costs what keyset existed to avoid. It also cannot report
  `totalPages` without the count that keyset omits.
- **Offset for the pager, keyset for the picker and the export.** Two pagination
  contracts in one API, and the walks are where offset drift matters least.
- **Remove the drift with a stable snapshot per page walk.** A page token that
  freezes the result set answers the anomaly exactly. It is state to store, expire,
  and reason about, for a console where a refresh already corrects the view.

## Consequences

- A row written while an operator reads page 3 shifts every later row by one place.
  A row can then appear twice, or not at all, and nothing reports it. The lists sort
  newest first, so a write lands on page 1 and disturbs the pages below by one row.
- A deep page reads and discards every row before it. A tenant large enough to feel
  this will search rather than page.
- `total` arrives on every page, so `getTotal` asks for one row and reads
  `meta.total`. The overview tiles, the sidebar badges, and the detail counts get
  their number from that. A caller already holding a page reads `page.total` and
  makes no request at all.
- Five console files change: `lib/console-api.ts`, `components/console/store.tsx`,
  `components/console/primitives.tsx`, `components/views/audit.tsx`, and
  `lib/csv.ts`. Two rules are deleted: the invalidation of a cursor when the
  ordering changes, and the page bound on a walk. The bound existed for the picker,
  and the picker no longer walks. What still walks — a CSV export, and the roster an
  add-member picker excludes — has to be complete to be correct, so it reads to the
  end.
- The console pager must land before the first resource slice. A backend that
  answers `page` while the console sends `cursor` renders page 1 and nothing else.
- `ao-go-api` needed one correction, not a change of rule: its pagination section
  named `created_at` as a sort key where every route uses `created`, and it read as
  if every list route mounts a pager.
- Reversing this is cheap on the database and not on the console. The keyset indexes
  remain, so a tenant that outgrows offset can return to keyset without a migration.


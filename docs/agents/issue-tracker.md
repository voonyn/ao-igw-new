# Issue tracker: Local Markdown

Issues and specs for this repo live as markdown files in this repository. Nothing is
published to a remote tracker, and the GitHub remote is used for code alone.

## Conventions

- One feature per directory: `.scratch/<feature-slug>/`
- Implementation issues are one file per ticket at
  `.scratch/<feature-slug>/issues/<NN>-<slug>.md`, numbered from `01` in dependency
  order. Never write a single combined tickets file.
- A `Blocked by:` line near the top of each ticket names the tickets that gate it, or
  says "None — can start immediately".
- Triage state is a `Status:` line near the top of each issue file. See
  `triage-labels.md` for the role strings.
- A closed ticket carries `Status: done`. It is the only closed word for a ticket under
  `issues/`. The word `resolved` belongs to a wayfinder map child ticket alone.
- Comments and conversation history append to the bottom of the file, under a
  `## Comments` heading.

## Specs

A spec is a durable document, not scratch work, so it does not live under `.scratch/`.
Specs go in `docs/adr/`-style numbering under `docs/specs/<NNNN>-<slug>.md`, beside the
architecture decision records they cite.

The first one is `docs/specs/0001-passkeys-as-a-second-factor.md`.

## When a skill says "publish to the issue tracker"

Create a new file under `.scratch/<feature-slug>/`. Create the directory if it does not
exist.

## When a skill says "fetch the relevant ticket"

Read the file at the referenced path. The user normally passes the path or the ticket
number directly.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a file with one **child** file per ticket.

- **Map**: `.scratch/<effort>/map.md` — the Notes, the Decisions-so-far, and the Fog.
- **Child ticket**: `.scratch/<effort>/issues/NN-<slug>.md`, numbered from `01`, with the
  question in the body. A `Type:` line records the ticket type (`research`, `prototype`,
  `grilling`, or `task`). A `Status:` line records `claimed` or `resolved`.
- **Blocking**: a `Blocked by: NN, NN` line near the top. A ticket is unblocked when
  every file it names is `resolved`.
- **Frontier**: scan `.scratch/<effort>/issues/` for files that are open, unblocked, and
  unclaimed. The first by number wins.
- **Claim**: set `Status: claimed` and save before any work.
- **Resolve**: append the answer under an `## Answer` heading, set `Status: resolved`,
  then append a context pointer to the Decisions-so-far in `map.md`.

## PRs as a request surface

Off. Pull requests do not enter the triage queue.

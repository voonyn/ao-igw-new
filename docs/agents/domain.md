# Domain Docs

How the engineering skills must consume this repo's domain documentation when they
explore the codebase.

This repo is **single-context**. One glossary and one decision log serve the whole
system.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root. It is the glossary, and it holds no implementation
  detail.
- **`docs/adr/`** — read the architecture decision records that touch the area you are
  about to work in.

If a file does not exist, proceed silently. Do not flag its absence, and do not suggest
that it be created upfront. The `/domain-modeling` skill creates these lazily, when a
term or a decision is actually resolved.

## File structure

```
/
├── CONTEXT.md
├── docs/
│   ├── adr/
│   │   ├── 0001-soft-delete-unique-keys.md
│   │   └── ...
│   ├── specs/
│   └── agents/
├── internal/
└── web/
```

A `CONTEXT-MAP.md` at the root would mean a multi-context repo, with one `CONTEXT.md`
per context. This repo has none, and it needs none. The three front ends under `web/`
share the one domain that the Go API serves.

## Use the glossary's vocabulary

When your output names a domain concept — an issue title, a refactor proposal, a
hypothesis, a test name — use the term as `CONTEXT.md` defines it. Do not drift to a
synonym the glossary explicitly avoids.

Three words in this glossary carry more than one meaning, and each one must always be
qualified: **enrolment**, **session**, and **code**. Read the notes under those entries
before you use them.

If the concept you need is not in the glossary, that is a signal. Either you are
inventing language the project does not use, and you must reconsider, or there is a real
gap to note for `/domain-modeling`.

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it rather than override it in
silence:

> _Contradicts ADR 0007 (offset pagination for admin lists), and it is worth reopening
> because..._

# Candidate integration verdict — evidence-inclusive `22a3bfc`

Durable index for the final, evidence-inclusive candidate-integration review
of WP-G2-Z01. The full report was not recorded in-repo; this file anchors its
hash and the public, SHA-linked PR comment that carries the verdict table.

## Verdict

| Field                     | Value                                                              |
| ------------------------- | ------------------------------------------------------------------ |
| Review                    | `candidate-integration` (final, evidence-inclusive)                |
| Reviewed commit           | `22a3bfc8cf6a121157e3891269ed26bbfd09c057`                         |
| Reviewed tree             | `51a1c5ae6e54d25acc53bf3dedc53ca844c29455`                         |
| Verdict                   | **APPROVE**                                                        |
| Blocking / major findings | none                                                               |
| Original report SHA-256   | `3b58aa38112f81434bd2223e4473ad87bcadbace14e3a76df88c164707026785` |

## Public anchor — PR #101 review-verdicts comment

The verdict table (including the report hash above) was published as a PR
comment before merge:

- URL: <https://github.com/libre-ai/libre-ai/pull/101#issuecomment-5010621187>
- Author: `constantin-jais`, posted `2026-07-18T08:41:13Z`
- Comment body SHA-256: `cb681d9e4c42d59d81affb4f15b7def1b8f630221d47fdbd4af8467c4e7e7ff7`

Reproduce the comment hash (the comment ID is immutable; `--jq .body` emits
the body with one trailing newline):

```sh
gh api repos/libre-ai/libre-ai/issues/comments/5010621187 --jq .body | shasum -a 256
```

## Relation to the merged history

- PR HEAD `5b3c220` = reviewed `22a3bfc` **plus a non-normative merge of
  contemporaneous `origin/main`** to satisfy the up-to-date branch
  requirement. Verified before merge:
  `git diff --quiet 22a3bfc..5b3c220 -- crates/authz-biscuit contracts Cargo.toml Cargo.lock deny.toml .cargo`
  is empty, so the reviewed scope is byte-identical and the verdict is not
  stale.
- Merged to `main` as `a6bee98` (PR #101), required and post-merge checks
  `SUCCESS`.

## Scope

This approval qualifies the bounded Z01 capability only. It grants no
production, application, secret, infrastructure or release authority
(`Production/Clever authorization: none` in
[`../../../G2-Z01-QUALIFICATION.md`](../../../G2-Z01-QUALIFICATION.md)).
Historical rejects `87a802e` and `fbbe360` remain immutable and are never
reclassified.

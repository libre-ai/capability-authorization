# capability-authorization Canonical Agent Rules

## Authority

Deny-by-default capability authorization on Biscuit Ed25519 tokens, couche 3
brick of the constellation.
Doctrine lives upstream: https://raw.githubusercontent.com/libre-ai/project-governance/HEAD/AGENTS.md
Project state lives in `project.v1.yaml`; the generated README status section
is rendered from it — never edit that section by hand.

## Boundaries

- The six Datalog policies under `vendored/authz/` are a byte-exact projection
  of `libre-ai/schemas-and-contracts`: never edit them in place; a policy change
  is a contracts pin bump followed by re-projection.
- `third_party/biscuit-auth-6.0.0/` and `third_party/patches/` hold the vendored
  `biscuit-auth` patch (I-28) and its provenance gate
  (`scripts/verify-vendored-biscuit-auth.sh`): never modify them outside a
  dedicated, reviewed change.
- The revocation store and the key ring are consumed, never held here.
- Serialized tokens never cross the browser boundary.

## Quality gates

Run `bun run check` from the local composition (`docs/development.md`) before
pushing; never hide a red test.

## Agents

- Security > quality > performance > completeness, in that order on conflict.
- Stage files before running tree-walking gates.
- Never put token bytes, private keys or rejected terms in logs or errors.
- Never commit a machine-local absolute filesystem path.

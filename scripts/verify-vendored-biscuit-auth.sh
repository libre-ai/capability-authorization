#!/usr/bin/env bash
# Provenance gate for the vendored biscuit-auth copy (third_party/biscuit-auth-6.0.0).
#
# Re-downloads the published crates.io archive, verifies its SHA-256 against
# the value declared in PATCH.md, unpacks it, applies the committed upstream
# diff (third_party/patches/), and diffs the result against the vendored tree.
# Any byte of difference — a file edited by hand, a file added, a file dropped,
# a diff that no longer applies — fails the gate. The only file the vendored
# tree is allowed to add is PATCH.md.
#
# Runs in CI (dependency-policy job, blocking) and locally:
#   scripts/verify-vendored-biscuit-auth.sh
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
crate_name="biscuit-auth"
crate_version="6.0.0"
vendored="$root/third_party/${crate_name}-${crate_version}"
patch_file="$root/third_party/patches/${crate_name}-${crate_version}-upstream-306.diff"
patch_doc="$vendored/PATCH.md"
archive_url="https://static.crates.io/crates/${crate_name}/${crate_name}-${crate_version}.crate"

expected_sha256="$(sed -n 's/^- archive SHA-256: `\([0-9a-f]\{64\}\)`.*/\1/p' "$patch_doc" | head -n 1)"
if [ -z "$expected_sha256" ]; then
  echo "verify-vendored: no archive SHA-256 declared in $patch_doc" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "verify-vendored: downloading $archive_url"
curl --fail --silent --show-error --location --retry 3 --output "$work/archive.crate" "$archive_url"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "$work/archive.crate" | cut -d' ' -f1)"
else
  actual_sha256="$(shasum -a 256 "$work/archive.crate" | cut -d' ' -f1)"
fi
if [ "$actual_sha256" != "$expected_sha256" ]; then
  echo "verify-vendored: archive SHA-256 mismatch: expected $expected_sha256, got $actual_sha256" >&2
  exit 1
fi
echo "verify-vendored: archive SHA-256 $actual_sha256 matches PATCH.md"

tar -xzf "$work/archive.crate" -C "$work"
unpacked="$work/${crate_name}-${crate_version}"

echo "verify-vendored: applying $(basename "$patch_file")"
(cd "$unpacked" && patch --strip=2 --no-backup-if-mismatch --forward --silent < "$patch_file")

echo "verify-vendored: diffing the patched archive against $vendored"
if diff --recursive --exclude=PATCH.md "$unpacked" "$vendored"; then
  echo "verify-vendored: OK — the vendored tree is the published archive plus the committed upstream diff"
else
  echo "verify-vendored: FAILED — the vendored tree differs from archive + upstream diff (see above)" >&2
  exit 1
fi

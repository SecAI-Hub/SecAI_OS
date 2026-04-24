Archived cosign public keys for historical release verification belong in this directory.

`files/scripts/verify-release.sh` tries `./cosign.pub` first and then every `*.pub`
file in `./release-keys/`. Keep the current key in the repo root `cosign.pub` and
add rotated-out keys here when the signing key changes.

# Python source-preparation cache

The image workflow materializes Linux wheels here from reviewed service lock
files and exact build requirements. It then generates `SHA256SUMS` and passes
the directory to the network-restricted application build as a short-lived
workflow artifact.

No placeholder checksum manifest is committed. A stage-2 build fails unless
source-prep supplied a non-empty wheelhouse and every staged wheel matches its
generated checksum.

# Staged external source

This directory is populated by the image workflow from
`.upstreams.lock.yaml`. External archives are fetched and checksum-verified in
the network-enabled source-preparation job, then passed to the application
build as immutable workflow artifacts.

Do not place unreviewed source here or bypass the lock manifest.

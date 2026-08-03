#!/usr/bin/env bash
# Enable the mount whose canonical systemd unit name contains a path escape.

set -euo pipefail

# Keep this single-quoted: \x2d is part of the canonical unit filename, not a
# shell or printf escape to decode.
mount_unit='run-secure\x2dai-tmp.mount'
unit_path="/usr/lib/systemd/system/${mount_unit}"
link_path="/etc/systemd/system/multi-user.target.wants/${mount_unit}"

if [ ! -f "$unit_path" ] || [ -L "$unit_path" ]; then
    echo "ERROR: canonical secure AI tmp mount unit is missing or unsafe" >&2
    exit 1
fi

systemctl -f enable "$mount_unit"

if [ ! -L "$link_path" ] || [ "$(readlink -- "$link_path")" != "$unit_path" ]; then
    echo "ERROR: canonical secure AI tmp mount unit was not enabled exactly" >&2
    exit 1
fi

# Native network profiles and recovery

This source implementation separates selected service configuration from effective kernel network scope. Use fresh `/run/secure-ai/network-status.json` evidence, not the name in persisted `profile.json`, to describe host networking. The sandbox/container profile does not enforce the host's firewall.

## Installation and boot prerequisites

The policy needs nftables **1.1.6 or newer** with kernel support for wildcard netdev egress hooks. Version text alone is insufficient: the controller requires the installed runtime chain to report `dev: "*"` and `policy: "drop"`. nftables 1.0.9 accepted the tested wildcard source but produced an unattached hook; the controller rejects that runtime. Wildcard support follows the [upstream nftables chain documentation](https://netfilter.org/projects/nftables/manpage.html#lbAH).

The recipe enables `secure-ai-network-boot.service` and its read-only observer timer, disables the generic `nftables.service` and automatic DNS/update timers, and orders the guard before sysinit, network-pre, NetworkManager, systemd-networkd and firstboot. Network-manager drop-ins require successful guard activation. The guard needs only CAP_NET_ADMIN and local AF_NETLINK/AF_UNIX; it has no external IP socket family. The firstboot and health paths use complete runtime observation instead of a grep for a drop rule.

An assembled image must qualify this ordering, actual nft/kernel packages, initrd handoff, SELinux and the declared systemd mounts. Do not infer these from source tests. If hook verification fails, do not start a network manager as a workaround. Inspect local journal evidence and repair the package/kernel prerequisites offline.

## Scopes and lifetime

All scopes allow loopback. Offline otherwise drops at both inet output and wildcard netdev egress. There is no established-flow output bypass. Forwarding remains denied. The device hook also covers interfaces created after activation; raw DHCP/ARP/IPv4/IPv6 and PACKET_QDISC_BYPASS were exercised in isolated namespace fixtures.

| Scope | Additional egress | Maximum lease |
| --- | --- | --- |
| `research` | DHCP4/6, ARP, IPv6 neighbor/router discovery; TCP sockets owned by the Tor primary group | 3600 seconds |
| `full_lab` | Research scope; airlock UID TCP 53/443 and UDP 53 | 3600 seconds |
| `maintenance` | Research scope; host TCP 53/443 and UDP 53/123 | 900 seconds, default 300 |

These are service/port restrictions, not destination allowlists or payload proof. DHCP and neighbor traffic is an explicit online exception. Tor's group may establish TCP to its configured peers; application mediation and TLS verification remain separate enforcement. IPv6 DNS addresses with interface scopes are not supported by resolver preparation. There is no DHCP, ARP, DNS or NTP exception offline.

The kernel expires leases during awake operation even if the observer stops. Its timeout clock excludes suspend: native Fedora44 testing found a five-second grant still passing packets after eight seconds asleep. The required sleep guard below closes grants before normal systemd sleep instead of relying on that timeout across suspension. Established TCP streams cease making progress after expiry or explicit close; applications may retain stalled sockets. A profile name can remain `full_lab` after the effective scope becomes offline. Services are not automatically stopped on lease expiry. Renewal must be deliberate.

## System sleep and recovery

The recipe enables `secure-ai-network-sleep.service` as a required dependency before `sleep.target`. Standard systemd suspend, hibernate, hybrid-sleep and suspend-then-hibernate services require that target. The guard calls the same verified restrictive controller reset before sleep and again during resume or aborted-request cleanup. Failure to verify closure fails the dependency; it must not permit normal sleep. Nothing restores a previous grant or selected profile automatically.

`sleep-close` writes a protected marker under the controller's existing lock before closing. Grant admission holds that same lock, denies any marker path, and requires the installed guard to be enabled, loaded, inactive/dead, without a pending job and with a successful result. Missing or unknown systemd evidence is unavailable. These checks prevent a concurrent grant in the interval between closure and suspension, and preserve inhibition if the marker is unexpectedly removed while the guard is active or failed. `sleep-release` verifies and publishes offline before removing a valid marker. Failed publication or cleanup is reported; no automatic failure reset reopens grant admission.

After a failed guard, first inspect its journal and repair the reported source, filesystem or controller error. Wait for the sleep transition to end; do not recover while the guard is activating, active or deactivating. Then a local administrator can explicitly recreate inhibition, verify closure and release it:

```sh
sudo /usr/libexec/secure-ai/network-profile.py sleep-close
sudo /usr/libexec/secure-ai/network-profile.py sleep-release
sudo /usr/libexec/secure-ai/network-profile.py observe
# Only after both commands succeed and observation verifies offline:
sudo systemctl reset-failed secure-ai-network-sleep.service
```

Do not reset a failure or delete a malformed marker to obtain an online grant. Preserve and inspect unsafe state; ordinary commands refuse to replace it. A later online lease still requires a separate explicit request. Resetting systemd failure state alone does not prove closure.

This boundary covers managed grants and normal systemd sleep paths. Privileged direct writes to power-state interfaces, direct invocation of `systemd-sleep`, changes to both marker and systemd state, and firmware-initiated sleep bypass this boundary. Actual hibernation/firmware and hardware offload behavior require separate platform qualification. Required dependency, failure, concurrency, repeat and guest suspend/wake behavior must be tested on the assembled runtime; unit-file assertions alone are insufficient.

## Explicit profile application

Use the existing authorized profile UI or a local administrator command, for example:

```sh
sudo /usr/libexec/secure-ai/apply-profile.sh research operator
sudo /usr/libexec/secure-ai/apply-profile.sh full_lab operator
sudo /usr/libexec/secure-ai/apply-profile.sh offline_private operator
```

Each transition closes networking before validating the request or changing services. Full lab stops airlock, prepares its resolver and starts it with a new binding before granting. Services and selected-state changes must validate and the transition audit write must complete before a lease is requested. Failed application restores the prior service snapshot/selection when possible, while leaving networking closed. A failed recovery is reported as `rollback_failed`; it does not restore online authority.

Calling the profile applicator without an explicit request selects offline. Persisted online selection, a locked online operator override, boot/path activation or an observer restart cannot create a new online lease. An override that forbids the offline service selection may cause application failure, while the initial network restriction remains. Only the existing explicit request file in volatile `/run` or a direct profile argument can request online application.

## Maintenance and diagnostics

Maintenance is a deliberate local administrator operation, not a new UI or polkit action. Inspect local state and quiesce or finish other network work before changing scope:

```sh
sudo /usr/libexec/secure-ai/network-profile.py close
sudo /usr/libexec/secure-ai/network-profile.py grant --scope maintenance --seconds 300
sudo /usr/libexec/secure-ai/network-profile.py observe
sudo /usr/libexec/secure-ai/update-verify.sh check
# Optional explicit DNS request, while the maintenance lease is still fresh:
sudo systemctl start secure-ai-dns-leak-check.service
sudo /usr/libexec/secure-ai/network-profile.py close
```

Do not enable the automatic update or DNS timers. Their ExecCondition and update subcommand guards reject missing, wrong-boot, stale, unknown or non-maintenance evidence, and kernel expiry still closes packets during long operations. A long update may require a separately reviewed, newly granted maintenance window; commands never renew it themselves. Package operations may leave partial downloads or a staged deployment; use the update runbook to inspect that state.

`network-profile.py grant` refuses renewal over an existing lease. Close first. The runtime controller changes only `inet secure_ai` and `netdev secure_ai_link`; it does not flush unrelated tables or emergency containment tables. Other restrictive tables can prevent permitted traffic from working. Do not remove them to obtain a positive status.

## Full-lab DNS binding

The root preparation step accepts only a bounded, nonsymlink, single-link, non-group/world-writable uplink file: root-owned `/run/NetworkManager/no-stub-resolv.conf`, or `/run/systemd/resolve/resolv.conf` owned by the installed `systemd-resolve` account. It extracts one to three direct non-loopback, non-multicast, non-unspecified nameservers and introduces no provider. Unsupported, changed, missing or malformed input makes full lab unavailable. It never grants root DNS to make a shared loopback stub work.

Preparation writes `/run/secure-ai-network/airlock-resolv.conf` behind a root-only directory, then stores its source and prepared dev/inode/hash reference. The airlock unit binds the file read-only onto `/etc/resolv.conf`. An unprivileged ExecStartPre receipt records the actually opened file, read-only mount flag, boot ID and current systemd invocation. A separate read-only boot-ID mount accommodates the unit's existing `ProcSubset=pid` restriction without opening additional proc data.

On a cold boot with DHCP-only DNS, no trusted uplink configuration may exist yet because offline correctly blocks DHCP. Explicitly apply research or a maintenance lease to obtain network configuration first; then apply full lab. Tor starts without waiting for network-online, so service startup does not deadlock behind the closed firewall. Static trusted uplink configuration can support direct full-lab application. No cold-boot DHCP exception is minted automatically to solve this prerequisite.

Grant and observation compare the receipt to the prepared file and to `systemctl show` ActiveState/SubState/InvocationID. D-Bus/query failure is unavailable. A running airlock retaining an older mounted inode cannot satisfy a newly prepared reference. Stop, prepare and restart in that order; profile application performs that sequence. A trusted uplink-file replacement, even with identical content, invalidates the binding until the next explicit preparation/restart. The observer then revokes existing scope sets on failure. That detection is periodic, not instantaneous.

The receipt is scoped service-namespace evidence under a trusted root/unit/service model. It is not remote attestation and does not resist a compromised administrator or a service capable of forging its own receipt. The native fixture measured read-only bind mounts, UID-separated DNS and a real TLS fetch through the Go airlock; systemd's invocation query was a test adapter. Actual systemd binding, Landlock, SELinux and restart behavior still need assembled-image qualification.

## Runtime evidence and failure handling

Status schema version 1 includes `boot_id`, RFC3339 UTC `checked_at`, `valid_until`, optional `lease_expires_at`, monotonic `checked_monotonic`, and integer `valid_for_seconds` at most 30. `status` is `verified` or `unknown`; `effective_scope` is `offline`, `research`, `full_lab`, `maintenance` or `unknown`. Verified observations set `ipv4_enforced`, `ipv6_enforced` and `arp_enforced` true. `host_offline` is true only for verified offline. Unknown records use null booleans. `allowed_egress` contains the exact declared scope descriptions; `automatic_network_tasks` is false and `evidence_source` is `nftables_runtime`.

The observer runs every 15 seconds with one second timer accuracy. Consumers must reject unsafe ownership/mode/symlink/hardlink state, another boot, wall-clock or monotonic staleness, and inconsistent scope/lease fields. Positive UI evidence expires at the earlier wall or monotonic deadline. A lease transition publishes unknown before opening packets. Public status is root-owned 0644; the private per-boot rule reference is root-owned 0600 in a 0700 directory. Neither is an external integrity anchor.

Observation compares the full owned runtime objects against the per-boot reference and separately checks bounded kernel leases. It sends no diagnostic traffic. Missing or changed reference/rules, unknown invocation or filesystem/query failure cannot generate a verified result. Failed observation attempts to revoke the current scope sets; it never silently recreates a missing reference. A failing nft operation may also prevent that restriction attempt; any previously installed lease still expires in the kernel. A stale result must therefore be displayed as unavailable, never offline.

Explicit `close` reinstalls only the restrictive policy and creates a new per-boot reference. Repair source/package/state errors first and inspect the local failure evidence before using it as recovery. If restrictive installation itself fails, there is no verified host-offline claim. No automatic failure path creates a new online grant.

Source upgrade rollback is explicit: preserve the prior image/source snapshot for review, but do not restore old runtime lease/reference files or re-enable the previous permissive firewall. A rollback to the older implementation changes the security contract and requires offline review. No live installation, profile transition or historical-state conversion was performed during this work.

## Qualification boundary

Private namespace tests prove the recorded kernel/toolchain behavior for synthetic veth links, IPv4/IPv6 packet scopes, raw packet sockets, timed/explicit transitions, unrelated-table preservation and the exercised native airlock binding. They do not establish radio/firmware silence, initrd behavior, privileged TC/XDP or alternate networking stacks, VM/hypervisor isolation, hardware offload behavior, malicious root resistance, production DNS availability or a complete Fedora boot. Preserve those distinctions in status wording and release qualification.

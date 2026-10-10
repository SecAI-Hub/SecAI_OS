# Telemetry and network policy

The appliance does not intentionally send usage analytics or automatic crash reports. This is a source policy, not a claim that a selected profile proves the running host is disconnected. Native network assurance requires a fresh, same-boot runtime firewall observation. Container deployments do not establish a host firewall guarantee.

The native boot guard installs empty online leases before the configured network managers. In verified `offline_private` operation, the owned IPv4/IPv6 and wildcard device-egress rules permit loopback and block non-loopback host egress, including established streams, DNS, NTP, HTTPS and tested raw packet sockets. Offline mode also blocks DHCP, ARP and IPv6 neighbor discovery. It does not promise radio, firmware, hypervisor or pre-guard/initrd silence.

Explicit online scopes expire in the kernel. They have visible network-configuration exceptions:

| Effective scope | Permitted egress, subject to other restrictive rules |
| --- | --- |
| Offline | Loopback only |
| Research | Loopback; DHCP, ARP and IPv6 neighbor discovery; Tor service TCP |
| Full lab | Research scope plus the dedicated airlock UID's HTTPS and direct DNS |
| Maintenance | Research scope plus host HTTPS, DNS and NTP |

Research and full-lab profile applications grant at most one hour. A separate local administrator maintenance grant defaults to five minutes and cannot exceed fifteen minutes. Renewal closes egress first and requires a new explicit action. Persisted profile selection and ordinary observation never renew a lease. A failed transition does not restore a previous online lease.

Automatic update-check and DNS-diagnostic timers are disabled. Their services and network-bearing update steps additionally require a fresh maintenance observation. The optional DNS diagnostic sends an explicit maintenance DNS request; it is not a leak-freedom test. Updates and diagnostics may fail when a lease expires; this does not authorize automatic renewal.

Full lab uses direct DNS only inside the airlock's read-only resolver binding, prepared from the host's existing trusted uplink configuration. It does not select a public DNS provider or permit the shared root resolver outside maintenance. DNS queries and allowed application requests remain disclosures to the configured network and destinations. Search sanitization, Tor and application policy do not justify a general anonymity or content-confidentiality claim.

Local audit coverage is mixed: some writers have authenticated chains, while others have structured durable records. Profile and diagnostic status are not universal cryptographic proof of every network event. Audit checks have their own enrollment, retention and external-anchor limits. Agent task history stores bounded metadata; live service results and other service logs follow their separate documented policies.

See [the native network runbook](network-profiles.md) for prerequisites, exact runtime status, maintenance and recovery commands, resolver renewal, and the boundary between namespace test evidence and assembled Fedora qualification.

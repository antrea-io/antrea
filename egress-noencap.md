# Implementation spec: Egress in noEncap mode via policy routing

Self-contained spec for an executing agent. Implements Antrea **Egress support in pure noEncap mode** (currently unsupported — `docs/egress.md` says encap/hybrid only). The datapath has been **validated end-to-end in a 4-namespace kernel testbed (8/8 checks pass)**; §2 is the ground-truth rule set. Do not deviate from §2 semantics.

Target: branch off `main`. All file:line references were taken against current `main` (2026-07-10) and may drift by a few lines — locate by symbol, not line.

---

## 1. Problem & approach

In encap/hybrid, Egress to a remote Egress-IP node uses an **OVS Geneve tunnel**: `snatRuleFlow` (`pkg/agent/openflow/pipeline.go`) sets `tun_dst = egressIP`, and the egress node selects the SNAT IP via `MatchTunnelDst`. Pure noEncap has **no tunnel interface** (`NetworkConfig.NeedsTunnelInterface()` in `pkg/agent/config/node_config.go` returns true only for `SupportsEncap()`), so this path cannot work — hence Egress is unsupported in noEncap.

Replacement (same-subnet on-link only; cross-subnet stays tunnel/unsupported):

- **Source node**: OVS marks the Pod's egress packets with a per-Egress-IP **steer mark**, then Linux **policy routing** (`ip rule fwmark → table → default via egressNodeTransportIP`) sends them to the egress node. The packet keeps its Pod source IP and external destination; it is L2-delivered to the on-link egress node, which `ip_forward`s it.
- **Egress node**: an **ipset of member Pod IPs** drives SNAT (`-m set --match-set … src -j SNAT --to-source egressIP`). This ipset replaces `tun_dst` as the "which Egress IP" selector, because the routed packet carries no mark (marks are node-local).
- **Reply**: external → egress node → conntrack un-SNAT (dst=PodIP) → routed back to the source node (noEncap Pod CIDRs are directly routable) → Pod. No reply-side policy routing needed on the egress node.

Feature gate: **`EgressSeparateSubnet`-style** new gate `EgressDirectRouting`, Alpha, default **false**.

---

## 2. Validated datapath (ground truth — reproduce these exact semantics)

Proven in `/home/ubuntu/egress-dp-validate/validate.sh` (netns testbed, real kernel). Node roles: SRC = source node (Pod lives here), EGR = egress node (Egress IP lives here), both on-link.

**SRC node** (Pod IP `P`, steer mark `M` bits 0–7, steer table `T`, egress node transport IP `G`, transport dev `UP`, pod-facing gateway `antrea-gw0`):

```
# 1. OVS sets skb mark = M on the Pod's egress packets (see §5, snatRuleFlow new branch).
#    (In the testbed this was stubbed by: iptables -t mangle -A PREROUTING -i antrea-gw0 -s P -j MARK --set-mark M/0xff)
# 2. Policy routing: mark M -> table T -> default via egress node.
ip rule add fwmark M/0xff lookup T                    # == route client AddEgressRule(T, M, isIPv6)
ip route add default via G dev UP table T             # == route client AddEgressRoutes(T, UP, G, prefixLen)
# 3. Masquerade bypass — CRITICAL. The node's pod-to-external MASQUERADE would rewrite the
#    Pod source, so EGR's ipset can never match. Steer-marked packets must bypass it.
iptables -t nat -I ANTREA-POSTROUTING 1 -o UP -m mark --mark M/0xff -j RETURN
# 4. rp_filter on the reply-ingress interface MUST be loose (2). Strict (1) DROPS the
#    asymmetric un-SNAT'd reply (independently reproduced: strict=dropped, loose=delivered).
sysctl net.ipv4.conf.<transport>.rp_filter=2          # antrea already does this on the gw, route_linux.go ~404
```

**EGR node** (owns Egress IP `E`, uplink `UP`, member Pod IPs in ipset `S`):

```
ipset create S hash:ip                                # per Egress IP; family-specific
ipset add S <memberPodIP> ...
iptables -t nat -A ANTREA-POSTROUTING -o UP -m set --match-set S src -j SNAT --to-source E
sysctl net.ipv4.ip_forward=1                           # already set by antrea
```

**Optional hardening (connmark) — NOT required for v1 parity.** OVS re-marks every forward packet, so steering is already stable within a fixed spec. Connmark only adds pinning of an *established* connection across a mid-flight Egress **spec change** (validated: works). Mirror the existing bit-30 pattern (`route_linux.go` ~1273–1299) if desired; otherwise omit. Current Antrea egress does not pin across spec change either, so omitting matches existing behavior.

Validated facts to preserve: unbypassed masquerade breaks SNAT selection; strict rp_filter drops the reply; conntrack on EGR provides the un-SNAT binding automatically.

---

## 3. What already exists (REUSE — do not reimplement)

- **Route client primitives** (`pkg/agent/route/route_linux.go`, iface `pkg/agent/route/interfaces.go`):
  - `AddEgressRoutes(tableID, dev, gateway, prefixLength)` / `DeleteEgressRoutes(tableID)` — installs `default via gateway dev X table tableID` (+ link route). **Use directly for the steer route**, gateway = egress node transport IP.
  - `AddEgressRule(tableID, mark, isIPv6)` / `DeleteEgressRule(...)` — installs `ip rule fwmark mark/0xff lookup tableID`. **Use directly for the steer rule.** Mask is `types.SNATIPMarkMask` (0xFF).
  - `AddSNATRule(snatIP, mark)` / `DeleteSNATRule(mark)` — mark-based SNAT for **local** Pods on the egress node; keep as-is.
  - `RestoreEgressRoutesAndRules(min, max)` — startup GC of egress tables/rules; extend its range or call for the new range.
- **ID allocators** (`pkg/agent/controller/egress/egress_controller.go`): `markAllocator` (`newIDAllocator`), `tableAllocator` = `newIDAllocator(MinRequestEgressRouteTable, MaxRequestEgressRouteTable)`. Reuse the pattern for a steer-table allocator.
- **ipset client** (`pkg/agent/util/ipset`): `CreateIPSet(name, ipset.HashIP, isIPv6)`, `AddEntry`, `DelEntry`, `DestroyIPSet`. Driven from `route_linux.go syncIPSet()`.
- **Egress controller realize path**: `realizeEgressIP(egressName, egressIP, subnetInfo)` decides local-vs-remote via `c.localIPDetector.IsLocalIP(egressIP)`; `realizeEgress` calls `ofClient.InstallPodSNATFlows(ofPort, egressIP, mark)` per member Pod OF port; teardown via `uninstallPodFlows` / `unrealizeEgressIP`.
- **Feature gate template**: `EgressSeparateSubnet` in `pkg/features/antrea_features.go` (registration at lines ~180/247/283/335).
- **Types** (`pkg/agent/types/net.go`): fwmark bits 0–7 = SNAT IP ID (`SNATIPMarkMask` 0xFF), 30 = egress reply, 31 = host-local; tables 101–120 request, 141 reply.

## 4. What is NEW (implement)

1. Egress-node **ipset-based SNAT by source Pod IP** (the tun_dst replacement).
2. Source-node **masquerade bypass** for steer marks.
3. Source-node **steer mark + steer table + OVS mark-and-forward branch** for a *remote* Egress IP in noEncap (today a remote IP gets mark=0 and the tunnel branch).
4. **Controller**: EgressGroup span must include candidate egress nodes so they receive the member list to build the ipset.
5. Resolve **egress node transport IP** from `Egress.status.egressNode` on the source node.

---

## 5. Implementation by phase

Each phase must `go build ./...` and `go vet ./...` clean. Add unit tests per phase.

### Phase 1 — Controller: EgressGroup span includes candidate egress nodes

File: `pkg/controller/egress/controller.go` (span computed in the EgressGroup sync; today `SpanMeta.NodeNames` = only Nodes running selected Pods, see the `nodeNames.Insert(pod.Spec.NodeName)` loop).

Change: union in the **candidate egress Nodes** = Nodes matching the Egress's `ExternalIPPool.spec.nodeSelector`. The controller already watches ExternalIPPools for IP allocation; resolve the pool's nodeSelector to Node names and add them to the group span. Rationale: the egress node needs the member Pod list *before* it owns the IP, so a new owner after failover can SNAT from the first packet (status-driven span would leak un-SNAT'd Pod-IP packets during the failover window — rejected).

Guard behind `EgressDirectRouting` (only extend span when the gate is on) to keep default behavior byte-identical.

Tests: span computation with/without the gate; pool nodeSelector resolution; Egress whose pods run on non-candidate nodes.

This phase is independently mergeable and inert without Phase 2–3.

### Phase 2 — Agent types + route client

File `pkg/agent/types/net.go`:
- Add steer-table range, e.g. `MinEgressSteerRouteTable = 121`, `MaxEgressSteerRouteTable = 140` (must not overlap 101–120 or 141). Add a doc comment that steer marks reuse the 0–7 `SNATIPMarkMask` space (same per-Node allocator as local SNAT marks, so a steer mark never collides in value with a local SNAT mark on the same Node).

File `pkg/agent/route/interfaces.go` + `route_linux.go` (+ `route_windows.go` stubs returning `nil`/unsupported):
- `AddEgressSNATIPSetRule(egressIP net.IP, ipsetName string, isIPv6 bool) error` — creates the ipset (idempotent, `CreateIPSet` with `-exist` semantics) and inserts `ANTREA-POSTROUTING -o <transport/uplink> -m set --match-set <ipsetName> src -j SNAT --to-source <egressIP>`; record in an ownership map for GC.
- `DeleteEgressSNATIPSetRule(egressIP, ipsetName, isIPv6) error`.
- `AddEgressSNATIPSetMember(ipsetName, podIP) / DeleteEgressSNATIPSetMember(...)` — maintain set membership as EgressGroup members change.
- `AddEgressSteerMasqueradeBypass(mark uint32) / Delete...` — insert `ANTREA-POSTROUTING -o <transport> -m mark --mark mark/0xff -j RETURN` **before** the existing MASQUERADE rule (`InsertRule` at position 1, or ensure ordering; the existing pod-to-external masquerade is added when `!c.noSNAT`, ~`route_linux.go:1437`). This is the single most correctness-critical rule — without it the egress node ipset never matches.
- Steer route/rule: **reuse** `AddEgressRoutes(tableID, dev, egressNodeTransportIP, prefixLen)` + `AddEgressRule(tableID, mark, isIPv6)`. No new route/rule code needed.
- Fold ipset + bypass rules into `syncIPTables`/`syncIPSet` so they survive agent restart (idempotent replay, like all existing rules). Extend `RestoreEgressRoutesAndRules` (or add a sibling) to GC the 121–140 range on startup.
- rp_filter: the transport interface used for reply ingress must be loose (2). Antrea already sets the gateway to loose; confirm the transport/uplink interface is also loose when this feature is on (add to the `shouldEnableEgressPolicyRouting`-style init), because §2 proved strict drops the reply.

Tests: rule/route/ipset lifecycle (add→list→delete), masquerade-bypass ordering, member add/remove, IPv4 and IPv6.

### Phase 3 — OVS flow + egress controller wiring

File `pkg/agent/openflow/pipeline.go`, `snatRuleFlow` (currently: `snatMark != 0` → local `LoadPktMarkRange`; else → remote `SetTunnelDst`). Add a **third case**: remote Egress IP **and** no tunnel (noEncap + `EgressDirectRouting`) → behave like the local branch shape — `LoadPktMarkRange(steerMark)` + `ToGatewayRegMark` → `stageSwitching` (output toward antrea-gw0/host stack), **not** `SetTunnelDst`. Plumb the choice via a new client method or an added parameter:

File `pkg/agent/openflow/client.go`: add `InstallPodSNATFlows` variant (e.g. `InstallPodSteerSNATFlows(ofPort, steerMark)`) or extend the existing signature; the caller decides based on mode+gate. Keep `InstallPodSNATFlows`/`snatIPFromTunnelFlow` untouched so encap/hybrid are unaffected (a hybrid cluster has both paths).

File `pkg/agent/controller/egress/egress_controller.go`:
- Add a `steerTableAllocator = newIDAllocator(MinEgressSteerRouteTable, MaxEgressSteerRouteTable)`.
- In `realizeEgressIP`: when the IP is **remote** and `EgressDirectRouting` and the egress node is **on-link same-subnet**: allocate a steer mark (reuse `markAllocator`), resolve the egress node's transport IP from `Egress.status.egressNode` (map Node name → transport IP via the existing node/peer info the agent holds), allocate a steer table, call `routeClient.AddEgressRoutes(table, transportDev, egressNodeTransportIP, prefixLen)` + `AddEgressRule(table, steerMark, isIPv6)` + `AddEgressSteerMasqueradeBypass(steerMark)`; keep `ipState.mark = steerMark`.
- In `realizeEgressIP` when the IP is **local** and `EgressDirectRouting`: additionally create the egress-node ipset (`AddEgressSNATIPSetRule(egressIP, setName, isIPv6)`) and maintain its members from the EgressGroup (Phase 1 delivers them). This is on top of the existing local mark-based SNAT (which still serves Pods local to the egress node).
- In `realizeEgress` (per-Pod): when remote+direct-routing, call the new `InstallPodSteerSNATFlows(ofPort, steerMark)` instead of the tunnel-mode `InstallPodSNATFlows`.
- Failover: when `status.egressNode` changes, update the steer route's `default via` (route replace; mark/rule/table stay). Existing conntrack entries on the old owner break — same as today's tunnel repoint; document, do not fix.
- Same-subnet guard: if the egress node's transport IP is **not** on-link from this Node, set an Egress condition = unsupported (today it is wholly unsupported in noEncap, so any covered case is net gain). Do not attempt cross-subnet direct routing.
- Teardown mirrors: delete steer route/rule/bypass/ipset, release mark + steer table, on unrealize.

File `pkg/features/antrea_features.go`: register `EgressDirectRouting` (Alpha, default false) at the four sites mirroring `EgressSeparateSubnet`. Add agent config validation if needed.

Tests: `snatRuleFlow` third branch flow asserts; controller state transitions (remote↔local flips, spec change, failover `status.egressNode` change); on-link vs cross-subnet guard; feature-gate off = no behavior change.

### Phase 4 — e2e, docs, rollout

- e2e (Linux, noEncap kind cluster, gate on): Pod on Node A, Egress IP on Node B; external observer sees the Egress IP (never the Pod IP or Node IP — this is the masquerade-bypass regression guard); reply reaches the Pod; failover moves the IP and traffic follows; IPv6 mirror.
- `docs/egress.md`: lift the "encap/hybrid only" limitation for noEncap **same-subnet**, with the cross-subnet caveat and the feature-gate note.
- Rollout: Alpha default-off → soak on a noEncap staging cluster with FlowExporter + `conntrack -L`/`ipset list` spot checks → Beta.

---

## 6. Correctness checklist (do not ship without)

1. **Masquerade bypass present and ordered before MASQUERADE** — the #1 failure mode. Verify externally: the destination must see the Egress IP, never the Node/transport IP.
2. **Transport interface rp_filter = loose (2)** — else the un-SNAT'd reply is silently dropped (strict-mode drop reproduced in validation).
3. **Egress node ipset populated before it owns the IP** (Phase 1 span) — else failover leaks Pod-IP-sourced packets.
4. **Same-subnet guard** — never install steer routes to a cross-subnet egress node; report unsupported.
5. **Feature gate off ⇒ zero behavior change** — all new code paths gated; encap/hybrid tunnel path untouched.
6. **Startup GC** for the new steer-table range and ipsets (idempotent restart).
7. IPv6 parity throughout (ip -6 rule/route, ip6tables, hash:ip inet6 sets).

## 7. Out of scope for v1

- Cross-subnet noEncap (needs a tunnel — that is the encap/hybrid case).
- Hybrid same-subnet reuse of this path (mechanically identical; separate follow-up).
- `networkPolicyOnly` mode (Pod IPs managed by primary CNI; different routing assumptions).
- `EgressTrafficShaping` (OVS meters on the egress node are bypassed by this path) — reject in webhook/condition when combined with the gate; revisit with tc-on-uplink later.
- `EgressSeparateSubnet` combined with this gate — exclude in v1, revisit.
- Windows.

## 8. Reference

- Design rationale & packet walks: `docs/egress-noencap-policy-routing-plan.md`.
- Datapath validation (run to re-confirm): `sudo bash /home/ubuntu/egress-dp-validate/validate.sh` (8/8).
# Implementation spec: Egress in noEncap mode via policy routing

Self-contained spec for an executing agent. Implements Antrea **Egress support in pure noEncap mode** (currently unsupported — `docs/egress.md` says encap/hybrid only). The datapath has been **validated end-to-end in a 4-namespace kernel testbed (8/8 checks pass)**; §2 is the ground-truth rule set. Do not deviate from §2 semantics.

Target: branch off `main`. All file:line references were taken against current `main` (2026-07-10) and may drift by a few lines — locate by symbol, not line.

---

## 1. Problem & approach

In encap/hybrid, Egress to a remote Egress-IP node uses an **OVS Geneve tunnel**: `snatRuleFlow` (`pkg/agent/openflow/pipeline.go`) sets `tun_dst = egressIP`, and the egress node selects the SNAT IP via `MatchTunnelDst`. Pure noEncap has **no tunnel interface** (`NetworkConfig.NeedsTunnelInterface()` in `pkg/agent/config/node_config.go` returns true only for `SupportsEncap()`), so this path cannot work — hence Egress is unsupported in noEncap.

Replacement (same-subnet on-link only; cross-subnet stays tunnel/unsupported):

- **Source node**: OVS marks the Pod's egress packets with a per-Egress-IP **steer mark**, then Linux **policy routing** (`ip rule fwmark → table → default via egressNodeTransportIP`) sends them to the egress node. The packet keeps its Pod source IP and external destination; it is L2-delivered to the on-link egress node, which `ip_forward`s it.
- **Egress node**: an **ipset of member Pod IPs** drives SNAT (`-m set --match-set … src -j SNAT --to-source egressIP`). This ipset replaces `tun_dst` as the "which Egress IP" selector, because the routed packet carries no mark (marks are node-local).
- **Reply**: external → egress node → conntrack un-SNAT (dst=PodIP) → routed back to the source node (noEncap Pod CIDRs are directly routable) → Pod. No reply-side policy routing needed on the egress node.

Feature gate: **`EgressSeparateSubnet`-style** new gate `EgressDirectRouting`, Alpha, default **false**.

---

## 2. Validated datapath (ground truth — reproduce these exact semantics)

Proven in `/home/ubuntu/egress-dp-validate/validate.sh` (netns testbed, real kernel). Node roles: SRC = source node (Pod lives here), EGR = egress node (Egress IP lives here), both on-link.

**SRC node** (Pod IP `P`, steer mark `M` bits 0–7, steer table `T`, egress node transport IP `G`, transport dev `UP`, pod-facing gateway `antrea-gw0`):

```
# 1. OVS sets skb mark = M on the Pod's egress packets (see §5, snatRuleFlow new branch).
#    (In the testbed this was stubbed by: iptables -t mangle -A PREROUTING -i antrea-gw0 -s P -j MARK --set-mark M/0xff)
# 2. Policy routing: mark M -> table T -> default via egress node.
ip rule add fwmark M/0xff lookup T                    # == route client AddEgressRule(T, M, isIPv6)
ip route add default via G dev UP table T             # == route client AddEgressRoutes(T, UP, G, prefixLen)
# 3. Masquerade bypass — CRITICAL. The node's pod-to-external MASQUERADE would rewrite the
#    Pod source, so EGR's ipset can never match. Steer-marked packets must bypass it.
iptables -t nat -I ANTREA-POSTROUTING 1 -o UP -m mark --mark M/0xff -j RETURN
# 4. rp_filter on the reply-ingress interface MUST be loose (2). Strict (1) DROPS the
#    asymmetric un-SNAT'd reply (independently reproduced: strict=dropped, loose=delivered).
sysctl net.ipv4.conf.<transport>.rp_filter=2          # antrea already does this on the gw, route_linux.go ~404
```

**EGR node** (owns Egress IP `E`, uplink `UP`, member Pod IPs in ipset `S`):

```
ipset create S hash:ip                                # per Egress IP; family-specific
ipset add S <memberPodIP> ...
iptables -t nat -A ANTREA-POSTROUTING -o UP -m set --match-set S src -j SNAT --to-source E
sysctl net.ipv4.ip_forward=1                           # already set by antrea
```

**Optional hardening (connmark) — NOT required for v1 parity.** OVS re-marks every forward packet, so steering is already stable within a fixed spec. Connmark only adds pinning of an *established* connection across a mid-flight Egress **spec change** (validated: works). Mirror the existing bit-30 pattern (`route_linux.go` ~1273–1299) if desired; otherwise omit. Current Antrea egress does not pin across spec change either, so omitting matches existing behavior.

Validated facts to preserve: unbypassed masquerade breaks SNAT selection; strict rp_filter drops the reply; conntrack on EGR provides the un-SNAT binding automatically.

---

## 3. What already exists (REUSE — do not reimplement)

- **Route client primitives** (`pkg/agent/route/route_linux.go`, iface `pkg/agent/route/interfaces.go`):
  - `AddEgressRoutes(tableID, dev, gateway, prefixLength)` / `DeleteEgressRoutes(tableID)` — installs `default via gateway dev X table tableID` (+ link route). **Use directly for the steer route**, gateway = egress node transport IP.
  - `AddEgressRule(tableID, mark, isIPv6)` / `DeleteEgressRule(...)` — installs `ip rule fwmark mark/0xff lookup tableID`. **Use directly for the steer rule.** Mask is `types.SNATIPMarkMask` (0xFF).
  - `AddSNATRule(snatIP, mark)` / `DeleteSNATRule(mark)` — mark-based SNAT for **local** Pods on the egress node; keep as-is.
  - `RestoreEgressRoutesAndRules(min, max)` — startup GC of egress tables/rules; extend its range or call for the new range.
- **ID allocators** (`pkg/agent/controller/egress/egress_controller.go`): `markAllocator` (`newIDAllocator`), `tableAllocator` = `newIDAllocator(MinRequestEgressRouteTable, MaxRequestEgressRouteTable)`. Reuse the pattern for a steer-table allocator.
- **ipset client** (`pkg/agent/util/ipset`): `CreateIPSet(name, ipset.HashIP, isIPv6)`, `AddEntry`, `DelEntry`, `DestroyIPSet`. Driven from `route_linux.go syncIPSet()`.
- **Egress controller realize path**: `realizeEgressIP(egressName, egressIP, subnetInfo)` decides local-vs-remote via `c.localIPDetector.IsLocalIP(egressIP)`; `realizeEgress` calls `ofClient.InstallPodSNATFlows(ofPort, egressIP, mark)` per member Pod OF port; teardown via `uninstallPodFlows` / `unrealizeEgressIP`.
- **Feature gate template**: `EgressSeparateSubnet` in `pkg/features/antrea_features.go` (registration at lines ~180/247/283/335).
- **Types** (`pkg/agent/types/net.go`): fwmark bits 0–7 = SNAT IP ID (`SNATIPMarkMask` 0xFF), 30 = egress reply, 31 = host-local; tables 101–120 request, 141 reply.

## 4. What is NEW (implement)

1. Egress-node **ipset-based SNAT by source Pod IP** (the tun_dst replacement).
2. Source-node **masquerade bypass** for steer marks.
3. Source-node **steer mark + steer table + OVS mark-and-forward branch** for a *remote* Egress IP in noEncap (today a remote IP gets mark=0 and the tunnel branch).
4. **Controller**: EgressGroup span must include candidate egress nodes so they receive the member list to build the ipset.
5. Resolve **egress node transport IP** from `Egress.status.egressNode` on the source node.

---

## 5. Implementation by phase

Each phase must `go build ./...` and `go vet ./...` clean. Add unit tests per phase.

### Phase 1 — Controller: EgressGroup span includes candidate egress nodes

File: `pkg/controller/egress/controller.go` (span computed in the EgressGroup sync; today `SpanMeta.NodeNames` = only Nodes running selected Pods, see the `nodeNames.Insert(pod.Spec.NodeName)` loop).

Change: union in the **candidate egress Nodes** = Nodes matching the Egress's `ExternalIPPool.spec.nodeSelector`. The controller already watches ExternalIPPools for IP allocation; resolve the pool's nodeSelector to Node names and add them to the group span. Rationale: the egress node needs the member Pod list *before* it owns the IP, so a new owner after failover can SNAT from the first packet (status-driven span would leak un-SNAT'd Pod-IP packets during the failover window — rejected).

Guard behind `EgressDirectRouting` (only extend span when the gate is on) to keep default behavior byte-identical.

Tests: span computation with/without the gate; pool nodeSelector resolution; Egress whose pods run on non-candidate nodes.

This phase is independently mergeable and inert without Phase 2–3.

### Phase 2 — Agent types + route client

File `pkg/agent/types/net.go`:
- Add steer-table range, e.g. `MinEgressSteerRouteTable = 121`, `MaxEgressSteerRouteTable = 140` (must not overlap 101–120 or 141). Add a doc comment that steer marks reuse the 0–7 `SNATIPMarkMask` space (same per-Node allocator as local SNAT marks, so a steer mark never collides in value with a local SNAT mark on the same Node).

File `pkg/agent/route/interfaces.go` + `route_linux.go` (+ `route_windows.go` stubs returning `nil`/unsupported):
- `AddEgressSNATIPSetRule(egressIP net.IP, ipsetName string, isIPv6 bool) error` — creates the ipset (idempotent, `CreateIPSet` with `-exist` semantics) and inserts `ANTREA-POSTROUTING -o <transport/uplink> -m set --match-set <ipsetName> src -j SNAT --to-source <egressIP>`; record in an ownership map for GC.
- `DeleteEgressSNATIPSetRule(egressIP, ipsetName, isIPv6) error`.
- `AddEgressSNATIPSetMember(ipsetName, podIP) / DeleteEgressSNATIPSetMember(...)` — maintain set membership as EgressGroup members change.
- `AddEgressSteerMasqueradeBypass(mark uint32) / Delete...` — insert `ANTREA-POSTROUTING -o <transport> -m mark --mark mark/0xff -j RETURN` **before** the existing MASQUERADE rule (`InsertRule` at position 1, or ensure ordering; the existing pod-to-external masquerade is added when `!c.noSNAT`, ~`route_linux.go:1437`). This is the single most correctness-critical rule — without it the egress node ipset never matches.
- Steer route/rule: **reuse** `AddEgressRoutes(tableID, dev, egressNodeTransportIP, prefixLen)` + `AddEgressRule(tableID, mark, isIPv6)`. No new route/rule code needed.
- Fold ipset + bypass rules into `syncIPTables`/`syncIPSet` so they survive agent restart (idempotent replay, like all existing rules). Extend `RestoreEgressRoutesAndRules` (or add a sibling) to GC the 121–140 range on startup.
- rp_filter: the transport interface used for reply ingress must be loose (2). Antrea already sets the gateway to loose; confirm the transport/uplink interface is also loose when this feature is on (add to the `shouldEnableEgressPolicyRouting`-style init), because §2 proved strict drops the reply.

Tests: rule/route/ipset lifecycle (add→list→delete), masquerade-bypass ordering, member add/remove, IPv4 and IPv6.

### Phase 3 — OVS flow + egress controller wiring

File `pkg/agent/openflow/pipeline.go`, `snatRuleFlow` (currently: `snatMark != 0` → local `LoadPktMarkRange`; else → remote `SetTunnelDst`). Add a **third case**: remote Egress IP **and** no tunnel (noEncap + `EgressDirectRouting`) → behave like the local branch shape — `LoadPktMarkRange(steerMark)` + `ToGatewayRegMark` → `stageSwitching` (output toward antrea-gw0/host stack), **not** `SetTunnelDst`. Plumb the choice via a new client method or an added parameter:

File `pkg/agent/openflow/client.go`: add `InstallPodSNATFlows` variant (e.g. `InstallPodSteerSNATFlows(ofPort, steerMark)`) or extend the existing signature; the caller decides based on mode+gate. Keep `InstallPodSNATFlows`/`snatIPFromTunnelFlow` untouched so encap/hybrid are unaffected (a hybrid cluster has both paths).

File `pkg/agent/controller/egress/egress_controller.go`:
- Add a `steerTableAllocator = newIDAllocator(MinEgressSteerRouteTable, MaxEgressSteerRouteTable)`.
- In `realizeEgressIP`: when the IP is **remote** and `EgressDirectRouting` and the egress node is **on-link same-subnet**: allocate a steer mark (reuse `markAllocator`), resolve the egress node's transport IP from `Egress.status.egressNode` (map Node name → transport IP via the existing node/peer info the agent holds), allocate a steer table, call `routeClient.AddEgressRoutes(table, transportDev, egressNodeTransportIP, prefixLen)` + `AddEgressRule(table, steerMark, isIPv6)` + `AddEgressSteerMasqueradeBypass(steerMark)`; keep `ipState.mark = steerMark`.
- In `realizeEgressIP` when the IP is **local** and `EgressDirectRouting`: additionally create the egress-node ipset (`AddEgressSNATIPSetRule(egressIP, setName, isIPv6)`) and maintain its members from the EgressGroup (Phase 1 delivers them). This is on top of the existing local mark-based SNAT (which still serves Pods local to the egress node).
- In `realizeEgress` (per-Pod): when remote+direct-routing, call the new `InstallPodSteerSNATFlows(ofPort, steerMark)` instead of the tunnel-mode `InstallPodSNATFlows`.
- Failover: when `status.egressNode` changes, update the steer route's `default via` (route replace; mark/rule/table stay). Existing conntrack entries on the old owner break — same as today's tunnel repoint; document, do not fix.
- Same-subnet guard: if the egress node's transport IP is **not** on-link from this Node, set an Egress condition = unsupported (today it is wholly unsupported in noEncap, so any covered case is net gain). Do not attempt cross-subnet direct routing.
- Teardown mirrors: delete steer route/rule/bypass/ipset, release mark + steer table, on unrealize.

File `pkg/features/antrea_features.go`: register `EgressDirectRouting` (Alpha, default false) at the four sites mirroring `EgressSeparateSubnet`. Add agent config validation if needed.

Tests: `snatRuleFlow` third branch flow asserts; controller state transitions (remote↔local flips, spec change, failover `status.egressNode` change); on-link vs cross-subnet guard; feature-gate off = no behavior change.

### Phase 4 — e2e, docs, rollout

- e2e (Linux, noEncap kind cluster, gate on): Pod on Node A, Egress IP on Node B; external observer sees the Egress IP (never the Pod IP or Node IP — this is the masquerade-bypass regression guard); reply reaches the Pod; failover moves the IP and traffic follows; IPv6 mirror.
- `docs/egress.md`: lift the "encap/hybrid only" limitation for noEncap **same-subnet**, with the cross-subnet caveat and the feature-gate note.
- Rollout: Alpha default-off → soak on a noEncap staging cluster with FlowExporter + `conntrack -L`/`ipset list` spot checks → Beta.

---

## 6. Correctness checklist (do not ship without)

1. **Masquerade bypass present and ordered before MASQUERADE** — the #1 failure mode. Verify externally: the destination must see the Egress IP, never the Node/transport IP.
2. **Transport interface rp_filter = loose (2)** — else the un-SNAT'd reply is silently dropped (strict-mode drop reproduced in validation).
3. **Egress node ipset populated before it owns the IP** (Phase 1 span) — else failover leaks Pod-IP-sourced packets.
4. **Same-subnet guard** — never install steer routes to a cross-subnet egress node; report unsupported.
5. **Feature gate off ⇒ zero behavior change** — all new code paths gated; encap/hybrid tunnel path untouched.
6. **Startup GC** for the new steer-table range and ipsets (idempotent restart).
7. IPv6 parity throughout (ip -6 rule/route, ip6tables, hash:ip inet6 sets).

## 7. Out of scope for v1

- Cross-subnet noEncap (needs a tunnel — that is the encap/hybrid case).
- Hybrid same-subnet reuse of this path (mechanically identical; separate follow-up).
- `networkPolicyOnly` mode (Pod IPs managed by primary CNI; different routing assumptions).
- `EgressTrafficShaping` (OVS meters on the egress node are bypassed by this path) — reject in webhook/condition when combined with the gate; revisit with tc-on-uplink later.
- `EgressSeparateSubnet` combined with this gate — exclude in v1, revisit.
- Windows.

## 8. Reference

- Design rationale & packet walks: `docs/egress-noencap-policy-routing-plan.md`.
- Datapath validation (run to re-confirm): `sudo bash /home/ubuntu/egress-dp-validate/validate.sh` (8/8).

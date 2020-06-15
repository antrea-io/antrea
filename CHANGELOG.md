# Changelog

All notable changes to this project will be documented in this file.  The format is based on [Keep a
Changelog](https://keepachangelog.com/en/1.0.0/).

Features in Alpha or Beta stage are tagged as such. We try to follow the same conventions as
Kubernetes for [feature development
stages](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api_changes.md#alpha-beta-and-stable-versions).

## Unreleased

## 0.7.2 - 2020-06-15

### Fixed

- Fix handling of StatefulSet Pod rescheduling on same Node: a fast rescheduling can cause unexpected ordering of CNI ADD and DELETE commands, which means Antrea cannot use the Pod Namespace+Name as the unique identifier for a Pod's network configuration. [#827](https://github.com/vmware-tanzu/antrea/pull/827)
- Fix IP address leak in IPAM caused by Antrea in-memory cache being out-of-sync with IPAM store. [#828](https://github.com/vmware-tanzu/antrea/pull/828)
- Increase timeout to 5 seconds when waiting for ovs-vswitchd to report the allocated of_port number. [#830](https://github.com/vmware-tanzu/antrea/pull/830)
- Fix CNI CHECK command implementation: the CNI server was always returning success even in case of failure. [#821](https://github.com/vmware-tanzu/antrea/pull/821)
- Update ofnet library version to avoid a goroutine leak. [#813](https://github.com/vmware-tanzu/antrea/pull/813)
- Exclude /healthz from authorization to avoid unnecessary calls to K8s API in readiness probes. [#816](https://github.com/vmware-tanzu/antrea/pull/816)

## 0.7.1 - 2020-06-05

### Fixed

- Fix Agent logic in charge of sending Gratuitous ARP messages when networking is configured for a Pod; stale ARP cache entries may otherwise cause connectivity issues. [#796](https://github.com/vmware-tanzu/antrea/pull/796)
- Fix Agent crash when running in "networkPolicyOnly" mode, and in particular when running Antrea in [EKS]. [#793](https://github.com/vmware-tanzu/antrea/issues/793), [#795](https://github.com/vmware-tanzu/antrea/pull/795)
- Replace usage of 'resubmit' with 'goto_table' action in new Windows-specific OVS flows. [#759](https://github.com/vmware-tanzu/antrea/issues/759)

## 0.7.0 - 2020-05-29

### Added

- Support for worker Nodes running Windows Server 2019 or higher. [Alpha]
   * Refer to [Antrea Windows documentation] for usage
   * A known limitation is that K8s NetworkPolicies are not enforced correctly for Service traffic, due to our reliance on userspace kube-proxy; this will be addressed in a future release
- Support server certificate verification for Controller APIs; users can provide their own certificates (TLS certificate and corresponding CA certificate) or let the Controller generate them.
- Add ability to collect Antrea support bundles (all the relevant information useful for providing support for Antrea) using new "antctl supportbundle" command, along with corresponding Antrea API resources at the Controller and Agent.
- Support local packet tracing in a Node by leveraging 'ovs-appctl ofproto/trace'.
- Add Antrea API port to the AgentInfo and ControllerInfo CRDs.
- Additional documentation:
   * user-facing documentation for antctl commands
   * information about non-default "encapsulation" modes ("hybrid", "noEncap", "networkPolicyOnly") in architecture document
   * design document for "networkPolicyOnly" mode (in particular, this mode is used for Antrea support in EKS)

### Changed

- Bump up K8s libraries to v0.17.6.
- Replace usage of 'resubmit' with 'goto_table' action in OVS pipeline: pipeline functionality is unaffected.
- Only include necessary Antrea binaries in Docker image to reduce its size.
- Support getting kubeconfig path from KUBECONFIG env variable for antctl.

### Fixed

- Fix implementation of K8s NetworkPolicies with overlapping ipBlock CIDRs; in particular, the issue manifested itself when there was overlap between a 'cidr' field in one rule and an 'except' field in another rule.
- Clean-up stale NetworkPolicies in the Agent after a reconnection to the Controller; this ensures that the corresponding stale flows are removed from the OVS bridge.
- Fix usage of iptables-restore in Antrea Agent to support iptables >= 1.6.2.
- Fix return path for NodePort Service traffic in EKS: an additional iptables rule is required in the mangle table, to ensure a correct reverse path through eth0 for traffic load-balanced to a Pod attached to a secondary ENI.
- Register "antrea_agent_local_pod_count" metric, which was defined without being registered properly.

## 0.6.0 - 2020-04-30

### Added

- Expose Prometheus metrics for Agent and Controller using the "/metrics" apiserver endpoint; "enablePrometheusMetrics" must be set to true in configuration.
- Add documentation for deploying Prometheus and scraping Antrea metrics, along with sample YAML manifest.
- Install portmap CNI by default in order to support Pods with "hostPort" set.
- Support configurable ports for Agent and Controller apiservers.
- Set default CPU resource requests for Antrea components in YAML manifest.
- Add "/ovsflows" API endpoint to Agent to query OVS flows and "antctl get ovsflows" command; flows can be filtered by Pod / NetworkPolicy / OVS Table.
- Improvements to "/networkpolicies" API endpoint and "antctl get networkpolicies" command:
   * namespace and name parameters to filter policies
   * ability to get NetworkPolicies applied to a Pod (Agent API only)
- Add object type aliases to antctl (plural form and short alias).
- Document known issues when deploying Antrea on Photon OS or CoreOS.

### Changed

- Add authentication to Agent apiserver to enable external access (from outside of Agent Pod), and generate bearer token for local access instead of delegating authentication to K8s apiserver.
- Send Agent and Controller logs to /var/log/antrea/ on the host as well as stderr.
- Make "table" output format the default for antctl get commands.
- Use custom formatter for logs originating from ofnet / libOpenflow (which use the logrus module) to mimic K8s log format.
- Use Go cross compilation support for "make bin": Antrea Linux binaries can now be built on other OS's.
- Ensure that OVS bridge datapath type is correct when Agent starts.

### Fixed

- Acquire xtables.lock before executing iptables-restore in Agent to avoid initialization error when kube-proxy uses iptables concurrently.
- Start ovs-vswitchd with flow-restore-wait config (only for OVS system datapath type) to avoid conntrack issues after antrea-ovs restarts; this could also reduce downtime during upgrades.
- Fix monitoring CRDs update: recover gracefully from transient errors.
- Handle DeletedFinalStateUnknown in NetworkPolicy Controller to avoid crashes when a watch deletion event is missed, e.g. because of a transient connectivity issue to the K8s apiserver.

## 0.5.1 - 2020-04-01

### Changed

- Remove performance bottleneck during NetworkPolicy computation in the Controller: add namespace-based indexers to quickly determine which internal objects need to be updated when a Pod is added / deleted.

### Fixed

- Fix implementation of deny-all egress policy (no egress traffic should be allowed for any Pod to which the policy is applied).
- Fix antctl segfault when kubeconfig cannot be resolved and print error instead.

## 0.5.0 - 2020-03-25

### Added

- Add "networkPolicyOnly" as a new "encapsulation mode": in this mode Antrea enforces NetworkPolicies with OVS, but is not in charge of forwarding.
- Support for running Antrea in [EKS] and [GKE] clusters; refer to the documentation.
- New antctl "get" commands:
   * in "agent mode": addressgroup, agentinfo, appliedtogroup, networkpolicy, podinterface
   * in "controller mode": addressgroup, appliedtogroup, controllerinfo, networkpolicy
- Support for a user-friendly "table" output format for antctl "get" commands.
- Add health checks to Antrea components by leveraging the apiserver /healthz endpoint (both the Antrea Agent and Controller are running an apiserver).
- Add documentation for connecting to the Antrea Agent or Controller apiserver, in order to check the resources created by Antrea.
- Ship antctl binaries as part of each release for different OS / CPU combinations: antctl-linux-x86_64, antctl-linux-arm, antctl-linux-arm64, antctl-windows-x86_64.exe, antctl-darwin-x86_64.
- Add documentation for antctl installation and usage.

### Changed

- Refactor antctl: most notable change is that the Antrea Agent now runs its own apiserver which the antctl CLI can connect to.
- Improve NetworkPolicy logging; in particular an Agent now logs (by default) a message when it receives a new NetworkPolicy that needs to be implemented locally.
- Upgrade OVS to version 2.13.0, which comes with userspace datapath improvements useful when running Antrea in Kind.
- Use ipset in iptables to match Pod-to-external traffic, which improves performance.
- Replace "beta.kubernetes.io/os" annotation (no longer supported in K8s 1.18) with "kubernetes.io/os".
- Enable running antctl from within the Antrea Controller Pod (by binding the antctl ClusterRrole to the antrea-controller ServiceAccount).

### Fixed

- Cancel ongoing OpenFlow bundle if switch disconnects, to prevent deadlock when replaying flows after a restart of the antrea-ovs container.
- Keep trying to reconnect to OVS switch indefinitely after a disconnection, instead of giving up after 5 seconds.
- Backport post-2.13 patch to OVS to avoid tunnel port deletion when the antrea-ovs container exits gracefully.
- Reduce memory usage of Antrea Controller when an Agent establishes a connection.
- Clean-up the appropriate iptables rules when a Node leaves the cluster.

## 0.4.1 - 2020-02-27

### Fixed

- Fix issues with IPsec support, which was broken in 0.4.0:
   * reduce MTU when IPsec is enabled to accommodate for IPsec overhead
   * add required flows to accept traffic received from IPsec tunnels
- Check and update (if needed) the type of the default tunnel port (tun0) after Agent starts.
- Fix race condition when the same OF port is reused for a new Pod.

## 0.4.0 - 2020-02-20

### Added

- Add support for new encapsulation modes: noEncap (inter-Node Pod traffic is never encapsulated) and hybrid (inter-Node Pod traffic is only encapsulated if Nodes are not on the same subnet).
- Add support for "named ports" to Network Policy implementation.
- Add user documentation for IPsec support.
- Add antctl "agent-info" command: command must be run from within the Agent container and will display information about the Agent (Node subnet, OVS bridge information, ...).
- Add support for new "table" output mode to antctl.

### Changed

- Changes in OpenFlow client:
   * use OpenFlow "bundle" to install related Network Policy flows as part of the same transaction
   * use flow-based tunnelling even when IPsec encryption is enabled
- Use patched OVS version in Antrea Docker image to avoid cleaning-up datapath flows on graceful antrea-ovs container exit.
- Reduce amount of Antrea Controller logs when computing Network Policies.

### Fixed

- Fix bug in the Agent that caused some Network Policies not to be enforced properly: for some flows the agent would overwrite existing conjunctive actions instead of adding new actions to the existing flow. This can notably happen when using a /32 ipBlock CIDR to select sources / destinations.
- Install loopback plugin on Nodes if missing, from the Agent's initContainer.
- Remove unnecessary periodical resync in Antrea K8s controllers to avoid overhead at scale.

## 0.3.0 - 2020-01-23

### Added

- Add support for the IPsec ESP protocol for GRE tunnels only; it can be enabled by applying antrea-ipsec.yml instead of antrea.yml.
- Add framework to develop CLI commands for Antrea; the antctl binary only supports the "version" command at the moment.
- Add octant/octant-antrea-ubuntu Docker image to dockerhub for easier deployment of [Octant] with the Antrea plugin.
- Add OpenFlow and OVSDB connection health information to the Agent's monitoring CRD.
- Add Network Policy information to monitoring CRDs for both the Agent and the Controller.
- Add documentation for OVS pipeline.

### Changed

- Change API group namings (for [CRDs] and Network Policies) from "crd.antrea.io" to "antrea.tanzu.vmware.com" and from "networkpolicy.antrea.io" to "networking.antrea.tanzu.vmware.com".
- Changes in OpenFlow client:
   * use OpenFlow "bundle" to install related flows as part of the same transaction (except for Network Policy flows)
   * all flows now have a cookie indicating their purpose (e.g. Pod flow) and encoding the Agent round number (which is incremented with every antrea-agent restart and persisted in OVSDB)
- Update to "Antrea on Kind" documentation to indicate that macOS hosts are also supported.

### Fixed

- Support NodePort services with externalTrafficPolicy set to Local.
- Mount xtables lock file to antrea-agent container to prevent concurrent iptables access by Antrea and kube-proxy.
- Replay flows to OVS switch after an OpenFlow reconnection (as it may indicate that vswitchd restarted and existing flows were deleted).
- Cleanup stale gateway routes (in host routing table) and tunnel ports (in OVSDB) on Agent startup.
- Cleanup stale flows in OVS switch on Agent startup.
- Improve the robustness of CNI DEL processing: cleanup resources even if provided container netns is no longer valid.
- Fix distribution of Network Polcies at scale: buffer size of the watchers channel is increased and unresponsive watchers (i.e. Agents) are terminated.

## 0.2.0 - 2019-12-19

The Monitoring [CRDs] feature is graduated from Alpha to Beta.

### Added

- Add "Last Hearbeat Time" to [Octant] plugin to visualize the last time the Agent / Controller reported its status.
- Add OVS version to Agent's monitoring CRD.
- Add instructions to run [Octant] and the Antrea plugin either in a Pod or as a process. A Dockerfile and YAML manifest are included for deploying [Octant] as a Pod.
- Support for GRE and STT tunnels for the Pod overlay network.

### Changed

- Use [libOpenflow] Go library to manage OVS flows instead of ovs-ofctl binary.
- Minor changes to the OVS pipeline, in particular to fix issues when using the netdev OVS datapath type.
- Officially-supported Go version is no longer 1.12 but 1.13.

### Fixed

- Allow the Node to reach all local Pods to support liveness probes even in the presence of Network Policies.
- Network Policy fixes:
   * fix implementation of Network Policies with multiple ingress / egress rules
   * support "except" field for "ipBlock" selectors
   * fix support for [default policies]
   * faster Network Policy enforcement by letting the CNI server notify the Agent's Network Policy controller when Pods are created
   * fix race condition that sometimes caused Network Policy span not to be updated properly and the Network Policy not to be disseminated to Nodes properly
   * ignore policy rules using named ports instead of allowing all traffic
- Remove stale Agent [CRDs] from the Controller: the Controller watches the Node list and removes the appropriate Agent CRD when a Node is deleted from the cluster.

## 0.1.1 - 2019-11-27

### Fixed

- Find host-local IPAM plugin even when kubelet is started with custom cni-bin-dir.
- Ensure that the Gratuitous ARP sent after adding container interface is not dropped. This ensures we can pass Kubernetes conformance tests reliably.
- Fix Kind support on Linux hosts.

## 0.1.0 - 2019-11-18

### Added

- Support for configuring and cleaning-up Pod networking as per the [CNI spec]. VXLAN or GENEVE tunnels are used for Pod connectivity across Nodes. [Beta]
- Support for [Kubernetes Network Policies]. [Alpha]
- Monitoring [CRDs] published by both the Antrea Agent and Controller to expose monitoring information. [Alpha]
- [Octant] plugin for visualizing the monitoring CRDs published by the Antrea Agent and Controller. [Alpha]

[CRDs]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
[CNI spec]: https://github.com/containernetworking/cni/blob/spec-v0.4.0/SPEC.md
[default policies]: https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-policies
[Kubernetes Network Policies]: https://kubernetes.io/docs/concepts/services-networking/network-policies/
[libOpenflow]: https://github.com/contiv/libOpenflow
[Octant]: https://github.com/vmware-tanzu/octant
[EKS]: https://aws.amazon.com/eks/
[GKE]: https://cloud.google.com/kubernetes-engine
[Antrea Windows documentation]: https://github.com/vmware-tanzu/antrea/blob/master/docs/windows.md

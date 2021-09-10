# GitHub Label List

We use GitHub labels to perform issue triage, track and report on development
progress, plan roadmaps, and automate issue grooming.

To ensure that contributing new issues and PRs remains straight-forward, we would
like to keep the labels required for submission to a minimum. The remaining
labels will be added either by automation or manual grooming by other
contributors and maintainers.

The labels in this list originated within Kubernetes at
<https://github.com/kubernetes/test-infra/blob/master/label_sync/labels.md>.

## Labels that apply to issues or PRs

| Label | Description | Added By |
|-------|-------------|----------|
| api-review                         | Categorizes an issue or PR as actively needing an API review. | Any |
| area/api                           | Issues or PRs related to an API | Any |
| area/blog                          | Issues or PRs related to blog entries | Any |
| area/build-release                 | Issues or PRs related to building and releasing | Any |
| area/component/antctl              | Issues or PRs related to the command line interface component | Any |
| area/component/agent               | Issues or PRs related to the Agent component | Any |
| area/component/cni                 | Issues or PRs related to the cni component | Any |
| area/component/controller          | Issues or PRs related to the Controller component | Any |
| area/component/flow-aggregator     | Issues or PRs related to the Flow Aggregator component | Any |
| area/component/octant-plugin       | Issues or PRs related to the octant-plugin component | Any |
| area/dependency                    | Issues or PRs related to dependency changes | Any |
| area/endpoint/identity             | Issues or PRs related to endpoint identity | Any |
| area/endpoint/selection            | Issues or PRs related to endpoint selection | Any |
| area/endpoint/type                 | Issues or PRs related to endpoint type | Any |
| area/flow-visibility               | Issues or PRs related to flow visibility support in Antrea | Any |
| area/flow-visibility/aggregation   | Issues or PRs related to flow aggregation | Any |
| area/flow-visibility/elk           | Issues or PRs related to the reference ELK configuration for flow visualization | Any |
| area/flow-visibility/export        | Issues or PRs related to the Flow Exporter functions in the Agent | Any |
| area/github-membership             | Categorizes an issue as a membership request to join the antrea-io Github organization | Any |
| area/grouping                      | Issues or PRs related to ClusterGroup, Group API | Any |
| area/ipam                          | Issues or PRs related to IP address management (IPAM) | Any |
| area/interface                     | Issues or PRs related to network interfaces | Any |
| area/licensing                     | Issues or PRs related to Antrea licensing | Any |
| area/monitoring/auditing           | Issues or PRs related to auditing | Any |
| area/monitoring/health-performance | Issues or PRs related to health and performance monitoring | Any |
| area/monitoring/logging            | Issues or PRs related to logging | Any |
| area/monitoring/mirroring          | Issues or PRs related to mirroring | Any |
| area/monitoring/traffic-analysis   | Issues or PRs related to traffic analysis | Any |
| area/network-policy/action         | Issues or PRs related to network policy actions | Any |
| area/network-policy/agent          | Issues or PRs related to the network policy agents | Any |
| area/network-policy/api            | Issues or PRs related to the network policy API | Any |
| area/network-policy/controller     | Issues or PRs related to the network policy controller | Any |
| area/network-policy/lifecycle      | Issues or PRs related to the network policy lifecycle | Any |
| area/network-policy/match          | Issues or PRs related to matching packets | Any |
| area/network-policy/precedence     | Issues or PRs related to network policy precedence | Any |
| area/octant                        | Issues or PRs related to Octant | Any |
| area/ops                           | Issues or PRs related to features which support network operations and troubleshooting | Any |
| area/ops/traceflow                 | Issues or PRs related to the Traceflow feature | Any |
| area/ovs/openflow                  | Issues or PRs related to Open vSwitch Open Flow | Any |
| area/ovs/ovsdb                     | Issues or PRs related to Open vSwitch database | Any |
| area/OS/linux                      | Issues or PRs related to the Linux operating system | Any |
| area/OS/windows                    | Issues or PRs related to the Windows operating system | Any |
| area/provider/aws                  | Issues or PRs related to aws provider | Any |
| area/provider/azure                | Issues or PRs related to azure provider | Any |
| area/provider/gcp                  | Issues or PRs related to gcp provider | Any |
| area/provider/vmware               | Issues or PRs related to vmware provider | Any |
| area/proxy                         | Issues or PRs related to proxy functions in Antrea | Any |
| area/proxy/clusterip               | Issues or PRs related to the implementation of ClusterIP Services | Any |
| area/proxy/nodeport                | Issues or PRs related to the implementation of NodePort Services | Any |
| area/proxy/nodeportlocal           | Issues or PRs related to the NodePortLocal feature | Any |
| area/security/access-control       | Issues or PRs related to access control | Any |
| area/security/controlplane         | Issues or PRs related to controlplane security | Any |
| area/security/dataplane            | Issues or PRs related to dataplane security | Any |
| area/test                          | Issues or PRs related to unit and integration tests. | Any |
| area/test/community                | Issues or PRs related to community testing | Any |
| area/test/e2e                      | Issues or PRs related to Antrea specific end-to-end testing. | Any |
| area/test/infra                    | Issues or PRs related to test infrastructure (Jenkins configuration, Ansible playbook, Kind wrappers, ...) | Any |
| area/transit/encapsulation         | Issues or PRs related to encapsulation | Any |
| area/transit/addressing            | Issues or PRs related to IP addressing category (unicast, multicast, broadcast, anycast) | Any |
| area/transit/encryption            | Issues or PRs related to transit encryption (IPSec, SSL) | Any |
| area/transit/qos                   | Issues or PRs related to transit qos or policing | Any |
| area/transit/routing               | Issues or PRs related to routing and forwarding | Any |
| kind/api-change                    | Categorizes issue or PR as related to adding, removing, or otherwise changing an API. | Any |
| kind/bug                           | Categorizes issue or PR as related to a bug.              | Any                |
| kind/cherry-pick                   | Categorizes issue or PR as related to the cherry-pick of a bug fix from the main branch to a release branch | Any |
| kind/cleanup                       | Categorizes issue or PR as related to cleaning up code, process, or technical debt | Any |
| kind/deprecation                   | Categorizes issue or PR as related to feature marked for deprecation | Any |
| kind/design                        | Categorizes issue or PR as related to design | Any |
| kind/documentation                 | Categorizes issue or PR as related to a documentation.    | Any                |
| kind/failing-test                  | Categorizes issue or PR as related to a consistently or frequently failing test | Any |
| kind/feature                       | Categorizes issue or PR as related to a new feature.      | Any                |
| kind/support                       | Categorizes issue or PR as related to a support question. | Any |
| kind/task                          | Categorizes issue or PR as related to a routine task that needs to be performed. | Any |
| lifecycle/active                   | Indicates that an issue or PR is actively being worked on by a contributor. | Any |
| lifecycle/frozen                   | Indicates that an issue or PR should not be auto-closed due to staleness. | Any |
| lifecycle/stale                    | Denotes an issue or PR has remained open with no activity and has become stale. | Any |
| priority/awaiting-more-evidence    | Lowest priority. Possibly useful, but not yet enough support to actually get it done. | Any |
| priority/backlog                   | Higher priority than priority/awaiting-more-evidence. | Any |
| priority/critical-urgent           | Highest priority. Must be actively worked on as someone's top priority right now. | Any |
| priority/important-longterm        | Important over the long term, but may not be staffed and/or may need multiple releases to complete. | Any |
| priority/import-soon               | Must be staffed and worked on either currently, or very soon, ideally in time for the next release. | Any |
| ready-to-work                      | Indicates that an issue or PR has been sufficiently triaged and prioritized and is now ready to work. | Any |
| size/L                             | Denotes a PR that changes 100-499 lines, ignoring generated files. | Any |
| size/M                             | Denotes a PR that changes 30-99 lines, ignoring generated files.| Any |
| size/S                             | Denotes a PR that changes 10-29 lines, ignoring generated files.| Any |
| size/XL                            | Denotes a PR that changes 500+ lines, ignoring generated files.| Any |
| size/XS                            | Denotes a PR that changes 0-9 lines, ignoring generated files.| Any |
| triage/duplicate                   | Indicates an issue is a duplicate of other open issue. | Humans |
| triage/needs-information           | Indicates an issue needs more information in order to work on it. | Humans |
| triage/not-reproducible            | Indicates an issue can not be reproduced as described. | Humans |
| triage/unresolved                  | Indicates an issue that can not or will not be resolved. | Humans |

## Labels that apply only to issues

| Label | Description | Added By |
|-------|-------------|----------|
| good first issue                   | Denotes an issue ready for a new contributor, according to the "help wanted" [guidelines](issue-management.md#good-first-issues-and-help-wanted). | Anyone |
| help wanted                        | Denotes an issue that needs help from a contributor. Must meet "help wanted" [guidelines](issue-management.md#good-first-issues-and-help-wanted). | Anyone |

## Labels that apply only to PRs

| Label | Description | Added By |
|-------|-------------|----------|
| approved                           | Indicates a PR has been approved by owners in accordance with [GOVERNANCE.md](../../GOVERNANCE.md) guidelines. | Maintainers |
| vmware-cla: no                     | Indicates the PR's author has not signed the [VMware CLA](https://cla.vmware.com/faq) | VMware CLA Bot |
| vmware-cla: yes                    | Indicates the PR's author has signed the [VMware CLA](https://cla.vmware.com/faq) | VMware CLA Bot |
| do-not-merge/hold                  | Indicates a PR should not be merged because someone has issued a /hold command | Merge Bot |
| do-not-merge/work-in-progress      | Indicates that a PR should not be merged because it is a work in progress. | Merge Bot |
| lgtm                               | Indicates that a PR is ready to be merged. | Merge Bot |

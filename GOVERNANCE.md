# Antrea Governance

This document defines the project governance for Antrea.

## Overview

**Antrea** is committed to building an open, inclusive, productive and
self-governing open source community focused on building a high-quality
[Kubernetes Network
Plugin](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/network-plugins/). The
community is governed by this document which defines how all members should work
together to achieve this goal.

## Code of Conduct

The Antrea community abides by this [code of conduct](CODE_OF_CONDUCT.md).

## Community Roles

* **Users:** Members that engage with the Antrea community via any medium
  (Slack, GitHub, mailing lists, etc.).
* **Contributors:** Do regular contributions to the Antrea project
  (documentation, code reviews, responding to issues, participating in proposal
  discussions, contributing code, etc.).
* **Maintainers**: Responsible for the overall health and direction of the
  project. They are the final reviewers of PRs and responsible for Antrea
  releases.

### Contributors

Anyone can contribute to the project (e.g. open a PR) as long as they follow the
guidelines in [CONTRIBUTING.md](CONTRIBUTING.md).

Frequent contributors to the project can become members of the antrea-io Github
organization and receive write access to the repository. Write access is
required to trigger re-runs of workflows in [Github
Actions](https://docs.github.com/en/actions/managing-workflow-runs/re-running-a-workflow). Becoming
a member of the antrea-io Github organization does not come with additional
responsibilities for the contributor, but simplifies the contributing
process. To become a member, you may [open an
issue](https://github.com/antrea-io/antrea/issues/new?template=membership.md&title=REQUEST%3A%20New%20membership%20for%20%3Cyour-GH-handle%3E)
and your membership needs to be approved by two maintainers: approval is
indicated by leaving a `+1` comment. If a contributor is not active for a
duration of 12 months (no contribution of any kind), they may be removed from
the antrea-io Github organization. In case of privilege abuse (members receive
write access to the organization), any maintainer can decide to remove the
member.

### Maintainers

The list of current maintainers can be found in
[MAINTAINERS.md](MAINTAINERS.md).

While anyone can review a PR and is encouraged to do so, only maintainers are
allowed to merge the PR. To maintain velocity, only one maintainer's approval is
required to merge a given PR. In case of a disagreement between maintainers, a
vote should be called (on Github or Slack) and a simple majority is required in
order for the PR to be merged.

New maintainers must be nominated from contributors by an existing maintainer
and must be elected by a [supermajority](#supermajority) of the current
maintainers. Likewise, maintainers can be removed by a supermajority of the
maintainers or can resign by notifying the maintainers.

### Supermajority

A supermajority is defined as two-thirds of members in the group.

## Code of Conduct

The code of conduct is overseen by the Antrea project maintainers. Possible code
of conduct violations should be emailed to the project maintainers at
cncf-antrea-maintainers@lists.cncf.io.

If the possible violation is against one of the project maintainers that member
will be recused from voting on the issue. Such issues must be escalated to the
appropriate CNCF contact, and CNCF may choose to intervene.

## Updating Governance

All substantive changes in Governance require a supermajority vote of the
maintainers.

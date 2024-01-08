# Developer Guide

Thank you for taking the time out to contribute to project Antrea!

This guide will walk you through the process of making your first commit and how
to effectively get it merged upstream.

<!-- toc -->
- [Getting Started](#getting-started)
  - [Accounts Setup](#accounts-setup)
- [Contribute](#contribute)
  - [Git Client Hooks](#git-client-hooks)
  - [GitHub Workflow](#github-workflow)
  - [Getting reviewers](#getting-reviewers)
  - [Getting your PR verified by CI](#getting-your-pr-verified-by-ci)
  - [Cherry-picks to release branches](#cherry-picks-to-release-branches)
  - [Conventions for Writing Documentation](#conventions-for-writing-documentation)
  - [Inclusive Naming](#inclusive-naming)
  - [Building and testing your change](#building-and-testing-your-change)
  - [Reverting a commit](#reverting-a-commit)
  - [Sign-off Your Work](#sign-off-your-work)
- [Issue and PR Management](#issue-and-pr-management)
  - [Filing An Issue](#filing-an-issue)
  - [Issue Triage](#issue-triage)
  - [Issue and PR Kinds](#issue-and-pr-kinds)
<!-- /toc -->

## Getting Started

To get started, let's ensure you have completed the following prerequisites for
contributing to project Antrea:

1. Read and observe the [code of conduct](CODE_OF_CONDUCT.md).
2. Check out the [Architecture document](docs/design/architecture.md) for the Antrea
   architecture and design.
3. Set up necessary [accounts](#accounts-setup).

Now that you're setup, skip ahead to learn how to [contribute](#contribute).

### Accounts Setup

At minimum, you need the following accounts for effective participation:

1. **Github**: Committing any change requires you to have a [github
   account](https://github.com/join).
2. **Slack**: Join the [Kubernetes Slack](http://slack.k8s.io/) and look for our
   [#antrea](https://kubernetes.slack.com/messages/CR2J23M0X) channel.
3. **Google Group**: Join our [mailing list](https://groups.google.com/forum/#!forum/projectantrea-dev).

## Contribute

There are multiple ways in which you can contribute, either by contributing
code in the form of new features or bug-fixes or non-code contributions like
helping with code reviews, triaging of bugs, documentation updates, filing
[new issues](#filing-an-issue) or writing blogs/manuals etc.

In order to help you get your hands "dirty", there is a list of
[starter](https://github.com/antrea-io/antrea/labels/Good%20first%20issue)
issues from which you can choose.

### Git Client Hooks

 There are a few recommended git client hooks which we advise you to use. You can find
 them here:
 [hack/git_client_side_hooks](hack/git_client_side_hooks).
 You can run `make install-hooks` to copy them to your local `.git/hooks/` folder, and remove them via `make uninstall-hooks`

### GitHub Workflow

Developers work in their own forked copy of the repository and when ready,
submit pull requests to have their changes considered and merged into the
project's repository.

1. Fork your own copy of the repository to your GitHub account by clicking on
   `Fork` button on [Antrea's GitHub repository](https://github.com/antrea-io/antrea).
2. Clone the forked repository on your local setup.

    ```bash
    git clone https://github.com/$user/antrea
    ```

    Add a remote upstream to track upstream Antrea repository.

    ```bash
    git remote add upstream https://github.com/antrea-io/antrea
    ```

    Never push to upstream remote

    ```bash
    git remote set-url --push upstream no_push
    ```

3. Create a topic branch.

    ```bash
    git checkout -b branchName
    ```

4. Make changes and commit it locally. Make sure that your commit is
   [signed](#sign-off-your-work).

    ```bash
    git add <modifiedFile>
    git commit -s
    ```

5. Keeping branch in sync with upstream.

    ```bash
    git checkout branchName
    git fetch upstream
    git rebase upstream/main
    ```

6. Push local branch to your forked repository.

    ```bash
    git push -f $remoteBranchName branchName
    ```

7. Create a Pull request on GitHub.
   Visit your fork at `https://github.com/antrea-io/antrea` and click
   `Compare & Pull Request` button next to your `remoteBranchName` branch.

### Getting reviewers

Once you have opened a Pull Request (PR), reviewers will be assigned to your
PR and they may provide review comments which you need to address.
Commit changes made in response to review comments to the same branch on your
fork. Once a PR is ready to merge, squash any *fix review feedback, typo*
and *merged* sorts of commits.

To make it easier for reviewers to review your PR, consider the following:

1. Follow the golang [coding conventions](https://github.com/golang/go/wiki/CodeReviewComments)
   and check out this [document](https://github.com/tnqn/code-review-comments#code-review-comments)
   for common comments we made during reviews and suggestions for fixing them.
2. Format your code with `make golangci-fix`; if the [linters](ci/README.md) flag an issue that
   cannot be fixed automatically, an error message will be displayed so you can address the issue.
3. Follow [git commit](https://chris.beams.io/posts/git-commit/) guidelines.
4. Follow [logging](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md) guidelines.
5. Please refer to [Conventions for Writing Documentation](#conventions-for-writing-documentation) for
spelling conventions when writing documentation or commenting code.

If your PR fixes a bug or implements a new feature, add the appropriate test
cases to our [automated test suite](ci/README.md) to guarantee enough
coverage. A PR that makes significant code changes without contributing new test
cases will be flagged by reviewers and will not be accepted.

### Getting your PR verified by CI

It is a requirement to get your PR verified with CI checks before it gets merged.
Also, it helps to find possible bugs before the review work starts. Once you create
a PR, or you push new commits, CI checks at the bottom of a PR page will be refreshed.
Checks include Github Action ones and Jenkins ones. Github Action ones will be
triggered automatically when you push to the head branch of the PR but Jenkins ones
need to be triggered manually with comments. Please note that if you are a first-time
contributor, the Github workflows need approval from someone with write access to
the repo. It's a Github security mechanism.

Here are the trigger phrases for individual checks:

* `/test-e2e`: Linux IPv4 e2e tests
* `/test-conformance`: Linux IPv4 conformance tests
* `/test-networkpolicy`: Linux IPv4 networkpolicy tests
* `/test-all-features-conformance`: Linux IPv4 conformance tests with all features enabled
* `/test-windows-e2e`: Windows IPv4 e2e tests
* `/test-windows-conformance`: Windows IPv4 conformance tests
* `/test-windows-networkpolicy`: Windows IPv4 networkpolicy tests
* `/test-ipv6-e2e`: Linux dual stack e2e tests
* `/test-ipv6-conformance`: Linux dual stack conformance tests
* `/test-ipv6-networkpolicy`: Linux dual stack networkpolicy tests
* `/test-ipv6-only-e2e`: Linux IPv6 only e2e tests
* `/test-ipv6-only-conformance`: Linux IPv6 only conformance tests
* `/test-ipv6-only-networkpolicy`: Linux IPv6 only networkpolicy tests
* `/test-flexible-ipam-e2e`: Flexible IPAM e2e tests
* `/test-multicast-e2e`: Multicast e2e tests
* `/test-multicluster-e2e`: Multicluster e2e tests
* `/test-vm-e2e`: ExternalNode e2e tests
* `/test-whole-conformance`: All conformance tests on Linux
* `/test-hw-offload`: Hardware offloading e2e tests
* `/test-rancher-e2e`: Linux IPv4 e2e tests on Rancher clusters.
* `/test-rancher-conformance`: Linux IPv4 conformance tests on Rancher clusters.
* `/test-rancher-networkpolicy`: Linux IPv4 networkpolicy tests on Rancher clusters.

Here are the trigger phrases for groups of checks:

* `/test-all`: Linux IPv4 tests
* `/test-windows-all`: Windows IPv4 tests, including e2e tests with proxyAll enabled. It also includes all containerd runtime based Windows tests since 1.10.0.
* `/test-ipv6-all`: Linux dual stack tests
* `/test-ipv6-only-all`: Linux IPv6 only tests

Besides, you can skip a check with `/skip-*`, e.g. `/skip-e2e`: skip Linux IPv4
e2e tests.

Skipping a check should be used only when the change doesn't influence the
specific function. For example:

* doc change: skip all checks
* comment change: skip all checks
* test/e2e/* change: skip conformance and networkpolicy checks
* *_windows.go change: skip Linux checks

Besides skipping specific checks you can also cancel all stale running or waiting capv jenkins jobs related to your PR with
`/stop-all-jobs`.

For more information about the tests we run as part of CI, please refer to
[ci/README.md](ci/README.md).

### Cherry-picks to release branches

If your PR fixes a critical bug, it may need to be backported to older release
branches which are still maintained. If this is the case, one of the Antrea
maintainers will let you know once your PR is approved. Please refer to the
documentation on [cherry-picks](docs/contributors/cherry-picks.md) for more
information.

### Conventions for Writing Documentation

* Short name of `IP Security` should be `IPsec` as per [rfc 6071](https://datatracker.ietf.org/doc/html/rfc6071).
* Any Kubernetes object in log/comment should start with upper case, eg: Namespace, Pod, Service.

### Inclusive Naming

For symbol names and documentation, do not introduce new usage of harmful
language such as 'master / slave' (or 'slave' independent of 'master') and
'blacklist / whitelist'. For more information about what constitutes harmful
language and for a reference word replacement list, please refer to the
[Inclusive Naming Initiative](https://inclusivenaming.org/).

We are committed to removing all harmful language from the project. If you
detect existing usage of harmful language in code or documentation, please
report the issue to us or open a Pull Request to address it directly. Thanks!

### Building and testing your change

To build the Antrea Docker image together with all Antrea bits, you can simply
do:

1. Checkout your feature branch and `cd` into it.
2. Run `make`

The second step will compile the Antrea code in a `golang` container, and build
an Ubuntu-based Docker image that includes all the generated binaries. [`Docker`](https://docs.docker.com/install)
must be installed on your local machine in advance. If you are a macOS user and
cannot use [Docker Desktop](https://www.docker.com/products/docker-desktop) to
contribute to Antrea for licensing reasons, check out this
[document](docs/contributors/docker-desktop-alternatives.md) for possible
alternatives.

Alternatively, you can build the Antrea code in your local Go environment. The
Antrea project uses the [Go modules support](https://github.com/golang/go/wiki/Modules) which was introduced in Go 1.11. It
facilitates dependency tracking and no longer requires projects to live inside
the `$GOPATH`.

To develop locally, you can follow these steps:

 1. [Install Go 1.21](https://golang.org/doc/install)
 2. Checkout your feature branch and `cd` into it.
 3. To build all Go files and install them under `bin`, run `make bin`
 4. To run all Go unit tests, run `make test-unit`
 5. To build the Antrea Ubuntu Docker image separately with the binaries generated in step 2, run `make ubuntu`

### Reverting a commit

1. Create a branch in your forked repo

    ```bash
    git checkout -b revertName
    ```

2. Sync the branch with upstream

    ```bash
    git fetch upstream
    git rebase upstream/main
    ```

3. Create a revert based on the SHA of the commit. The commit needs to be
   [signed](#sign-off-your-work).

    ```bash
    git revert -s SHA
    ```

4. Push this new commit.

    ```bash
    git push $remoteRevertName revertName
    ```

5. Create a Pull Request on GitHub.
   Visit your fork at `https://github.com/antrea-io/antrea` and click
   `Compare & Pull Request` button next to your `remoteRevertName` branch.

### Sign-off Your Work

As a CNCF project, Antrea must enforce the [Developer Certificate of
Origin](https://developercertificate.org/) (DCO) on all Pull Requests. We
require that for all commits constituting the Pull Request, the commit message
contains the `Signed-off-by` line with an email address that matches the commit
author. By adding this line to their commit messages, contributors *sign-off*
that they adhere to the requirements of the DCO.

Git provides the `-s` command-line option to append the required line
automatically to the commit message:

```bash
git commit -s -m 'This is my commit message'
```

For an existing commit, you can also use this option with `--amend`:

```bash
git commit -s --amend
```

If more than one person works on something it's possible for more than one
person to sign-off on it. For example:

```bash
Signed-off-by: Some Developer somedev@example.com
Signed-off-by: Another Developer anotherdev@example.com
```

We use the [DCO Github App](https://github.com/apps/dco) to enforce that all
commits in a Pull Request include the required `Signed-off-by` line. If this is
not the case, the app will report a failed status for the Pull Request and it
will be blocked from being merged.

Compared to our earlier CLA, DCO tends to make the experience simpler for new
contributors. If you are contributing as an employee, there is no need for your
employer to sign anything; the DCO assumes you are authorized to submit
contributions (it's your responsibility to check with your employer).

## Issue and PR Management

We use labels and workflows (some manual, some automated with GitHub Actions) to
help us manage triage, prioritize, and track issue progress. For a detailed
discussion, see [docs/issue-management.md](docs/contributors/issue-management.md).

### Filing An Issue

Help is always appreciated. If you find something that needs fixing, please file
an issue [here](https://github.com/antrea-io/antrea/issues). Please ensure
that the issue is self explanatory and has enough information for an assignee to
get started.

Before picking up a task, go through the existing
[issues](https://github.com/antrea-io/antrea/issues) and make sure that your
change is not already being worked on. If it does not exist, please create a new
issue and discuss it with other members.

For simple contributions to Antrea, please ensure that this minimum set of
labels are included on your issue:

* **kind** -- common ones are `kind/feature`, `kind/support`, `kind/bug`,
  `kind/documentation`, or `kind/design`. For an overview of the different types
  of issues that can be submitted, see [Issue and PR
  Kinds](#issue-and-pr-kinds).
  The kind of issue will determine the issue workflow.
* **area** (optional) -- if you know the area the issue belongs in, you can assign it.
  Otherwise, another community member will label the issue during triage. The
  area label will identify the area of interest an issue or PR belongs in and
  will ensure the appropriate reviewers shepherd the issue or PR through to its
  closure. For an overview of areas, see the
  [`docs/github-labels.md`](docs/contributors/github-labels.md).
* **size** (optional) -- if you have an idea of the size (lines of code,
  complexity, effort) of the issue, you can label it using a size label. The
  size can be updated during backlog grooming by contributors. This estimate is
  used to guide the number of features selected for a milestone.

All other labels will be assigned during issue triage.

### Issue Triage

Once an issue has been submitted, the CI (GitHub actions) or a human will
automatically review the submitted issue or PR to ensure that it has all relevant
information. If information is lacking or there is another problem with the
submitted issue, an appropriate `triage/<?>` label will be applied.

After an issue has been triaged, the maintainers can prioritize the issue with
an appropriate `priority/<?>` label.

Once an issue has been submitted, categorized, triaged, and prioritized it
is marked as `ready-to-work`. A ready-to-work issue should have labels
indicating assigned areas, prioritization, and should not have any remaining
triage labels.

### Issue and PR Kinds

Use a `kind` label to describe the kind of issue or PR you are submitting. Valid
kinds include:

* [`kind/api-change`](docs/contributors/issue-management.md#api-change) -- for api changes
* [`kind/bug`](docs/contributors/issue-management.md#bug) -- for filing a bug
* [`kind/cleanup`](docs/contributors/issue-management.md#cleanup) -- for code cleanup and organization
* [`kind/deprecation`](docs/contributors/issue-management.md#deprecation) -- for deprecating a feature
* [`kind/design`](docs/contributors/issue-management.md#design) -- for proposing a design or architectural change
* [`kind/documentation`](docs/contributors/issue-management.md#documentation) -- for updating documentation
* [`kind/failing-test`](docs/contributors/issue-management.md#failing-test) -- for reporting a failed test (may
  create with automation in future)
* [`kind/feature`](docs/contributors/issue-management.md#feature) -- for proposing a feature
* [`kind/support`](docs/contributors/issue-management.md#support) -- to request support. You may also get support by
  using our [Slack](https://kubernetes.slack.com/archives/CR2J23M0X) channel for
  interactive help. If you have not set up the appropriate accounts, please
  follow the instructions in [accounts setup](#accounts-setup).

For more details on how we manage issues, please read our [Issue Management doc](docs/contributors/issue-management.md).

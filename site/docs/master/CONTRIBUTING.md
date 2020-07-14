# Developer Guide

Thank you for taking the time out to contribute to project Antrea!

This guide will walk you through the process of making your first commit and how
to effectively get it merged upstream.

- [Developer Guide](#developer-guide)
  - [Getting Started](#getting-started)
    - [CLA](#cla)
    - [Accounts Setup](#accounts-setup)
  - [Contribute](#contribute)
    - [GitHub Workflow](#github-workflow)
    - [Getting reviewers](#getting-reviewers)
    - [Building and testing your change](#building-and-testing-your-change)
    - [CI testing](#ci-testing)
    - [Running the end-to-end tests](#running-the-end-to-end-tests)
    - [Reverting a commit](#reverting-a-commit)
  - [Issue and PR Management](#issue-and-pr-management)
    - [Filing An Issue](#filing-an-issue)
    - [Issue Triage](#issue-triage)
    - [Issue and PR Kinds](#issue-and-pr-kinds)

## Getting Started

To get started, let's ensure you have completed the following prerequisites for
contributing to project Antrea:
1. Read and observe the [code of conduct](CODE_OF_CONDUCT.md).
2. Sign the [CLA](#cla).
3. Check out the [Architecture document](architecture.md) for the Antrea architecture and design.
4. Set up necessary [accounts](#accounts-setup).
5. Set up your [development environment](manual-installation.md)

Now that you're setup, skip ahead to learn how to [contribute](#contribute). 

### CLA

We welcome contributions from everyone but we can only accept them if you sign
our Contributor License Agreement (CLA). If you would like to contribute and you
have not signed it, our CLA-bot will walk you through the process when you open
a Pull Request. For questions about the CLA process, see the
[FAQ](https://cla.vmware.com/faq) or submit a question through the GitHub issue
tracker.

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
[starter](https://github.com/vmware-tanzu/antrea/labels/Good%20first%20issue)
issues from which you can choose.

### GitHub Workflow

Developers work in their own forked copy of the repository and when ready,
submit pull requests to have their changes considered and merged into the
project's repository.

1. Fork your own copy of the repository to your GitHub account by clicking on
   `Fork` button on [Antrea's GitHub repository](https://github.com/vmware-tanzu/antrea).
2. Clone the forked repository on your local setup.
    ```
    git clone https://github.com/$user/antrea
    ```
    Add a remote upstream to track upstream Antrea repository.
    ```
    git remote add upstream https://github.com/vmware-tanzu/antrea
    ```
    Never push to upstream master
    ```
    git remote set-url --push upstream no_push
    ```
3. Create a topic branch.
    ```
    git checkout -b branchName
    ```
4. Make changes and commit it locally.
    ```
    git add <modifiedFile>
    git commit
    ```
5. Update the "Unreleased" section of the [CHANGELOG](CHANGELOG.md) for any
   significant change that impacts users.
6. Keeping branch in sync with upstream.
    ```
    git checkout branchName
    git fetch upstream
    git rebase upstream/master
    ```
7. Push local branch to your forked repository.
    ```
    git push -f $remoteBranchName branchName
    ```
8. Create a Pull request on GitHub.
   Visit your fork at `https://github.com/vmware-tanzu/antrea` and click
   `Compare & Pull Request` button next to your `remoteBranchName` branch.

### Getting reviewers

Once you have opened a Pull Request (PR), reviewers will be assigned to your
PR and they may provide review comments which you need to address.
Commit changes made in response to review comments to the same branch on your
fork. Once a PR is ready to merge, squash any *fix review feedback, typo*
and *merged* sorts of commits.

To make it easier for reviewers to review your PR, consider the following:
1. Follow the golang [coding conventions](https://github.com/golang/go/wiki/CodeReviewComments)
2. Follow [git commit](https://chris.beams.io/posts/git-commit/) guidelines.
3. Follow [logging](https://github.com/kubernetes/community/blob/master/contributors/devel/sig-instrumentation/logging.md) guidelines.

### Building and testing your change

To build the Antrea Docker image together with all Antrea bits, you can simply
do:

1. Checkout your feature branch and `cd` into it.
2. Run `make`

The second step will compile the Antrea code in a `golang` container, and build
a `Ubuntu 18.04` Docker image that includes all the generated binaries. [`Docker`](https://docs.docker.com/install)
must be installed on your local machine in advance.

Alternatively, you can build the Antrea code in your local Go environment. The
Antrea project uses the [Go modules support](https://github.com/golang/go/wiki/Modules) which was introduced in Go 1.11. It
facilitates dependency tracking and no longer requires projects to live inside
the `$GOPATH`.

To develop locally, you can follow these steps:

 1. [Install Go 1.13](https://golang.org/doc/install)
 2. Checkout your feature branch and `cd` into it.
 3. To build all Go files and install them under `bin`, run `make bin`
 4. To run all Go unit tests, run `make test-unit`

### CI testing

For more information about the tests we run as part of CI, please refer to
[ci/README.md](ci/README.md).

### Running the end-to-end tests

In addition to the unit tests, we provide a suite of end-to-end tests, which
require a running Kubernetes cluster. Instructions on how to run these tests,
including how to setup a local Kubernetes cluster, can be found in
[test/e2e/README.md](test/e2e/README.md).

### Reverting a commit

1. Create a branch in your forked repo
    ```
    git checkout -b revertName
    ```
2. Sync the branch with upstream
    ```
    git fetch upstream
    git rebase upstream/master
    ```
3. Create a revert based on the SHA of the commit.
    ```
    git revert SHA
    ```
4. Push this new commit.
    ```
    git push $remoteRevertName revertName
    ```
5. Create a Pull Request on GitHub.
   Visit your fork at `https://github.com/vmware-tanzu/antrea` and click
   `Compare & Pull Request` button next to your `remoteRevertName` branch.

## Issue and PR Management

We use labels and workflows (some manual, some automated with GitHub Actions) to
help us manage triage, prioritize, and track issue progress. For a detailed
discussion, see [docs/issue-management.md](issue-management.md).

### Filing An Issue

Help is always appreciated. If you find something that needs fixing, please file
an issue [here](https://github.com/vmware-tanzu/antrea/issues). Please ensure
that the issue is self explanatory and has enough information for an assignee to
get started.

Before picking up a task, go through the existing
[issues](https://github.com/vmware-tanzu/antrea/issues) and make sure that your
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
  [`docs/github-labels.md`](github-labels.md).
* **size** (optional) -- if you have an idea of the size (lines of code, complexity,
  effort) of the issue, you can label it using a [size label](#size). The size
  can be updated during backlog grooming by contributors. This estimate is used
  to guide the number of features selected for a milestone.

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

* [`kind/api-change`](issue-management.md#api-change) -- for api changes
* [`kind/bug`](issue-management.md#bug) -- for filing a bug
* [`kind/cleanup`](issue-management.md#cleanup) -- for code cleanup and organization
* [`kind/deprecation`](issue-management.md#deprecation) -- for deprecating a feature
* [`kind/design`](issue-management.md#design) -- for proposing a design or architectural change
* [`kind/documentation`](issue-management.md#documentation) -- for updating documentation
* [`kind/failing-test`](issue-management.md#failing-test) -- for reporting a failed test (may
  create with automation in future)
* [`kind/feature`](issue-management.md#feature) -- for proposing a feature
* [`kind/support`](issue-management.md#support) -- to request support. You may also get support by
  using our [Slack](https://kubernetes.slack.com/archives/CR2J23M0X) channel for
  interactive help. If you have not set up the appropriate accounts, please
  follow the instructions in [accounts setup](#accounts-setup).

For more details on how we manage issues, please read our [Issue Management doc](issue-management.md).

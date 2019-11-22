# Developer Guide

Thank you for taking the time out to contribute to project Antrea!

This guide will walk you through the process of making your first commit and
how to effectively get it merged upstream.

Before getting started, go through the following:
1. Read and observe the [code of conduct](CODE_OF_CONDUCT.md).
2. Sign the [CLA](#cla).
3. Check out the [Architecture document](/docs/architecture.md) for the Antrea architecture and design.
4. Set up necessary [accounts](#accounts-setup).
5. Set up your [development environment](docs/manual-installation.md)

## Accounts setup

At minimum, you need the following accounts for effective participation:
1. **Github** : Committing any change requires you to have a [github account](https://github.com/join).
2. **Google Group**: Join our [mailing list](https://groups.google.com/forum/#!forum/projectantrea-dev).

## Contribute

There are multiple ways in which you can contribute, either by contributing
code in the form of new features or bug-fixes or non-code contributions like
helping with code reviews, triaging of bugs, documentation updates, filing
new issues or writing blogs/manuals etc.

In order to help you get your hands "dirty", there is a list of [starter](https://github.com/vmware-tanzu/antrea/labels/Good%20first%20issue)
issues from which you can choose.

## CLA

We welcome contributions from everyone but we can only accept them if you sign
our Contributor License Agreement (CLA). If you would like to contribute and you
have not signed it, our CLA-bot will walk you through the process when you open
a Pull Request. For questions about the CLA process, see the
[FAQ](https://cla.vmware.com/faq) or submit a question through the GitHub issue
tracker.

## Developer workflow

Before picking up a task, go through the existing [issues](https://github.com/vmware-tanzu/antrea/issues)
and make sure that your change is not already being worked on. If it does not
exist, please create a new issue and discuss it with other members.

## Filing an issue

Help is always appreciated. If you find something that needs fixing, please
file an issue [here](https://github.com/vmware-tanzu/antrea/issues). Please ensure that the issue is
self explanatory and has enough information for an assignee to get started.

### GitHub workflow

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

 1. [Install Go 1.12](https://golang.org/doc/install)
 2. Checkout your feature branch and `cd` into it.
 3. To build all Go files and install them under `bin`, run `make bin`
 4. To run all Go unit tests, run `make test-unit`

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

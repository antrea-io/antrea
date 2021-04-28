# Cherry-picks to release branches

Some Pull Requests (PRs) which fix bugs in the main branch of Antrea can be
identified as good candidates for backporting to currently maintained release
branches (using a Git [cherry-pick](https://git-scm.com/docs/git-cherry-pick)),
so that they can be included in subsequent patch releases. If you have authored
such a PR (thank you!!!), one of the Antrea maintainers may comment on your PR
to ask for your assistance with that process. This document provides the steps
you can use to cherry-pick your change to one or more release branches, with the
help of the [cherry-pick script][cherry-pick-script].

For information about which changes are good candidates for cherry-picking,
please refer to our [versioning
policy](../versioning.md#minor-releases-and-patch-releases).

## Prerequisites

* A PR which was approved and merged into the main branch.
* The PR was identified as a good candidate for backporting by an Antrea
  maintainer: they will leave a comment on Github for the PR and provide a list
  of release branches to which the patch should be backported (example:
  [`release-1.0`](https://github.com/vmware-tanzu/antrea/tree/release-1.0)).
* Have the [Github CLI](https://cli.github.com/) installed (version >= 1.3) and
  make sure you authenticate yourself by running `gh auth`.
* Your own fork of the Antrea repository, and a clone of this fork with two
  remotes: the `origin` remote tracking your fork and the `upstream` remote
  tracking the upstream Antrea repository. If you followed our recommended
  [Github Workflow], this should already be the case.

## Cherry-pick your changes

* Set the GITHUB_USER environment variable.
* _Optional_ If your remote names do not match our recommended [Github
  Workflow], you must set the `UPSTREAM_REMOTE` and `FORK_REMOTE` environment
  variables.
* Run the [cherry-pick script][cherry-pick-script]

  This example applies a main branch PR #2134 to the remote branch
  `upstream/release-1.0`:

  ```shell
  hack/cherry-pick-pull.sh upstream/release-1.0 2134
  ```

  If the cherry-picked PR does not apply cleanly against an old release branch,
  the script will let you resolve conflicts manually. This is one of the reasons
  why we ask contributors to backport their own bug fixes, as thei participation
  is critical in case of such a conflict.

The script will create a PR on Github for you, which will automatically be
labelled with `kind/cherry-pick`. This PR will go through the normal testing
process, although it should be very quickly given that the original PR was
already approved and merged into the main branch. The PR should also go through
normal CI testing. In some cases, a few CI tests may fail because we do not have
dedicated CI infrastructure for past Antrea releases. If this happens, the PR
will be merged despite the presence of CI test failures.

You will need to run the cherry pick script separately for each release branch
you need to cherry-pick to. Typically, cherry-picks should be applied to all
[maintained](../versioning.md#release-cycle) release branches for which the fix
is applicable.

[cherry-pick-script]: ../../hack/cherry-pick-pull.sh
[Github Workflow]: ../../CONTRIBUTING.md#github-workflow

# Antrea Release Process

This file documents the list of steps to perform to create a new Antrea
release. We use `<TAG>` as a placeholder for the release tag (e.g. `v1.4.0`).

1. *For a minor release* On the code freeze date (typically one week before the
   actual scheduled release date), create a release branch for the new minor
   release (e.g `release-1.4`).
   - after that time, only bug fixes should be merged into the release branch,
     by [cherry-picking](../contributors/cherry-picks.md) the fix after it has
     been merged into main. The maintainer in charge of that specific minor
     release can either do the cherry-picking directly or ask the person who
     contributed the fix to do it.

2. Open a PR against the appropriate release branch with the following commits:
   - a commit to update the [CHANGELOG](../../CHANGELOG). *For a minor release*,
     all significant changes and all bug fixes since the first version of the
     previous minor release should be mentioned, even bug fixes which have
     already been included in some patch release. *For a patch release*, you
     will mention all the bug fixes since the previous release with the same
     minor version. The commit message must be *exactly* `"Update CHANGELOG for
     <TAG> release"`, as a bot will look for this commit and cherry-pick it to
     update the main branch (starting with Antrea v1.0). The
     [process-changelog.go](../../hack/release/process-changelog.go) script may
     be used to easily generate links to PRs and the Github profiles of PR
     authors.
   - a commit to update [VERSION](../../VERSION) as needed, using the following
     commit message: `"Set VERSION to <TAG>"`.

3. Run all the tests for the PR, investigating test failures and re-triggering
   the tests as needed.
   - Github worfklows are run automatically whenever the head branch is updated.
   - Jenkins tests need to be [triggered manually](../../CONTRIBUTING.md#getting-your-pr-verified-by-ci).
   - Cloud tests need to be triggered manually through the
     [Jenkins web UI](https://jenkins.antrea-ci.rocks/). Admin access is
     required. For each job (AKS, EKS, GKE), click on `Build with Parameters`,
     and enter the name of your fork as `ANTREA_REPO` and the name of your
     branch as `ANTREA_GIT_REVISION`. Test starting times need to be staggered:
     if multiple jobs run at the same time, the Jenkins worker may run
     out-of-memory.

4. Request a review from the other maintainers, and anyone else who may need to
   review the release notes. In case of feedback, you may want to consider
   waiting for all the tests to succeed before updating your PR. Once all the
   tests have run successfully once, address review comments, get approval for
   your PR, and merge.
   - this is the only case for which the "Rebase and merge" option should be
     used instead of the "Squash and merge" option. This is important, in order
     to ensure that changes to the CHANGELOG are preserved as an individual
     commit. You will need to enable the "Allow rebase merging" setting in the
     repository settings temporarily, and remember to disable it again right
     after you merge.

5. Make the release on Github **with the release branch as the target** and copy
   the relevant section of the CHANGELOG as the release description (make sure
   all the markdown links work). You typically should **not** be checking the
   `pre-release` box. This would only be necessary for a release candidate
   (e.g., `<TAG>` is `1.4.0-rc.1`), which we do not have at the moment. There is
   no need to upload any assets as this will be done automatically by a Github
   workflow, after you create the release.

6. After a while (time for the Github workflows to complete), check that:
   - the docker image has been pushed to
     [dockerhub](https://hub.docker.com/u/antrea) with the correct tag.
   - the assets have been uploaded to the release (`antctl` binaries and yaml
     manifests). In particular, the following link should work:
     `https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea.yml`.

7. After the appropriate Github workflow completes, a bot will automatically
   submit a PR to update the CHANGELOG in the main branch. You should verify the
   contents of the PR and merge it (no need to run the tests, use admin
   privileges).

8. *For a minor release* Finally, open a PR against the main branch with a
   single commit, to update [VERSION](../../VERSION) to the next minor version
   (+ `-dev` suffix). For example, if the release was for `v1.4.0`, the VERSION
   file should be updated to `v1.5.0-dev`. After a patch release, the VERSION
   file in the main branch is never updated.

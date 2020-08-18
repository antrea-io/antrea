This file documents the list of steps to perform to create a new Antrea
release. We use `<TAG>` as a placeholder for the release tag (e.g. `v0.1.0`).

 * Create a release branch for each new minor release (e.g `release-0.1`). For
   bug fixes, use the appropriate release branch.

 * Open a PR against the appropriate release branch with the following commits:
    1. a commit to update the [CHANGELOG](CHANGELOG.md).
    2. a commit to update [VERSION](/VERSION) as needed.

 * Make the release on Github with the release branch as the target: copy the
   relevant section of the [CHANGELOG](CHANGELOG.md) for the release
   description and check the `pre-release` box if applicable. There is no need
   to upload any assets as this will be done automatically by a Github workflow,
   after you create the release.

 * After a while (time for the Github workflows to complete), check that:
    1. the docker image has been pushed to
       [dockerhub](https://hub.docker.com/u/antrea) with the correct tag.
    2. the assets have been uploaded to the release (`antctl` binaries and yaml
       manifests). In particular, the following link should work:
       `https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea.yml`.

 * Open a PR against the master branch with the following commits:
    1. the commit updating the [CHANGELOG](CHANGELOG.md), cherry-picked from
       the release branch.
    2. a commit to update [VERSION](/VERSION) to the next minor version (+
       "-dev" suffix) if needed (i.e. if we have just released a new minor
       version). For example, if the release was for `v0.1.0`, the VERSION file
       should be updated to `v0.2.0-dev`. If the release was for `v0.1.1`, the
       VERSION file in the master branch is left untouched (should be
      `v0.2.0-dev`).


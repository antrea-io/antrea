This file documents the list of steps to perform to create a new Antrea
release. We use `<TAG>` as a placeholder for the release tag (e.g. `v0.1.0`).

 * Create a release branch for each new minor release (e.g `release-0.1`). For
   bug fixes, use the appropriate release branch.

 * Open a PR against the appropriate release branch with the following commits:
    1. a commit to update the [CHANGELOG]({{site.gh_repo}}/tree/master/CHANGELOG.md).
    2. a commit to update [VERSION]({{site.gh_repo}}/tree/master/VERSION) as needed.

 * Generate the deployment manifest for the release:
   `IMG_NAME=antrea/antrea-ubuntu IMG_TAG=<TAG> ./hack/generate-manifest.sh --mode release > antrea.yml`

 * Make the release on Github with the release branch as the target: copy the
   relevant section of the [CHANGELOG]({{site.gh_repo}}/CHANGELOG.md) for the release
   description and upload the deployment manifest generated in the previous step
   (as antrea.yml, otherwise the manifest link advertised in
   [getting-started.md](getting-started.md) will not work!). Check the
   `pre-release` box if applicable.

 * Check that:
    1. after a while (time for the Github workflows to complete) the docker
     image has been pushed to [dockerhub](https://hub.docker.com/u/antrea) with
     the correct tag.
    2. the following link works: `https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea.yml`

 * Open a PR against the master branch with the following commits:
    1. the commit updating the [CHANGELOG]({{site.gh_repo}}/tree/master/CHANGELOG.md), cherry-picked from
       the release branch.
    2. a commit to update [VERSION]({{site.gh_repo}}/tree/master/VERSION) to the next minor version (+
       "-dev" suffix) if needed (i.e. if we have just released a new minor
       version). For example, if the release was for `v0.1.0`, the VERSION file
       should be updated to `v0.2.0-dev`. If the release was for `v0.1.1`, the
       VERSION file in the master branch is left untouched (should be
      `v0.2.0-dev`).


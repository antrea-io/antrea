# images/base-windows

This Docker image includes download libraries for building windows image.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/base-windows
GO_VERSION=$(head -n 1 ../deps/go-version)
CNI_BINARIES_VERSION=$(head -n 1 ../deps/cni-binaries-version)
NANOSERVER_VERSION=$(head -n 1 ../deps/nanoserver-version)
WIN_BUILD_TAG=$(echo $GO_VERSION $CNI_BINARIES_VERSION $NANOSERVER_VERSION| md5sum| head -c 10)
docker build -t antrea/base-windows:$WIN_BUILD_TAG --build-arg GO_VERSION=$GO_VERSION --build-arg CNI_BINARIES_VERSION=$CNI_BINARIES_VERSION --build-arg NANOSERVER_VERSION=$NANOSERVER_VERSION .
docker push antrea/base-windows:$WIN_BUILD_TAG
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

However, the easiest way to push a new image on Dockerhub is to run the
`Manually update antrea/base-windows Docker image` Github workflow. Only
contributors with `write` access to the antrea-io/antrea Github repository can
trigger the workflow. If you need to update the image, please check with a
maintainer first.

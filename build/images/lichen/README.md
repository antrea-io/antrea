# images/golicense

This Docker image includes the [lichen](https://github.com/uw-labs/lichen) tool,
used to check the licenses of all the dependencies included in a Go binary.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/lichen
GO_VERSION=$(head -n 1 ../deps/go-version)
LICHEN_VERSION=<VERSION>
docker build -t antrea/lichen:$LICHEN_VERSION --build-arg GO_VERSION=$GO_VERSION --build-arg LICHEN_VERSION=$LICHEN_VERSION .
docker push antrea/lichen:$LICHEN_VERSION
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

# images/codegen

This Docker image is a very lightweight image based on the golang image, which
includes codegen tools.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/codegen
GO_VERSION=$(head -n 1 ../deps/go-version)
docker build -t antrea/codegen:<TAG> --build-arg GO_VERSION=$GO_VERSION .
docker push antrea/codegen:<TAG>
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

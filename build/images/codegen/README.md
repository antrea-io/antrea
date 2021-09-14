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

Here is the table of codegen images that have been uploaded:

| Tag                            | Change                                  |
| :----------------------------- | --------------------------------------- |
| kubernetes-1.21.0-build.1      | Upgraded protoc-gen-go to v1.5.2        |
| kubernetes-1.21.0-build.0      | Upgraded Go to v1.17                    |
| kubernetes-1.21.0              | Upgraded K8s libraries to v1.21.0       |
| kubernetes-1.19.8              | Upgraded K8s libraries to v1.19.8       |
| kubernetes-1.18.4              | Upgraded K8s libraries to v1.18.4       |
| kubernetes-1.17.6              | Upgraded K8s libraries to v1.17.6       |

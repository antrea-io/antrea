# images/codegen

This Docker image is a very lightweight image based on the golang image, which
includes codegen tools.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/codegen
GO_VERSION=$(head -n 1 ../deps/go-version)
docker build --pull -t antrea/codegen:<TAG> --build-arg GO_VERSION=$GO_VERSION .
docker push antrea/codegen:<TAG>
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

The image can only be built on an x86_64 machine (no arm support).

Here is the table of codegen images that have been uploaded:

| Tag                       | Change                                                                        |
| :------------------------ | ----------------------------------------------------------------------------- |
| kubernetes-1.31.1-build.0 | Upgraded go.uber.org/mock/mockgen to v0.5.0                                   |
| kubernetes-1.31.1         | Upgraded K8s libraries to v1.31.1, controller-gen to v0.16.3, ubuntu to 24.04 |
| kubernetes-1.29.2-build.3 | Upgraded Go to v1.23                                                          |
| kubernetes-1.29.2-build.2 | Upgraded go.uber.org/mock/mockgen to v0.4.0                                   |
| kubernetes-1.29.2-build.1 | Upgraded controller-gen to v0.14.0                                            |
| kubernetes-1.29.2-build.0 | Upgraded protoc (v26.0), protoc-gen-go (v1.33.0), protoc-gen-go-grpc (v1.3.0) |
| kubernetes-1.29.2         | Upgraded K8s libraries to v1.29.2                                             |
| kubernetes-1.26.4-build.1 | Replace github.com/golang/mock with go.uber.org/mock                          |
| kubernetes-1.26.4-build.0 | Upgraded Go to v1.21                                                          |
| kubernetes-1.26.4         | Upgraded K8s libraries to v1.26.4                                             |
| kubernetes-1.24.0-build.2 | Upgraded base image to ubuntu:22.04                                           |
| kubernetes-1.24.0-build.1 | Upgraded Go to v1.19                                                          |
| kubernetes-1.24.0-build.0 | Add controller-gen v0.9.0                                                     |
| kubernetes-1.24.0         | Upgraded K8s libraries to v1.24.0                                             |
| kubernetes-1.21.0-build.1 | Upgraded protoc-gen-go to v1.5.2                                              |
| kubernetes-1.21.0-build.0 | Upgraded Go to v1.17                                                          |
| kubernetes-1.21.0         | Upgraded K8s libraries to v1.21.0                                             |
| kubernetes-1.19.8         | Upgraded K8s libraries to v1.19.8                                             |
| kubernetes-1.18.4         | Upgraded K8s libraries to v1.18.4                                             |
| kubernetes-1.17.6         | Upgraded K8s libraries to v1.17.6                                             |

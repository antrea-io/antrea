# images/multicluster

This Docker image is a very lightweight image based on distroless image.
It includes Antrea multi-cluster controllers.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following code in the Antrea base directory:

```bash
GO_VERSION=1.17
docker build -t antrea/antrea-multicluster-controller -f build/images/multicluster/Dockerfile --build-arg GO_VERSION=$GO_VERSION .
docker push antrea/antrea-multicluster-controller:<TAG>
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

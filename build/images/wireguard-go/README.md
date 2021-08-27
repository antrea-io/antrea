# images/wireguard-go

This Docker image is a very lightweight image based on Ubuntu 20.04 which
includes WireGuard golang implementation and wireguard-tools. It can be used
for Kind clusters for tests when injected as a sidecar to antrea-agent.
The version is available at <https://github.com/WireGuard/wireguard-go/releases>.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/wireguard-go
GO_VERSION=$(head -n 1 ../deps/go-version)
WIREGUARD_GO_VERSION=0.0.20210424
docker build -t antrea/wireguard-go:$WIREGUARD_GO_VERSION --build-arg GO_VERSION=$GO_VERSION --build-arg WIREGUARD_GO_VERSION=$WIREGUARD_GO_VERSION .
docker push antrea/wireguard-go:$WIREGUARD_GO_VERSION
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

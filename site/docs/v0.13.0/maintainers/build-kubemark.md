# Build the kubemark image

This documentation simply describes how to build the kubemark image used in
[Antrea scale testing](../antrea-agent-simulator.md)

   ```bash
cd $KUBERNETES_PATH
git checkout v1.18.4
make WHAT=cmd/kubemark KUBE_BUILD_PLATFORMS=linux/amd64
cp ./_output/local/go/bin/linux_amd64/kubemark cluster/images/kubemark
cd cluster/images/kubemark
docker build -t antrea/kubemark:v1.18.4 .
   ```

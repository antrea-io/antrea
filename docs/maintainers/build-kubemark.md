# Build the kubemark image
  This documentation simply describes how to build kubemark image.

   ```bash
   cd $KUBERNETES_PATH
   make WHAT=cmd/kubemark KUBE_BUILD_PLATFORMS=linux/amd64
   cp ./_output/local/go/bin/linux_amd64/kubemark cluster/images/kubemark
   cd cluster/images/kubemark
   docker build -t antrea/kubemark:latest .
   ```
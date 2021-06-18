# Antrea ARM support

Starting with Antrea v0.13, we provide Antrea Docker images for both the arm/v7
and arm64 architectures. At the moment, the standard Antrea Docker manifest
(`projects.registry.vmware.com/antrea/antrea-ubuntu`) does not include support
for ARM, and the image name needs to be updated manually in the Antrea
Kubernetes YAML manifest when deploying Antrea on a cluster which includes ARM
Nodes.

To download the manifest for Antrea v0.13.0, substitute the image name, and
deploy Antrea, you can use the following command:

```bash
curl -sL https://github.com/vmware-tanzu/antrea/releases/download/v0.13.0/antrea.yml | sed 's/antrea\/antrea-ubuntu/antrea\/antrea-ubuntu-march/' | kubectl apply -f -
```

Or to deploy the latest version of Antrea (built from the main branch), use:

```bash
curl -sL https://raw.githubusercontent.com/vmware-tanzu/antrea/main/build/yamls/antrea.yml | sed 's/antrea\/antrea-ubuntu/antrea\/antrea-ubuntu-march/' | kubectl apply -f -
```

In a future release, we will update the standard Docker manifest for Antrea to
support ARM architectures, and this manual edit will not longer be required.

Note that while we do run a subset of the Kubernetes conformance tests on both
the arm/v7 and arm64 images (using [k3s](https://k3s.io/) as the Kubernetes
distribution), our testing is not as thorough as for the amd64 image. However,
we do not anticipate any issue.

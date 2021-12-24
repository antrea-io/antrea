# images/ovs

This directory contains utilities to build a Docker image which includes Open
vSwitch (OVS) built from source. We build OVS from source because some features
of Antrea (such as IPsec) require a recent version of OVS, more recent than the
version included in Ubuntu 20.04. The built image is then used as the base image
for the Antrea main Docker image.

The image is re-built and pushed to Dockerhub periodically (every 12 hours) by a
[Github workflow](/.github/workflows/update_ovs_image.yml). Therefore, there
should be no need to update the registry image manually. If it's needed for any
reason, you can follow the instructions below.

## Manually building the image and pushing it to Dockerhub

```bash
cd build/images/ovs
./build.sh --pull --push
```

The image will be pushed to Dockerhub as `antrea/openvswitch:<OVS_VERSION>`. The
OVS version used is determined by the contents of the
`build/images/deps/ovs-version` file.

The script will fail if you do not have permission to push to the `antrea`
Dockerhub repository.

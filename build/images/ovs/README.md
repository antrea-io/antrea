# images/ovs

This directory contains utilities to build a Docker image which includes Open
vSwitch (OVS) built from source. We build OVS from source because some features
of Antrea (such as IPSec) require a recent version of OVS, more recent than the
version included in Ubuntu 18.04. The built image is then used as the base image
for the Antrea main Docker image.

## Building the image and pushing it to Dockerhub

Choose the version of OVS you want to build by setting the `OVS_VERSION`
environment variable. Then run the `build_and_push.sh` script. For example:

```bash
OVS_VERSION=2.11.1 ./ovs/build_and_push.sh
```

The image will be pushed to Dockerhub as `antrea/openvswitch:$OVS_VERSION`.

The script will fail if you do not have permission to push to the `antrea`
Dockerhub repository.

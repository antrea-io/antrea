# images/ethtool

This Docker image is a very lightweight image based on Ubuntu 20.04 which
includes ethtool, the ip tools and iptables.

If you need to build a new version of the image locally, you can run the following:

```bash
cd build/images/ethtool
docker build -t antrea/ethtool:latest .
```

To update the version of the image on Dockerhub, you can run the `Manually
update antrea/ethtool Docker image` Github workflow. Only contributors with
`write` access to the antrea-io/antrea Github repository can trigger the
workflow. If you need to update the image, please check with a maintainer first.

# images/ethtool

This Docker image is a very lightweight image based on Ubuntu 20.04 which
includes ethtool, the ip tools and iptables.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/ethtool
docker build -t antrea/ethtool:latest .
docker push antrea/ethtool:latest
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

# cni-dhcp-daemon

This Docker image can be used to run the [DHCP daemon from the
containernetworking
project](https://github.com/containernetworking/plugins/tree/master/plugins/ipam/dhcp).

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
docker build -t antrea/cni-dhcp-daemon:latest .
docker push antrea/cni-dhcp-daemon:latest
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

# images/perftool

This Docker image is a very lightweight image based on Ubuntu 20.04 which
includes the apache2-utils and iperf3 packages.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/perftool
docker build -t antrea/perftool:latest .
docker push antrea/perftool:latest
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

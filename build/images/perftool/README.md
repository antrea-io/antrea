# images/perftool

This Docker image is for performance testing with iperf3. For Linux, it is
based on Ubuntu 20.04 which includes the apache2-utils and iperf3 packages.
For Windows, it downloads iperf3 binary and adds it to `PATH`.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

Linux
```bash (Linux)
cd build/images/perftool
docker build -t antrea/perftool-ubuntu:latest -f Dockerfile.ubuntu .
docker push antrea/perftool-ubuntu:latest
```

Windows
```bash (Windows)
cd build/images/perftool
docker build -t antrea/perftool-windows:latest -f Dockerfile.windows .
docker push antrea/perftool-windows:latest
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

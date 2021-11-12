# images/netperf

This Docker image is for latency testing with netperf. For Linux, it is
based on gcc latest which downloads netperf v2.7 source code and build it.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

netperf 2.7
```bash (Linux)
cd build/images/netperf
docker build -t antrea/netperf-ubuntu:2.7 -f Dockerfile.netperf27.ubuntu .
docker push antrea/netperf-ubuntu:2.7
```

netperf 2.5
```bash (Linux)
cd build/images/netperf
docker build -t antrea/netperf-ubuntu:2.5 -f Dockerfile.netperf25.ubuntu .
docker push antrea/netperf-ubuntu:2.5
```

For Windows, if you already have netperf.exe and netserver.exe ready, you can
run the following:

netperf 2.5
```bash (Windows)
cd build/images/netperf
docker build -t antrea/netperf-windows:2.7 -f Dockerfile.ubuntu .
docker push antrea/netperf-windows:2.7
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

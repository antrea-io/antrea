# images/ipfixcollector

This Docker image is based on Ubuntu 18.04 which includes ipfix collector based on libipfix, a C library.
In this image, IPFIX collector listening on tcp:4739 port.

libipfix package is downloaded from https://svwh.dl.sourceforge.net/project/libipfix/libipfix/libipfix-impd4e_110224.tgz

New version of the image can be built and pushed to Dockerhub using following instructions:

```bash
cd build/images/ipfixcollector
docker build -t antrea/ipfixcollector:latest .
docker push antrea/ipfixcollector:latest
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

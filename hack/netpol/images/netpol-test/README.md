# images/perftool

This Docker image is a very lightweight Alpine image which includes
[ncat](https://nmap.org/ncat/).

If you need to build a new version of the image and push it to Dockerhub, you
can run the following from this directory:

```bash
docker build -t antrea/netpol-test:latest .
docker push antrea/netpol-test:latest
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

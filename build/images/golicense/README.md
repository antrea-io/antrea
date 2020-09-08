# images/golicense

This Docker image is a "distroless" image which includes the
[golicense](https://github.com/mitchellh/golicense) tool.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/golicense
docker build -t antrea/golicense .
docker push antrea/golicense
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

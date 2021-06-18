# images/golicense

This Docker image includes the [lichen](https://github.com/uw-labs/lichen) tool,
used to check the licenses of all the dependencies included in a Go binary.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/lichen
docker build -t antrea/lichen .
docker push antrea/lichen
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

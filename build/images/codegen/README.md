# images/codegen

This Docker image is a very lightweight image based on golang 1.15 which
includes codegen tools.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/codegen
docker build -t antrea/codegen:<TAG> .
docker push antrea/codegen:<TAG>
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

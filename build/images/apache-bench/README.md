# images/apache-bench

This Docker image is a very lightweight image based on Ubuntu 18.04 which
includes the apache2-utils package, and in particular the
[ApacheBench](https://httpd.apache.org/docs/2.4/programs/ab.html) program.

If you need to build a new version of the image and push it to Dockerhub, you
can run the following:

```bash
cd build/images/apache-bench
docker build -t antrea/apache-bench:latest .
docker push antrea/apache-bench:latest
```

The `docker push` command will fail if you do not have permission to push to the
`antrea` Dockerhub repository.

## Antrea CI

This directory includes all the scripts required to run CI on Antrea.

For information about our Jenkins CI jobs and how to run the same tests locally,
see [here](jenkins/README.md).

File [k8s-conformance-image-version](k8s-conformance-image-version) stores the
version number of the K8s conformance container image we currently use to run
tests.

## Go linters

As part of CI, we run the following linters via
[golangci-lint](https://github.com/golangci/golangci-lint):
 * `misspell` - Finds commonly misspelled English words in comments.
 * `gofmt` - Gofmt checks whether code was gofmt-ed.
 * `deadcode` - Finds unused code.

You can run the linters locally with `make golangci` from the root of the
repository. Some issues can be fixed automatically for you if you run `make
golangci-fix`.

See our [golangci-lint configuration file](/.golangci.yml) for more details.

You can also run the `golint` linter with `make lint` to see suggestions about
how to improve your code, and we encourage you to do so when submitting a
patch. The reason why we do not run this linter by default in CI is that, unlike
`gofmt`, it is not considered [trustworthy enough for its suggestions to be
enforced automatically](https://github.com/golang/lint#purpose).

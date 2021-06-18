# Antrea CI

This directory includes all the scripts required to run CI on Antrea.

For information about our Jenkins CI jobs and how to run the same tests locally,
see [here](jenkins/README.md).

File [k8s-conformance-image-version](k8s-conformance-image-version) stores the
version number of the K8s conformance container image we currently use to run
tests.

## Antrea test suite

We run 4 different categories of tests as part of CI:

* **unit tests**: most Go packages for Antrea include some unit tests written
  using the Go [`testing`] package. Unit tests typically rely on mock testing to
  isolate the package being tested, and abstract platform-specific functionality
  hidden behind interfaces. When adding a new package or modifying an existing
  one, add the appropriate unit tests.
* **integration tests**: these tests are located under [test/integration] and
  are also written using the Go [`testing`] package. Unlike unit tests, they
  typically exercise multiple Go packages to ensure that they are working
  correctly together. In the case of Antrea, integration tests may create an
  actual OVS bridge, which is why they depend on the OVS daemons running, and
  are typically run inside a Docker image, even on Linux. Write integration
  tests when you require an actual OVS bridge or you need access to
  platform-specific utilities.
* **end-to-end (e2e) tests**: these tests are located under [test/e2e] and are
  also written using the Go [`testing`] package. Unlike the two previous test
  categories, these assume that Antrea is running on an actual cluster and
  require a kubeconfig file as well as SSH access to the cluster Nodes.
  Instructions on how to run these tests, including how to setup a local
  Kubernetes cluster, can be found in [test/e2e/README.md]. Typical use cases
  for e2e tests include: validate the Antrea manifest and ensure Antrea
  components can be deployed successfully, check end-to-end connectivity for
  different types of traffic (e.g. Pod-to-Pod, Pod-to-Service), validate the
  implementation of Antrea-speicifc APIs
  (e.g. [ClusterNetworkPolicy](/docs/network-policy.md),
  [Traceflow](/docs/traceflow-guide.md), ...).
* **Kubernetes upstream tests**: our CI relies on Kubernetes community tests to
  ensure conformance and validate the implementation of the NetworkPolicy API.

The table below recaps the different categories of tests and indicates how to
run them locally:

| Test category                 | Location              | How to run locally                                 | Automation |
| ----------------------------- | --------------------- | -------------------------------------------------- | ---------- |
| **unit tests**                | most Go packages      | `make test-unit` (Linux) / `make docker-test-unit` | [Github Actions] |
| **integration tests**         | [test/integration]    | `make docker-test-integration`                     | [Github Actions] (soon to be Jenkins) |
| **e2e tests**                 | [test/e2e]            | see [test/e2e/README.md]                           | [Github Actions] ([Kind] cluster) + [Jenkins] |
| **Kubernetes upstream tests** | [upstream Kubernetes] | see [ci/jenkins/README.md]                         | [Jenkins] |

[test/integration]: /test/integration
[test/e2e]: /test/e2e
[test/e2e/README.md]: /test/e2e/README.md
[ci/jenkins/README.md]: /ci/jenkins/README.md
[Jenkins]: /ci/jenkins/README.md
[Kind]: https://kind.sigs.k8s.io/
[upstream Kubernetes]: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-testing/e2e-tests.md
[`testing`]: https://golang.org/pkg/testing/
[Github Actions]: https://github.com/features/actions

## Go linters

As part of CI, we run the following linters via
[golangci-lint](https://github.com/golangci/golangci-lint):

* [`misspell`](https://github.com/client9/misspell) - Finds commonly misspelled English words in comments.
* [`gofmt`](https://golang.org/cmd/gofmt/) - Checks whether code was gofmt-ed.
* [`deadcode`](https://github.com/remyoudompheng/go-misc/tree/master/deadcode) - Finds unused code.
* [`staticcheck`](https://staticcheck.io/) - Static analysis toolset with a large number of tests.
* [`gosec`](https://github.com/securego/gosec) - Checks for common security problems.
* [`goimports`](https://godoc.org/golang.org/x/tools/cmd/goimports) - A superset of `gofmt` organizes imports and checks for unused ones.
* [`go vet`](https://golang.org/cmd/vet/) - Examines Go source code and reports suspicious constructs.

You can run the linters locally with `make golangci` from the root of the
repository. Some issues can be fixed automatically for you if you run `make
golangci-fix`.

See our [golangci-lint configuration file](/.golangci.yml) for more details.

You can also run the `golint` linter with `make lint` to see suggestions about
how to improve your code, and we encourage you to do so when submitting a
patch. The reason why we do not run this linter by default in CI is that, unlike
`gofmt`, it is not considered [trustworthy enough for its suggestions to be
enforced automatically](https://github.com/golang/lint#purpose).

## Markdown formatting

As part of CI, we run [markdownlint](https://github.com/DavidAnson/markdownlint)
through the [markdownlint
CLI](https://github.com/igorshubovych/markdownlint-cli) to ensure consistent
formatting of the documentation and compatibility with Markdown rendering tools
(and in particular the ones we use for the Antrea website).

To install the CLI locally, follow these
[instructions](https://github.com/igorshubovych/markdownlint-cli#installation). You
can then validate your changes to the documentation with `make
markdownlint`. Note that some formatting errors can be fixed automatically with
`make markdownlint-fix`.

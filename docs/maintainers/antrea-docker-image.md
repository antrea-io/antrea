# Antrea Docker image

The main Antrea Docker images (`antrea/antrea-agent-ubuntu` and
`antrea/antrea-controller-ubuntu`) are multi-arch images. For example, the
`antrea/antrea-agent-ubuntu` manifest is a list of three manifests:
`antrea/antrea-agent-ubuntu-amd64`, `antrea/antrea-agent-ubuntu-arm64` and
`antrea/antrea-agent-ubuntu-arm`. Of these three manifests, only the first one
is built and uploaded to Dockerhub by Github workflows defined in the
`antrea-io/antrea` repositories. The other two are built and uploaded by Github
workflows defined in a private repository (`vmware-tanzu/antrea-build-infra`),
to which only the project maintainers have access. These workflows are triggered
every time the `main` branch of `antrea-io/antrea` is updated, as well as every
time a new Antrea Github release is created. They build the
`antrea/antrea-agent-ubuntu-arm64` and `antrea/antrea-agent-ubuntu-arm` Docker
images on native arm64 workers, then create the `antrea/antrea-agent-ubuntu`
multi-arch manifest and push it to Dockerhub. The same goes for the controller
images. They are also in charge of testing the images in a
[K3s](https://github.com/k3s-io/k3s) cluster.

## Why do we use a private repository?

The `vmware-tanzu/antrea-build-infra` repository uses self-hosted ARM64 workers
provided by the [Open Source Lab](https://osuosl.org/services/aarch64/) at
Oregon State University. These workers enable us to build, and more importantly
*test*, the Antrea Docker images for the arm64 and arm/v7 architectures. Being
able to build Docker images on native ARM platforms is convenient as it is much
faster than emulation. But if we just wanted to build the images, emulation
would probably be good enough. However, testing Kubernetes ARM support using
emulation is no piece of cake. Which is why we prefer to use native ARM64
workers.

Github strongly
[recommends](https://docs.github.com/en/actions/hosting-your-own-runners/about-self-hosted-runners#self-hosted-runner-security-with-public-repositories)
not to use self-hosted runners with public repositories, for security
reasons. It would be too easy for a malicious person to run arbitrary code on
the runners by opening a pull request. Were we to make this repository public,
we would therefore at least need to disable pull requests, which is sub-optimal
for a public repository. We believe Github will address the issue eventually and
provide safeguards to enable using self-hosted runners with public
repositories, at which point we will migrate workflows from this repository to
the main Antrea repository.

In the future, we may switch over to ARM hosted Github runners provided by the
CNCF.

# Docker Desktop Alternatives

The Antrea build system relies on Docker to build container images, which can
then be used to test Antrea locally. As an Antrea developer, if you run `make`,
`docker build` will be invoked to build the `antrea-ubuntu` container image. On
Linux, Docker Engine (based on moby) runs natively, but if you use macOS or
Windows for Antrea development, Docker needs to run inside a Linux Virtual
Machine (VM). This VM is typically managed by [Docker
Desktop](https://www.docker.com/products/docker-desktop). Starting January 31
2022, Docker Desktop requires a per user paid subscription for professional use
in "large" companies (more than 250 employees or more than $10 million in annual
revenue). See [https://www.docker.com/pricing/faq for details]. For developers
who contribute to Antrea as an employee of such a company (and not in their own
individual capacity), it is no longer possible to use Docker Desktop to build
(and possibly run) Antrea Docker images locally, unless they have a Docker
subscription.

For contributors who do not have a Docker subscription, we recommend the
following Docker Desktop alternatives.

## Colima (macOS)

[Colima](https://github.com/abiosoft/colima) is a UI built with
[Lima](https://github.com/lima-vm/lima). It supports running a container runtime
(docker, containerd or kuberneters) on macOS, inside a Lima VM. Major benefits
of Colima include its ability to be used as a drop-in replacement for Docker
Desktop and its ability to coexist with Docker Desktop on the same macOS
machine.

To install and run Colima, follow these steps:

* `brew install colima`
* `colima start` to start Colima (the Linux VM) with the default
  configuration. Check the Colima documentation for configuration options. By
  default, Colima will use the Docker runtime. This means that you can keep
  using the `docker` CLI and that no changes are required to build Antrea.
* `docker context list` and check that the `colima` context is selected. You can
  use `docker context use desktop-linux` to go back to Docker Desktop.
* `make` to build Antrea locally. Check that the `antrea-ubuntu` image is
  available by listin all images with `docker images`.

TODO: validate that Kind can be used with Colima without any issue.

## Rancher Desktop (macOS and Windows)

Rancher Desktop is another possible alternative to Docker Desktop, which
supports Windows in addition to macOS. On macOS, it also uses Lima as the Linux
VM. Two major differences with Colima are that Rancher Desktop will always run
Kubernetes, and that Rancher Desktop uses the
[`nerdctl`](https://github.com/containerd/nerdctl) UI for container management
instead of `docker`. However, the `nerdctl` and `docker` UIs are supposed to be
compatible, so in theory it should be possible to alias `docker` to `nerdctl`
and keep using the Antrea build system as is (to be tested).

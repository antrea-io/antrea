## Antrea CI: Jenkins

### Reasons for Jenkins
We have tests as Github Actions but Jenkins allows tests running on a cluster of
multiple nodes and offers better environment setup options.

### Jenkins on cloud
At the moment these Jenkins jobs are running on VMC (VMware on AWS). As a
result, all jobs' results and details are available publicly
[here](https://jenkins.antrea-ci.rocks/). We are using Cluster API for vSphere
([CAPV](https://github.com/kubernetes-sigs/cluster-api-provider-vsphere)) for
creating and managing workload clusters. The management cluster is a kind cluster
on Jenkins node. For each job build, a completely new workload cluster will be created
by this management cluster. As soon as the build finishes, the cluster
should be deleted. This ensures that all tests are run on a clean testbed.

### List of Jenkins jobs
* [e2e](https://jenkins.antrea-ci.rocks/job/antrea-e2e-for-pull-request/):
  [end-to-end tests](/test/e2e) for Antrea.
* [conformance](https://jenkins.antrea-ci.rocks/job/antrea-conformance-for-pull-request/):
  community tests using sonobuoy, focusing on "Conformance", and skipping "Slow",
  "Serial", "Disruptive", "Flaky", "Feature", "sig-cli",
  "sig-storage", "sig-auth", "sig-api-machinery", "sig-apps" and "sig-node".
* [network policy](https://jenkins.antrea-ci.rocks/job/antrea-networkpolicy-for-pull-request/):
  community tests using sonobuoy, focusing on "Feature:NetworkPolicy".
* Microsoft Windows conformance: community tests related to Microsoft Windows.
  It focuses on: "[sig-network].+[Conformance]|[sig-windows]".
  It skips: "[LinuxOnly]|[Slow]|[Serial]|[Disruptive]|[Flaky]|[Feature:.+]|[sig-cli]|[sig-storage]|[sig-auth]|[sig-api-machinery]|[sig-apps]|[sig-node]|[Privileged]|should be able to change the type from|[sig-network] Services should be able to create a functioning NodePort service [Conformance]".
* jenkins jobs validator: this job only executes for PRs that include changes to
  [ci/jenkins/jobs](/ci/jenkins/jobs). It validates the syntax of the jenkins jobs'
  configuration.

If you need to run the K8s community tests locally, you may use the
[ci/run-k8s-e2e-tests.sh](/ci/run-k8s-e2e-tests.sh) script. It takes care of
installing the correct version of
[sonobuoy](https://github.com/vmware-tanzu/sonobuoy) and running the correct
subset of community tests for Antrea:
* To run conformance tests: `./run-k8s-e2e-tests.sh --e2e-conformance
  [--kubeconfig <Kubeconfig>]`.
* To run network policy tests: `./run-k8s-e2e-tests.sh --e2e-network-policy
  [--kubeconfig <Kubeconfig>]`.
* To run a single test by name: `./run-k8s-e2e-tests.sh --e2e-focus <TestRegex>
  [--kubeconfig <Kubeconfig>]`.

### Requirements
Yaml files under [ci/jenkins/jobs](/ci/jenkins/jobs) can be generated via
jenkins-job-builder. If you want to try out the tests on your local jenkins
setup, please notice the following requirements:
* Jenkins setup
  * Plugins: ghprb, throttle-concurrents
* Install
  [jenkins-job-builder](https://docs.openstack.org/infra/jenkins-job-builder/index.html)
* Define your `ANTREA_GIT_CREDENTIAL` which is the credential for your private
  repo
* Define your `ghpr_auth`, `antrea_admin_list`, `antrea_org_list` and
  `antrea_white_list` as
  [defaults](https://docs.openstack.org/infra/jenkins-job-builder/definition.html#defaults)
  variables in a separate file

### Apply the jobs
Run the command to test if jobs can be generated correctly.  
```bash
jenkins-jobs test -r ci/jenkins/jobs
```

Run the command to apply these jobs.  
```bash
jenkins-jobs update -r ci/jenkins/jobs
```

### Jenkins job updater
To follow GitOps best practices, there is a job-updater job in Jenkins to detect
any change in [ci/jenkins/jobs](/ci/jenkins/jobs) for every 15 min. As long as
a PR to modify code under that path is merged, Jenkins jobs on cloud should be
updated with new code.

### Tips for Developer
* [macro.yaml](/ci/jenkins/jobs/macros.yaml): Use "{{}}" instead of "{}" in "builder-list-tests" and "builder-conformance".
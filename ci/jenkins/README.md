## Antrea CI: Jenkins

### Reasons for Jenkins
We have tests as Github Actions but Jenkins allows tests running on a cluster of
multiple nodes and offers better environment setup options.

### List of Jenkins jobs
* e2e: [end-to-end tests](/test/e2e) for Antrea.
* conformance: community tests using sonobuoy, focusing on "Conformance", and
  skipping "Slow", "Serial", "Disruptive", "Flaky", "Feature", "sig-cli",
  "sig-storage", "sig-auth", "sig-api-machinery", "sig-apps" and "sig-node".
* network policy: community tests using sonobuoy, focusing on
  "Feature:NetworkPolicy".

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

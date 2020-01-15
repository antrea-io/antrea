## Antrea CI: Jenkins

### Reasons for Jenkins
We have tests as Github Action but Jenkins allows tests running on a cluster of multiple nodes and offers better environment setup options.

### List of Jenkins jobs
* [e2e](https://github.com/vmware-tanzu/antrea/tree/master/test/e2e): end-to-end tests for Antrea.
* conformance: community tests using sonobuoy, focusing on "Conformance", and skipping "Slow", "Serial", "Disruptive", "Flaky", "Feature", "sig-cli", "sig-storage", "sig-auth", "sig-api-machinery", "sig-apps" and "sig-node".
* network policy: community tests using sonobuoy, focusing on "Feature:NetworkPolicy", and skipping "allow ingress access from updated pod" and "named port".
Test "named port" will be supported soon, see issue [#122](https://github.com/vmware-tanzu/antrea/issues/122).  
Test "allow ingress access from updated pod" fails because of a bug in the test definition, see issue [#85908](https://github.com/kubernetes/kubernetes/issues/85908).

### Requirements
Yaml files under [`ci/jenkins/jobs`](https://github.com/vmware-tanzu/antrea/tree/master/ci/jenkins/jobs) can be generated via jenkins-job-builder. If you want to try out the tests on your local jenkins setup, please notice the following requirements:
* Jenkins setup
  * Plugins: ghprb, throttle-concurrents
* Install [jenkins-job-builder](https://docs.openstack.org/infra/jenkins-job-builder/index.html)
* Define your `ANTREA_GIT_CREDENTIAL` which is the credential for your private repo
* Define your `ghpr_auth`, `antrea_admin_list`, `antrea_org_list` and `antrea_white_list` as [defaults](https://docs.openstack.org/infra/jenkins-job-builder/definition.html#defaults) variables in a separate file

### Apply the jobs
Run the command to test if jobs can be generated correctly.  
```bash
jenkins-jobs test -r ci/jenkins/jobs
```

Run the command to apply these jobs.  
```bash
jenkins-jobs update -r ci/jenkins/jobs
```

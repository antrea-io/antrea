# Maintaining Kubernetes Compatibility

Upon the release of a Kubernetes minor release (e.g. [v1.28.0, on 15th August 2023](https://github.com/kubernetes/sig-release/tree/master/releases/release-1.28)),
the maintainer in charge of release should do the following to maintain
compatibility with this K8s release.

1. Check out its changelog to see if there are any changes that may affect its
   compatibility with Antrea.

2. Run Kubernetes Conformance tests with the new K8s minor release and the
   Antrea releases under maintenance (the two most recent minor releases).
   - For Linux, you can run the tests through [the workflow](https://github.com/antrea-io/antrea/actions/workflows/conformance.yml)
     Click on `Run workflow`, enter the Antrea versions to test (e.g.
     `v1.12.0`, `v1.11.2`), enter the K8s versions to test (e.g. `v1.28.0`).
     You typically do not need to specify the Antrea Chart values and change
     the test suite to run.
   - For Windows, it is not automated at the moment. You need to manually
     set up the testbed and run the tests.

3. Regardless of whether a compatibility issue is found, open a PR against the
   main branch to update [Kubernetes Compatibility](../../README.md#kubernetes-compatibility)
   and [Supported K8s versions](../versioning.md#supported-k8s-versions) with
   the actual results.

4. If there are any compatibility issues, open issues to track them.

5. If the issues are resolvable and the patches are backportable, you should
   create Antrea patch versions to recover compatibility with this K8s release,
   and open a PR to update [Kubernetes Compatibility](../../README.md#kubernetes-compatibility)
   and [Supported K8s versions](../versioning.md#supported-k8s-versions) with
   the latest results.
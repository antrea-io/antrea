# Monitoring CRDs for both controller and agent

Antrea Uses [k8s.io/code-generator (release-1.14)](https://github.com/kubernetes/code-generator/tree/release-1.14) to
generate both controller and agent monitoring CRDs.

* Monitoring CRDs definitions are located in [Monitoring CRDs API](pkg/apis/clusterinformation/crd/antrea/v1beta1).

* Client generated is located in [Generated Client](pkg/client/clientset/versioned).

* Deepcopy generated is located in [Generated Deepcopy](pkg/apis/clusterinformation/crd/antrea/v1beta1).

If you need to make any change to api or client, you can re-generate deepcopy and client code 
by invoking `make crd-gen` from the top-level directory.

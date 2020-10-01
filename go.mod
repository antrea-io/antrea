module github.com/vmware-tanzu/antrea

go 1.13

require (
	github.com/Mellanox/sriovnet v1.0.1
	github.com/Microsoft/go-winio v0.4.15-0.20190919025122-fc70bd9a86b5
	github.com/Microsoft/hcsshim v0.8.10-0.20200715222032-5eafd1556990
	github.com/TomCodeLV/OVSDB-golang-lib v0.0.0-20200116135253-9bbdfadcd881
	github.com/awalterschulze/gographviz v2.0.1+incompatible
	github.com/benmoss/go-powershell v0.0.0-20190925205200-09527df358ca
	github.com/blang/semver v3.5.0+incompatible
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20180727162946-9642ea02d0aa // indirect
	github.com/cheggaaa/pb/v3 v3.0.4
	github.com/confluentinc/bincover v0.0.0-20200910210245-839e88185831
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.8.2-0.20190724153215-ded2f1757770
	github.com/contiv/libOpenflow v0.0.0-20200728044739-7c6534390721
	github.com/contiv/ofnet v0.0.0-00010101000000-000000000000
	github.com/coreos/go-etcd v2.0.0+incompatible // indirect
	github.com/coreos/go-iptables v0.4.5
	github.com/cpuguy83/go-md2man v1.0.10 // indirect
	github.com/elazarl/goproxy v0.0.0-20190911111923-ecfe977594f1 // indirect
	github.com/go-openapi/spec v0.19.3
	github.com/godbus/dbus v0.0.0-20190422162347-ade71ed3457e // indirect
	github.com/gogo/protobuf v1.3.1
	github.com/golang/mock v1.4.3
	github.com/golang/protobuf v1.4.2
	github.com/google/uuid v1.1.1
	github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.10.0
	github.com/rakelkar/gonetsh v0.0.0-20190930180311-e5c5ffe4bdf0
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/afero v1.3.4
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/streamrail/concurrent-map v0.0.0-20160823150647-8bf1e9bacbf6 // indirect
	github.com/stretchr/testify v1.5.1
	github.com/ti-mo/conntrack v0.3.0
	github.com/ugorji/go/codec v0.0.0-20181204163529-d75b2dcb6bc8 // indirect
	github.com/vishvananda/netlink v1.1.0
	github.com/vmware/go-ipfix v0.2.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/exp v0.0.0-20191227195350-da58074b4299
	golang.org/x/net v0.0.0-20200822124328-c89045814202 // indirect
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	golang.org/x/sys v0.0.0-20200622214017-ed371f2e16b4
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/grpc v1.27.0
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.19.2
	k8s.io/apimachinery v0.19.2
	k8s.io/apiserver v0.19.2
	k8s.io/client-go v0.19.2
	k8s.io/component-base v0.19.2
	k8s.io/klog v1.0.0
	k8s.io/kube-aggregator v0.18.4
	k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6
	k8s.io/kubernetes v1.19.2
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73
)

replace (
	// antrea/plugins/octant/go.mod also has this replacement since replace statement in dependencies
	// were ignored. We need to change antrea/plugins/octant/go.mod if there is any change here.
	github.com/contiv/ofnet => github.com/wenyingd/ofnet v0.0.0-20200911061943-57045ae085da
	// fake.NewSimpleClientset is quite slow when it's initialized with massive objects due to
	// https://github.com/kubernetes/kubernetes/issues/89574. It takes more than tens of minutes to
	// init a fake client with 200k objects, which makes it hard to run the NetworkPolicy scale test.
	// There is an optimization https://github.com/kubernetes/kubernetes/pull/89575 but will only be
	// available from 1.19.0 and later releases. Use this commit before Antrea bumps up its K8s
	// dependency version.
	k8s.io/client-go => k8s.io/client-go v0.19.2
)

replace k8s.io/api => k8s.io/api v0.19.2

replace k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.2

replace k8s.io/apimachinery => k8s.io/apimachinery v0.19.3-rc.0

replace k8s.io/apiserver => k8s.io/apiserver v0.19.2

replace k8s.io/cli-runtime => k8s.io/cli-runtime v0.19.2

replace k8s.io/cloud-provider => k8s.io/cloud-provider v0.19.2

replace k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.19.2

replace k8s.io/code-generator => k8s.io/code-generator v0.19.3-rc.0

replace k8s.io/component-base => k8s.io/component-base v0.19.2

replace k8s.io/controller-manager => k8s.io/controller-manager v0.19.3-rc.0

replace k8s.io/cri-api => k8s.io/cri-api v0.19.3-rc.0

replace k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.19.2

replace k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.19.2

replace k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.19.2

replace k8s.io/kube-proxy => k8s.io/kube-proxy v0.19.2

replace k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.19.2

replace k8s.io/kubectl => k8s.io/kubectl v0.19.2

replace k8s.io/kubelet => k8s.io/kubelet v0.19.2

replace k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.19.2

replace k8s.io/metrics => k8s.io/metrics v0.19.2

replace k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.19.2

replace k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.19.2

replace k8s.io/sample-controller => k8s.io/sample-controller v0.19.2

module github.com/vmware-tanzu/antrea

go 1.15

require (
	github.com/Mellanox/sriovnet v1.0.1
	github.com/Microsoft/go-winio v0.4.15-0.20190919025122-fc70bd9a86b5
	github.com/Microsoft/hcsshim v0.8.9
	github.com/TomCodeLV/OVSDB-golang-lib v0.0.0-20200116135253-9bbdfadcd881
	github.com/awalterschulze/gographviz v2.0.1+incompatible
	github.com/benmoss/go-powershell v0.0.0-20190925205200-09527df358ca
	github.com/blang/semver v3.5.0+incompatible
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20180727162946-9642ea02d0aa // indirect
	github.com/cheggaaa/pb/v3 v3.0.4
	github.com/confluentinc/bincover v0.1.0
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.8.2-0.20190724153215-ded2f1757770
	github.com/contiv/libOpenflow v0.0.0-20201014051314-c1702744526c
	github.com/contiv/ofnet v0.0.0-00010101000000-000000000000
	github.com/coreos/go-iptables v0.4.5
	github.com/elazarl/goproxy v0.0.0-20190911111923-ecfe977594f1 // indirect
	github.com/go-openapi/spec v0.19.3
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
	github.com/vishvananda/netlink v1.1.0
	github.com/vmware/go-ipfix v0.3.1
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/exp v0.0.0-20191227195350-da58074b4299
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20201112073958-5cba982894dd
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	google.golang.org/grpc v1.27.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.19.5
	k8s.io/apimachinery v0.19.5
	k8s.io/apiserver v0.19.5
	k8s.io/client-go v0.19.5
	k8s.io/component-base v0.19.5
	k8s.io/klog v1.0.0
	k8s.io/kube-aggregator v0.19.5
	k8s.io/kube-openapi v0.0.0-20200805222855-6aeccd4b50c6
	k8s.io/kubectl v0.19.5
	k8s.io/utils v0.0.0-20200729134348-d5654de09c73
)

// antrea/plugins/octant/go.mod also has this replacement since replace statement in dependencies
// were ignored. We need to change antrea/plugins/octant/go.mod if there is any change here.
replace github.com/contiv/ofnet => github.com/wenyingd/ofnet v0.0.0-20201109024835-6fd225d8c8d1

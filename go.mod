module github.com/vmware-tanzu/antrea

go 1.15

require (
	github.com/Mellanox/sriovnet v1.0.2
	github.com/Microsoft/go-winio v0.4.16-0.20201130162521-d1ffc52c7331
	github.com/Microsoft/hcsshim v0.8.9
	github.com/TomCodeLV/OVSDB-golang-lib v0.0.0-20200116135253-9bbdfadcd881
	github.com/antoninbas/go-powershell v0.1.0
	github.com/awalterschulze/gographviz v2.0.1+incompatible
	github.com/blang/semver v3.5.1+incompatible
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20180727162946-9642ea02d0aa // indirect
	github.com/cheggaaa/pb/v3 v3.0.4
	github.com/confluentinc/bincover v0.1.0
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.8.7
	github.com/contiv/libOpenflow v0.0.0-20210312221048-1d504242120d
	github.com/contiv/ofnet v0.0.0-00010101000000-000000000000
	github.com/coreos/go-iptables v0.4.5
	github.com/elazarl/goproxy v0.0.0-20190911111923-ecfe977594f1 // indirect
	github.com/go-openapi/spec v0.19.3
	github.com/gogo/protobuf v1.3.1
	github.com/golang/mock v1.4.4
	github.com/golang/protobuf v1.4.3
	github.com/google/uuid v1.1.2
	github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd
	github.com/kr/text v0.2.0 // indirect
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.10.0
	github.com/rakelkar/gonetsh v0.0.0-20210226024844-dfffed138500
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/afero v1.4.1
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/streamrail/concurrent-map v0.0.0-20160823150647-8bf1e9bacbf6 // indirect
	github.com/stretchr/testify v1.6.1
	github.com/ti-mo/conntrack v0.3.0
	github.com/vishvananda/netlink v1.1.0
	github.com/vmware/go-ipfix v0.4.7
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/exp v0.0.0-20200224162631-6cc2880d07d6
	golang.org/x/mod v0.4.0
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20201201145000-ef89a241ccb3
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	google.golang.org/grpc v1.27.1
	gopkg.in/check.v1 v1.0.0-20200902074654-038fdea0a05b // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.3.0
	k8s.io/api v0.19.8
	k8s.io/apimachinery v0.19.8
	k8s.io/apiserver v0.19.8
	k8s.io/client-go v0.19.8
	k8s.io/component-base v0.19.8
	k8s.io/klog/v2 v2.4.0
	k8s.io/kube-aggregator v0.19.8
	k8s.io/kube-openapi v0.0.0-20210305164622-f622666832c1
	k8s.io/kubectl v0.19.8
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920
)

replace (
	// hcshim repo is modifed to add "AdditionalParams" field to HNSEndpoint struct.
	// We will use this replace before pushing the change to hcshim upstream repo.
	github.com/Microsoft/hcsshim v0.8.9 => github.com/ruicao93/hcsshim v0.8.10-0.20210114035434-63fe00c1b9aa
	// antrea/plugins/octant/go.mod also has this replacement since replace statement in dependencies
	// were ignored. We need to change antrea/plugins/octant/go.mod if there is any change here.
	github.com/contiv/ofnet => github.com/wenyingd/ofnet v0.0.0-20210205051801-5a4f247248d4
)

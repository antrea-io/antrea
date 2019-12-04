module github.com/vmware-tanzu/antrea

go 1.12

require (
	github.com/Sirupsen/logrus v0.8.8-0.20160119000032-f7f79f729e0f // indirect
	github.com/TomCodeLV/OVSDB-golang-lib v0.0.0-20190103132138-cf96a9e61bd1
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20180727162946-9642ea02d0aa // indirect
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.8.2-0.20190724153215-ded2f1757770
	github.com/contiv/libOpenflow v0.0.0-20191113031650-a32467f65a17
	github.com/contiv/libovsdb v0.0.0-20160406174930-bbc744d8ddc8 // indirect
	github.com/contiv/ofnet v0.0.0-00010101000000-000000000000
	github.com/coreos/go-iptables v0.4.1
	github.com/elazarl/goproxy v0.0.0-20190911111923-ecfe977594f1 // indirect
	github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/gogo/protobuf v1.2.1
	github.com/golang/mock v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/google/uuid v1.1.1
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/gorilla/context v1.1.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/j-keck/arping v1.0.0
	github.com/json-iterator/go v1.1.6 // indirect
	github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd
	github.com/prometheus/client_golang v0.9.3-0.20190127221311-3c4408c8b829 // indirect
	github.com/satori/go.uuid v1.2.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.3
	github.com/streamrail/concurrent-map v0.0.0-20160823150647-8bf1e9bacbf6 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/vishvananda/netlink v1.0.0
	github.com/vmware/octant v0.8.0
	golang.org/x/crypto v0.0.0-20190701094942-4def268fd1a4
	golang.org/x/net v0.0.0-20190628185345-da137c7871d7 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 // indirect
	golang.org/x/sys v0.0.0-20190710143415-6ec70d6a5542
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	google.golang.org/grpc v1.22.0
	gopkg.in/yaml.v2 v2.2.2
	k8s.io/api v0.0.0-20190620084959-7cf5895f2711
	k8s.io/apimachinery v0.0.0-20190612205821-1799e75a0719
	k8s.io/apiserver v0.0.0-20190620085212-47dc9a115b18
	k8s.io/client-go v0.0.0-20190620085101-78d2af792bab
	k8s.io/component-base v0.0.0-20190620085130-185d68e6e6ea
	k8s.io/klog v0.3.3
	k8s.io/utils v0.0.0-20190607212802-c55fbcfc754a // indirect
)

replace (
	github.com/contiv/ofnet => github.com/wenyingd/ofnet v0.0.0-20191128031608-5339eaf55aa1
	// Octant is renamed from vmware/octant to vmware-tanzu/octant since v0.9.0.
	// However, Octant v0.9.0 K8s API is not compatible with Antrea K8s API version.
	// Furthermore, octant v0.8 and v0.9 do not check-in some generated code required for testing
	// (mocks), which breaks "go mod". This has been fixed in master.
	// Will remove this and upgrade Octant version after finding another compatible Octant release.
	github.com/vmware/octant => github.com/antoninbas/octant v0.8.1-0.20191116223915-811df1acc59f
)

module github.com/vmware-tanzu/antrea

go 1.13

require (
	github.com/TomCodeLV/OVSDB-golang-lib v0.0.0-20190103132138-cf96a9e61bd1
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20180727162946-9642ea02d0aa // indirect
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.8.2-0.20190724153215-ded2f1757770
	github.com/contiv/libOpenflow v0.0.0-20200115035645-b22edc53818e
	github.com/contiv/ofnet v0.0.0-00010101000000-000000000000
	github.com/coreos/go-iptables v0.4.1
	github.com/davecgh/go-spew v1.1.1
	github.com/elazarl/goproxy v0.0.0-20190911111923-ecfe977594f1 // indirect
	github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/fatih/structtag v1.2.0
	github.com/gogo/protobuf v1.2.1
	github.com/golang/mock v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/google/gofuzz v1.0.0 // indirect
	github.com/google/uuid v1.1.1
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/imdario/mergo v0.3.7 // indirect
	github.com/j-keck/arping v1.0.0
	github.com/json-iterator/go v1.1.6 // indirect
	github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd
	github.com/satori/go.uuid v1.2.0
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.3
	github.com/streamrail/concurrent-map v0.0.0-20160823150647-8bf1e9bacbf6 // indirect
	github.com/stretchr/testify v1.4.0
	github.com/vishvananda/netlink v1.0.0
	github.com/vmware/octant v0.8.0
	golang.org/x/crypto v0.0.0-20191128160524-b544559bb6d1
	golang.org/x/exp v0.0.0-20190121172915-509febef88a4
	golang.org/x/net v0.0.0-20191126235420-ef20fe5d7933 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 // indirect
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e // indirect
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
	github.com/contiv/ofnet => github.com/wenyingd/ofnet v0.0.0-20200116061148-fd9e64ac3ebb
	// Octant is renamed from vmware/octant to vmware-tanzu/octant since v0.9.0.
	// However, Octant v0.9.0 K8s API is not compatible with Antrea K8s API version.
	// Furthermore, octant v0.8 and v0.9 do not check-in some generated code required for testing
	// (mocks), which breaks "go mod". This has been fixed in master.
	// Will remove this and upgrade Octant version after finding another compatible Octant release.
	github.com/vmware/octant => github.com/antoninbas/octant v0.8.1-0.20191116223915-811df1acc59f
)

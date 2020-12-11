module github.com/vmware-tanzu/antrea/plugins/octant

go 1.15

require (
	github.com/vmware-tanzu/antrea v0.0.0
	github.com/vmware-tanzu/octant v0.16.1
	k8s.io/apimachinery v0.19.5
	k8s.io/client-go v0.19.5
)

replace (
	github.com/contiv/ofnet => github.com/wenyingd/ofnet v0.0.0-20201109024835-6fd225d8c8d1
	github.com/vmware-tanzu/antrea => ../../
	k8s.io/api => k8s.io/api v0.19.0-alpha.3
	k8s.io/client-go => k8s.io/client-go v0.19.0-alpha.3
)

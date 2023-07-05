module antrea.io/antrea

go 1.19

require (
	antrea.io/libOpenflow v0.10.3
	antrea.io/ofnet v0.7.3
	github.com/ClickHouse/clickhouse-go/v2 v2.6.1
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/Mellanox/sriovnet v1.1.0
	github.com/Microsoft/go-winio v0.6.1
	github.com/Microsoft/hcsshim v0.9.8
	github.com/TomCodeLV/OVSDB-golang-lib v0.0.0-20200116135253-9bbdfadcd881
	github.com/aws/aws-sdk-go-v2 v1.16.10
	github.com/aws/aws-sdk-go-v2/config v1.16.0
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.11.23
	github.com/aws/aws-sdk-go-v2/service/s3 v1.27.4
	github.com/blang/semver v3.5.1+incompatible
	github.com/cheggaaa/pb/v3 v3.1.2
	github.com/confluentinc/bincover v0.1.0
	github.com/containernetworking/cni v1.1.1
	github.com/containernetworking/plugins v1.1.1
	github.com/coreos/go-iptables v0.6.0
	github.com/fsnotify/fsnotify v1.6.0
	github.com/gammazero/deque v0.1.2
	github.com/go-logr/logr v1.2.4
	github.com/gogo/protobuf v1.3.2
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.3
	github.com/google/btree v1.1.2
	github.com/google/uuid v1.3.0
	github.com/hashicorp/memberlist v0.5.0
	github.com/k8snetworkplumbingwg/network-attachment-definition-client v1.3.0
	github.com/k8snetworkplumbingwg/sriov-cni v2.1.0+incompatible
	github.com/kevinburke/ssh_config v1.2.0
	github.com/lithammer/dedent v1.1.0
	github.com/mdlayher/arp v0.0.0-20220221190821-c37aaafac7f9
	github.com/mdlayher/ethernet v0.0.0-20220221185849-529eae5b6118
	github.com/mdlayher/ndp v0.8.0
	github.com/mdlayher/packet v1.0.0
	github.com/miekg/dns v1.1.55
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822
	github.com/onsi/ginkgo/v2 v2.11.0
	github.com/onsi/gomega v1.27.8
	github.com/pkg/errors v0.9.1
	github.com/pkg/sftp v1.13.5
	github.com/prometheus/client_golang v1.16.0
	github.com/prometheus/common v0.44.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/afero v1.9.5
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.8.4
	github.com/ti-mo/conntrack v0.4.0
	github.com/vishvananda/netlink v1.1.1-0.20211101163509-b10eb8fe5cf6
	github.com/vmware/go-ipfix v0.6.2
	golang.org/x/crypto v0.10.0
	golang.org/x/exp v0.0.0-20230321023759-10a507213a29
	golang.org/x/mod v0.11.0
	golang.org/x/net v0.11.0
	golang.org/x/sync v0.3.0
	golang.org/x/sys v0.10.0
	golang.org/x/time v0.3.0
	golang.org/x/tools v0.10.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20210506160403-92e472f520a5
	google.golang.org/grpc v1.56.1
	google.golang.org/protobuf v1.31.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	k8s.io/api v0.26.4
	k8s.io/apiextensions-apiserver v0.26.4
	k8s.io/apimachinery v0.26.4
	k8s.io/apiserver v0.26.4
	k8s.io/client-go v0.26.4
	k8s.io/component-base v0.26.4
	k8s.io/klog/v2 v2.80.1
	k8s.io/kube-aggregator v0.26.4
	k8s.io/kube-openapi v0.0.0-20221012153701-172d655c2280
	k8s.io/kubectl v0.26.4
	k8s.io/kubelet v0.26.4
	k8s.io/utils v0.0.0-20221128185143-99ec85e7a448
	sigs.k8s.io/controller-runtime v0.14.6
	sigs.k8s.io/mcs-api v0.1.0
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/ClickHouse/ch-go v0.51.2 // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/VividCortex/ewma v1.2.0 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr v1.4.10 // indirect
	github.com/armon/go-metrics v0.0.0-20180917152333-f0300d1749da // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.4.4 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.12.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.12.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.1.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.4.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.3.18 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.0.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.9.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.1.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.9.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.13.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.11.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.16.12 // indirect
	github.com/aws/smithy-go v1.12.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cenk/hub v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.0 // indirect
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20180727162946-9642ea02d0aa // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/containerd/cgroups v1.0.4 // indirect
	github.com/contiv/libovsdb v0.0.0-20170227191248-d0061a53e358 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/elazarl/goproxy v0.0.0-20190911111923-ecfe977594f1 // indirect
	github.com/emicklei/go-restful/v3 v3.9.0 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/felixge/httpsnoop v1.0.3 // indirect
	github.com/go-faster/city v1.0.1 // indirect
	github.com/go-faster/errors v0.6.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.20.0 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/cel-go v0.12.6 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.7.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.0.0 // indirect
	github.com/hashicorp/go-msgpack v0.5.3 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-sockaddr v1.0.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/compress v1.15.14 // indirect
	github.com/kr/fs v0.1.0 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mattn/go-runewidth v0.0.12 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mdlayher/genetlink v1.0.0 // indirect
	github.com/mdlayher/netlink v1.4.0 // indirect
	github.com/mdlayher/socket v0.2.1 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/paulmach/orb v0.8.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.17 // indirect
	github.com/pion/dtls/v2 v2.2.4 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.0.0 // indirect
	github.com/pion/udp v0.1.4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/prometheus/procfs v0.10.1 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/safchain/ethtool v0.0.0-20210803160452-9aa261dae9b1 // indirect
	github.com/sean-/seed v0.0.0-20170313163322-e2103e2c3529 // indirect
	github.com/segmentio/asm v1.2.0 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/streamrail/concurrent-map v0.0.0-20160823150647-8bf1e9bacbf6 // indirect
	github.com/ti-mo/netfilter v0.3.1 // indirect
	github.com/vishvananda/netns v0.0.0-20210104183010-2eb08e3e575f // indirect
	gitlab.com/golang-commonmark/puny v0.0.0-20191124015043-9f83538fa04f // indirect
	go.etcd.io/etcd/api/v3 v3.5.5 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.5.5 // indirect
	go.etcd.io/etcd/client/v3 v3.5.5 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.35.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.35.0 // indirect
	go.opentelemetry.io/otel v1.11.2 // indirect
	go.opentelemetry.io/otel/exporters/otlp/internal/retry v1.11.2 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.11.2 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.11.2 // indirect
	go.opentelemetry.io/otel/metric v0.34.0 // indirect
	go.opentelemetry.io/otel/sdk v1.11.2 // indirect
	go.opentelemetry.io/otel/trace v1.11.2 // indirect
	go.opentelemetry.io/proto/otlp v0.19.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	go.uber.org/zap v1.24.0 // indirect
	golang.org/x/oauth2 v0.8.0 // indirect
	golang.org/x/term v0.9.0 // indirect
	golang.org/x/text v0.10.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20210427022245-097af6e1351b // indirect
	gomodules.xyz/jsonpatch/v2 v2.2.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/kms v0.26.4 // indirect
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.0.36 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)

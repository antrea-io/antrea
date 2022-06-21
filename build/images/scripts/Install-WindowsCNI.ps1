$ErrorActionPreference = "Stop";

mkdir -force /host/var/run/secrets/kubernetes.io/serviceaccount
cp -force /var/run/secrets/kubernetes.io/serviceaccount/* /host/var/run/secrets/kubernetes.io/serviceaccount/
mkdir -force /host/k/antrea/etc/
cp /k/antrea/cni/* /host/opt/cni/bin/
cp /etc/antrea/antrea-agent.conf /host/k/antrea/etc/

cp /etc/antrea/antrea-cni.conflist /host/etc/cni/net.d/10-antrea.conflist

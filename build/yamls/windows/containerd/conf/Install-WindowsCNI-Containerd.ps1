$ErrorActionPreference = "Stop";
mkdir -force c:/var/log/antrea
$mountPath = $env:CONTAINER_SANDBOX_MOUNT_POINT
$mountPath =  ($mountPath.Replace('\', '/')).TrimEnd('/')
mkdir -force C:/var/run/secrets/kubernetes.io/serviceaccount
cp $mountPath/var/run/secrets/kubernetes.io/serviceaccount/ca.crt C:/var/run/secrets/kubernetes.io/serviceaccount
cp $mountPath/var/run/secrets/kubernetes.io/serviceaccount/token C:/var/run/secrets/kubernetes.io/serviceaccount
cp $mountPath/k/antrea/cni/* c:/opt/cni/bin/
cp $mountPath/etc/antrea/antrea-cni.conflist c:/etc/cni/net.d/10-antrea.conflist
mkdir -force c:/k/antrea/bin
cp $mountPath/k/antrea/bin/antctl.exe c:/k/antrea/bin/antctl.exe

$ErrorActionPreference = "Stop";
mkdir -force c:/var/log/antrea
$mountPath = $env:CONTAINER_SANDBOX_MOUNT_POINT
$mountPath =  ($mountPath.Replace('\', '/')).TrimEnd('/')

# From containerd version 1.7 onwards, the servcieaccount directory, the ca.cert and token files will automatically be created.
$serviceAccountPath = "C:\var\run\secrets\kubernetes.io\serviceaccount"
if (-Not $(Test-Path $serviceAccountPath)) {
    mkdir -force $serviceAccountPath
}

$localTokenFile = "$serviceAccountPath/token"
$localCAFile="$serviceAccountPath/ca.crt"

$tokenPath = "$mountPath/var/run/secrets/kubernetes.io/serviceaccount/token"
$caPath = "$mountPath/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# Check if the local token file is not present or its content is different
if (-Not (Test-Path $localTokenFile) -or (Get-Content -Raw $localTokenFile) -ne (Get-Content -Raw $tokenPath)) {
    Copy-Item -Path $tokenPath -Destination $localTokenFile -Force
}

# Check if the local ca.crt file is not present or its content is different
if (-Not (Test-Path $localCAFile) -or (Get-Content -Raw $localCAFile) -ne (Get-Content -Raw $caPath)) {
    Copy-Item -Path $caPath -Destination $localCAFile -Force
}

mkdir -force c:/opt/cni/bin/
mkdir -force c:/etc/cni/net.d/
cp $mountPath/k/antrea/cni/* c:/opt/cni/bin/
cp $mountPath/etc/antrea/antrea-cni.conflist c:/etc/cni/net.d/10-antrea.conflist
mkdir -force c:/k/antrea/bin
cp $mountPath/k/antrea/bin/antctl.exe c:/k/antrea/bin/antctl.exe

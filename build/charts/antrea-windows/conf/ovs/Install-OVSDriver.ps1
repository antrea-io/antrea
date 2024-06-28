$ErrorActionPreference = "Stop"
$mountPath = $env:CONTAINER_SANDBOX_MOUNT_POINT
$mountPath = ($mountPath.Replace('\', '/')).TrimEnd('/')
$OVSInstallScript = "$mountPath\k\antrea\Install-OVS.ps1"
if (-not (Test-Path $OVSInstallScript)) {
  Write-Host "Installation script not found: $OVSInstallScript, you may be using an invalid antrea-windows container image"
  exit 1
}
& $OVSInstallScript -LocalFile "$mountPath/openvswitch" -InstallUserspace $false
If (!$?) {
  Write-Host "Failed to install OVS driver"
  exit 1
}
Write-Host "Completed OVS driver installation"

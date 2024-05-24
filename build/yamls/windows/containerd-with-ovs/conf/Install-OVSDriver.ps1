$ErrorActionPreference = "Stop"
$mountPath = $env:CONTAINER_SANDBOX_MOUNT_POINT
$mountPath = ($mountPath.Replace('\', '/')).TrimEnd('/')
$OVSDriverDir = "$mountPath\openvswitch\driver"

# Check if OVSExt driver is already installed
$driverStatus = netcfg -q ovsext
if ($driverStatus -like '*not installed*') {
  # Install OVS Driver
  $result = netcfg -l $OVSDriverDir/ovsext.inf -c s -i OVSExt
  if ($result -like '*failed*') {
    Write-Host "Failed to install OVSExt driver: $result"
    exit 1
  }
  Write-Host "OVSExt driver has been installed"
}

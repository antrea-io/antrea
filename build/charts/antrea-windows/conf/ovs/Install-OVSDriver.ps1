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

# Check if the VC redistributable is already installed.
$OVSRedistDir="$mountPath\openvswitch\redist"
if (Test-Path $OVSRedistDir) {
  $dllFound = $false
  $paths = $env:PATH -split ';'
  foreach ($path in $paths) {
    $dllFiles = Get-ChildItem -Path $path -Filter "vcruntime*.dll" -File -ErrorAction SilentlyContinue
    if ($dllFiles.Count -gt 0) {
      $dllFound = $true
      break
    }
  }

  # vcruntime dlls are not installed on the host, then install the binaries.
  if (-not $dllFound) {
    Get-ChildItem $OVSRedistDir -Filter *.exe | ForEach-Object {
      Start-Process -FilePath $_.FullName -Args '/install /passive /norestart' -Verb RunAs -Wait
    }
  }
}

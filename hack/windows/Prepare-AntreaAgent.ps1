<#
.SYNOPSIS
Prepare environment for antrea-agent.

.DESCRIPTION
This script prepares environment needed by antrea-agent which includes:
- Cleaning stale Antrea network resources if they exist.
- Prepare a network interface which is needed by kube-proxy. Without the interface, kube-proxy cannot
  provide the proxy for Kubernetes Services.
#>

$ErrorActionPreference = 'Stop'

$ScriptDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$CleanAntreaNetworkScript = Join-Path $ScriptDirectory "Clean-AntreaNetwork.ps1"
$PrepareServiceInterfaceScript = Join-Path $ScriptDirectory "Prepare-ServiceInterface.ps1"
# Clean stale Antrea HNSNetwork and OVS bridge.
$NeedCleanNetwork = $true
$AntreaHnsNetwork = Get-HnsNetwork | Where-Object {$_.Name -eq "antrea-hnsnetwork"}
if ($AntreaHnsNetwork) {
    $OVSExtension = $AntreaHnsNetwork.Extensions | Where-Object {$_.Name -eq "Open vSwitch Extension"}
    if ($OVSExtension.IsEnabled) {
        $NeedCleanNetwork = $false
    }
}
if ($NeedCleanNetwork) {
    Write-Host "Cleaning stale Antrea network resources if they exist..."
    & $CleanAntreaNetworkScript
}
# Enure OVS services are running.
Write-Host "Starting ovsdb-server service..."
Start-Service ovsdb-server
Write-Host "Starting ovs-vswitchd service..."
Start-Service ovs-vswitchd
# Prepare service network interface for kube-proxy.
Write-Host "Preparing service network interface for kube-proxy..."
& $PrepareServiceInterfaceScript

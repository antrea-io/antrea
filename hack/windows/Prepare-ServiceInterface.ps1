<#
.SYNOPSIS
Create virtual netadapter for kube-proxy. The default full name of the virtual adapter is "vEthernet (HNS Internal NIC)"

.DESCRIPTION
This script creates virtual netadapter for kube-proxy. The created virtual adapter is used by kube-proxy to configure Kubernetes Services IPs on it.

.PARAMETER KubernetesVersion
Kubernetes version to download and use

.EXAMPLE
PS> .\PrepareServiceInterface.ps1 -InterfaceAlias "HNS Internal NIC"

#>
Param(
    [parameter(Mandatory = $false, HelpMessage="Interface to be added Services IPs by kube-proxy")] [string] $InterfaceAlias="HNS Internal NIC",
    [parameter(Mandatory = $false, HelpMessage="Stop existing kube-proxy process after creating interface")] [bool] $StopKubeProxyOnCreation=$true
)
$ErrorActionPreference = 'Stop'

$INTERFACE_TO_ADD_SERVICE_IP = "vEthernet ($InterfaceAlias)"
Write-Host "Creating netadapter $INTERFACE_TO_ADD_SERVICE_IP for kube-proxy"
if (Get-NetAdapter -InterfaceAlias $INTERFACE_TO_ADD_SERVICE_IP -ErrorAction SilentlyContinue) {
    Write-Host "NetAdapter $INTERFACE_TO_ADD_SERVICE_IP exists, exit."
    return
}
[Environment]::SetEnvironmentVariable("INTERFACE_TO_ADD_SERVICE_IP", $INTERFACE_TO_ADD_SERVICE_IP, [System.EnvironmentVariableTarget]::Machine)
$hnsSwitchName = $(Get-VMSwitch -SwitchType Internal).Name
Add-VMNetworkAdapter -ManagementOS -Name $InterfaceAlias -SwitchName $hnsSwitchName
Set-NetIPInterface -ifAlias $INTERFACE_TO_ADD_SERVICE_IP -Forwarding Enabled

if ($StopKubeProxyOnCreation) {
  # Restart kube-proxy to ensure that the newly created interface can be used.
  # Terminate kube-proxy and the process will be automatically restarted by the kube-proxy Pod.
  Write-Host "stopping running kube-proxy process if exists..."
  taskkill /fi "IMAGENAME eq rancher-wins-kube-proxy.exe" /f
}

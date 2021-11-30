<#
  .SYNOPSIS
  Clean OVS bridge and HnsNetwork created by Antrea Agent

  .PARAMETER OVSInstallDir
  OVS installation directory. It is the path argument when using Install-OVS.ps1. The default path is "C:\openvswitch".
  .PARAMETER RenewIPConfig
  Renew the ipconfig on the host. The default value is $false.
#>
Param(
    [parameter(Mandatory = $false)] [string] $OVSInstallDir = "C:\openvswitch",
    [parameter(Mandatory = $false)] [bool] $RenewIPConfig   = $false
)

# Replace the path using the actual path where ovs-vswitchd.pid locates. It is always under path $OVSInstallDir\var\run\openvswitch.
$OVS_PID_PATH = "$OVSInstallDir\var\run\openvswitch\ovs-vswitchd.pid"
$OVS_DB_SCHEMA_PATH = "$OVSInstallDir\usr\share\openvswitch\vswitch.ovsschema"
# Replace the path using the actual path where OVS conf.db locates. It is always under path OVSInstallDir\etc\openvswitch.
$OVSDB_CONF_DIR = "$OVSInstallDir\etc\openvswitch"
$OVS_DB_PATH = "$OVSDB_CONF_DIR\conf.db"
$OVS_BR_ADAPTER = "br-int"

function GetHnsnetworkId($NetName) {
    $NetList= $(Get-HnsNetwork -ErrorAction SilentlyContinue)
    if ($NetList -eq $null) {
        return $null
    }
    foreach ($Net in $NetList) {
        if ($Net.Name -eq $NetName) {
            return $Net.Id
        }
    }
    return $null
}

function ClearHyperVBinding($adapter) {
    $status= $(Get-NetAdapterBinding -Name $adapter.Name -ComponentID vms_pp).Enabled
    if ($status -EQ "False") {
        Set-NetAdapterBinding -Name $adapter.Name -ComponentID vms_pp -Enabled $False
    }
}

function ClearHyperVBindingOnAdapter($adapterName) {
    if ($adapterName -NE "") {
        $adapter = $(Get-NetAdapter -Name $adapterName)
        if ($adapter -eq $null) {
            return
        }
        ClearHyperVBinding($adapter)
    } else {
        $adapters= $(Get-NetAdapter | ? Virtual -EQ $false)
        if ($adapters -eq $null) {
            Write-Host "Physical network adapters not found"
            return
        }
        foreach ($adapter in $adapters) {
            ClearHyperVBinding($adapter)
        }
    }
}

function ResetOVSService() {
    $ovsVswitchdSvc = Get-Service ovs-vswitchd -ErrorAction Ignore
    if ($ovsVswitchdSvc -EQ $null) {
        return
    }
    $ovsStatus = $(Get-Service ovs-vswitchd).Status
    if ("$ovsStatus" -EQ "StartPending") {
        sc.exe delete ovs-vswitchd
        stop-service ovsdb-server

        Remove-Item -Path $OVS_PID_PATH -Force
        Remove-Item -Path "$OVSDB_CONF_DIR\*"
        ovsdb-tool create "$OVS_DB_PATH" "$OVS_DB_SCHEMA_PATH"

        start-service ovsdb-server
        sc.exe create ovs-vswitchd binpath="$OVSInstallDir\usr\sbin\ovs-vswitchd.exe  --pidfile -vfile:info --log-file  --service" start= auto depend= "ovsdb-server"
        sc.exe failure ovs-vswitchd reset= 0 actions= restart/0/restart/0/restart/0
        start-service ovs-vswitchd
    }
}

function RemoveNetworkAdapter($adapterName) {
    $adapter = $(Get-NetAdapter "$adapterName" -ErrorAction Ignore)
    if ($adapter -ne $null) {
        Remove-NetIPAddress -IfAlias $adapterName -Confirm:$false
        Write-Host "Network adapter $adapter.Name is left on the Windows host with status $adapter.Status, please remove it manually."
    }
}

function RemoveHiddenNetDevices() {
    $Devs = $(Get-PnpDevice -Class net | ? Status -eq Unknown | Select InstanceId)
    foreach ($Dev in $Devs) {
        $RemoveKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($Dev.InstanceId)"
        Get-Item $RemoveKey | Select-Object -ExpandProperty Property | %{Remove-ItemProperty -Path $RemoveKey -Name $_ -Verbose }
    }
}

function clearOVSBridge() {
    $ovsStatus = $(Get-Service ovs-vswitchd).Status
    if ("$ovsStatus" -EQ "running") {
        Write-Host "Delete OVS bridge: br-int"
        ovs-vsctl.exe --no-wait --if-exists del-br br-int
        $MaxRetryCount = 10
        $RetryCountRange = 1..$MaxRetryCount
        $BrIntDeleted = $false
        foreach ($RetryCount in $RetryCountRange) {
            Write-Host "Waiting for OVS bridge deletion complete ($RetryCount/$MaxRetryCount)..."
            $BrIntAdapter = $(Get-NetAdapter "$OVS_BR_ADAPTER" -ErrorAction SilentlyContinue)
            if ($BrIntAdapter -eq $null) {
                $BrIntDeleted = $true
                break
            }
            if ($RetryCount -eq $MaxRetryCount) {
                break
            }
            Start-Sleep -Seconds 5
        }
        if (!$BrIntDeleted) {
            Write-Host "Failed to delete OVS Bridge, please retry the script or delete the bridge and HNS network manually."
            return
        }
    }
}

$BrIntDeleted = $(Get-NetAdapter "$OVS_BR_ADAPTER") -Eq $null
if ($BrIntDeleted -eq $false) {
    clearOVSBridge
}
$uplink = ""
$AntreaHnsNetworkName = "antrea-hnsnetwork"
$NetId = GetHnsnetworkId($AntreaHnsNetworkName)
if ($NetId -ne $null) {
    Write-Host "Remove HnsNetwork: $AntreaHnsNetworkName"
    $uplink = $(Get-HnsNetwork -Id $NetId).NetworkAdapterName
    Get-HnsNetwork -Id $NetId | Remove-HnsNetwork
}

# ResetOVSService is called if the Windows Service "ovs-vswitchd" is not running correctly (Service status is StartPending).
# This might happen after the Windows host is restarted abnormally, in which case some stale configurations block
# ovs-vswitchd running, like the pid file and the misconfigurations in OVSDB.
ResetOVSService "ovs-vswitchd"
RemoveNetworkAdapter $OVS_BR_ADAPTER
RemoveNetworkAdapter "antrea-gw0"
ClearHyperVBindingOnAdapter($uplink)
if ($RenewIPConfig) {
    ipconfig /renew
}

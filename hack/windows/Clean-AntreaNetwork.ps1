<#
  .SYNOPSIS
  Clean OVS bridge and HnsNetwork created by Antrea Agent

  .PARAMETER OVSInstallDir
  OVS installation directory. It is the path argument when using Install-OVS.ps1. The default path is "C:\openvswitch".
  .PARAMETER RenewIPConfig
  Renew the ipconfig on the host. The default value is $false.
  .PARAMETER RemoveOVS
  Remove ovsdb-server and ovs-vswitchd services fom the host. The default value is $false. If this argument is set
  as true, this script would remove the two Windows services from the host. Otherwise, we consider that these
  services are supposed to be running on the host, so the script would try to recover them if their statuses are
  not as expected. The parameter is ignored when OVSRunMode is "container".
  .PARAMETER OVSRunMode
  OVS run mode can be <container> if OVS userspace processes were running inside a container in antrea-agent Pod 
  or <service> if OVS userspace processes were running as a Service on host. Default mode is <service>.
#>
Param(
    [parameter(Mandatory = $false)] [string] $OVSInstallDir = "C:\openvswitch",
    [parameter(Mandatory = $false)] [bool] $RenewIPConfig   = $false,
    [parameter(Mandatory = $false)] [bool] $RemoveOVS       = $false,
    [parameter(Mandatory = $false)] [ValidateSet("service", "container")] [string] $OVSRunMode = "service"
)
$ErrorActionPreference = 'Stop'

# Replace the path using the actual path where ovs-vswitchd.pid locates. It is always under path $OVSInstallDir\var\run\openvswitch.
$OVS_PID_PATH = "$OVSInstallDir\var\run\openvswitch\ovs-vswitchd.pid"
$OVS_DB_SCHEMA_PATH = "$OVSInstallDir\usr\share\openvswitch\vswitch.ovsschema"
# Replace the path using the actual path where OVS conf.db locates. It is always under path OVSInstallDir\etc\openvswitch.
$OVSDB_CONF_DIR = "$OVSInstallDir\etc\openvswitch"
$OVS_DB_PATH = "$OVSDB_CONF_DIR\conf.db"
$OVS_BR_ADAPTER = "br-int"
$AntreaHnsNetworkName = "antrea-hnsnetwork"

function RemoveOVSService() {
    $ovsSvc = Get-Service ovs-vswitchd -ErrorAction SilentlyContinue
    if ($ovsSvc -ne $null ) {
        stop-service ovs-vswitchd
        sc.exe delete ovs-vswitchd
    }
    $ovsdbSvc = Get-Service ovsdb-server -ErrorAction SilentlyContinue
    if ($ovsdbSvc -ne $null ) {
        stop-service ovsdb-server
        sc.exe delete ovsdb-server
    }
}

function ResetOVSService() {
    $ovsdbSvc = Get-Service ovsdb-server -ErrorAction Ignore
    if ($ovsdbSvc -EQ $null) {
        CreateStartOVSDB
    }
    $ovsVswitchdSvc = Get-Service ovs-vswitchd -ErrorAction Ignore
    if ($ovsVswitchdSvc -EQ $null) {
        CreateStartOVSvSwitchd
        return
    }
    $ovsStatus = $(Get-Service ovs-vswitchd).Status
    if ("$ovsStatus" -ne "Running") {
        sc.exe delete ovs-vswitchd
        stop-service ovsdb-server

        Remove-Item -Path $OVS_PID_PATH -Force
        Remove-Item -Path "$OVSDB_CONF_DIR\*"
        ovsdb-tool create "$OVS_DB_PATH" "$OVS_DB_SCHEMA_PATH"

        start-service ovsdb-server
        CreateStartOVSvSwitchd
    }
}

function CreateStartOVSDB() {
    $OVS_DB_SCHEMA_PATH = "$OVSInstallDir\usr\share\openvswitch\vswitch.ovsschema"
    $OVS_DB_PATH = "$OVSInstallDir\etc\openvswitch\conf.db"
    if ($(Test-Path $OVS_DB_SCHEMA_PATH) -and !$(Test-Path $OVS_DB_PATH)) {
        ovsdb-tool create "$OVS_DB_PATH" "$OVS_DB_SCHEMA_PATH"
    }
    sc.exe create ovsdb-server binPath= "$OVSInstallDir\usr\sbin\ovsdb-server.exe $OVSInstallDir\etc\openvswitch\conf.db  -vfile:info --remote=punix:db.sock  --remote=ptcp:6640  --log-file  --pidfile --service" start= auto
    sc.exe failure ovsdb-server reset= 0 actions= restart/0/restart/0/restart/0
    Start-Service ovsdb-server
}

function CreateStartOVSvSwitchd() {
    sc.exe create ovs-vswitchd binpath="$OVSInstallDir\usr\sbin\ovs-vswitchd.exe  --pidfile -vfile:info --log-file  --service" start= auto depend= "ovsdb-server"
    sc.exe failure ovs-vswitchd reset= 0 actions= restart/0/restart/0/restart/0
    start-service ovs-vswitchd
    $OVS_VERSION=$(Get-Item $OVSInstallDir\driver\OVSExt.sys).VersionInfo.ProductVersion
    ovs-vsctl --no-wait set Open_vSwitch . ovs_version=$OVS_VERSION
}

function clearOVSBridge() {
    $ovsdbService =  Get-Service ovsdb-server -ErrorAction SilentlyContinue
    if ( $ovsdbService -ne $null -and $ovsdbService.Status -eq "Running") {
        Write-Host "Delete OVS bridge from OVSDB: br-int"
        ovs-vsctl.exe --no-wait --if-exists del-br $OVS_BR_ADAPTER
    }
}

function ClearHnsNetwork() {
    $vmSwitch = Get-VMSwitch -Name $AntreaHnsNetworkName -ErrorAction SilentlyContinue
    if ($vmSwitch -ne $null) {
        Write-Host "Remove vNICs"
        Remove-VMNetworkAdapter -SwitchName $AntreaHnsNetworkName -ManagementOS -Confirm:$false -ErrorAction SilentlyContinue
        $hnsNetwork = Get-HnsNetwork | Where-Object {$_.Name -eq $AntreaHnsNetworkName}
        if ($hnsNetwork -ne $null) {
            Write-Host "Remove HnsNetwork: $AntreaHnsNetworkName"
            $uplink = $hnsNetwork.NetworkAdapterName
            Get-HnsNetwork -Id $hnsNetwork.Id | Remove-HnsNetwork -ErrorAction Continue
            Set-NetAdapterBinding -Name $uplink -ComponentID vms_pp -Enabled $false
        }
        Remove-VMSwitch -Name $AntreaHnsNetworkName -Force -ErrorAction SilentlyContinue
    }
}

clearOVSBridge
ClearHnsNetwork
switch ($OVSRunMode) 
{
    "service" {
        if ($RemoveOVS) {
            RemoveOVSService
        } else {
            # ResetOVSService is called to recover Windows Services "ovsdb-server" and "ovs-vswitchd" if they are removed
            # unexpectedly or their status is not correct, e.g., ovs-vswitchd fails to go into Running.
            # This might happen after the Windows host is restarted abnormally, in which case some stale configurations
            # can prevent ovs-vswitchd from running, like a stale pid file or misconfigurations in OVSDB.
            ResetOVSService
        }
    }
    "container" {
        if (Test-Path -Path $OVS_DB_PATH) {
            Remove-Item -Path $OVS_DB_PATH -Force
        }
    }
}

if ($RenewIPConfig) {
    ipconfig /renew
}

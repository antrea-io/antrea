Param(
    [parameter(Mandatory = $false)] [string] $OVSInstallDir = "C:\openvswitch",
    [parameter(Mandatory = $false)] [switch] $RemoveDir = $false,
    [parameter(Mandatory = $false)] [switch] $DeleteBridges = $false
)

$ErrorActionPreference = "Continue"
$usrBinPath="$OVSInstallDir\usr\bin"
if ($DeleteBridges) {
    $ovsDbSock="$OVSInstallDir\var\run\openvswitch\db.sock"
    if ((Test-Path $usrBinPath) -and (Test-Path $ovsDbSock)){
        $env:Path="$env:Path;$usrBinPath"
        $brList = ovs-vsctl.exe list-br
        foreach ($br in $brList) {
            Write-Host "Delete OVS Bridge: %s $br"
            ovs-vsctl.exe --no-wait del-br $br
        }
    }
}

# Stop and delete ovs-vswitchd service if it exists
if (Get-Service ovs-vswitchd -ErrorAction SilentlyContinue) {
    stop-service ovs-vswitchd
    sc.exe delete ovs-vswitchd
    if (Get-Service ovs-vswitchd -ErrorAction SilentlyContinue) {
        Write-Host "Failed to delete ovs-vswitchd service, exit."
        exit 1
    }
}

# Stop and delete ovsdb-service service if it exists
if (Get-Service ovsdb-server -ErrorAction SilentlyContinue) {
    stop-service ovsdb-server
    sc.exe delete ovsdb-server
    if (Get-Service ovsdb-server -ErrorAction SilentlyContinue) {
        Write-Host "Failed to delete ovs-vswitchd service, exit."
        exit 1
    }
}
# Uninstall OVS kernel driver
$ovsInstalled = $(netcfg -q ovsext) -like "*is installed*"
if ($ovsInstalled) {
    netcfg -u ovsext
}
if (!$?) {
    Write-Host "Failed to uninstall OVS kernel driver."
    exit 1
}

# Remove OVS installation dir
if ($RemoveDir -and (Test-Path $OVSInstallDir)) {
    Remove-Item -Recurse $OVSInstallDir
    if (!$?) {
        Write-Host "Failed to remove OVS dir: $OVSInstallDir."
        exit 1
    }
}

# Remove OVS bin paths from environment variables.
$envPaths = @()
$usrSbinPath="$OVSInstallDir\usr\sbin"
foreach ($item in $($env:Path -split ";" | Select-Object -Unique)) {
    if (($item -ne "$usrBinPath") -and ($item -ne "$usrSbinPath")) {
        $envPaths += $item
    }
}
$env:Path =$envPaths -join ";"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)

Write-Host "Uninstall OVS success."

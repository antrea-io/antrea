<#
  .SYNOPSIS
  Installs Antrea-Agent service.

  .PARAMETER NameSpace
  ExternalNode Namespace to be used.

  .PARAMETER BinaryPath
  Specifies the path of the antrea-agent binary to be used.

  .PARAMETER ConfigPath
  Specifies the path of the antrea-agent configuration file to be used.

  .PARAMETER KubeConfigPath
  Specifies the path of the kubeconfig to access K8s API Server.

  .PARAMETER AntreaKubeConfigPath
  Specifies the path of the kubeconfig to access Antrea API Server.

  .PARAMETER InstallDir
  The target installation directory. The default path is "C:\antrea-agent".
#>
Param(
    [parameter(Mandatory = $true)] [string] $NameSpace,
    [parameter(Mandatory = $true)] [string] $BinaryPath,
    [parameter(Mandatory = $true)] [string] $ConfigPath,
    [parameter(Mandatory = $true)] [string] $KubeConfigPath,
    [parameter(Mandatory = $true)] [string] $AntreaKubeConfigPath,
    [parameter(Mandatory = $false)] [string] $NodeName = $env:COMPUTERNAME,
    [parameter(Mandatory = $false)] [string] $InstallDir = "C:\antrea-agent"
)

$ErrorActionPreference = "Stop"

$WorkDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
$InstallLog = "$WorkDir\install_vm.log"

# Antrea paths
$AntreaAgentPath = [io.path]::combine($InstallDir, "antrea-agent.exe")
$AntreaAgentConfDir = [io.path]::combine($InstallDir, "conf")
$AntreaAgentLogDir = [io.path]::combine($InstallDir, "logs")
$AntreaAgentConfPath = [io.path]::combine($AntreaAgentConfDir, "antrea-agent.conf")
$AntreaAgentLogFile = [io.path]::combine($AntreaAgentLogDir, "antrea-agent.log")

# Constants
$K8sKubeconfig = "antrea-agent.kubeconfig"
$AntreaKubeconfig = "antrea-agent.antrea.kubeconfig"
$OVSServices = "ovsdb-server", "ovs-vswitchd"
$AntreaAgent = "antrea-agent"
$Kubeconfig = "kubeconfig"
$ExternalNodeNamespace = "externalNodeNamespace"

function Log($Info) {
    $time = $(get-date -Format g)
    "$time $Info " | Tee-Object $InstallLog -Append | Write-Host
}

function ServiceExists($ServiceName) {
    If (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        return $true
    }
    return $false
}

function CheckSupportedVersions() {
    $script:OS_VERSION = [System.Environment]::OSVersion.Version
    if (-Not ($OS_VERSION.Major -eq 10 -and $OS_VERSION.Minor -eq 0 -and $OS_VERSION.Build -ge 17763)) {
        Log "Error only Windows version 10 build 17763 onwards is supported"
        exit 1
    }
}

function PrintPrerequisites()
{
    echo "Please execute these commands to enable Hyper-V"
    echo "Install-WindowsFeature Hyper-V-Powershell"
    echo "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart"
    exit 1
}

function CheckPrerequisites()
{
    CheckSupportedVersions
    $valid = $true
    Log "Check Hyper-v feature is enabled"
    if ((Get-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V" -Online).State -eq "Disabled") {
        Log "Windows optional feature Microsoft-Hyper-V is disabled"
        $valid = $false
    }

    if ((Get-WindowsFeature -Name "Hyper-V-Powershell").InstallState -ne "Installed") {
        Log "Windows feature Hyper-V-Powershell is not installed"
        $valid = $false
    }

    if ($valid -eq $false) {
        PrintPrerequisites
    }

    Log "Check OVS services are installed"
    foreach ($daemon in $OVSServices) {
        If (-Not (ServiceExists($daemon))) {
            Log "Service $daemon does not exist."
            exit 1
        }
    }
}

function SetupInstallDir() {
    Log "Create install directories"
    if (-Not (Test-Path $AntreaAgentConfDir)) {
        New-Item $AntreaAgentConfDir -type directory -Force | Out-Null
    }

    if (-Not (Test-Path $AntreaAgentLogDir)) {
        New-Item $AntreaAgentLogDir -type directory -Force | Out-Null
    }
}

function CopyAntreaAgentFiles() {
    if ( -Not (Test-Path $BinaryPath)) {
        Log "$BinaryPath file not found"
        exit 1
    }
    Log "Copying $BinaryPath to $InstallDir"
    Copy-Item -Path "$BinaryPath" -Destination $InstallDir -Force |  Out-Null

    if ( -Not (Test-Path $KubeConfigPath)) {
        Log "$KubeConfigPath file not found"
        exit 1
    }
    Log "Copying $KubeConfigPath to $AntreaAgentConfDir"
    Copy-Item -Path "$KubeConfigPath" -Destination "$AntreaAgentConfDir\$K8sKubeconfig" -Force

    if ( -Not (Test-Path $AntreaKubeConfigPath)) {
        Log "$AntreaKubeConfigPath file not found"
        exit 1
    }
    Log "Copying $AntreaKubeConfigPath to $AntreaAgentConfDir"
    Copy-Item -Path "$AntreaKubeConfigPath" -Destination "$AntreaAgentConfDir\$AntreaKubeconfig" -Force
}

function UpdateAgentConf() {
    if ( -Not (Test-Path $ConfigPath)) {
        Log "$ConfigPath file not found"
        exit 1
    }
    New-Item $AntreaAgentConfPath -type file -Force | Out-Null
    $file = Get-Content $ConfigPath
    foreach ($line in $file) {
        if ($line -like "*$Kubeconfig") {
            $key, $val = $line.split(":", 2).trim()
            $newval = "${AntreaAgentConfDir}\${val}"
            Log "Updating $AntreaAgentConfPath with ${key}: ${newval}"
            [System.IO.File]::AppendAllText($AntreaAgentConfPath, "  ${key}: ${newval}" +
                    ([Environment]::NewLine))
        } elseif ($line -like "*$ExternalNodeNamespace*") {
            Log "Updating $AntreaAgentConfPath with ${ExternalNodeNamespace}: ${NameSpace}"
            [System.IO.File]::AppendAllText($AntreaAgentConfPath, "  ${ExternalNodeNamespace}: ${NameSpace}" +
                    ([Environment]::NewLine))
        } else {
            [System.IO.File]::AppendAllText($AntreaAgentConfPath, $line +
                    ([Environment]::NewLine))
        }
    }
}

function ConfigureAntreaAgentService() {
    # Set environment variables
    [Environment]::SetEnvironmentVariable("NODE_NAME", $NodeName, [System.EnvironmentVariableTarget]::Machine)
    # Assume nssm is installed and configure service
    $AntreaAgentArgs = "--config $AntreaAgentConfPath --log_file $AntreaAgentLogFile --logtostderr=false"
    log "Creating service $AntreaAgent $AntreaAgentPath $AntreaAgentArgs"
    try {
        # Configured to auto-restart upon reboot
        & nssm install $AntreaAgent $AntreaAgentPath $AntreaAgentArgs
    } catch {
        log "Failed to create service for $AntreaAgent, rc $_"
        exit 1
    }
}

function StartAntreaAgentService()
{
    try {
        & nssm start $AntreaAgent
    } catch {
        log "Failed to start service for $AntreaAgent, rc $_"
        exit 1
    }
}

CheckPrerequisites
SetupInstallDir
CopyAntreaAgentFiles
UpdateAgentConf
ConfigureAntreaAgentService
StartAntreaAgentService

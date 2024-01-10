<#
.SYNOPSIS
(Test Only)Assists with preparing a Windows VM prior to calling kubeadm join

.DESCRIPTION
This script is only used for test to assist with joining a Windows node to a cluster.
For production environment please follow the antrea windows installation guide and use Kubernetes official PrepareNode.ps1
script from the sig-windows-tools repo release page: https://github.com/kubernetes-sigs/sig-windows-tools/releases
- Downloads Kubernetes binaries (kubelet, kubeadm) at the version specified
- Registers wins as a service in order to run kube-proxy and antrea-agent as DaemonSets.
- Registers kubelet as an nssm service. More info on nssm: https://nssm.cc/
- Adds node ip in kubelet startup params.
- (Optional) Create virtual netadapter for kube-proxy.
- (Optional) Installs OVS kerner driver, userspace binaries. Registers ovsdb-server and ovs-vswitchd services.

.PARAMETER KubernetesVersion
Kubernetes version to download and use

.PARAMETER InstallKubeProxy
Install kube-proxy

.PARAMETER InstallOVS
Install OVS

.PARAMETER NodeIP
The node ip used by kubelet

.PARAMETER ContainerRuntime
Container runtime that Kubernetes will use. (docker or containerd)

.PARAMETER InstallOVSUserspace
Specifies whether OVS userspace processes are included in the installation. If false, these processes will not 
be installed as a Windows service on the host.

.EXAMPLE
PS> .\Prepare-Node.ps1 -KubernetesVersion v1.27.0 -NodeIP 192.168.1.10 -ContainerRuntime containerd 

#>

Param(
    [parameter(Mandatory = $false, HelpMessage="Kubernetes version to use")] [string] $KubernetesVersion="v1.18.0",
    [parameter(Mandatory = $true, HelpMessage="Node IP")] [string] $NodeIP,
    [parameter(Mandatory = $false)] [switch] $InstallKubeProxy = $false,
    [parameter(Mandatory = $false)] [switch] $InstallOVS = $false,
    [parameter(Mandatory = $false, HelpMessage="Kubernetes download")] [string] $KubernetesURL="dl.k8s.io",
    [parameter(HelpMessage="Container runtime that Kubernets will use")] [ValidateSet("containerd", "docker")] [string] $ContainerRuntime = "containerd",
    [parameter(Mandatory = $false)] [bool] $InstallOVSUserspace = $true 
)
$ErrorActionPreference = 'Stop'

function DownloadFile($destination, $source) {
    Write-Host("Downloading $source to $destination")
    curl.exe --silent --fail -Lo $destination $source

    if (!$?) {
        Write-Error "Download $source failed"
        exit 1
    }
}

If (Get-Service kubelet -ErrorAction SilentlyContinue) {
    Write-Host("Found existing kubelet service, exit.")
    exit 0
}

if ($ContainerRuntime -eq "docker") {
    if (-not(Test-Path "//./pipe/docker_engine")) {
        Write-Error "Docker service was not detected - please install and start Docker before calling Prepare-Node.ps1 with -ContainerRuntime docker"
        exit 1
    }
} elseif ($ContainerRuntime -eq "containerd") {
    if (-not(Test-Path "//./pipe/containerd-containerd")) {
        Write-Error "Containerd service was not detected - please install and start Containerd before calling Prepare-Node.ps1 with -ContainerRuntime containerd"
        exit 1
    }
}

if (!$KubernetesVersion.StartsWith("v")) {
    $KubernetesVersion = "v" + $KubernetesVersion
}
Write-Host "Using Kubernetes version: $KubernetesVersion"
$global:Powershell = (Get-Command powershell).Source
$global:PowershellArgs = "-ExecutionPolicy Bypass -NoProfile"
$global:KubernetesPath = "$env:SystemDrive\k"
$global:StartKubeletScript = "$global:KubernetesPath\StartKubelet.ps1"
$global:NssmInstallDirectory = "$env:ProgramFiles\nssm"
$kubeletBinPath = "$global:KubernetesPath\kubelet.exe"

mkdir -force "$global:KubernetesPath"
$env:Path += ";$global:KubernetesPath"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable("NODE_IP", $NodeIP, [System.EnvironmentVariableTarget]::Machine)

DownloadFile $kubeletBinPath "https:/$KubernetesURL/$KubernetesVersion/bin/windows/amd64/kubelet.exe"
DownloadFile "$global:KubernetesPath\kubeadm.exe" "https:/$KubernetesURL/$KubernetesVersion/bin/windows/amd64/kubeadm.exe"

if ($ContainerRuntime -eq "docker") {
    Write-Host "Registering wins service"
    DownloadFile "$global:KubernetesPath\wins.exe" https://github.com/rancher/wins/releases/download/v0.0.4/wins.exe
    wins.exe srv app run --register
    start-service rancher-wins
}


mkdir -force C:\var\log\kubelet
mkdir -force C:\var\lib\kubelet\etc\kubernetes
mkdir -force C:\etc\kubernetes\pki
New-Item -path C:\var\lib\kubelet\etc\kubernetes\pki -type SymbolicLink -value C:\etc\kubernetes\pki\


$StartKubeletFileContent = '$FileContent = Get-Content -Path "/var/lib/kubelet/kubeadm-flags.env"
$global:KubeletArgs = $FileContent.Trim("KUBELET_KUBEADM_ARGS=`"")'+ [Environment]::NewLine

if ($ContainerRuntime -eq "docker") {
    $StartKubeletFileContent +=[Environment]::NewLine +'$netId = docker network ls -f name=host --format "{{ .ID }}"

if ($netId.Length -lt 1) {
    docker network create -d nat host
}' + [Environment]::NewLine
}

if ($InstallKubeProxy) {
    $StartKubeletFileContent += [Environment]::NewLine + '& C:\k\Prepare-ServiceInterface.ps1 -InterfaceAlias "HNS Internal NIC"' + [Environment]::NewLine
}

$StartKubeletFileContent += [Environment]::NewLine + '$global:KubeletArgs += " --cert-dir=$env:SYSTEMDRIVE\var\lib\kubelet\pki --config=/var/lib/kubelet/config.yaml --bootstrap-kubeconfig=/etc/kubernetes/bootstrap-kubelet.conf --kubeconfig=/etc/kubernetes/kubelet.conf --hostname-override=$(hostname) --pod-infra-container-image=`"mcr.microsoft.com/oss/kubernetes/pause:1.4.1`" --enable-debugging-handlers --cgroups-per-qos=false --enforce-node-allocatable=`"`" --resolv-conf=`"`" --node-ip=$env:NODE_IP"'

$targetVersion = [version]"1.28.0"

if ($ContainerRuntime -eq "containerd" -and [version]($KubernetesVersion -replace '^v') -lt $targetVersion) {
    $StartKubeletFileContent += [Environment]::NewLine + '$global:KubeletArgs += " --feature-gates=WindowsHostProcessContainers=true"'
}

$StartKubeletFileContent += [Environment]::NewLine + '$cmd = "C:\k\kubelet.exe $global:KubeletArgs"
Invoke-Expression $cmd'

Set-Content -Path $global:StartKubeletScript -Value $StartKubeletFileContent

Write-Host "Installing nssm"
$arch = "win32"
if ([Environment]::Is64BitOperatingSystem) {
    $arch = "win64"
}

mkdir -Force $global:NssmInstallDirectory
DownloadFile nssm.zip https://k8stestinfrabinaries.blob.core.windows.net/nssm-mirror/nssm-2.24.zip
C:\Windows\system32\tar.exe C $global:NssmInstallDirectory -xvf .\nssm.zip --strip-components 2 */$arch/*.exe
Remove-Item -Force .\nssm.zip

$env:path += ";$global:NssmInstallDirectory"
$newPath = "$global:NssmInstallDirectory;" +
[Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::Machine)

[Environment]::SetEnvironmentVariable("PATH", $newPath, [EnvironmentVariableTarget]::Machine)

Write-Host "Registering kubelet service"
nssm install kubelet $global:Powershell $global:PowershellArgs $global:StartKubeletScript

nssm set kubelet DependOnService $ContainerRuntime

New-NetFirewallRule -Name kubelet -DisplayName 'kubelet' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 10250

if ($InstallKubeProxy) {
    # Create netadapter for kube-proxy, the default full name of the adapter is "vEthernet (HNS Internal NIC)"
    & ./Prepare-ServiceInterface.ps1
}

if ($InstallOVS) {
    Write-Host "Installing OVS"
    & .\Install-OVS.ps1 -InstallUserspace $InstallOVSUserspace
}

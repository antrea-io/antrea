<#
  .SYNOPSIS
  Installs Windows OpenvSwitch from a web location or local file.

  .PARAMETER DownloadURL
  The URL of the OpenvSwitch package to be downloaded.

  .PARAMETER DownloadDir
  The path of the directory to be used to download OpenvSwitch package. The default path is the working directory.

  .PARAMETER OVSInstallDir
  The target installation directory. The default path is "C:\openvswitch".

  .PARAMETER CheckFileHash
  Skips checking file hash. The default value is true.

  .PARAMETER LocalFile
  Specifies the path of a local OpenvSwitch package to be used for installation.
  When the param is used, "DownloadURL" and "DownloadDir" params will be ignored.

  .PARAMETER ImportCertificate
  Specifies if a certificate file is needed for OVS package. If true, certificate
  will be retrieved from OVSExt.sys and a package.cer file will be generated.
#>
Param(
    [parameter(Mandatory = $false)] [string] $DownloadDir,
    [parameter(Mandatory = $false)] [string] $DownloadURL,
    [parameter(Mandatory = $false)] [string] $OVSInstallDir = "C:\openvswitch",
    [parameter(Mandatory = $false)] [bool] $CheckFileHash = $true,
    [parameter(Mandatory = $false)] [string] $LocalFile,
    [parameter(Mandatory = $false)] [bool] $ImportCertificate = $true
)

$ErrorActionPreference = "Stop"
$OVSDownloadURL = "https://downloads.antrea.io/ovs/ovs-2.14.2-antrea.1-win64.zip"
# Use a SHA256 hash to ensure that the downloaded archive is correct.
$OVSPublishedHash = '98f0b1cf051b8ad46d736b5b493a750c14db97ec031bde8f5193ad114b765b39'
$WorkDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
$OVSDownloadDir = $WorkDir
$PowerShellModuleBase = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"

if (!$LocalFile) {
    $OVSZip = "$OVSDownloadDir\ovs-win64.zip"
} else {
    $OVSZip = $LocalFile
    $DownloadDir = Split-Path -Path $LocalFile
}

if ($DownloadDir -ne "") {
    $OVSDownloadDir = $DownloadDir
}

$InstallLog = "$OVSDownloadDir\install_ovs.log"

if ($DownloadURL -ne "") {
    $OVSDownloadURL = $DownloadURL
    # For user-provided URLs, do not verify the hash for the archive.
    $OVSPublishedHash = ""
}

function Log($Info) {
    $time = $(get-date -Format g)
    "$time $Info `n`r" | Tee-Object $InstallLog -Append | Write-Host
}

function CreatePath($Path){
    if ($(Test-Path $Path)) {
        mv $Path $($Path + "_bak")
    }
    mkdir -p $Path | Out-Null
}

function SetEnvVar($key, $value) {
    [Environment]::SetEnvironmentVariable($key, $value, [EnvironmentVariableTarget]::Machine)
}

function WaitExpandFiles($Src, $Dest) {
    Log "Extract $Src to $Dest"
    Expand-Archive -Path $Src -DestinationPath $Dest | Out-Null
}

function ServiceExists($ServiceName) {
    If (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        return $true
    }
    return $false
}

function CheckIfOVSInstalled() {
    if (Test-Path -Path $OVSInstallDir) {
        Log "$OVSInstallDir already exists, exit OVS installation."
        exit 1
    }
    If (ServiceExists("ovs-vswitchd")) {
        Log "Found existing OVS service, exit OVS installation."
        exit 0
    }
}

function DownloadOVS() {
    if ($LocalFile -ne "") {
        Log "Skipping OVS download, using local file: $LocalFile"
        return
    }

    If (!(Test-Path $OVSDownloadDir)) {
        mkdir -p $OVSDownloadDir
    }
    Log "Downloading OVS package from $OVSDownloadURL to $OVSZip"
    curl.exe -sLo $OVSZip $OVSDownloadURL
    If (!$?) {
        Log "Download OVS failed, URL: $OVSDownloadURL"
        exit 1
    }

    if ($CheckFileHash) {
        $FileHash = Get-FileHash $OVSZip
        If ($OVSPublishedHash -ne "" -And $FileHash.Hash -ne $OVSPublishedHash) {
            Log "SHA256 mismatch for OVS download"
            exit 1
        }
    }

    Log "Download OVS package success."
}

function InstallOVS() {
    # unzip OVS.
    WaitExpandFiles $OVSZip $OVSDownloadDir
    # Copy OVS package to target dir.
    Log "Copying OVS package from $OVSDownloadDir\openvswitch to $OVSInstallDir"
    mv "$OVSDownloadDir\openvswitch" $OVSInstallDir
    if (!$LocalFile) {
        rm $OVSZip
    }
    # Create log and run dir.
    $OVS_LOG_PATH = $OVSInstallDir + "\var\log\openvswitch"
    CreatePath $OVS_LOG_PATH
    $OVSRunDir = $OVSInstallDir + "\var\run\openvswitch"
    CreatePath $OVSRunDir
    $OVSDriverDir = "$OVSInstallDir\driver"

    # Install OVS driver certificate.
    $DriverFile="$OVSDriverDir\OVSExt.sys"
    if ($ImportCertificate) {
        $CertificateFile = "$OVSDriverDir\package.cer"
        if (!(Test-Path $CertificateFile)) {
            $ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
            $Cert = (Get-AuthenticodeSignature $DriverFile).SignerCertificate;
            [System.IO.File]::WriteAllBytes($CertificateFile, $Cert.Export($ExportType));
        }
        Log "Installing OVS driver certificate."
        Import-Certificate -FilePath "$CertificateFile" -CertStoreLocation cert:\LocalMachine\TrustedPublisher
        Import-Certificate -FilePath "$CertificateFile" -CertStoreLocation cert:\LocalMachine\Root
    }

    # Install Microsoft Visual C++ Redistributable Package.
    if (Test-Path $OVSInstallDir\redist) {
        Log "Installing Microsoft Visual C++ Redistributable Package."
        $RedistFiles = Get-ChildItem "$OVSInstallDir\redist" -Filter *.exe
        $RedistFiles | ForEach-Object {
            Log "Installing $_"
            Start-Process -FilePath $_.FullName -Args '/install /passive /norestart' -Verb RunAs -Wait
        }
    }

    # Install powershell modules
    if (Test-Path $OVSInstallDir\scripts) {
        Log "Installing powershell modules."
        $PSModuleFiles = Get-ChildItem "$OVSInstallDir\scripts" -Filter *.psm1
        $PSModuleFiles | ForEach-Object {
            $PSModulePath = Join-Path -Path $PowerShellModuleBase -ChildPath $_.BaseName
            if (!(Test-Path $PSModulePath)) {
                Log "Installing $_"
                mkdir -p $PSModulePath
                Copy-Item $_.FullName $PSModulePath
            }
        }
    }

    # Install OVS kernel driver.
    Log "Installing OVS kernel driver"
    $VMMSStatus = $(Get-Service vmms -ErrorAction SilentlyContinue).Status
    if (!$VMMSStatus) {
        $VMMSStatus = "not exist"
    }
    Log "Hyper-V Virtual Machine Management service status: $VMMSStatus"
    if ($VMMSStatus -eq "Running") {
        cmd /c "cd $OVSDriverDir && install.cmd"
    } else {
        cd $OVSDriverDir ; netcfg -l .\ovsext.inf -c s -i OVSExt; cd $WorkDir
    }
    if (!$?) {
        Log "Install OVS kernel driver failed, exit"
        exit 1
    }
    $OVS_BIN_PATH="$OVSInstallDir\usr\bin;$OVSInstallDir\usr\sbin"
    $env:Path += ";$OVS_BIN_PATH"
    SetEnvVar "Path" $env:Path
}

function ConfigOVS() {
    # Create ovsdb config file
    $OVS_DB_SCHEMA_PATH = "$OVSInstallDir\usr\share\openvswitch\vswitch.ovsschema"
    $OVS_DB_PATH = "$OVSInstallDir\etc\openvswitch\conf.db"
    if ($(Test-Path $OVS_DB_SCHEMA_PATH) -and !$(Test-Path $OVS_DB_PATH)) {
        Log "Creating ovsdb file"
        ovsdb-tool create "$OVS_DB_PATH" "$OVS_DB_SCHEMA_PATH"
    }
    # Create and start ovsdb-server service.
    Log "Create and start ovsdb-server service"
    sc.exe create ovsdb-server binPath= "$OVSInstallDir\usr\sbin\ovsdb-server.exe $OVSInstallDir\etc\openvswitch\conf.db  -vfile:info --remote=punix:db.sock  --remote=ptcp:6640  --log-file  --pidfile --service" start= auto
    sc.exe failure ovsdb-server reset= 0 actions= restart/0/restart/0/restart/0
    Start-Service ovsdb-server
    # Create and start ovs-vswitchd service.
    Log "Create and start ovs-vswitchd service."
    sc.exe create ovs-vswitchd binpath="$OVSInstallDir\usr\sbin\ovs-vswitchd.exe  --pidfile -vfile:info --log-file  --service" start= auto depend= "ovsdb-server"
    sc.exe failure ovs-vswitchd reset= 0 actions= restart/0/restart/0/restart/0
    Start-Service ovs-vswitchd
    # Set OVS version.
    $OVS_VERSION=$(Get-Item $OVSInstallDir\driver\OVSExt.sys).VersionInfo.ProductVersion
    Log "Set OVS version to: $OVS_VERSION"
    ovs-vsctl --no-wait set Open_vSwitch . ovs_version=$OVS_VERSION
}

Log "Installation log location: $InstallLog"

CheckIfOVSInstalled

DownloadOVS

InstallOVS

ConfigOVS

Log "OVS Installation Complete!"

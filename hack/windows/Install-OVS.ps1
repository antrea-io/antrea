Param(
    [parameter(Mandatory = $false)] [string] $DownloadDir,
    [parameter(Mandatory = $false)] [string] $DownloadURL,
    [parameter(Mandatory = $false)] [string] $OVSInstallDir = "C:\openvswitch"
)

$ErrorActionPreference = "Stop"
# TODO: set up HTTPS so that the archive can be downloaded securely. In the
# meantime, we use a SHA256 hash to ensure that the downloaded archive is
# correct.
$OVSDownloadURL = "http://downloads.antrea.io/ovs/ovs-2.14.0-antrea.1-win64.zip"
$OVSPublishedHash = 'E81800A6B8E157C948BAE548E5AFB425B2AD98CE18BC8C6148AB5B7F81E76B7D'
$OVSDownloadDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
$InstallLog = "$OVSDownloadDir\install.log"
$OVSZip = "$OVSDownloadDir\ovs-win64.zip"

if ($DownloadDir -ne "") {
    $OVSDownloadDir = $DownloadDir
    $InstallLog = "$OVSDownloadDir\install_ovs.log"
}

if ($DownloadURL -ne "") {
    $OVSDownloadURL = $DownloadURL
    # For user-provided URLs, do not verify the hash for the archive.
    $OVSPublishedHash = ""
}

function Log($Info) {
    $time = $(get-date -Format g)
    Write-Host "$time $Info `n`r" | Tee-Object $InstallLog -Append
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
    If (!(Test-Path $OVSDownloadDir)) {
        mkdir -p $OVSDownloadDir
    }
    Log "Downloading OVS package from $OVSDownloadURL to $OVSZip"
    curl.exe -sLo $OVSZip $OVSDownloadURL
    If (!$?) {
        Log "Download OVS failed, URL: $OVSDownloadURL"
        exit 1
    }
    $FileHash = Get-FileHash $OVSZip
    If ($OVSPublishedHash -ne "" -And $FileHash.Hash -ne $OVSPublishedHash) {
        Log "SHA256 mismatch for OVS download"
        exit 1
    }
    Log "Download OVS package success."
}

function InstallOVS() {
    # unzip OVS.
    WaitExpandFiles $OVSZip $OVSDownloadDir
    # Copy OVS package to target dir.
    Log "Copying OVS package from $OVSDownloadDir\openvswitch to $OVSInstallDir"
    mv "$OVSDownloadDir\openvswitch" $OVSInstallDir
    rm $OVSZip
    # Create log and run dir.
    $OVS_LOG_PATH = $OVSInstallDir + "\var\log\openvswitch"
    CreatePath $OVS_LOG_PATH
    $OVSRunDir = $OVSInstallDir + "\var\run\openvswitch"
    CreatePath $OVSRunDir
    # Install OVS driver certificate.
    Log "Installing OVS driver certificate."
    $OVSDriverDir = "$OVSInstallDir\driver"
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$OVSDriverDir\package.cer")
    $rootStore = Get-Item cert:\LocalMachine\TrustedPublisher
    $rootStore.Open("ReadWrite")
    $rootStore.Add($cert)
    $rootStore.Close()
    $rootStore = Get-Item cert:\LocalMachine\Root
    $rootStore.Open("ReadWrite")
    $rootStore.Add($cert)
    $rootStore.Close()
    # Install Microsoft Visual C++ 2010 Redistributable Package.
    Log "Installing Microsoft Visual C++ 2010 Redistributable Package."
    Start-Process -FilePath $OVSInstallDir/redist/vcredist_x64.exe -Args '/install /passive /norestart' -Verb RunAs -Wait
    # Install OVS kernel driver.
    Log "Installing OVS kernel driver"
    cmd /c "cd $OVSDriverDir && install.cmd"
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
    sc.exe create ovsdb-server binPath= "$OVSInstallDir\usr\sbin\ovsdb-server.exe $OVSInstallDir\etc\openvswitch\conf.db  -vfile:info --remote=punix:db.sock  --remote=ptcp:6640  --log-file  --pidfile --service --service-monitor" start= auto
    Start-Service ovsdb-server
    $MaxRetryCount = 10
    $RetryCountRange = 1..$MaxRetryCount
    $OVSDBServiceStarted = $false
    foreach ($RetryCount in $RetryCountRange) {
        Log "Waiting for ovsdb-server service start ($RetryCount/$MaxRetryCount)..."
        if (ServiceExists("ovsdb-server")) {
            $OVSDBServiceStarted = $true
            break
        }
        if ($RetryCount -eq $MaxRetryCount) {
            break
        }
        Start-Sleep -Seconds 5
    }
    if (!$OVSDBServiceStarted) {
        Log "Waiting for ovsdb-server service start timeout to set the OVS version."
        LOG "Please manually set the OVS version after installation."
    } else {
        # Set OVS version.
        Log "Set OVS version: $OVS_VERSION"
        $OVS_VERSION=$(Get-Item $OVSInstallDir\driver\ovsext.sys).VersionInfo.ProductVersion
        ovs-vsctl --no-wait set Open_vSwitch . ovs_version=$OVS_VERSION
    }

    # Create and start ovs-vswitchd service.
    Log "Create and start ovs-vswitchd service."
    sc.exe create ovs-vswitchd binpath="$OVSInstallDir\usr\sbin\ovs-vswitchd.exe  --pidfile -vfile:info --log-file  --service --service-monitor" start= auto
    Start-Service ovs-vswitchd
}

CheckIfOVSInstalled

DownloadOVS

InstallOVS

ConfigOVS

Log "OVS Installation Complete!"

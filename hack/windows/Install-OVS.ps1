<#
  .SYNOPSIS
  Installs Windows OpenvSwitch from a web location or local file.

  .PARAMETER DownloadURL
  The URL of the OpenvSwitch package to be downloaded.

  .PARAMETER OVSInstallDir
  The target installation directory. The default path is "C:\openvswitch".
  If this script is run from a HostProcess Container, this path must be an absolute "host path", and no be
  under the container's mount path.

  .PARAMETER LocalFile
  Specifies the path of a local OpenvSwitch package to be used for installation.
  When this param is used, "DownloadURL" is ignored. LocalFile is supposed to point to a directory or to a zip
  archive, with the following contents,
  - driver/, a directory in which the OVSext driver files are provided, including ovsext.cat, ovsext.inf, OVSExt.sys
  - include/, a directory in which the OVS header files are provided
  - lib/, a directory in which the libraries required by OVS are provided,
  - usr/, a directory in which the OVS userspace binaries and libraries are provided, e.g, usr/bin/ovs-vsctl.exe, usr/sbin/ovsdb-server.exe
  When this param points to a directory, it must be a location different from OVSInstallDir.

  .PARAMETER InstallUserspace
  Specifies whether OVS userspace processes are included in the installation. If false, these processes will not 
  be installed as a Windows service on the host.

  .PARAMETER LocalSSLFile
  Specifies the path of a local SSL package to be used for installation.
#>
Param(
    [parameter(Mandatory = $false)] [string] $DownloadURL,
    [parameter(Mandatory = $false)] [string] $OVSInstallDir = "C:\openvswitch",
    [parameter(Mandatory = $false)] [string] $LocalFile,
    [parameter(Mandatory = $false)] [bool] $InstallUserspace = $true,
    [parameter(Mandatory = $false)] [string] $LocalSSLFile
)

$global:ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "Stop"
$DefaultOVSDownloadURL = "https://downloads.antrea.io/ovs/ovs-3.0.5-antrea.1-win64.zip"
# Use a SHA256 hash to ensure that the downloaded archive is correct.
$DefaultOVSPublishedHash = '813a0c32067f40ce4aca9ceb7cd745a120e26906e9266d13cc8bf75b147bb6a5'
# $MininalVCRedistVersion is the minimal version required by the provided Windows OVS binary. If a higher
# version of VC redistributable file exists on the Windows host, we can skip the installation.
$MininalVCRedistVersion="14.12.25810"
$DefaultVCRedistsDownloadURL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

$invocationName=$($myInvocation.MyCommand.Name)
$WorkDir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
$InstallLog = "$WorkDir\install_ovs.log"
$PowerShellModuleBase = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
$OVSZip=""
$DefaultOVSRunDir = "C:\openvswitch\var\run\openvswitch"
$tempOVSDir="$env:TEMP\openvswitch"

function Log($Info) {
    $time = $(get-date -Format g)
    "$time $Info `n`r" | Tee-Object $InstallLog -Append | Write-Host
}

function ServiceExists($ServiceName) {
    If (Get-Service $ServiceName -ErrorAction SilentlyContinue) {
        return $true
    }
    return $false
}

function DownloadOVS() {
    param (
        [parameter(Mandatory = $true)] [string] $localZipFile,
        [parameter(Mandatory = $true)] [string] $downloadURL,
        [parameter(Mandatory = $true)] [string] $desiredHash
    )
    Log "Downloading OVS package from $downloadURL to $localZipFile"
    curl.exe -sLo $localZipFile $downloadURL
    If (!$?) {
        Log "Download OVS failed, URL: $downloadURL"
        exit 1
    }

    if ($desiredHash -ne "invalid") {
        $fileHash = Get-FileHash $localZipFile
        If ($fileHash.Hash -ne $desiredHash) {
            Log "SHA256 mismatch for OVS download"
            exit 1
        }
    }

    Log "Download OVS package success."
}

function AddToEnvPath(){
    param (
        [Parameter(Mandatory = $true)] [String]$path
    )
    $envPaths = $env:Path -split ";" | Select-Object -Unique
    if (-not $envPaths.Contains($path)) {
        $envPaths += $path
    }
    $env:Path = [system.String]::Join(";", $envPaths)
    [Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)
}

function CheckAndInstallScripts {
    param (
        [Parameter(Mandatory = $true)] [String]$OVSScriptsPath
    )
    if (Test-Path $OVSScriptsPath) {
        Log "Installing powershell modules."
        $PSModuleFiles = Get-ChildItem "$OVSScriptsPath" -Filter *.psm1
        $PSModuleFiles | ForEach-Object {
            $PSModulePath = Join-Path -Path $PowerShellModuleBase -ChildPath $_.BaseName
            if (!(Test-Path $PSModulePath)) {
                Log "Installing $_"
                mkdir -p $PSModulePath
                Copy-Item $_.FullName $PSModulePath
            }
        }
    }
}

function CheckAndInstallVCRedists {
    param (
        [Parameter(Mandatory = $true)] [String]$VCRedistPath,
        [Parameter(Mandatory = $true)] [String]$VCRedistsVersion
    )
    $mininalVersion = [version]$VCRedistsVersion
    $existingVCRedists = getInstalledVcRedists
    foreach ($redist in $existingVCRedists) {
        $installedVersion = [version]$redist.Version
        # VC redists files with a higher version are installed, return.
        if ($installedVersion -ge $mininalVersion) {
            return
        }
    }
    if (-not (Test-Path $VCRedistPath)) {
        mkdir -p $VCRedistPath
        curl.exe -Lo $VCRedistPath\vc_redist.x64.exe $DefaultVCRedistsDownloadURL
    }
    # Install the VC redistributable files.
    Get-ChildItem $VCRedistPath -Filter *.exe | ForEach-Object {
        Start-Process -FilePath $_.FullName -Args '/install /passive /norestart' -Verb RunAs -Wait
    }
}

function CheckAndInstallOVSDriver {
    param (
        [Parameter(Mandatory = $true)]
        [String]$OVSDriverPath
    )

    $expVersion = [version]$(Get-Item $OVSDriverPath\ovsext.sys).VersionInfo.ProductVersion
    $ovsInstalled = $(netcfg -q ovsext) -like "*is installed*"
    $installedDrivers = getInstalledOVSDrivers

    # OVSext driver with the desired version is already installed, return
    if ($ovsInstalled -and (@($installedDrivers).Length -eq 1) -and ($installedDrivers[0].DriverVersion -eq $expVersion)){
        return
    }

    # Uninstall the existing driver which is with a different version.
    if ($ovsInstalled) {
        netcfg -u ovsext
    }

    # Clean up the installed ovsext drivers packages.
    foreach ($driver in $installedDrivers) {
        $publishdName = $driver.PublishedName
        pnputil.exe -d $publishdName
    }

    # Import OVSext driver certificate to TrustedPublisher and Root.
    $DriverFile="$OVSDriverPath\ovsext.sys"
    $CertificateFile = "$OVSDriverPath\package.cer"
    $ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
    $Cert = (Get-AuthenticodeSignature $DriverFile).SignerCertificate
    [System.IO.File]::WriteAllBytes($CertificateFile, $Cert.Export($ExportType))
    Import-Certificate -FilePath "$CertificateFile" -CertStoreLocation cert:\LocalMachine\TrustedPublisher
    Import-Certificate -FilePath "$CertificateFile" -CertStoreLocation cert:\LocalMachine\Root

    # Install the OVSext driver with the desired version
    # Copy $OVSDriverPath to a host path (must not be under the container's mount path) and then install
    # ovsext.inf using the host path. This is a workaround for error code "0x80070003" with containerd v1.7+.
    # The error happens when Windows utitilty netcfg tries to access the container's mount path "C:/hpc/".
    $driverStagingPath="${OVSInstallDir}\driver"
    Remove-Item -Recurse $driverStagingPath -ErrorAction SilentlyContinue
    mkdir -p $driverStagingPath
    cp -r $OVSDriverPath\* $driverStagingPath\
    $result = netcfg -l $driverStagingPath\ovsext.inf -c s -i OVSExt

    if ($result -like '*failed*') {
        Log "Failed to install OVSExt driver: $result"
        exit 1
    }
    Log "OVSExt driver has been installed"
}

function getInstalledVcRedists {
    # Get all installed Visual C++ Redistributables installed components
    $VcRedists = listInstalledSoftware -SoftwareLike 'Microsoft Visual C++'

    # Add Architecture property to each entry
    $VcRedists | ForEach-Object { If ( $_.Name.ToLower().Contains("x64") ) `
        { $_ | Add-Member -NotePropertyName "Architecture" -NotePropertyValue "x64" } }

    return $vcRedists
}

function listInstalledSoftware {
    param (
        [parameter(Mandatory = $false)] [string] $SoftwareLike
    )
    Begin {
        $SoftwareOutput = @()
        $InstalledSoftware = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*)
    }
    Process {
        Try
        {
            if ($SoftwareLike -ne "") {
                $nameFilter = "${SoftwareLike}*"
                $InstalledSoftware = $InstalledSoftware |
                        Where-Object {$_.DisplayName -like "$nameFilter"}
            }

            $SoftwareOutput = $InstalledSoftware |
                    Select-Object -Property @{
                        Name = 'Date Installed'
                        Exp  = {
                            $_.Installdate
                        }
                    }, @{
                        Name = 'Version'
                        Exp  = {
                            $_.DisplayVersion
                        }
                    }, @{
                        Name = 'Name'
                        Exp = {
                            $_.DisplayName
                        }
                    }, UninstallString
        }
        Catch
        {
            # get error record
            [Management.Automation.ErrorRecord]$e = $_

            # retrieve information about runtime error
            $info = New-Object -TypeName PSObject -Property @{
                Exception = $e.Exception.Message
                Reason    = $e.CategoryInfo.Reason
                Target    = $e.CategoryInfo.TargetName
                Script    = $e.InvocationInfo.ScriptName
                Line      = $e.InvocationInfo.ScriptLineNumber
                Column    = $e.InvocationInfo.OffsetInLine
            }

            # output information. Post-process collected info, and log info (optional)
            $info
        }
    }

    End{
        $SoftwareOutput | Sort-Object -Property Name
    }
}

# getInstalledOVSDrivers lists the existing drivers on Windows host, and uses "ovsext" as a filter
# on the "OriginalName" field of the drivers. As the output of "pnputil.exe" is not structured, the
# function translates to structured objects first, and then applies the filter.
#
# A sample of the command output is like this,
#
# $ pnputil.exe /enum-drivers
# Microsoft PnP Utility
#
# Published Name:     oem3.inf
# Original Name:      efifw.inf
# Provider Name:      VMware, Inc.
# Class Name:         Firmware
# Class GUID:         {f2e7dd72-6468-4e36-b6f1-6488f42c1b52}
# Driver Version:     04/24/2017 1.0.0.0
# Signer Name:        Microsoft Windows Hardware Compatibility Publisher
#
# Published Name:     oem5.inf
# Original Name:      pvscsi.inf
# Provider Name:      VMware, Inc.
# Class Name:         Storage controllers
# Class GUID:         {4d36e97b-e325-11ce-bfc1-08002be10318}
# Driver Version:     04/06/2018 1.3.10.0
# Signer Name:        Microsoft Windows Hardware Compatibility Publisher
#
# Published Name:     oem9.inf
# Original Name:      vmci.inf
# Provider Name:      VMware, Inc.
# Class Name:         System devices
# Class GUID:         {4d36e97d-e325-11ce-bfc1-08002be10318}
# Driver Version:     07/11/2019 9.8.16.0
# Signer Name:        Microsoft Windows Hardware Compatibility Publisher
#
function getInstalledOVSDrivers {
    $pnputilOutput = pnputil.exe /enum-drivers
    $drivers = @()
    $lines = $pnputilOutput -split "`r`n"
    $driverlines = @()
    foreach ($line in $lines) {
        # Ignore the title line in the output.
        if ($line -like "*Microsoft PnP Utility*") {
            continue
        }
        if ($line.Trim() -eq "") {
            if ($driverlines.Count -gt 0) {
                $driver = $(parseDriver $driverlines)
                $drivers += $driver
                $driverlines = @()
            }
            continue
        }
        $driverlines += $line
    }
    if ($driverlines.Count -gt 0) {
        $driver = parseDriver $driverlines
        $drivers += $driver
    }
    $drivers = $drivers | Where-Object { $_.OriginalName -like "ovsext*"}
    return $drivers
}

function parseDriver {
    param (
        [String[]]$driverlines
    )
    $driver = [PSCustomObject]@{
        PublishedName = $null
        ProviderName = $null
        ClassName = $null
        DriverVersion = $null
        InstalledDate = $null
        SignerName = $null
        ClassGUID = $null
        OriginalName = $null
    }
    $driverlines | ForEach-Object {
        if ($_ -match "Published Name\s*:\s*(.+)") {
            $driver.PublishedName = $matches[1].Trim()
        }
        elseif ($_ -match "Provider Name\s*:\s*(.+)") {
            $driver.ProviderName = $matches[1].Trim()
        }
        elseif ($_ -match "Class Name\s*:\s*(.+)") {
            $driver.ClassName = $matches[1].Trim()
        }
        elseif ($_ -match "Driver Version\s*:\s*(.+)") {
            $dateAndVersion = $matches[1].Trim() -split " "
            $driver.DriverVersion = [version]$dateAndVersion[1]
            $driver.InstalledDate = $dateAndVersion[0]
        }
        elseif ($_ -match "Signer Name\s*:\s*(.+)") {
            $driver.SignerName = $matches[1].Trim()
        }
        elseif ($_ -match "Class GUID\s*:\s*(.+)") {
            $driver.ClassGUID = $matches[1].Trim()
        }
        elseif ($_ -match "Original Name\s*:\s*(.+)") {
            $driver.OriginalName = $matches[1].Trim()
        }
    }
    return $driver
}

function InstallOpenSSLFiles {
    param (
        [parameter(Mandatory = $true)] [string] $destinationPaths
    )

    # Check if SSL library has been installed
    $paths = $destinationPaths.Split(";")
    foreach($path in $paths) {
        if ((Test-Path "$path\ssleay32.dll" -PathType Leaf) -and (Test-Path "$path\libeay32.dll" -PathType Leaf)) {
            Log "Found existing SSL library."
            return
        }
    }
    if ($LocalSSLFile) {
        if ($LocalSSLFile -like "*.zip") {
            Log "Install local SSL library."
            Expand-Archive $LocalSSLFile -DestinationPath openssl
        } else {
            Log "The local SSL package must be in ZIP format, exit"
            exit 1
        }
    } else {
        $SSLZip = "openssl-1.0.2u-x64_86-win64.zip"
        $SSLMD5 = "E723E1C479983F35A0901243881FA046"
        $SSLDownloadURL = "https://github.com/IndySockets/OpenSSL-Binaries/raw/21d81384bfe589273e6b2ac1389c40e8f0ca610d/$SSLZip"
        curl.exe -LO $SSLDownloadURL
        If (!$?) {
            Log "Download SSL files failed, URL: $SSLDownloadURL"
            Log "Please install ssleay32.dll and libeay32.dll to $OVSInstallDir\usr\sbin\ manually"
            exit 1
        }
        $MD5Result = Get-FileHash $SSLZip -Algorithm MD5 | Select -ExpandProperty "Hash"
        If ($MD5Result -ne $SSLMD5){
            Log "Wrong md5sum, Please check the file integrity"
            exit 1
        }
        Expand-Archive $SSLZip -DestinationPath openssl
        rm $SSLZip
    }
    $destinationPaths -Split ";" | Foreach-Object {
        cp -Force openssl\*.dll $_\
    }
    rm -Recurse -Force openssl
}

function ConfigOVS() {
    param (
        [parameter(Mandatory = $true)] [string] $OVSLocalPath
    )
    # Create log dir.
    $OVSLogDir = "${OVSInstallDir}\var\log\openvswitch"
    if (-not (Test-Path $OVSLogDir)) {
        mkdir -p $OVSLogDir | Out-Null
    }

    # Create OVS run dir
    $OVSRunDir = "${OVSInstallDir}\var\run\openvswitch"
    if (-not (Test-Path $OVSRunDir)) {
        mkdir -p $OVSRunDir | Out-Null
    }
    $OVSRunDirPath = $(Get-Item -Path $OVSRunDir).FullName
    if ($OVSRunDirPath -ne $DefaultOVSRunDir) {
        $env:OVS_RUNDIR = $OVSRunDirPath
        [Environment]::SetEnvironmentVariable("OVS_RUNDIR", $env:OVS_RUNDIR, [EnvironmentVariableTarget]::Machine)
    }

    $OVSUsrBinDir = $(Get-Item "$OVSLocalPath\usr\bin").FullName
    # Create ovsdb config file
    $OVSDBDir = "${OVSInstallDir}\etc\openvswitch"
    if (-not (Test-Path $OVSDBDir)) {
        mkdir -p $OVSDBDir | Out-Null
    }
    $OVS_DB_PATH = "${OVSDBDir}\conf.db"
    Remove-Item $OVS_DB_PATH -ErrorAction SilentlyContinue
    $OVS_DB_SCHEMA_PATH = "$OVSLocalPath\usr\share\openvswitch\vswitch.ovsschema"
    if ($(Test-Path $OVS_DB_SCHEMA_PATH)) {
        Log "Creating ovsdb file"
        & $OVSUsrBinDir\ovsdb-tool.exe create "$OVS_DB_PATH" "$OVS_DB_SCHEMA_PATH"
    }

    # Copy OVS userspace programs to ${OVSInstallDir}
    $installUsrSbinDir = "${OVSInstallDir}\usr\sbin"
    if ("$installUsrSbinDir" -ne "${OVSLocalPath}\usr\sbin") {
        Remove-Item -Recurse $installUsrSbinDir -ErrorAction SilentlyContinue
        mkdir -p $installUsrSbinDir
        cp -r ${OVSLocalPath}\usr\sbin\* $installUsrSbinDir\
    }

    # Create and start ovsdb-server service.
    $OVSUsrSbinPath = $(Get-Item $installUsrSbinDir).FullName
    Log "Create and start ovsdb-server service"
    sc.exe create ovsdb-server binPath= "$OVSUsrSbinPath\ovsdb-server.exe $OVS_DB_PATH  -vfile:info --remote=punix:db.sock  --remote=ptcp:6640  --log-file=$OVSLogDir\ovsdb-server.log  --pidfile --service" start= auto
    sc.exe failure ovsdb-server reset= 0 actions= restart/0/restart/0/restart/0
    Start-Service ovsdb-server
    # Create and start ovs-vswitchd service.
    Log "Create and start ovs-vswitchd service."
    sc.exe create ovs-vswitchd binpath="$OVSUsrSbinPath\ovs-vswitchd.exe  --pidfile -vfile:info --log-file=$OVSLogDir\ovs-vswitchd.log  --service" start= auto depend= "ovsdb-server"
    sc.exe failure ovs-vswitchd reset= 0 actions= restart/0/restart/0/restart/0
    Start-Service ovs-vswitchd

    # Set OVS version.
    $OVS_VERSION=$(Get-Item $OVSLocalPath\driver\OVSExt.sys).VersionInfo.ProductVersion
    Log "Set OVS version to: $OVS_VERSION"
    & $OVSUsrBinDir\ovs-vsctl.exe --no-wait set Open_vSwitch . ovs_version=$OVS_VERSION

    # Add OVS usr/sbin to the environment path.
    AddToEnvPath($installUsrSbinDir)

    # Antrea Pod runs as NT AUTHORITY\SYSTEM user on Windows, antrea-ovs container writes
    # PID and conf.db files to $OVSInstallDir on Windows Node when it is running.
    icacls ${OVSInstallDir} /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T
}

function InstallOVSServices() {
    param (
        [parameter(Mandatory = $true)] [string] $OVSLocalPath
    )

    # Remove the existing OVS Services to avoid issues.
    If (ServiceExists("ovs-vswitchd")) {
        stop-service ovs-vswitchd
        sc.exe delete ovs-vswitchd
    }
    if (ServiceExists("ovsdb-server")) {
        stop-service ovsdb-server
        sc.exe delete ovsdb-server
    }

    # Install OVS Services and configure OVSDB.
    ConfigOVS($OVSLocalPath)
}

function PrepareOVSLocalFiles() {
    $OVSDownloadURL = $DefaultOVSDownloadURL
    $desiredOVSPublishedHash = $DefaultOVSPublishedHash
    if ($LocalFile -ne "") {
        if (-not (Test-Path $LocalFile)){
            Log "Path $LocalFile doesn't exist, exit"
            exit 1
        }

        $ovsFile = Get-Item $LocalFile
        if ($ovsFile -is [System.IO.DirectoryInfo])  {
            return $ovsFile.FullName
        }

        # $ovsFile as a zip file is supported
        $attributes = $ovsFile.Attributes
        if (("$attributes" -eq "Archive") -and ($ovsFile.Extension -eq ".zip" ) ) {
            $OVSZip = $LocalFile
            $OVSDownloadURL = ""
            $OVSPublishedHash = ""
        } else {
            Log "Unsupported local file $LocalFile; it should be a zip archive"
            exit 1
        }
    } else {
        $OVSZip = "$WorkDir\ovs-win64.zip"
        if ($DownloadURL -ne "" -and $DownloadURL -ne "$OVSDownloadURL") {
            $OVSDownloadURL = $DownloadURL
            $desiredOVSPublishedHash = "invalid"
        }
    }

    # Extract zip file to $env:TEMP\openvswitch
    if (Test-Path -Path $tempOVSDir) {
        rm -r $tempOVSDir
    }
    $removeZipFile = $false
    if ($OVSDownloadURL -ne "") {
        DownloadOVS -localZipFile $OVSZip -downloadURL $OVSDownloadURL -desiredHash $desiredOVSPublishedHash
        $removeZipFile = $true
    }
    Expand-Archive -Path $OVSZip -DestinationPath $env:TEMP | Out-Null
    if ($removeZipFile) {
        rm $OVSZip
    }
    return $tempOVSDir
}

function CopyOVSUtilities() {
    param (
        [parameter(Mandatory = $true)] [string] $OVSLocalPath
    )
    $installUsrBinPath = "${OVSInstallDir}\usr\bin"
    $usrBinPath="${OVSLocalPath}\usr\bin"
    Remove-Item -Recurse $installUsrBinPath -ErrorAction SilentlyContinue
    mkdir -p $installUsrBinPath
    cp -r $usrBinPath\* $installUsrBinPath
    AddToEnvPath($installUsrBinPath)
}

function InstallOVS() {
    param (
        [parameter(Mandatory = $true)] [string] $OVSLocalPath
    )
    # Install powershell modules
    $OVSScriptsPath = "${OVSLocalPath}\scripts"
    CheckAndInstallScripts($OVSScriptsPath)

    # Install VC redistributables.
    $OVSRedistDir="${OVSLocalPath}\redist"
    # Check if the VC redistributable is already installed. If not installed, or the installed version
    # is lower than $MininalVCRedistVersion, install the local provided VC redistributable files or
    # download the file and install it.
    CheckAndInstallVCRedists -VCRedistPath $OVSRedistDir -VCRedistsVersion $MininalVCRedistVersion

    # Install OVS driver.
    $OVSDriverDir = "${OVSLocalPath}\driver"
    Log "Installing OVS kernel driver"
    CheckAndInstallOVSDriver($OVSDriverDir)

    # Install OpenSSL dependencies.
    $OVSBinPaths="${OVSLocalPath}\usr\bin"
    if ($InstallUserspace -eq $true) {
        $OVSBinPaths="${OVSBinPaths};${OVSLocalPath}\usr\sbin"
    }
    InstallOpenSSLFiles "$OVSBinPaths"

    # Copy OVS utilities to host path "c:/openvswitch/"
    CopyOVSUtilities($OVSLocalPath)

    if ($InstallUserspace -eq $true) {
        InstallOVSServices($OVSLocalPath)
    }
}

if (($LocalFile -ne "") -and ($DownloadURL -ne "")) {
    Log "LocalFile and DownloadURL are mutually exclusive, exiting"
    exit 1
}
if (($LocalFile -ne "") -and ("$LocalFile" -eq "$OVSInstallDir")) {
    Log "LocalFile and OVSInstallDir must not be the same, exiting"
    exit 1
}
Log "Installation log location: $InstallLog"

$OVSPath = PrepareOVSLocalFiles
# $OVSFullPath is the location of all the OVS artifacts
# If LocalFile was provided and points to a directory, this is the path to this directory.
# If LocalFile was provided and points to a zip archive, or if LocalFile was not provided
# (in which case we would have downloaded a default zip archive), this is the path to
# a temporary directory to which the archive was extracted.
$OVSFullPath = $(Get-Item -Path $OVSPath).FullName
InstallOVS($OVSFullPath)
# Clean up the temp OVS directory if exists
if (Test-Path -Path $tempOVSDir) {
    rm -r $tempOVSDir
}

Log "OVS Installation Complete!"

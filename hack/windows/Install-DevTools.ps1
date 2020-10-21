<#
Install development tools used to build Antrea:
- 7zip
- Git-for-windows
- mingw64
- Golang
#>

function Add-Path($newPath) {
    $env:Path = "$newPath;" + $env:Path
    [Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)
}

function CommandExists($cmd) {
    If (Get-Command $cmd -ErrorAction SilentlyContinue) {
        Write-Host "Command: $cmd already exists."
        return $true
    }
    return $false
}

function InstallSevenZip() {
    Write-Host "Installing 7-Zip"
    Write-Host "================"
    if (CommandExists("7z")) {
        return
    }
    $exePath = "$env:USERPROFILE\7z1900-x64.exe"
    curl.exe -Lo $exePath https://www.7-zip.org/a/7z1900-x64.exe
    cmd /c start /wait $exePath /S
    del $exePath
    $sevenZipFolder = 'C:\Program Files\7-Zip'
    Add-Path "$sevenZipFolder"
    Write-Host "Installed 7-Zip"
}

function InstallGit() {
    Write-Host "Installing Git"
    Write-Host "=============="
    if (CommandExists("git")) {
        return
    }
    $gitVersion="Git-2.26.2"
    $exePath = "$env:TEMP\Git-$gitVersion-64-bit.exe"
    Write-Host "Downloading Git $gitVersion..."
    curl.exe -Lo $exePath https://github.com/git-for-windows/git/releases/download/v2.21.0.windows.1/Git-2.21.0-64-bit.exe
    Write-Host "Installing..."
    cmd /c start /wait $exePath /VERYSILENT /NORESTART /NOCANCEL /SP- /NOICONS /COMPONENTS="icons,icons\quicklaunch,ext,ext\reg,ext\reg\shellhere,ext\reg\guihere,assoc,assoc_sh" /LOG
    del $exePath
    Add-Path "$env:ProgramFiles\Git\cmd"
    Add-Path "$env:ProgramFiles\Git\usr\bin"
    Write-Host "Installed Git"
}

function InstallMingw() {
    Write-Host "Installing MinGW..."
    Write-Host "=============="
    if (CommandExists("make")) {
        return
    }
    $mingwPath = "C:\mingw-w64"
    $destPath = "c:\"
    $zipPath = "$env:TEMP\mingw-w64.7z"
    curl.exe -Lo $zipPath https://iweb.dl.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/seh/x86_64-8.1.0-release-posix-seh-rt_v6-rev0.7z
    7z x $zipPath -o"$destPath" -aoa
    cp C:\mingw64\bin\mingw32-make.exe  C:\mingw64\bin\make.exe
    Add-Path("C:\mingw64\bin")
    Remove-Item $zipPath
    Write-Host "Installed MinGW"
}

function InstallGolang() {
    $GOLANG_VERSION = "1.15.3"
    Write-Host "Installing Golang $GOLANG_VERSION"
    Write-Host "=============="
    if (CommandExists("go")) {
        return
    }
    $url = ('https://golang.org/dl/go{0}.windows-amd64.zip' -f $GOLANG_VERSION)
    $zipPath = "$env:TEMP\go.zip"
    curl.exe -Lo $zipPath $url
    Expand-Archive $zipPath -DestinationPath C:\
    Remove-Item $zipPath -Force
    Add-Path("C:\go\bin")
    mkdir C:\gopath
    $env:GOPATH = "C:\gopath"
    [Environment]::SetEnvironmentVariable("GOPATH", $env:GOPATH, [EnvironmentVariableTarget]::Machine)
    Add-Path("$env:GOPATH\bin")
    Write-Host "Installed Golang $GOLANG_VERSION"
}

# 7-Zip
InstallSevenZip
# Git
InstallGit
# MinGW 8.1
InstallMingw
# Golang
InstallGolang

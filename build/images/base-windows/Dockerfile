ARG GO_VERSION
FROM golang:${GO_VERSION}

# Install 7zip, git-for-windows, mingw64 to support "make tool"
RUN curl.exe -LO https://www.7-zip.org/a/7z1900-x64.exe; \
    cmd /c start /wait 7z1900-x64.exe /S; \
	del 7z1900-x64.exe; $env:Path=$env:Path + ';C:/Program Files/7-Zip'; [Environment]::SetEnvironmentVariable('PATH', $env:Path, [EnvironmentVariableTarget]::Machine)
RUN curl.exe -LO https://cfhcable.dl.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/seh/x86_64-8.1.0-release-posix-seh-rt_v6-rev0.7z; \
    7z x x86_64-8.1.0-release-posix-seh-rt_v6-rev0.7z; $env:Path = 'C:\mingw64\bin;' + $env:Path; cp C:\mingw64\bin\mingw32-make.exe  C:\mingw64\bin\make.exe; \
	del x86_64-8.1.0-release-posix-seh-rt_v6-rev0.7z; [Environment]::SetEnvironmentVariable('PATH', $env:Path, [EnvironmentVariableTarget]::Machine)
RUN curl.exe -LO https://github.com/git-for-windows/git/releases/download/v2.26.2.windows.1/Git-2.26.2-64-bit.exe; \
    cmd /c start /wait Git-2.26.2-64-bit.exe /VERYSILENT /NORESTART /NOCANCEL /SP- /NOICONS /COMPONENTS='icons,icons\quicklaunch,ext,ext\reg,ext\reg\shellhere,ext\reg\guihere,assoc,assoc_sh' /LOG; \
	$env:Path='C:\Program Files\Git\cmd;C:\Program Files\Git\usr\bin;' + $env:Path; [Environment]::SetEnvironmentVariable('PATH', $env:Path, [EnvironmentVariableTarget]::Machine)

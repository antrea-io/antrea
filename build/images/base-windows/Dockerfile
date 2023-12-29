# Copyright 2022 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG GO_VERSION
ARG NANOSERVER_VERSION

FROM mcr.microsoft.com/windows/servercore:${NANOSERVER_VERSION} as windows-utility-base

ARG CNI_BINARIES_VERSION

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

ENV CNI_BINARIES_VERSION ${CNI_BINARIES_VERSION}
ENV CNI_PLUGINS="./host-local.exe"

WORKDIR /

RUN mkdir -Force C:\opt\cni\bin

RUN Invoke-WebRequest -UseBasicParsing -Uri https://github.com/containernetworking/plugins/releases/download/${env:CNI_BINARIES_VERSION}/cni-plugins-windows-amd64-${env:CNI_BINARIES_VERSION}.tgz -OutFile cni-plugins-windows-amd64-${env:CNI_BINARIES_VERSION}.tgz; \
    tar -xzf cni-plugins-windows-amd64-${env:CNI_BINARIES_VERSION}.tgz  -C C:\opt\cni\bin ${env:CNI_PLUGINS}; \
    rm cni-plugins-windows-amd64-${env:CNI_BINARIES_VERSION}.tgz

# Install 7zip, git-for-windows, mingw64 to support "make tool"
RUN Invoke-WebRequest -UseBasicParsing -Uri https://www.7-zip.org/a/7z2107-x64.exe -OutFile 7z2107-x64.exe; \
    cmd /c start /wait 7z2107-x64.exe /S; \
    del 7z2107-x64.exe;  $env:Path = $env:Path+';C:/Program Files/7-Zip'; \
    Invoke-WebRequest -UseBasicParsing -Uri https://cfhcable.dl.sourceforge.net/project/mingw-w64/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/seh/x86_64-8.1.0-release-posix-seh-rt_v6-rev0.7z -OutFile mingw.7z; \
    7z x mingw.7z; cp c:/mingw64/bin/mingw32-make.exe c:/mingw64/bin/make.exe; \
    Invoke-WebRequest -UseBasicParsing -Uri https://github.com/git-for-windows/git/releases/download/v2.35.1.windows.2/PortableGit-2.35.1.2-64-bit.7z.exe -OutFile git.exe; \
    7z x git.exe -oC:\git; \
    mkdir C:\wins; \
    Invoke-WebRequest -UseBasicParsing -Uri https://github.com/rancher/wins/releases/download/v0.0.4/wins.exe -OutFile C:/wins/wins.exe

FROM golang:${GO_VERSION}-nanoserver as windows-golang

FROM mcr.microsoft.com/windows/nanoserver:${NANOSERVER_VERSION}

SHELL ["cmd", "/S", "/C"]

ENV GOPATH="C:\go"

USER ContainerAdministrator

COPY --from=windows-utility-base ["C:\\\\opt\\\\cni\\\\bin","C:\\\\opt\\\\cni\\\\bin"]
COPY --from=windows-utility-base ["C:\\\\Program Files\\\\7-Zip","C:\\\\Program Files\\\\7-Zip"]
COPY --from=windows-utility-base ["C:\\\\git","C:\\\\git"]
COPY --from=windows-utility-base ["C:\\\\mingw64","C:\\\\mingw64"]
COPY --from=windows-utility-base ["C:\\\\wins","C:\\\\wins"]
COPY --from=windows-golang ["C:\\\\Program Files\\\\Go", "C:\\\\Program Files\\\\Go"]

RUN setx /m PATH "C:\Program Files\7-Zip;C:\git\bin;C:\git\usr\bin;C:\mingw64\bin;C:\Program Files\Go\bin;%GOPATH\bin%;%PATH%"

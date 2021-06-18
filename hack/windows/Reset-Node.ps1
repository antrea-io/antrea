<#
.SYNOPSIS
Performs a best effort revert of changes made to this host by 'kubeadm join'
#>
Write-Host "Running kubeadm reset"
kubeadm.exe reset -f
rm -r -force C:\etc\kubernetes\pki
rm -r -force C:\var\lib\kubelet

mkdir -force C:\var\lib\kubelet\etc\kubernetes
mkdir -force C:\etc\kubernetes\pki
New-Item -path C:\var\lib\kubelet\etc\kubernetes\pki -type SymbolicLink -value C:\etc\kubernetes\pki\

# Installing ContainerD support for antrea on Windows

Antrea support for Containerd is new, but has been tested and works.  It comes with some caveats, such as the fact that VNIC creation may not happen immediately, due to a race condition in containerd.
These instructions will be improved over time, but they will get you started with antrea on containerd, in a manner that fully supports K8s network policys on windows.

## define a startup script

c:\k\antrea\antrea-startup.ps1'

```       
          $service = Get-Service -Name ovs-vswitchd -ErrorAction SilentlyContinue
          Push-Location C:\k\antrea
          if($service -eq $null) {
            curl.exe -LO "https://raw.githubusercontent.com/vmware-tanzu/antrea/master/hack/windows/Install-OVS.ps1"
            & ./Install-OVS.ps1
            Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
            & nssm install kube-proxy "c:/k/kube-proxy.exe" "--proxy-mode=userspace --kubeconfig=C:/etc/kubernetes/kubelet.conf --log-dir=c:/var/log/kube-proxy --logtostderr=false --alsologtostderr"
            & nssm install antrea-agent "c:/k/antrea/bin/antrea-agent.exe" "--config=c:/k/antrea/etc/antrea-agent.conf --logtostderr=false --log_dir=c:/k/antrea/logs --alsologtostderr --log_file_max_size=100 --log_file_max_num=4"
            & nssm set antrea-agent DependOnService kube-proxy ovs-vswitchd
            & nssm set antrea-agent Start SERVICE_DELAYED_START
            start-service kube-proxy
            start-service antrea-agent
          }
```

## define an installation script 

C:/Temp/antrea.ps1

```
          $service = Get-Service -Name ovs-vswitchd -ErrorAction SilentlyContinue
          if($service -ne $null) {
            exit
          }
          invoke-expression "bcdedit /set TESTSIGNING ON"
          New-Item -ItemType Directory -Force -Path C:\k\antrea
          New-Item -ItemType Directory -Force -Path C:\k\antrea\logs
          New-Item -ItemType Directory -Force -Path C:\k\antrea\bin
          New-Item -ItemType Directory -Force -Path C:\var\log\kube-proxy
          [Environment]::SetEnvironmentVariable("NODE_NAME", (hostname).ToLower())
          $trigger = New-JobTrigger -AtStartup
          $options = New-ScheduledJobOption -RunElevated
          Register-ScheduledJob -Name PrepareAntrea -Trigger $trigger -FilePath 'c:\k\antrea\antrea-startup.ps1' -ScheduledJobOption $options
          $env:HostIP = (
              Get-NetIPConfiguration |
              Where-Object {
                  $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"
              }
          ).IPv4Address.IPAddress
          $file = 'C:\var\lib\kubelet\kubeadm-flags.env'
          $newstr="--node-ip=" + $env:HostIP
          $raw = Get-Content -Path $file -TotalCount 1
          $raw = $raw -replace ".$"
          $new = "$($raw) $($newstr)`""
          Set-Content $file $new
          $nssm = (Get-Command nssm).Source
          $serviceName = 'Kubelet'
          & $nssm set $serviceName start SERVICE_AUTO_START
          cd c:\k\antrea
          curl.exe -LO https://raw.githubusercontent.com/vmware-tanzu/antrea/master/hack/windows/Start.ps1
          curl.exe -LO https://raw.githubusercontent.com/vmware-tanzu/antrea/master/hack/windows/Helper.psm1
          curl.exe -LO http://w3-dbc302.eng.vmware.com/rcao/image/containerd/antrea-agent.exe
          mv antrea-agent.exe c:\k\antrea\bin
          Import-Module ./helper.psm1
          & Install-AntreaAgent -KubernetesVersion "v1.19.1" -KubernetesHome "c:/k" -KubeConfig "C:/etc/kubernetes/kubelet.conf" -AntreaVersion "v0.12.0" -AntreaHome "c:/k/antrea"
          New-KubeProxyServiceInterface
          Add-MpPreference -ExclusionProcess "ctr.exe"
          Add-MpPreference -ExclusionProcess "containerd.exe"
          Restart-Computer -Force
```

# Run the install script

When you boot up your kubelet the first time, run the install script.

Then , make sure your services startup script is triggered from then on, on boot, based on your machine policys.

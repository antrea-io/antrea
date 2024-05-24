$ErrorActionPreference = "Stop"
$mountPath = $env:CONTAINER_SANDBOX_MOUNT_POINT
$mountPath =  ($mountPath.Replace('\', '/')).TrimEnd('/')
$env:PATH = $env:PATH + ";$mountPath/Windows/System32;$mountPath/k/antrea/bin;$mountPath/openvswitch/usr/bin;$mountPath/openvswitch/usr/sbin"
& antrea-agent --config=$mountPath/etc/antrea/antrea-agent.conf --logtostderr=false --log_dir=c:/var/log/antrea --alsologtostderr --log_file_max_size=100 --log_file_max_num=4 --v=0

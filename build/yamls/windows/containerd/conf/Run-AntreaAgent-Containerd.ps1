$ErrorActionPreference = "Stop"
$mountPath = $env:CONTAINER_SANDBOX_MOUNT_POINT
$mountPath =  ($mountPath.Replace('\', '/')).TrimEnd('/')
& "$mountPath/k/antrea/bin/antrea-agent.exe" --config=$mountPath/etc/antrea/antrea-agent.conf --logtostderr=false --log_dir=c:/var/log/antrea --alsologtostderr --log_file_max_size=100 --log_file_max_num=4 --v=4

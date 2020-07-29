$ErrorActionPreference = "Stop"
# wins will rename the binary when executing it. So we need to copy the binary everytime before running it.
mkdir -force /host/k/antrea/bin
cp /k/antrea/bin/* /host/k/antrea/bin/
C:/k/antrea/utils/wins.exe cli process run --path /k/antrea/bin/antrea-agent.exe --args "--config=/k/antrea/etc/antrea-agent.conf --logtostderr=false --log_dir=/k/antrea/logs/ --alsologtostderr --log_file_max_size=100 --log_file_max_num=4" --envs "KUBERNETES_SERVICE_HOST=$env:KUBERNETES_SERVICE_HOST KUBERNETES_SERVICE_PORT=$env:KUBERNETES_SERVICE_PORT ANTREA_SERVICE_HOST=$env:ANTREA_SERVICE_HOST ANTREA_SERVICE_PORT=$env:ANTREA_SERVICE_PORT NODE_NAME=$env:NODE_NAME"

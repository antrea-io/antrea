1. What is Antrea?  
Antrea is a CNI PLUGIN for providing networking services in Kubernetes pods (using OVS).

2. Concepts I have applied in the given task:

2.1 Kind Cluster  
- Local Kubernetes-in-Docker (Kind) setup with one control-plane and one worker node  
- To deploy Antrea as networking plugin, disabled CNI so that networking services provided by Antrea are used.

2.2 Helm  
- Helm is a package manager which allows user to install Antrea and specify custom feature gates

2.3 Docker Image Task  
- Loaded custom images into Kind  
- Tagged and pulled `antrea-controller-ubuntu:latest` and `antrea-agent-ubuntu:latest`

2.4 Go, Make, Docker  
- Installed locally to compile the Antrea code, build container images, and push them into the Kind cluster.

2.5 klog.InfoS  
- Uses structured logging to generate logs in the form of key-value pairs

2.6 Flow of Execution  
- `make` calls `docker build` to compile Antrea with Go modules and package the result into Docker images  
- These images are then loaded into the Kind cluster  
- Helm applies the custom feature gate settings and performs the deployment using these loaded images

2.7 Log & OVS Version Collection  
- `kubectl logs` captures the first 10 lines of each Antrea Pod’s log  
- `ovs-vsctl --version` shows the OVS version

2.8 Namespaces  
- Namespaces are used to define scope where resources to be used can be organized  
- Organized the work in a namespace called `lfx-mentorship`

2.9 PacketCapture CR  
- Directs Antrea to tap TCP SYN traffic to port 53 on 8.8.8.8  
- Capture 5 packets or wait 300 seconds  
- Then traffic is generated, the PacketCapture CR status is checked to get the capture file path  
- Finally, content is copied from `.pcapng` and the recorded packets are dumped using `tcpdump`
 
 

#!/bin/bash
# Copyright 2022 Antrea Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


export WORKSPACE=${WORKSPACE:-/tmp/k8s_$$}
export LOGDIR=$WORKSPACE/logs
export ARTIFACTS=$WORKSPACE/artifacts

export GOROOT=${GOROOT:-/usr/local/go}
export GOPATH=${WORKSPACE}
export PATH=/usr/local/go/bin/:$GOPATH/src/k8s.io/kubernetes/third_party/etcd:$PATH
export TIMEOUT=${TIMEOUT:-300}

export POLL_INTERVAL=${POLL_INTERVAL:-10}
export NETWORK=${NETWORK:-'192.168'}

export KUBECONFIG=${KUBECONFIG:-/etc/kubernetes/admin.conf}

function pod_create {
    pod_name="$1"
    sriov_pod=$ARTIFACTS/"$pod_name"
    cat > $sriov_pod <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
spec:
  containers:
    - name: antrea-app
      image: harbor.mellanox.com/cloud-orchestration/rping-test
      imagePullPolicy: IfNotPresent
      securityContext:
        capabilities:
          add: [ "IPC_LOCK" ]
      command: [ "/bin/bash", "-c", "--" ]
      args: [ "while true; do sleep 300000; done;" ]
      resources:
        requests:
          mellanox.com/sriov_antrea: '1'
        limits:
          mellanox.com/sriov_antrea: '1'
EOF
    kubectl get pods
    kubectl delete -f $sriov_pod 2>&1|tee > /dev/null
    sleep ${POLL_INTERVAL}
    kubectl create -f $sriov_pod

    pod_status=$(kubectl get pods | grep "$pod_name" |awk  '{print $3}')
    let stop=$(date '+%s')+$TIMEOUT
    d=$(date '+%s')
    while [ $d -lt $stop ]; do
        echo "Waiting for pod to became Running"
        pod_status=$(kubectl get pods | grep "$pod_name" |awk  '{print $3}')
        if [ "$pod_status" == "Running" ]; then
            return 0
        elif [ "$pod_status" == "UnexpectedAdmissionError" ]; then
            kubectl delete -f $sriov_pod
            sleep ${POLL_INTERVAL}
            kubectl create -f $sriov_pod
        fi
        kubectl get pods | grep "$pod_name"
        kubectl describe pod "$pod_name"
        sleep ${POLL_INTERVAL}
        d=$(date '+%s')
    done
    echo "Error $pod_name is not up"
    return 1
}

function test_pods {
    local status=0
    POD_NAME_1=$1
    POD_NAME_2=$2

    ip_1=$(/usr/local/bin/kubectl exec -i ${POD_NAME_1} -- ifconfig eth0 |grep inet|awk '{print $2}')
    /usr/local/bin/kubectl exec -i ${POD_NAME_1} -- ifconfig eth0
    echo "${POD_NAME_1} has ip ${ip_1}"

    ip_2=$(/usr/local/bin/kubectl exec -i ${POD_NAME_2} -- ifconfig eth0 |grep inet|awk '{print $2}')
    /usr/local/bin/kubectl exec -i ${POD_NAME_2} -- ifconfig eth0
    echo "${POD_NAME_2} has ip ${ip_2}"

    /usr/local/bin/kubectl exec ${POD_NAME_2} -- bash -c "ping $ip_1 -c 10 >/dev/null 2>&1"
    let status=status+$?

    if [ "$status" != 0 ]; then
        echo "Error: There is no connectivity between the pods"
        return $status
    fi

    echo "connectivity test passed!!!"
    echo ""
    echo "checking if the pod have the vf"

    if [[ -z "$(kubectl exec -it test-pod-1 -- ls -l /sys/class/net/ | grep eth0 | grep -o pci000)" ]]; then
	echo "Error: pod test-pod-1 did not get the vf"
	return 1
    fi

    if [[ -z "$(kubectl exec -it test-pod-2 -- ls -l /sys/class/net/ | grep eth0 | grep -o pci000)" ]]; then
        echo "Error: pod test-pod-2 did not get the VF"
        return 1
    fi

    if [[ -z "$(kubectl exec -it test-pod-1 -- ls -l /sys/class/net/eth0/device/driver | grep mlx)" ]]; then
        echo "Error: pod test-pod-1 driver is not Mellanox driver!"
	return 1
    fi

    if [[ -z "$(kubectl exec -it test-pod-2 -- ls -l /sys/class/net/eth0/device/driver | grep mlx)" ]]; then
         echo "Error: pod test-pod-2 driver is not Mellanox driver!"
         return 1
    fi


    echo "Success!! The pods have the vfs."
    echo ""
    echo "Checking if hw-offload is enabled inside the ovs container."
    
    agent_pod_name=$(kubectl get pods -A -o name | grep antrea-agent | cut -d/ -f2)
    if [[ -z "$agent_pod_name" ]];then
        echo "Couldn't find the Antrea agent pod!"
	return 1
    fi
    ovs_options=$(kubectl -n kube-system -c antrea-ovs exec -t $agent_pod_name -- ovs-vsctl get Open_vSwitch . other_config)
    if [[ "$?" != "0" ]];then
        echo "Cloud not retrieve ovs configuration!"
	return 1
    fi
    echo "ovs options are: $ovs_options"
    if [[ "$ovs_options" =~ "hw-offload=\"true\"" ]];then
        echo "hardware offload is enabled."
    else
        echo "hardware offload is not enabled."
	return 1
    fi

    return $status
 }

function exit_code {
    rc="$1"
    echo "All logs $LOGDIR"
    echo "All confs $ARTIFACTS"
    echo "To stop K8S run # WORKSPACE=${WORKSPACE} ./scripts/stop.sh"
    exit $status
}

pushd $WORKSPACE

status=0
echo "Creating pod test-pod-1"
pod_create 'test-pod-1'
let status=status+$?

if [ "$status" != 0 ]; then
    echo "Error: error in creating the first pod"
    exit_code $status
fi

echo "Creating pod test-pod-2"
pod_create 'test-pod-2'
let status=status+$?

if [ "$status" != 0 ]; then
    echo "Error: error in creating the second pod"
    exit_code $status
fi

test_pods 'test-pod-1' 'test-pod-2'

let status=status+$?

if [ "$status" != 0 ]; then
    echo "Error: error in testing the pods"
    exit_code $status
fi

echo "all tests succeeded!!"

exit_code $status

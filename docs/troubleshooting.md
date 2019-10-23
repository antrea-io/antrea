# Troubleshooting

## Looking at the Antrea logs

You can inspect the logs for the `antrea-agent` and `antrea-ovs` containers in any
`antrea-agent` Pod by running this `kubectl` command:
```
kubectl logs -n kube-system <POD_NAME> -c [antrea-agent|antrea-ovs]
```

The list of `antrea-agent` Pods, along with the node on which the Pod is scheduled,
can be obtained with:
```
kubectl get pods -n kube-system -l app=antrea -o wide
```

To check the Open vSwitch logs (e.g. if the `antrea-ovs` container logs indicate
that one of the Open vSwitch daemons generated an error), you can use `kubectl
exec`:
```
kubectl exec -n kube-system <POD_NAME> -c antrea-ovs tail /var/log/openvswitch/<DAEMON>.log
```
The Open vSwitch daemon logs for each `antrea-agent` Pod are also stored on the
persistent storage of the corresponding node (i.e. the node on which the Pod is
scheduled), under `/var/log/antrea/openvswitch`.

## Debugging OVS

OVS agents (`ovsdb-server` and `ovs-vswitchd`) run inside the `antrea-ovs`
container of the `antrea-agent` Pod. You can use `kubectl exec` to execute OVS
command line tools (e.g. `ovs-vsctl`, `ovs-ofctl`) in the container, for
example:
```
kubectl exec -n kube-system <POD_NAME> -c antrea-ovs ovs-vsctl show
```

By default the host directory `/var/run/antrea/openvswitch/` is mounted to
`/var/run/openvswitch/` of the `antrea-ovs` container and is used as the parent
directory of the OVS UNIX domain sockets and configuration database file.
Therefore, you may execute some OVS command line tools (inc. `ovs-vsctl` and
`ovs-ofctl`) from a Kubernetes Node - assuming they are installed on the Node -
by specifying the socket file path explicitly, for example:
```
ovs-vsctl --db unix:/var/run/antrea/openvswitch/db.sock show
ovs-ofctl show unix:/var/run/antrea/openvswitch/br-int.mgmt
```

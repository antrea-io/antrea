# Troubleshooting

## Looking at the OKN logs

You can inspect the logs for the `okn-agent` and `okn-ovs` containers in any
`okn-agent` Pod by running this `kubectl` command:
```
kubectl logs -n kube-system <POD_NAME> -c [okn-agent|okn-ovs]
```

The list of `okn-agent` Pods, along with the node on which the Pod is scheduled,
can be obtained with:
```
kubectl get pods -n kube-system -l app=okn -o wide
```

To check the Open vSwitch logs (e.g. if the `okn-ovs` container logs indicate
that one of the Open vSwitch daemons generated an error), you can use `kubectl
exec`:
```
kubectl exec -n kube-system <POD_NAME> -c okn-ovs tail /var/log/openvswitch/<DAEMON>.log
```
The Open vSwitch daemon logs for each `okn-agent` Pod are also stored on the
persistent storage of the corresponding node (i.e. the node on which the Pod is
scheduled), under `/var/log/okn/openvswitch`.

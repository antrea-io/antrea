# Run Antrea agent simulator

This document describes how to run the Antrea agent simulator. The simulator is
useful for Antrea scalability testing, without having to create a very large
cluster.

## Build the images

```bash
make build-scale-simulator
```

## Create the yaml file

This demo uses 1 simulator, this command will create a yaml file
build/yamls/antrea-scale.yml

```bash
make manifest-scale
```

The above yaml will create one simulated Node/Pod, to change the number of
instances, you can modify `spec.replicas` of the StatefulSet
`antrea-agent-simulator` in the yaml, or scale it via
`kubectl scale statefulset/antrea-agent-simulator -n kube-system --replicas=<COUNT>`
after deploying it.

## Taint the simulator node

To prevent Pods from being scheduled on the simulated Node(s), you can use the
following taint.

```bash
kubectl taint -l 'antrea/instance=simulator' node mocknode=true:NoExecute
```

## Create secret for kubemark

```bash
kubectl create secret generic kubeconfig --type=Opaque --namespace=kube-system --from-file=admin.conf=<path to kubeconfig file>
```

## Apply the yaml file

```bash
kubectl apply -f build/yamls/antrea-scale.yml
```

check the simulated Node:

  ```bash
kubectl get nodes -l 'antrea/instance=simulator'
  ```

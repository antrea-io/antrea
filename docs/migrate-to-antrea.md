# Migrate from another CNI to Antrea

This document provides guidance on migrating from other CNIs to Antrea
starting from version v1.15.0 onwards.

NOTE: The following is a reference list of CNIs and versions for which we have
verified the migration process. CNIs and versions that are not listed here
might also work. Please create an issue if you run into problems during the
migration to Antrea. During the migration process, no Kubernetes resources
should be created or deleted, otherwise the migration process might fail or
some unexpected problems might occur.

| CNI     | Version |
|---------|---------|
| Calico  | v3.26   |
| Flannel | v0.22.0 |

The migration process is divided into three steps:

1. Clean up the old CNI.
2. Install Antrea in the cluster.
3. Deploy Antrea migrator.

## Clean up the old CNI

The cleanup process varies across CNIs, typically you should remove
the DaemonSet, Deployment, and CRDs of the old CNI from the cluster.
For example, if you used `kubectl apply -f <CNI_MANIFEST>` to install
the old CNI, you could then use `kubectl delete -f <CNI_MANIFEST>` to
uninstall it.

## Install Antrea

The second step is to install Antrea in the cluster. You can follow the
[installation guide](https://github.com/antrea-io/antrea/blob/main/docs/getting-started.md)
to install Antrea. The following is an example of installing Antrea v1.14.1:

```bash
kubectl apply -f https://github.com/antrea-io/antrea/releases/download/v1.14.1/antrea.yml
```

## Deploy Antrea migrator

After Antrea is up and running, you can now deploy Antrea migrator
by the following command. The migrator runs as a DaemonSet, `antrea-migrator`,
in the cluster, which will restart all non hostNetwork Pods in the cluster
in-place and perform necessary network resource cleanup.

```bash
kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-migrator.yml
```

The reason for restarting all Pods is that Antrea needs to take over the
network management and IPAM from the old CNI. In order to avoid the Pods
being rescheduled and minimize service downtime, the migrator restarts
all non-hostNetwork Pods in-place by restarting their sandbox containers.
Therefore, it's expected to see the `RESTARTS` count for these Pods being
increased by 1 like below:

```bash
$ kubectl get pod -o wide
NAME                               READY   STATUS    RESTARTS      AGE    IP          NODE          NOMINATED NODE   READINESS GATES
migrate-example-6d6b97f96b-29qbq   1/1     Running   1 (24s ago)   2m5s   10.10.1.3   test-worker   <none>           <none>
migrate-example-6d6b97f96b-dqx2g   1/1     Running   1 (23s ago)   2m5s   10.10.1.6   test-worker   <none>           <none>
migrate-example-6d6b97f96b-jpflg   1/1     Running   1 (23s ago)   2m5s   10.10.1.5   test-worker   <none>           <none>
```

When the `antrea-migrator` Pods on all Nodes are in `Running` state,
the migration process is completed. You can then remove the `antrea-migrator`
DaemonSet safely with the following command:

```bash
kubectl delete -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-migrator.yml
```

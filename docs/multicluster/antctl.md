# Antctl Multi-cluster commands

Starting from version 1.6.0, Antrea supports the `antctl mc` commands, which can
collect information from a leader cluster in a ClusterSet for troubleshooting
issues in an Antrea Multi-cluster ClusterSet, create and delete resources in an
Antrea Multi-cluster ClusterSet, and so on. The command `antctl mc get` is supported
since Antrea version 1.6.0 and other commands are supported from 1.7.0. These commands
cannot run inside the `antrea-controller`, `antrea-agent` and `antrea-mc-controller`
Pods. The antctl will look for your kubeconfig file at `$HOME/.kube/config` by default.
You can select a different one by setting the `KUBECONFIG` environment variable or with
`--kubeconfig`.

## antctl mc get

- `antctl mc get clusterset` (or `get clustersets`) command can print all
ClusterSets, a specified Clusterset, or the ClusterSet in a specified leader cluster
Namespace.
- `antctl mc get resourceimport` (or `get resourceimports`, `get ri`) command can print
all ResourceImports, a specified ResourceImport, or ResourceImports in a specified
Namespace.
- `antctl mc get resourceexport` (or `get resourceexports`, `get re`) command can print
all ResourceExports, a specified ResourceExport, ResourceExports in a specified
Namespace, or ResourceExports in a specific member cluster.

Using the `json` or `yaml` antctl output format can print more information of
ClusterSet, ResourceImport, and ResourceExport than using the default table
output format.

```bash
antctl mc get clusterset [NAME] [-n NAMESPACE] [-o json|yaml] [-A]
antctl mc get resourceimport [NAME] [-n NAMESPACE] [-o json|yaml] [-A]
antctl mc get resourceexport [NAME] [-n NAMESPACE] [-clusterid CLUSTERID] [-o json|yaml] [-A]
```

To see the usage examples of these commands, you may also run `antctl mc get [subcommand] --help`.

## antctl mc create

`antctl mc create` command can create access-token and other resources like ClusterSet, ClusterClaims for
Antrea Multi-cluster setup

+ `antctl mc create accesstoken` command can create accesstoken for member clusters.
+ `antctl mc create clusterclaims` command can create two ClusterClaims in a leader or member cluster. One for the leader or member cluster, and another for the ClusterSet.
+ `antctl mc create clusterset` command can create a ClusterSet in a leader or member cluster.

```bash
anctcl mc create accesstoken [NAME] [-n NAMESPACE] [--serviceaccount SERVICE_ACCOUNT] [--role-binding ROLE_BINDING]
antctl mc create clusterclaims [-n NAMESPACE] [--clusterset-id CLUSTERSET_ID] [--cluster-id CLUSTER_ID]
antctl mc create clusterset [NAME] [-n NAMESPACE] [--leader-server LEADER_SERVER] [--service-account SERVICE_ACCOUNT] [--secret SECRET] [--leader-cluster LEADER_CLUSTER_ID]
```

To see the usage examples of these commands, you may also run `antctl mc create [subcommand] --help`.

## antctl mc add

`antctl mc add` command can add a new member cluster to a ClusterSet.

```bash
antctl mc add membercluster [CLUSTER_ID] [-n NAMESPACE] [--clusterset CLUSTERSET] [--service-account SERVICE_ACCOUNT]
```

To see the usage examples of these commands, you may also run `antctl mc add [subcommand] --help`.

## antctl mc delete

`antctl mc delete` command can delete resources in an Antrea Multi-cluster ClusterSet.

+ `antctl mc delete clusterclaims` command can delete the two ClusterClaims in a specified Namespace. One for the leader or member cluster, and another for the ClusterSet.
+ `antctl mc delete clusterset` command can delete a ClusterSet in a leader or member cluster.
+ `antctl mc delete member-cluster` command can delete a member cluster in a specified Antrea Multi-cluster ClusterSet.

```bash
antctl mc delete clusterclaims [-n NAMESPACE]
antctl mc delete clusterset [NAME] [-n NAMESPACE]
antctl mc delete membercluster [MEMBER_CLUSTER_ID] [-n NAMESPACE] [--clusterset CLUSTERSET]
```

To see the usage examples of these commands, you may also run `antctl mc delete [subcommand] --help`.

## antctl mc deploy

`antctl mc deploy` command can deploy Antrea Multi-cluster Controller to a leader or member cluster.

+ `antctl mc deploy leadercluster` command can deploy Antrea Multi-cluster Controller to a leader cluster, and define all the CRDs the leader cluster needed.
+ `antctl mc deploy membercluster` command can deploy Antrea Multi-cluster Controller to a member cluster, and define all the CRDs the member cluster needed.

```bash
antctl mc deploy leadercluster [--antrea-version ANTREA_VERSION] [-n NAMESPACE] [-f PATH_TO_MANIFEST]
antctl mc deploy membercluster [--antrea-version ANTREA_VERSION] [-n NAMESPACE] [-f PATH_TO_MANIFEST]
```

To see the usage examples of these commands, you may also run `antctl mc deploy [subcommand] --help`.

# Antctl Multi-cluster commands

Starting from version 1.6.0, Antrea supports the `antctl mc` commands, which can
collect information from a leader cluster for troubleshooting Antrea
Multi-cluster issues, deploy Antrea Multi-cluster and set up ClusterSets in both
leader and member clusters. The `antctl mc get` command is supported since
Antrea v1.6.0, while other commands are supported since v1.8.0. These commands
cannot run inside the `antrea-controller`, `antrea-agent` or
`antrea-mc-controller` Pods. antctl needs a kubeconfig file to access the target
cluster's API server, and it will look for the kubeconfig file at
`$HOME/.kube/config` by default. You can select a different file by setting the
`KUBECONFIG` environment variable or with the `--kubeconfig` option of antctl.

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

`antctl mc create` command can create tokens for member clusters to join a ClusterSet. The command will
also create a Secret to store the token, as well as a ServiceAccount and a RoleBinding. The `--output-file`
option saves the member token Secret manifest to a file.

```bash
anctcl mc create membertoken NAME -n NAMESPACE [-o OUTPUT_FILE]
```

To see the usage examples of these commands, you may also run `antctl mc create [subcommand] --help`.

## antctl mc deploy

`antctl mc deploy` command deploys Antrea Multi-cluster Controller to a leader or member cluster.

+ `antctl mc deploy leadercluster` command deploys Antrea Multi-cluster Controller to a leader cluster and imports
  all the Antrea Multi-cluster CRDs.
+ `antctl mc deploy membercluster` command deploys Antrea Multi-cluster Controller to a member cluster and imports
  all the Antrea Multi-cluster CRDs.

```bash
antctl mc deploy leadercluster -n NAMESPACE [--antrea-version ANTREA_VERSION] [-f PATH_TO_MANIFEST]
antctl mc deploy membercluster -n NAMESPACE [--antrea-version ANTREA_VERSION] [-f PATH_TO_MANIFEST]
```

To see the usage examples of these commands, you may also run `antctl mc deploy [subcommand] --help`.

## antctl mc init

`antctl mc init` command initializes an Antrea Multi-cluster ClusterSet in a leader cluster. It will create a
ClusterSet and ClusterClaims for the leader cluster. If the `--output-file` option is specified, the config arguments
for member clusters to join the ClusterSet will be saved to the specified file.

```bash
antctl mc init -n NAMESPACE --clusterset CLUSTERSET_ID --clusterid CLUSTERID [--create-token] [-o OUTPUT_FILE]
```

To see the usage examples of this command, you may also run `antctl mc init --help`.

## antctl mc join

`antctl mc join` command lets a member cluster join an existing Antrea Multi-cluster ClusterSet. It will create a
ClusterSet and ClusterClaims for the member cluster. Users can use command line options or a config file (which can
be the output file of the `anctl mc init` command) to specify the ClusterSet join arguments.

When the config file is provided, the command line options may be overwritten by the file. A token is needed for a
member cluster to access the leader cluster API server. Users can either specify a pre-created token Secret with the
`--token-secret-name` option, or pass a Secret manifest to create the Secret with either the `--token-secret-file`
option or the config file.

```bash
antctl mc join --clusterset=CLUSTERSET_ID \
                   --clusterid=CLUSTER_ID \
                   --namespace=[MEMBER_NAMESPACE] \
                   --leader-clusterid=LEADER_CLUSTER_ID \
                   --leader-namespace=LEADER_NAMESPACE \
                   --leader-apiserver=LEADER_APISERVER \
                   --token-secret-name=[TOKEN_SECRET_NAME] \
                   --token-secret-file=[TOKEN_SECRET_FILE]

antctl mc join --config-file PATH_TO_CONFIG_FILE [--clusterid=CLUSTER_ID] [--token-secret-name=TOKEN_SECRET_NAME] [--token-secret-file=TOKEN_SECRET_FILE]
```

Below is a config file example:

```yaml
apiVersion: multicluster.antrea.io/v1alpha1
kind: ClusterSetJoinConfig
clusterSetID: clusterset1
clusterID: cluster-east
namespace: kube-system
leaderClusterID: cluster-north
leaderNamespace: antrea-multicluster
leaderAPIServer: https://172.18.0.3:6443
tokenSecretName: cluster-east-token
```

## antctl mc leave

`antctl mc leave` command lets a member cluster leave a ClusterSet. It will delete the ClusterSet and ClusterClaims
and other resources created by antctl for the member cluster.

```bash
antctl mc leave --clusterset CLUSTERSET_ID --namespace [NAMESPACE]
```

## antctl mc destroy

`antctl mc destroy` command can destroy an Antrea Multi-cluster ClusterSet in a leader cluster. It will delete the
ClusterSet and ClusterClaims and other resources created by antctl for the leader cluster.

```bash
antctl mc destroy --clusterset=CLUSTERSET_ID --namespace NAMESPACE
```

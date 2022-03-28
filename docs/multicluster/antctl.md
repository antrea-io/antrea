# Antctl Multi-cluster commands

Starting from version 1.6.0, Antrea supports the `antctl mc` commands, which can
collect information from a leader cluster in a ClusterSet, for troubleshooting
issues in an Antrea Multi-cluster ClusterSet.

All antctl Multi-cluster commands can only run correctly after [deploying Antrea
Multi-cluster](./user-guide.md) successfully.

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

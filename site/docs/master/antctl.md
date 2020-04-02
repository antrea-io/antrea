# Antctl

Antctl is the command-line tool for Antrea. At the moment, antctl supports
running in two different modes:
 * "controller mode": when run out-of-cluster or from within the Antrea
 Controller Pod, antctl can connect to the Antrea Controller and query
 information from it (e.g. the set of computed NetworkPolicies).
 * "agent mode": when run from within an Antrea Agent Pod, antctl can connect to
 the Antrea Agent and query information local to that Agent (e.g. the set of
 computed NetworkPolicies received by that Agent from the Antrea Controller, as
 opposed to the entire set of computed policies).

## Installation

The antctl binary is included in the Antrea Docker image
(`antrea/antrea-ubuntu`) which means that there is no need to install anything
to connect to the Antrea Agent. Simply exec into the antrea-agent container for
the appropriate antrea-agent Pod and run `antctl`:
```
kubectl exec -it <antrea-agent Pod name> -n kube-system -c antrea-agent bash
> antctl help
```

Starting with Antrea release v0.5.0, we publish the antctl binaries for
different OS / CPU Architecture combinations. Head to the [releases
page](https://github.com/vmware-tanzu/antrea/releases) and download the
appropriate one for your machine. For example:

On Mac & Linux:
```
curl -Lo ./antctl "https://github.com/vmware-tanzu/antrea/releases/download/v0.5.0/antctl-$(uname)-x86_64"
chmod +x ./antctl
mv ./antctl /some-dir-in-your-PATH/antctl
antctl version
```

For Linux, we also publish binaries for Arm-based systems.

On Windows, using PowerShell:
```
Invoke-WebRequest -Uri https://github.com/vmware-tanzu/antrea/releases/download/v0.5.0/antctl-windows-x86_64.exe -Outfile antctl.exe
Move-Item .\antctl.exe c:\some-dir-in-your-PATH\antctl.exe
antctl version
```

## Usage

To see the list of available commands and options, run `antctl help`. The list
will be different based on whether you are connecting to the Antrea Controller
or Agent.

When running out-of-cluster ("controller mode" only), antctl will look for your
kubeconfig file at `$HOME/.kube/config` by default. You can select a different
one with `--kubeconfig`.

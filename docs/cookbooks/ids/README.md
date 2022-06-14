# Using Antrea with IDS

This guide will describe how to use Project Antrea with threat detection
engines, in order to provide network-based intrusion detection service to your
Pods. In this scenario, Antrea is used for the default Pod network. For the sake
of this guide, we will use [Suricata](https://suricata.io/) as the threat
detection engine, but similar steps should apply for other engines as well.

The solution works by configuring a TrafficControl resource applying to specific
Pods. Traffic originating from the Pods or destined for the Pods is mirrored,
and then inspected by Suricata to provide threat detection. Suricata is
configured with IDS mode in this example, but it can also be configured with
IPS/inline mode to proactively drop the traffic determined to be malicious.

<!-- toc -->
- [Prerequisites](#prerequisites)
- [Practical steps](#practical-steps)
  - [Step 1: Deploy Antrea](#step-1-deploy-antrea)
  - [Step 2: Configure TrafficControl resource](#step-2-configure-trafficcontrol-resource)
  - [Step 3: Deploy Suricata as a DaemonSet](#step-3-deploy-suricata-as-a-daemonset)
- [Testing](#testing)
<!-- /toc -->

## Prerequisites

The general prerequisites are:

* a K8s cluster running a K8s version supported by Antrea.
* [`kubectl`](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

The [TrafficControl](../../traffic-control.md) capability was added in Antrea
version 1.7. Therefore, an Antrea version >= v1.7.0 should be used to configure
Pod traffic mirroring.

All the required software will be deployed using YAML manifests, and the
corresponding container images will be downloaded from public registries.

## Practical steps

### Step 1: Deploy Antrea

For detailed information on the Antrea requirements and instructions on how to
deploy Antrea, please refer to [getting-started.md](../../getting-started.md).
As of now, the `TrafficControl` feature gate is disabled by default, you will
need to enable it like the following command.

To deploy the latest version of Antrea, use:

```bash
curl -s https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea.yml | \
  sed "s/.*TrafficControl:.*/      TrafficControl: true/" | \
  kubectl apply -f -
```

You may also choose a [released Antrea
version](https://github.com/antrea-io/antrea/releases).

### Step 2: Configure TrafficControl resource

To replicate Pod traffic to Suricata for analysis, create a TrafficControl with
the `Mirror` action, and set the `targetPort` to an OVS internal port that
Suricata will capture traffic from. This cookbook uses `tap0` as the port name
and performs intrusion detection for Pods with the `app=web` label:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: crd.antrea.io/v1alpha2
kind: TrafficControl
metadata:
  name: mirror-web-app-to-tap0
spec:
  appliedTo:
    podSelector:
      matchLabels:
        app: web
  direction: Both
  action: Mirror
  targetPort:
    ovsInternal:
      name: tap0
EOF
```

### Step 3: Deploy Suricata as a DaemonSet

Suricata supports many possible configuration options, but we will just focus on
the basics in the cookbook. The YAML file for Suricata DaemonSet is included in
the [resources](resources) directory. The DaemonSet uses the image
`jasonish/suricata` from <https://github.com/jasonish/docker-suricata>.

As the TrafficControl resource configured in the second step mirrors traffic to
`tap0`, we run Suricata in the host network and specify the network interface to
`tap0`.

```yaml
spec:
  hostNetwork: true
  containers:
    - name: suricata
      image: jasonish/suricata:latest
      command:
        - /usr/bin/suricata
        - -i
        - tap0
```

Suricata uses Signatures (rules) to trigger alerts. We use the default ruleset
installed at `/var/lib/suricata/rules` of the image `jasonish/suricata`.

The directory `/var/log/suricata` contains alert events. We mount the directory
as a `hostPath` volume to expose and persist them on the host:

```yaml
spec:
  containers:
    - name: suricata
      volumeMounts:
        - name: host-var-log-suricata
          mountPath: /var/log/suricata
  volumes:
    - name: host-var-log-suricata
      hostPath:
        path: /var/log/suricata
        type: DirectoryOrCreate
```

To deploy Suricata, run:

```bash
kubectl apply -f docs/cookbooks/ids/resources/suricata.yml
```

## Testing

To test the IDS functionality, you can create a Pod with the `app=web` label,
using the following command:

```bash
kubectl create deploy web --image nginx:1.21.6
```

Let's log into the Node that the test Pod runs on and start `tail` to see
updates to the alert log `/var/log/suricata/fast.log`:

```bash
tail -f /var/log/suricata/fast.log
```

You can then generate malicious requests to trigger alerts. For ingress traffic,
you can fake a web application attack against the Pod with the following command
(assuming that the Pod IP is 10.10.2.3):

```bash
curl http://10.10.2.3/dlink/hwiz.html
```

The following output should now be seen in the log:

```text
05/17/2022-04:29:51.717452  [**] [1:2008942:8] ET POLICY Dlink Soho Router Config Page Access Attempt [**] [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 10.10.2.1:48600 -> 10.10.2.3:80
```

For egress traffic, you can `kubectl exec` into the Pods and generate malicious
requests against external web server with the following command:

```bash
kubectl exec deploy/web -- curl -s http://testmynids.org/uid/index.html
```

The following output should now be seen in the log:

```text
05/17/2022-04:36:46.706373  [**] [1:2013028:6] ET POLICY curl User-Agent Outbound [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.10.2.3:55132 -> 65.8.161.92:80
05/17/2022-04:36:46.708833  [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**] [Classification: Potentially Bad Traffic] [Priority: 2] {TCP} 65.8.161.92:80 -> 10.10.2.3:55132
```

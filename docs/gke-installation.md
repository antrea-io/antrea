# Deploying Antrea on a GKE cluster

We support running Antrea inside of GKE clusters on Ubuntu Node. Antrea would operate
in NetworkPolicy only mode, in which no encapsulation is required for any kind of traffic
(Intra Node, Inter Node, etc) and NetworkPolicies are enforced using OVS. Antrea is supported
on both VPC-native Enable/Disable modes.

## GKE Prerequisites

1. Install the Google Cloud SDK (gcloud). Refer to [Google Cloud SDK installation guide](https://cloud.google.com/sdk/install)

    ```bash
    curl https://sdk.cloud.google.com | bash
    ```

2. Make sure you are authenticated to use the Google Cloud API

    ```bash
    export ADMIN_USER=user@email.com
    gcloud auth login
    ```

3. Create a project or use an existing one

    ```bash
    export GKE_PROJECT=gke-clusters
    gcloud projects create $GKE_PROJECT
    ```

## Creating the cluster

You can use any method to create a GKE cluster (gcloud SDK, gcloud Console, etc). The example
given here is using the Google Cloud SDK.

**Note:** Antrea is supported on Ubuntu Nodes only for GKE cluster. When creating the cluster, you
  must use the default network provider and must *not* enable "Dataplane V2".

1. Create a GKE cluster

    ```bash
    export GKE_ZONE="us-west1"
    export GKE_HOST="UBUNTU"
    gcloud container --project $GKE_PROJECT clusters create cluster1 --image-type $GKE_HOST \
       --zone $GKE_ZONE --enable-ip-alias
    ```

2. Access your cluster

    ```bash
    kubectl get nodes
    NAME                                      STATUS   ROLES    AGE     VERSION
    gke-cluster1-default-pool-93d7da1c-61z4   Ready    <none>   3m11s   1.25.7-gke.1000
    gke-cluster1-default-pool-93d7da1c-rkbm   Ready    <none>   3m9s    1.25.7-gke.1000
    ```

3. Create a cluster-admin ClusterRoleBinding

    ```bash
    kubectl create clusterrolebinding cluster-admin-binding --clusterrole cluster-admin --user user@email.com
    ```

    **Note:** To create clusterRoleBinding, the user must have `container.clusterRoleBindings.create` permission.
Use this command to enable it, if the previous command fails due to permission error. Only cluster Admin can
assign this permission.

    ```bash
    gcloud projects add-iam-policy-binding $GKE_PROJECT --member user:user@email.com --role roles/container.admin
    ```

## Deploying Antrea

1. Prepare the Cluster Nodes

    Deploy ``antrea-node-init`` DaemonSet to enable ``kubelet`` to operate in CNI mode.

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-gke-node-init.yml
    ```

2. Deploy Antrea

    To deploy a released version of Antrea, pick a deployment manifest from the
[list of releases](https://github.com/antrea-io/antrea/releases).
Note that GKE support was added in release 0.5.0, which means you cannot
pick a release older than 0.5.0. For any given release `<TAG>` (e.g. `v0.5.0`),
you can deploy Antrea as follows:

    ```bash
    kubectl apply -f https://github.com/antrea-io/antrea/releases/download/<TAG>/antrea-gke.yml
    ```

    To deploy the latest version of Antrea (built from the main branch), use the
checked-in [deployment yaml](/build/yamls/antrea-gke.yml):

    ```bash
    kubectl apply -f https://raw.githubusercontent.com/antrea-io/antrea/main/build/yamls/antrea-gke.yml
    ```

    The command will deploy a single replica of Antrea controller to the GKE
cluster and deploy Antrea agent to every Node. After a successful deployment
you should be able to see these Pods running in your cluster:

    ```bash
    $ kubectl get pods --namespace kube-system  -l app=antrea -o wide
    NAME                                READY   STATUS    RESTARTS   AGE   IP              NODE                                      NOMINATED NODE   READINESS GATES
    antrea-agent-24vwr                  2/2     Running   0          46s   10.138.15.209   gke-cluster1-default-pool-93d7da1c-rkbm   <none>           <none>
    antrea-agent-7dlcp                  2/2     Running   0          46s   10.138.15.206   gke-cluster1-default-pool-9ba12cea-wjzn   <none>           <none>
    antrea-controller-5f9985c59-5crt6   1/1     Running   0          46s   10.138.15.209   gke-cluster1-default-pool-93d7da1c-rkbm   <none>           <none>
    ```

3. Restart remaining Pods

    Once Antrea is up and running, restart all Pods in all Namespaces (kube-system, etc) so they can be managed by Antrea.

    ```bash
    $ kubectl delete pods -n kube-system $(kubectl get pods -n kube-system -o custom-columns=NAME:.metadata.name,HOSTNETWORK:.spec.hostNetwork --no-headers=true | grep '<none>' | awk '{ print $1 }')
    pod "event-exporter-gke-755c4b4d97-wqlcg" deleted
    pod "konnectivity-agent-5cb8ff9b9-2cv5j" deleted
    pod "konnectivity-agent-5cb8ff9b9-5jpvp" deleted
    pod "konnectivity-agent-autoscaler-7dc78c8c9-kqn9f" deleted
    pod "kube-dns-5b5dfcd97b-79m4c" deleted
    pod "kube-dns-5b5dfcd97b-q49qj" deleted
    pod "kube-dns-autoscaler-5f56f8997c-kqrgx" deleted
    pod "l7-default-backend-d6b749b76-bsv9l" deleted
    pod "metrics-server-v0.5.2-67864775dc-bhd9p" deleted
    ```

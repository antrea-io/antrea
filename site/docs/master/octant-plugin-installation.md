# Octant and antrea-octant-plugin installation

## Overview

There are two ways to deploy Octant and antrea-octant-plugin.

* Deploy Octant and antrea-octant-plugin as a Pod.

* Deploy Octant and antrea-octant-plugin as a process.


### Prerequisites
antrea-octant-plugin depends on the Antrea monitoring CRDs, AntreaControllerInfo and AntreaAgentInfo.

To run Octant together with antrea-octant-plugin, please make sure you have these two CRDs defined in you K8s cluster.

If Antrea is deployed before antrea-octant-plugin starts by using the standard deployment yaml, Antrea monitoring
CRDs should already be added. If not, please refer to [antrea.yaml](/build/yamls/antrea.yml) to
create these two CRDs first.

### Deploy Octant and antrea-octant-plugin as a Pod

You can follow the sample below to run Octant and antrea-octant-plugin in Pod.
In this example, we expose UI as a NodePort service for accessing externally.
You can update [antrea-octant.yaml](build/yamls/antrea-octant.yml) according to
your environment and preference.

1. Create a secret that contains your kubeconfig.

    ```bash
    # Change --from-file according to kubeconfig location in your set up.
    kubectl create secret generic octant-kubeconfig --from-file=/etc/kubernetes/admin.conf -n kube-system
    ```

2. You may need to update [build/yamls/antrea-octant.yml](/build/yamls/antrea-octant.yml) according to your kubeconfig file name.

3. You can change the sample yaml according to your requirements and environment, then apply the yaml to create both deployment and NodePort service.

    ```bash
    kubectl apply -f build/yamls/antrea-octant.yml
    ```
4. You can get the NodePort of antrea-octant service via kubectl.

    ```bash
    # See field NodePort
    kubectl describe service antrea-octant -n kube-system
    ```

Now, you are supposed to see Octant is running together with antrea-octant-plugin via URL http://(IP or $HOSTNAME):NodePort.

Note:
1. Docker image antrea/octant-antrea-ubuntu should be automatically downloaded
when you apply antrea-octant.yml in step 3. If the image is not successfully
downloaded which may be due to network issues, you can run command `make
octant-antrea-ubuntu` to build the image locally. If it is the case, you need
to make sure that the image exists on all the K8s Nodes since the antrea-octant
Pod may run on any of them.
2. If the Pod is running without any explicit issue but you can not access the
URL, please take a further look at the network configurations in your
environment. It may be due to the network policies or other security rules
configured on your hosts.
3. To deploy a released version of the plugin, you can download
`https://github.com/vmware-tanzu/antrea/releases/download/<TAG>/antrea-octant.yml`,
where `<TAG>` (e.g. `v0.7.0`) is the desired version (should match the version
of Antrea you are using). After making the necessary edits, you can apply the
yaml with `kubectl`.

### Deploy Octant and antrea-octant-plugin as a process

Refer to [Octant README](https://github.com/vmware-tanzu/octant/blob/master/README.md#installation) for 
detailed installation instructions.

You can follow the steps listed below to install octant and antrea-octant-plugin on linux.

1. Get and install Octant v0.10.2.

    Depending on your linux operating system, to install Octant v0.10.2, you can
    use either
    
    ```bash
    wget https://github.com/vmware-tanzu/octant/releases/download/v0.10.2/octant_0.10.2_Linux-64bit.deb
    dpkg -i octant_0.10.2_Linux-64bit.deb
    ```

    or

    ```bash
    wget https://github.com/vmware-tanzu/octant/releases/download/v0.10.2/octant_0.10.2_Linux-64bit.rpm
    rpm -i octant_0.10.2_Linux-64bit.rpm
    ```

2. Export your kubeconfig path (file location depends on your setup) to environment variable $KUBECONFIG.

    ```bash
    export KUBECONFIG=/etc/kubernetes/admin.conf
    ```

3. Build antrea-octant-plugin.

    ```bash
    make antrea-octant-plugin
    ```

4. Move antrea-octant-plugin to OCTANT_PLUGIN_PATH.

    ```bash
    # If you did not change OCTANT_PLUGIN_PATH, the default folder should be $HOME/.config/octant/plugins.
    mv antrea/bin/antrea-octant-plugin $HOME/.config/octant/plugins/
    ```

5. Start Octant as a background process with UI related environment variables.

    ```bash
    # Change port 80 according to your environment and set OCTANT_ACCEPTED_HOSTS based on your requirements
    OCTANT_LISTENER_ADDR=0.0.0.0:80 OCTANT_ACCEPTED_HOSTS=0.0.0.0 OCTANT_DISABLE_OPEN_BROWSER=true nohup octant &
    ```

Now, you are supposed to see Octant is running together with antrea-octant-plugin via URL `http://(IP or $HOSTNAME):80`.

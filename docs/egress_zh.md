# Egress

## 目录

<!-- toc -->
- [什么是Egress?](#Egress)
- [打开特性开关](#打开特性开关)
- [Egress资源](#Egress资源)
  - [AppliedTo字段](#AppliedTo字段)
  - [EgressIP字段](#EgressIP字段)
  - [ExternalIPPool字段](#ExternalIPPool字段)
- [ExternalIPPool资源](#ExternalIPPool资源)
  - [IPRanges字段](#IPRanges字段)
  - [NodeSelector字段](#NodeSelector字段)
- [使用示例](#使用示例)
  - [配置高可用的Egress来实现故障转移](#配置高可用的Egress来实现故障转移)
  - [配置静态Egress](#配置静态Egress)
- [限制条件](#限制条件)
<!-- /toc -->


## 什么是Egress?

`Egress`资源是用来管理集群内Pods的出口流量的CRD API。
它支持指定特定的Pods的出口流量从特定egressIP（源地址转换SNAT）出。
当一个被选择的Pod访问外部网络时，出口流量将被隧道到承载egressIP的节点，
如果该节点与Pod运行的节点不同，流量离开该节点时将被SNATed到对应的egressIP。

如果您有以下业务场景，您将有兴趣使用这个功能:

- 使用特定的pod连接到外部服务时，需要一个固定一致的IP地址在集群外，例如在审计日志中跟踪源，
或需要列入外部防火墙的源IP白名单等。

- 强制集群的出口连接通过某些固定节点，用于安全控制，或由于网络拓扑限制。

本指南指导如何配置`Egress`以实现上述结果。


## 打开特性开关

Egress在v1.0.0版本中作为alpha特性引入，和其他alpha特性一样，需要在antrea-controller和antrea-agent组件的配置文件
中打开`Egress`特性开关才能使用该特性。如下是`antrea-config`ConfigMap的示例：

```yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: antrea-config-dcfb6k2hkm
  namespace: kube-system
data:
  antrea-agent.conf: |
    featureGates:
      Egress: true
  antrea-controller.conf: |
    featureGates:
      Egress: true
```

## Egress资源

一个Egress资源示例:

```yaml
apiVersion: crd.antrea.io/v1alpha2
kind: Egress
metadata:
  name: egress-prod-web
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        env: prod
    podSelector:
      matchLabels:
        role: web
  egressIP: 10.10.0.8 # can be populated by Antrea after assigning an IP from the pool below
  externalIPPool: prod-external-ip-pool
status:
  egressNode: node01
```

### AppliedTo字段

AppliedTo指定Egress起作用的Pods范围。
可以使用`podSelector`在集群范围内选择Pods。也可以使用`namespaceSelector`来选定特定namespace内的所有Pods。
当然也可以同时指定`namespaceSelector`和`podSelector`，在特定的namespace中选定特定的Pods。
空的`appliedTo`将不指定任何Pods。注意这个字段是必选的。

### EgressIP字段

`egressIP`指定从选定的Pods到外部网络的出口流量的出口IP（SNAT）。**此IP必须对所有Nodes可达**
可以在创建Egress资源的时候指定该IP。从v1.2.0版本开始，可以通过`ExternalIPPool`资源来自动分配一个EgressIP。

- 如果没有指定`egressIP`，`externalIPPool`必须指定，
  antrea-controller将从externalIPPool指定的IP池中指定一个IP，即egressIP，
  随后antrea-agent将根据egressIP选择一个满足条件（`nodeSelector`）的Node，将egressIP配置到该Node上。

- 如何同时指定`egressIP`和`externalIPPool`，EgressIP必须在externalIPPool的IP范围内。
antrea-agent将把EgressIP自动配置到一个合适的Node。
  
- 如果只指定`egressIP`，则默认用户会手动配置相应的IP，Antrea不会做相应处理。

**从v1.2.0版本开始，Antrea提供了Egress故障转移功能**，如果指定了`externalIPPool`，
且满足`nodeSelector`条件的Node不止一个，如果egressIP所在的Node发生故障或被删除，
此时egressIP将被自动转移到其他满足条件的Node上。

**注意**如果一个Pod匹配了不止一个Egress而且他们的`egressIP`不同，将出口流量的egress IP将随机选择。

### ExternalIPPool字段

`externalIPPool`字段指定对应的`ExternalIPPool`资源名字，如果该字段不为空，egressIP将从对应的`ExternalIPPool`
中选择，对应egressIP的主机也将根据`ExternalIPPool`的`nodeSelector`从满足条件的Nodes中选择。
如果`externalIPPool`为空，则`egressIP`表示用户需要手动给Node配置一个egressIP。

## ExternalIPPool资源

ExternalIPPool定义一个或多个外部网络的IP池。IP池中的IP可以分配给Egress资源即egressIP。
如下是一个ExternalIPPool资源的示例：

```yaml
- apiVersion: crd.antrea.io/v1alpha2
  kind: ExternalIPPool
  metadata:
    name: prod-external-ip-pool
  spec:
    ipRanges:
    - start: 10.10.0.2
      end: 10.10.0.10
    - cidr: 10.10.1.0/28
    nodeSelector:
      matchLabels:
        network-role: egress-gateway
```

### IPRanges字段

`ipRanges`指定一个IP范围，代表该范围内的IP可用。每个IP范围由一个`cidr`或者`start`和
`end`定义，该集合是开集。

### NodeSelector字段

通过`nodeSelector`指定满足条件的Nodes范围，满足该条件的Nodes都可以作为IP池的可用主机。
该字段可以用来把出口流量限制在特定的Nodes范围内，`nodeSelector`的语法和其他Kubernetes资源标签的语法一致。
同时支持`matchLabels` 和 `matchExpressions`，如果`nodeSelector`为空，则表示所有Nodes都可选。

## 使用示例

### 配置高可用的Egress来实现故障转移

在下面的例子中，我们将在不同namespaces中的Pods使用不同的egressIPs来接入外部网络。

首先，创建一个带有可用IP地址池的`ExternalIPPool`资源。

```yaml
- apiVersion: crd.antrea.io/v1alpha2
  kind: ExternalIPPool
  metadata:
    name: external-ip-pool
  spec:
    ipRanges:
    - start: 10.10.0.11  # 10.10.0.11-10.10.0.20 can be used as Egress IPs
      end: 10.10.0.20
    nodeSelector: {}     # All Nodes can be Egress Nodes
```

创建两个`Egress`，分别指定到不同Namespace的web apps。

```yaml
apiVersion: crd.antrea.io/v1alpha2
kind: Egress
metadata:
  name: egress-prod-web
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: prod
    podSelector:
      matchLabels:
        app: web
  externalIPPool: external-ip-pool
---
apiVersion: crd.antrea.io/v1alpha2
kind: Egress
metadata:
  name: egress-staging-web
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: staging
    podSelector:
      matchLabels:
        app: web
  externalIPPool: external-ip-pool
```

列出所有`Egress`资源。
输出显示，每个Egress都被指定了一个IP池内的EgressIP，并指定了对应的Node节点。

```yaml
# kubectl get egress
NAME                 EGRESSIP       AGE   NODE
egress-prod-web      10.10.0.11     1m    node-4
egress-staging-web   10.10.0.12     1m    node-6
```

现在，Namespace`prod`中带有`app=web`标签的Pods的出口流量都将被重定向到节点`node-4`，源地址转化为`10.10.0.11`；
Namespace`staging`中带有`app=web`标签的Pods的出口流量都将被重定向到节点`node-6`，源地址转化为`10.10.0.12`。

最后，如果`node-4`掉电，`10.10.0.11`将很快被重新分配到其他满足条件的节点，
Namespace`prod`中带有`app=web`标签的Pods的出口流量都将被重定向到新的节点，
不用人工干预即可将egress连接的中断影响降到最小。

### 配置静态Egress

在下面这个例子中，我们将在不同namespaces中的Pods使用指定的Node IPs（任何配置到Node接口的IP地址）来接入外部网络。

由于egressIP已经配置到节点上了，在创建`Egress`资源时指定对应的IPs。

```yaml
apiVersion: crd.antrea.io/v1alpha2
kind: Egress
metadata:
  name: egress-prod
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: prod
  egressIP: 10.10.0.104   # node-4's IP
---
apiVersion: crd.antrea.io/v1alpha2
kind: Egress
metadata:
  name: egress-staging
spec:
  appliedTo:
    namespaceSelector:
      matchLabels:
        kubernetes.io/metadata.name: staging
  egressIP: 10.10.0.105   # node-5's IP
```

列出所有`Egress`资源。输出显示IP`10.10.0.104`在节点`node-4`上而IP`10.10.0.105`在节点`node-5`上。

```yaml
# kubectl get egress
NAME                 EGRESSIP       AGE   NODE
egress-prod          10.10.0.104    1m    node-4
egress-staging       10.10.0.105    1m    node-5
```

现在，Namespace`prod`中带有`app=web`标签的Pods的出口流量都将被重定向到节点`node-4`，源地址转化为`10.10.0.104`；
Namespace`staging`中带有`app=web`标签的Pods的出口流量都将被重定向到节点`node-5`，源地址转化为`10.10.0.105`。

在此种情况下，如果`node-4`掉电，重新配置IP`10.10.0.104`到别的节点上，
或者更新Egress`egress-prod`的egressIP为其他节点的IP，可以恢复出口连接。
Antrea将检测到配置变更并重定向Namespace`prod`内的Pods的流量包到新的节点。

## 限制条件

该特性目前只适用于"encap"模式的Linux系统的节点。
对Windows系统和其他流量模式的支持还在开发当中。

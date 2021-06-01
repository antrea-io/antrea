# Introduction

The purpose of this Kubernetes CNI scale testing tool is to evaluate the performance and scalability of
CNI within Kubernetes clusters.

The following sections detail these features and explain how to use the tool.

## 1. Scalability

Whether it's a cluster with a single node or hundreds of nodes, you can execute tests with just
a command line.

```shell
make bin
./bin/antrea-scale --kubeConfigPath=/root/.kube/config --timeout=120 --config=./test/performance/scale.yml
```

## 2. Configurability

You can easily configure the test parameters to meet various testing scenarios through a YAML file.

```yaml
real_node: true
repeat_times: 1
namespace_num: 5
pods_num_per_ns: 10
svc_num_per_ns: 4
np_num_per_ns: 5
skip_deploy_workload: false
teardown: false
scales:
  - name: "ScaleUpWorkloadPods"
    package: "test/performance/framework"
    repeat_times: 1
  - name: "ScaleService"
    package: "test/performance/framework"
    repeat_times: 1
  - name: "ScaleRestartAgent"
    package: "test/performance/framework"
    repeat_times: 1
  - name: "RestartController"
    package: "test/performance/framework"
    repeat_times: 1
  - name: "ScaleNetworkPolicy"
    package: "test/performance/framework"
    repeat_times: 1
```

## 3. Flexibility & Assemblability

The configuration file can be divided into two parts:
the first part controls the scale of the test,

```yaml
real_node: true
repeat_times: 1
namespace_num: 5
pods_num_per_ns: 10
svc_num_per_ns: 4
np_num_per_ns: 5
skip_deploy_workload: false
teardown: false
```

and the second part controls different test cases through the combination and arrangement of
individual test cases.

```yaml
scales:
  - name: "ScaleNetworkPolicy"
    package: "test/performance/framework"
    repeat_times: 1
  - name: "ScaleRestartAgent"
    package: "test/performance/framework"
    repeat_times: 1
```

For example, if we want to test whether the startup speed of the agent is affected after creating
NetworkPolicy on a large scale, we can place "ScaleNP" under "ScaleAgent."

Also, we can control the number of tests by setting the "repeat" parameter.

## 4. Efficient resource utilization(Antrea simulator agent)

A significant concern is that large-scale testing requires a vast amount of cluster resources.
We can use simulated agents to conduct tests to save resources and achieve the goal of scaling
tests with fewer resources.

If we want to test the performance of the Antrea Controller with limited node resources, we can
use the "realNode" parameter. Once disabled, the system will use simulated Antrea agent.
The simulator can watch the Antrea controller just like the real agent does, and it makes us
able to simulate a large number of agents in a smaller number of nodes. It is useful for Antrea
scalability testing, without having to create a very large cluster.

## 5. Multiple platforms(Different CNIs)

Additionally, for some common functional features, it's essential to compare the performance
differences between different CNIs to understand our shortcomings or advantages.
The scale test tool can run tests on different Kubernetes platforms and compare the performance
metrics of different CNIs.

## 6. Measure and monitoring

The Antrea scale test tool also integrates monitoring tools, with Prometheus and Grafana,
it's easy to view metrics such as CPU/Memory usage and the number of Pods/Networks during the
testing process.

![img.png](img.png)

## 7. Expanding test cases

Regarding the extensibility of the testing framework, we've designed a model in which test data is
separated from the framework. We expect the scale test tool to make it easy to add test cases
for new features.

You only need to design the test cases, add a separate YAML file, write and register the
test cases.

The detailed steps can be broken down into the following three steps:

1. Add a YAML file in the specified file path: `test/performance/assets`.

2. Write and register the test cases.

3. Configure the test cases to the file and execute the tests.

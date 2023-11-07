# Changelog CN 1.14

## 1.14.0

Antrea[1]项目是一个基于Open vSwitch（OVS）的开源Kubernetes CNI网络解决方案，旨在为Kubernetes集群提供更高效、更安全的跨平台网络和安全策略。
2023年10月28日，Antrea发布了最新版本v1.14.0[2]，Theia v0.8.0[3]也已经同步发布！
Antrea v1.14.0的发布非常值得关注，首先AntreaProxy、NodePortLocal和EndpointSlice这三个关键特性升级至GA版本，其可靠性在生产实践中得到测试验证，显示了我们致力于为Kubernetes提供强大可靠的网络解决方案的决心和能力。其次，此次发布还包含了许多亮眼的功能增强，例如Egress实现了QoS，用户现在可以通过Egress API指定和控制其apply的Pod的南北向出口流量的速率，实现网络资源的高效利用和QoS服务质量管理。同时Egress新增了新的字段可以查询Egress IP分配和挂载的状态，其可见性和可用性得到显著提升，更容易监测和定位相关问题。最后，此次发布还引入了可将Secondary Pod网络接口附加到VLAN网络的能力，确保了更广泛用例的最佳性能和网络隔离。Antrea NetworkPolicy也进行了一些增强：支持审计日志轮换配置以及Namespaced Group Membership API。在新的版本，我们也简化了Windows节点的部署流程，无需手动安装依赖项，同时多集群现在也可以通过一键yaml部署。
以下是本版本更新的详细清单：

## 主要功能
- 新增Egress速率限制配置，用于指定该Egress指定Pod的南北向出口流量的速率限制。（#5425, @GraysonWu）
- 在Egress状态中添加IPAllocated和IPAssigned状态，可以查询Egress IP的分配和挂载状态，以提高Egress的可见性。（#5282, @AJPL88 @tnqn）
- 在SupportBundle中为Antrea Agent和Antrea Controller添加goroutine堆栈转储。（#5538, @aniketraj1947）
- 在AntreaProxy服务的健康检查中添加“X-Load-Balancing-Endpoint-Weight”标头。（#5299, @hongliangl）
- 在Antrea Agent配置中为审计日志添加日志轮转配置。（#5337 #5366, @antoninbas @mengdie-song）
- 为Antrea Go clientset添加GroupMembers API分页支持。（#5533, @qiyueyao）
- 为Antrea Controller添加Namespaced Group Membership API。（#5380, @qiyueyao）
- 在VLAN网络上支持Pod的secondary interface。（#5341 #5365 #5279, @jianjuns）
- Windows OVS容器可以在主机环境上直接运行，无需提前手动安装某些依赖项。（#5440, @NamanAg30）
- 更新Install-WindowsCNI-Containerd.ps1脚本，使其兼容containerd 1.7。（#5528, @NamanAg30）
- 为Multi-cluster leader集群添加新的一键安装yaml，并更新Multi-cluster用户指南。（#5389 #5531, @luolanzone）
- 在删除ClusterSet时清理leader和member集群中的自动生成资源，并在member集群重新加入ClusterSet时重新创建资源。（#5351 #5410, @luolanzone）

## 其他变更

- 多个API从beta版本升级至GA版本，Antrea配置文件中相应的功能开关已移除。
   将EndpointSlice功能提升至GA版本。（#5393, @hongliangl）
   将NodePortLocal功能提升至GA版本。（#5491, @hjiajing）
   将AntreaProxy功能门提至GA版本，并添加antreaProxy.enable选项，以允许用户禁用该功能。（#5401, @hongliangl）
- 使antrea-controller不容忍不可达的Node，以加速故障转移过程。（#5521, @tnqn）
- 改进antctl get featuregates输出。（#5314, @cr7258）
- 增加PacketInMeter的速率限制设置和PacketInQueue的大小。（#5460, @GraysonWu）
- 为Flow Aggregator的Helm values添加hostAliases。（#5386, @yuntanghsu）
- 解除审计日志对AntreaPolicy功能门的依赖，以在禁用AntreaPolicy时启用NetworkPolicy的日志记录。（#5352, @qiyueyao）
- 将Traceflow CRD验证更改为webhook验证。（#5230, @shi0rik0）
- 停止在Antrea Agent中使用/bin/sh，并直接调用二进制文件执行OVS命令。（#5364, @antoninbas）
- 仅在启用Antrea Multi-cluster时，在EndpointDNAT中为嵌套服务安装流。（#5411, @hongliangl）
- 使PacketIn消息的速率限制可配置；对于依赖PacketIn消息的每个功能（例如Traceflow），都适用相同的速率限制值，但针对每个功能独立执行限制。（#5450, @GraysonWu）
- 将ARPSpoofGuardTable中默认流的动作更改为drop，有效地防止ARP欺骗。（#5378, @hongliangl）
- 删除ConfigMap名称的自动生成后缀，并在Windows yaml的Deployment注释中添加配置校验和，以在更新Antrea时避免旧的ConfigMaps，同时保留Pod的自动滚动更新。（#5545, @Atish-iaf）
- 为leader集群添加ClusterSet删除webhook，以拒绝存在任何MemberClusterAnnounce资源的ClusterSet删除请求。（#5475, @luolanzone）
- 将Go版本更新至v1.21。（#5377, @antoninbas）


## 问题修复

- 移除MulticastGroup API对NetworkPolicyStats功能开关的依赖，以修复用户运行kubectl get multicastgroups时即使启用了Multicast，仍出现空列表的问题。（#5367, @ceclinux）
- 修复Traceflow使用IPv6地址时antctl tf CLI失败的问题。（#5588, @Atish-iaf）
- 修复NetworkPolicy Controller中的死锁问题，此问题可能导致FQDN解析失败。（#5566 #5583, @Dyanngg @tnqn）
- 修复NetworkPolicy span计算问题，避免多个NetworkPolicies具有相同选择器时过时数据的问题。（#5554, @tnqn）
- 获取Node地址时使用第一个匹配地址，以找到正确的传输接口。（#5529, @xliuxu）
- 修复在CNI服务在CmdAdd失败后触发回滚调用的问题，并改进日志记录。（#5548, @antoninbas）
- 在Antrea网络的MTU超过Suricata支持的最大值时添加错误日志。（#5408, @hongliangl）
- 在路由协调器中不要删除IPv6链路本地路由，以修复跨Node Pod流量或Pod到外部流量的问题。（#5483, @wenyingd）
- 不将Egress应用于ServiceCIDRs的流量，以避免性能问题和意外行为。（#5495, @tnqn）
- 统一TCP和UDP DNS拦截流，以修复DNS响应的无效流匹配问题。（#5392, @GraysonWu）
- 更改PacketInQueue的burst设置，以减少应用FQDN策略的Pod的DNS响应延迟。（#5456, @tnqn）
- 修复Install-OVS.ps1在Windows上SSL库下载失败的问题。（#5510, @XinShuYang）
- 避免将Windows antrea-agents加入到memberlist集群，以避免引起误导的错误日志。（#5434, @tnqn）
- 修复antctl proxy未使用用户指定端口的问题。（#5435, @tnqn）
- 在桥接模式下，根据需要在OVS内部端口上启用IPv6，以修复启用IPAM时Agent崩溃的问题。（#5409, @antoninbas）
- 修复处理ANP命名端口时Service中的协议丢失问题，以确保可以正确执行OVS中的规则。（#5370, @Dyanngg）
- 修复在Agent无法连接到K8s API时的错误日志。（#5353, @tnqn）
- 修复Antrea Multi-cluster中ClusterSet状态未更新的bug。（#5338, @luolanzone）
- 修复Antrea Multi-cluster启用enableStretchedNetworkPolicy时，Antrea Controller在处理LabelIdentity中空Pod标签时导致的崩溃问题。（#5404 #5449, @Dyanngg）
- 始终初始化ovs_meter_packet_dropped_count指标，以修复如果系统不支持OVS Meter，则指标未显示的bug。（#5413, @tnqn）
- 为避免RBAC警告导致日志泛滥，跳过不需要的VM Agent模块的启动。（#5391, @mengdie-song）


## 致谢

感谢参与Antrea开源社区的每一位贡献者！


[@AJPL88]: https://github.com/AJPL88
[@Atish-iaf]: https://github.com/Atish-iaf
[@Dyanngg]: https://github.com/Dyanngg
[@GraysonWu]: https://github.com/GraysonWu
[@NamanAg30]: https://github.com/NamanAg30
[@XinShuYang]: https://github.com/XinShuYang
[@aniketraj1947]: https://github.com/aniketraj1947
[@antoninbas]: https://github.com/antoninbas
[@ceclinux]: https://github.com/ceclinux
[@cr7258]: https://github.com/cr7258
[@hongliangl]: https://github.com/hongliangl
[@hjiajing]: https://github.com/hjiajing
[@jianjuns]: https://github.com/jianjuns
[@luolanzone]: https://github.com/luolanzone
[@mengdie-song]: https://github.com/mengdie-song
[@qiyueyao]: https://github.com/qiyueyao
[@shi0rik0]: https://github.com/shi0rik0
[@tnqn]: https://github.com/tnqn
[@wenyingd]: https://github.com/wenyingd
[@xliuxu]: https://github.com/xliuxu
[@yuntanghsu]: https://github.com/yuntanghsu


## Antrea中文社区

✨ GitHub：https://github.com/antrea-io/antrea

💻 官网：https://antrea.io

👨‍💻 微信群：请搜索添加“Antrea”微信官方公众号进群





## 参考链接


[1]Antrea:

https://github.com/antrea-io/antrea

[2]v1.14.0:

https://github.com/antrea-io/antrea/releases/tag/v1.14.0


[3] Theia v0.8.0:

https://github.com/antrea-io/theia/releases/tag/v0.8.0

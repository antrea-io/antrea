<p>Packages:</p>
<ul>
<li>
<a href="#controlplane.antrea.io%2fv1beta1">controlplane.antrea.io/v1beta1</a>
</li>
<li>
<a href="#controlplane.antrea.io%2fv1beta2">controlplane.antrea.io/v1beta2</a>
</li>
<li>
<a href="#crd.antrea.io%2fv1alpha1">crd.antrea.io/v1alpha1</a>
</li>
<li>
<a href="#crd.antrea.io%2fv1alpha2">crd.antrea.io/v1alpha2</a>
</li>
<li>
<a href="#crd.antrea.io%2fv1beta1">crd.antrea.io/v1beta1</a>
</li>
<li>
<a href="#stats.antrea.io%2fv1alpha1">stats.antrea.io/v1alpha1</a>
</li>
<li>
<a href="#system.antrea.io%2fv1beta1">system.antrea.io/v1beta1</a>
</li>
</ul>
<h2 id="controlplane.antrea.io/v1beta1">controlplane.antrea.io/v1beta1</h2>
<p>
<p>Package v1beta1 is the v1beta1 version of the Antrea NetworkPolicy API messages.</p>
</p>
Resource Types:
<ul><li>
<a href="#controlplane.antrea.io/v1beta1.NodeStatsSummary">NodeStatsSummary</a>
</li></ul>
<h3 id="controlplane.antrea.io/v1beta1.NodeStatsSummary">NodeStatsSummary
</h3>
<p>
<p>NodeStatsSummary contains stats produced on a Node. It&rsquo;s used by the antrea-agents to report stats to the antrea-controller.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
controlplane.antrea.io/v1beta1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>NodeStatsSummary</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>networkPolicies</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyStats">
[]NetworkPolicyStats
</a>
</em>
</td>
<td>
<p>The TrafficStats of K8s NetworkPolicies collected from the Node.</p>
</td>
</tr>
<tr>
<td>
<code>antreaClusterNetworkPolicies</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyStats">
[]NetworkPolicyStats
</a>
</em>
</td>
<td>
<p>The TrafficStats of Antrea ClusterNetworkPolicies collected from the Node.</p>
</td>
</tr>
<tr>
<td>
<code>antreaNetworkPolicies</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyStats">
[]NetworkPolicyStats
</a>
</em>
</td>
<td>
<p>The TrafficStats of Antrea NetworkPolicies collected from the Node.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.AddressGroup">AddressGroup
</h3>
<p>
<p>AddressGroup is the message format of antrea/pkg/controller/types.AddressGroup in an API response.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>pods</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMemberPod">
[]GroupMemberPod
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>groupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.AddressGroupPatch">AddressGroupPatch
</h3>
<p>
<p>AddressGroupPatch describes the incremental update of an AddressGroup.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>addedPods</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMemberPod">
[]GroupMemberPod
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>removedPods</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMemberPod">
[]GroupMemberPod
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>addedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>removedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.AppliedToGroup">AppliedToGroup
</h3>
<p>
<p>AppliedToGroup is the message format of antrea/pkg/controller/types.AppliedToGroup in an API response.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>pods</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMemberPod">
[]GroupMemberPod
</a>
</em>
</td>
<td>
<p>Pods is a list of Pods selected by this group.</p>
</td>
</tr>
<tr>
<td>
<code>groupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
<p>GroupMembers is list of resources selected by this group. This eventually will replace Pods</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.AppliedToGroupPatch">AppliedToGroupPatch
</h3>
<p>
<p>AppliedToGroupPatch describes the incremental update of an AppliedToGroup.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>addedPods</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMemberPod">
[]GroupMemberPod
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>removedPods</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMemberPod">
[]GroupMemberPod
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>addedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>removedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.Direction">Direction
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyRule">NetworkPolicyRule</a>)
</p>
<p>
<p>Direction defines traffic direction of NetworkPolicyRule.</p>
</p>
<h3 id="controlplane.antrea.io/v1beta1.Endpoint">Endpoint
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.GroupMember">GroupMember</a>)
</p>
<p>
<p>Endpoint represents an external endpoint.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>ip</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.IPAddress">
IPAddress
</a>
</em>
</td>
<td>
<p>IP is the IP address of the Endpoint.</p>
</td>
</tr>
<tr>
<td>
<code>ports</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NamedPort">
[]NamedPort
</a>
</em>
</td>
<td>
<p>Ports is the list NamedPort of the Endpoint.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.ExternalEntityReference">ExternalEntityReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.GroupMember">GroupMember</a>)
</p>
<p>
<p>ExternalEntityReference represents a ExternalEntity Reference.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>The name of this ExternalEntity.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>The namespace of this ExternalEntity.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.GroupMember">GroupMember
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.AddressGroup">AddressGroup</a>, 
<a href="#controlplane.antrea.io/v1beta1.AddressGroupPatch">AddressGroupPatch</a>, 
<a href="#controlplane.antrea.io/v1beta1.AppliedToGroup">AppliedToGroup</a>, 
<a href="#controlplane.antrea.io/v1beta1.AppliedToGroupPatch">AppliedToGroupPatch</a>)
</p>
<p>
<p>GroupMember represents resource member to be populated in Groups.
This supersedes GroupMemberPod, and will eventually replace it.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>pod</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.PodReference">
PodReference
</a>
</em>
</td>
<td>
<p>Pod maintains the reference to the Pod.</p>
</td>
</tr>
<tr>
<td>
<code>externalEntity</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.ExternalEntityReference">
ExternalEntityReference
</a>
</em>
</td>
<td>
<p>ExternalEntity maintains the reference to the ExternalEntity.</p>
</td>
</tr>
<tr>
<td>
<code>endpoints</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.Endpoint">
[]Endpoint
</a>
</em>
</td>
<td>
<p>Endpoints maintains a list of EndPoints associated with this groupMember.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.GroupMemberPod">GroupMemberPod
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.AddressGroup">AddressGroup</a>, 
<a href="#controlplane.antrea.io/v1beta1.AddressGroupPatch">AddressGroupPatch</a>, 
<a href="#controlplane.antrea.io/v1beta1.AppliedToGroup">AppliedToGroup</a>, 
<a href="#controlplane.antrea.io/v1beta1.AppliedToGroupPatch">AppliedToGroupPatch</a>)
</p>
<p>
<p>GroupMemberPod represents a GroupMember related to Pods.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>pod</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.PodReference">
PodReference
</a>
</em>
</td>
<td>
<p>Pod maintains the reference to the Pod.</p>
</td>
</tr>
<tr>
<td>
<code>ip</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.IPAddress">
IPAddress
</a>
</em>
</td>
<td>
<p>IP maintains the IPAddress associated with the Pod.</p>
</td>
</tr>
<tr>
<td>
<code>ports</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NamedPort">
[]NamedPort
</a>
</em>
</td>
<td>
<p>Ports maintain the named port mapping of this Pod.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.GroupMemberPodSet">GroupMemberPodSet
(<code>map[github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1.groupMemberPodKey]*github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1.GroupMemberPod</code> alias)</p></h3>
<p>
<p>GroupMemberPodSet is a set of GroupMemberPods.</p>
</p>
<h3 id="controlplane.antrea.io/v1beta1.GroupMemberSet">GroupMemberSet
(<code>map[github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1.groupMemberKey]*github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta1.GroupMember</code> alias)</p></h3>
<p>
<p>GroupMemberSet is a set of GroupMembers.</p>
</p>
<h3 id="controlplane.antrea.io/v1beta1.IPAddress">IPAddress
(<code>[]byte</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.Endpoint">Endpoint</a>, 
<a href="#controlplane.antrea.io/v1beta1.GroupMemberPod">GroupMemberPod</a>, 
<a href="#controlplane.antrea.io/v1beta1.IPNet">IPNet</a>)
</p>
<p>
<p>IPAddress describes a single IP address. Either an IPv4 or IPv6 address must be set.</p>
</p>
<h3 id="controlplane.antrea.io/v1beta1.IPBlock">IPBlock
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyPeer">NetworkPolicyPeer</a>)
</p>
<p>
<p>IPBlock describes a particular CIDR (Ex. &ldquo;192.168.1.<sup>1</sup>&frasl;<sub>24</sub>&rdquo;). The except entry describes CIDRs that should
not be included within this rule.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>cidr</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.IPNet">
IPNet
</a>
</em>
</td>
<td>
<p>CIDR is an IPNet represents the IP Block.</p>
</td>
</tr>
<tr>
<td>
<code>except</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.IPNet">
[]IPNet
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Except is a slice of IPNets that should not be included within an IP Block.
Except values will be rejected if they are outside the CIDR range.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.IPNet">IPNet
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.IPBlock">IPBlock</a>)
</p>
<p>
<p>IPNet describes an IP network.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>ip</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.IPAddress">
IPAddress
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>prefixLength</code></br>
<em>
int32
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.NamedPort">NamedPort
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.Endpoint">Endpoint</a>, 
<a href="#controlplane.antrea.io/v1beta1.GroupMemberPod">GroupMemberPod</a>)
</p>
<p>
<p>NamedPort represents a Port with a name on Pod.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>port</code></br>
<em>
int32
</em>
</td>
<td>
<p>Port represents the Port number.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name represents the associated name with this Port number.</p>
</td>
</tr>
<tr>
<td>
<code>protocol</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.Protocol">
Protocol
</a>
</em>
</td>
<td>
<p>Protocol for port. Must be UDP, TCP, or SCTP.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.NetworkPolicy">NetworkPolicy
</h3>
<p>
<p>NetworkPolicy is the message format of antrea/pkg/controller/types.NetworkPolicy in an API response.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>rules</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyRule">
[]NetworkPolicyRule
</a>
</em>
</td>
<td>
<p>Rules is a list of rules to be applied to the selected Pods.</p>
</td>
</tr>
<tr>
<td>
<code>appliedToGroups</code></br>
<em>
[]string
</em>
</td>
<td>
<p>AppliedToGroups is a list of names of AppliedToGroups to which this policy applies.</p>
</td>
</tr>
<tr>
<td>
<code>priority</code></br>
<em>
float64
</em>
</td>
<td>
<p>Priority represents the relative priority of this Network Policy as compared to
other Network Policies. Priority will be unset (nil) for K8s NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>tierPriority</code></br>
<em>
int32
</em>
</td>
<td>
<p>TierPriority represents the priority of the Tier associated with this Network
Policy. The TierPriority will remain nil for K8s NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>sourceRef</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyReference">
NetworkPolicyReference
</a>
</em>
</td>
<td>
<p>Reference to the original NetworkPolicy that the internal NetworkPolicy is created for.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.NetworkPolicyPeer">NetworkPolicyPeer
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyRule">NetworkPolicyRule</a>)
</p>
<p>
<p>NetworkPolicyPeer describes a peer of NetworkPolicyRules.
It could be a list of names of AddressGroups and/or a list of IPBlock.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>addressGroups</code></br>
<em>
[]string
</em>
</td>
<td>
<p>A list of names of AddressGroups.</p>
</td>
</tr>
<tr>
<td>
<code>ipBlocks</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.IPBlock">
[]IPBlock
</a>
</em>
</td>
<td>
<p>A list of IPBlock.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.NetworkPolicyReference">NetworkPolicyReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicy">NetworkPolicy</a>, 
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyStats">NetworkPolicyStats</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>type</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyType">
NetworkPolicyType
</a>
</em>
</td>
<td>
<p>Type of the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>Namespace of the NetworkPolicy. It&rsquo;s empty for Antrea ClusterNetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name of the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>uid</code></br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/types#UID">
k8s.io/apimachinery/pkg/types.UID
</a>
</em>
</td>
<td>
<p>UID of the NetworkPolicy.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.NetworkPolicyRule">NetworkPolicyRule
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicy">NetworkPolicy</a>)
</p>
<p>
<p>NetworkPolicyRule describes a particular set of traffic that is allowed.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>direction</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.Direction">
Direction
</a>
</em>
</td>
<td>
<p>The direction of this rule.
If it&rsquo;s set to In, From must be set and To must not be set.
If it&rsquo;s set to Out, To must be set and From must not be set.</p>
</td>
</tr>
<tr>
<td>
<code>from</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyPeer">
NetworkPolicyPeer
</a>
</em>
</td>
<td>
<p>From represents sources which should be able to access the pods selected by the policy.</p>
</td>
</tr>
<tr>
<td>
<code>to</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyPeer">
NetworkPolicyPeer
</a>
</em>
</td>
<td>
<p>To represents destinations which should be able to be accessed by the pods selected by the policy.</p>
</td>
</tr>
<tr>
<td>
<code>services</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.Service">
[]Service
</a>
</em>
</td>
<td>
<p>Services is a list of services which should be matched.</p>
</td>
</tr>
<tr>
<td>
<code>priority</code></br>
<em>
int32
</em>
</td>
<td>
<p>Priority defines the priority of the Rule as compared to other rules in the
NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>action</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.RuleAction">
RuleAction
</a>
</em>
</td>
<td>
<p>Action specifies the action to be applied on the rule. i.e. Allow/Drop. An empty
action “nil” defaults to Allow action, which would be the case for rules created for
K8s Network Policy.</p>
</td>
</tr>
<tr>
<td>
<code>enableLogging</code></br>
<em>
bool
</em>
</td>
<td>
<p>EnableLogging indicates whether or not to generate logs when rules are matched. Default to false.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.NetworkPolicyStats">NetworkPolicyStats
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NodeStatsSummary">NodeStatsSummary</a>)
</p>
<p>
<p>NetworkPolicyStats contains the information and traffic stats of a NetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>networkPolicy</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyReference">
NetworkPolicyReference
</a>
</em>
</td>
<td>
<p>The reference of the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>trafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.TrafficStats">
TrafficStats
</a>
</em>
</td>
<td>
<p>The stats of the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>ruleTrafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.RuleTrafficStats">
[]RuleTrafficStats
</a>
</em>
</td>
<td>
<p>The stats of the NetworkPolicy rules. It&rsquo;s empty for K8s NetworkPolicies as they don&rsquo;t have rule name to identify a rule.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.NetworkPolicyType">NetworkPolicyType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyReference">NetworkPolicyReference</a>)
</p>
<p>
</p>
<h3 id="controlplane.antrea.io/v1beta1.PodReference">PodReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.GroupMember">GroupMember</a>, 
<a href="#controlplane.antrea.io/v1beta1.GroupMemberPod">GroupMemberPod</a>)
</p>
<p>
<p>PodReference represents a Pod Reference.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>The name of this pod.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>The namespace of this pod.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta1.Protocol">Protocol
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NamedPort">NamedPort</a>, 
<a href="#controlplane.antrea.io/v1beta1.Service">Service</a>)
</p>
<p>
<p>Protocol defines network protocols supported for things like container ports.</p>
</p>
<h3 id="controlplane.antrea.io/v1beta1.Service">Service
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyRule">NetworkPolicyRule</a>)
</p>
<p>
<p>Service describes a port to allow traffic on.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>protocol</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta1.Protocol">
Protocol
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The protocol (TCP, UDP, or SCTP) which traffic must match. If not specified, this
field defaults to TCP.</p>
</td>
</tr>
<tr>
<td>
<code>port</code></br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/util/intstr#IntOrString">
k8s.io/apimachinery/pkg/util/intstr.IntOrString
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The port name or number on the given protocol. If not specified, this matches all port numbers.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<h2 id="controlplane.antrea.io/v1beta2">controlplane.antrea.io/v1beta2</h2>
<p>
<p>Package v1beta2 is the v1beta2 version of the Antrea NetworkPolicy API messages.</p>
</p>
Resource Types:
<ul><li>
<a href="#controlplane.antrea.io/v1beta2.NodeStatsSummary">NodeStatsSummary</a>
</li></ul>
<h3 id="controlplane.antrea.io/v1beta2.NodeStatsSummary">NodeStatsSummary
</h3>
<p>
<p>NodeStatsSummary contains stats produced on a Node. It&rsquo;s used by the antrea-agents to report stats to the antrea-controller.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
controlplane.antrea.io/v1beta2
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>NodeStatsSummary</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>networkPolicies</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyStats">
[]NetworkPolicyStats
</a>
</em>
</td>
<td>
<p>The TrafficStats of K8s NetworkPolicies collected from the Node.</p>
</td>
</tr>
<tr>
<td>
<code>antreaClusterNetworkPolicies</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyStats">
[]NetworkPolicyStats
</a>
</em>
</td>
<td>
<p>The TrafficStats of Antrea ClusterNetworkPolicies collected from the Node.</p>
</td>
</tr>
<tr>
<td>
<code>antreaNetworkPolicies</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyStats">
[]NetworkPolicyStats
</a>
</em>
</td>
<td>
<p>The TrafficStats of Antrea NetworkPolicies collected from the Node.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.AddressGroup">AddressGroup
</h3>
<p>
<p>AddressGroup is the message format of antrea/pkg/controller/types.AddressGroup in an API response.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>groupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.AddressGroupPatch">AddressGroupPatch
</h3>
<p>
<p>AddressGroupPatch describes the incremental update of an AddressGroup.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>addedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>removedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.AppliedToGroup">AppliedToGroup
</h3>
<p>
<p>AppliedToGroup is the message format of antrea/pkg/controller/types.AppliedToGroup in an API response.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>groupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
<p>GroupMembers is list of resources selected by this group.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.AppliedToGroupPatch">AppliedToGroupPatch
</h3>
<p>
<p>AppliedToGroupPatch describes the incremental update of an AppliedToGroup.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>addedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>removedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.ClusterGroupMembers">ClusterGroupMembers
</h3>
<p>
<p>ClusterGroupMembers is a list of GroupMember objects that are currently selected by a ClusterGroup.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>effectiveMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.Direction">Direction
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyRule">NetworkPolicyRule</a>)
</p>
<p>
<p>Direction defines traffic direction of NetworkPolicyRule.</p>
</p>
<h3 id="controlplane.antrea.io/v1beta2.EgressGroup">EgressGroup
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>groupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
<p>GroupMembers is list of resources selected by this group.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.EgressGroupPatch">EgressGroupPatch
</h3>
<p>
<p>EgressGroupPatch describes the incremental update of an EgressGroup.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>ObjectMeta</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>AddedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>RemovedGroupMembers</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">
[]GroupMember
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.ExternalEntityReference">ExternalEntityReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">GroupMember</a>)
</p>
<p>
<p>ExternalEntityReference represents a ExternalEntity Reference.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>The name of this ExternalEntity.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>The Namespace of this ExternalEntity.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.GroupAssociation">GroupAssociation
</h3>
<p>
<p>GroupAssociation is the message format in an API response for groupassociation queries.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>associatedGroups</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.GroupReference">
[]GroupReference
</a>
</em>
</td>
<td>
<p>AssociatedGroups is a list of GroupReferences that is associated with the
Pod/ExternalEntity being queried.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.GroupMember">GroupMember
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.AddressGroup">AddressGroup</a>, 
<a href="#controlplane.antrea.io/v1beta2.AddressGroupPatch">AddressGroupPatch</a>, 
<a href="#controlplane.antrea.io/v1beta2.AppliedToGroup">AppliedToGroup</a>, 
<a href="#controlplane.antrea.io/v1beta2.AppliedToGroupPatch">AppliedToGroupPatch</a>, 
<a href="#controlplane.antrea.io/v1beta2.ClusterGroupMembers">ClusterGroupMembers</a>, 
<a href="#controlplane.antrea.io/v1beta2.EgressGroup">EgressGroup</a>, 
<a href="#controlplane.antrea.io/v1beta2.EgressGroupPatch">EgressGroupPatch</a>)
</p>
<p>
<p>GroupMember represents resource member to be populated in Groups.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>pod</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.PodReference">
PodReference
</a>
</em>
</td>
<td>
<p>Pod maintains the reference to the Pod.</p>
</td>
</tr>
<tr>
<td>
<code>externalEntity</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.ExternalEntityReference">
ExternalEntityReference
</a>
</em>
</td>
<td>
<p>ExternalEntity maintains the reference to the ExternalEntity.</p>
</td>
</tr>
<tr>
<td>
<code>ips</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.IPAddress">
[]IPAddress
</a>
</em>
</td>
<td>
<p>IP is the IP address of the Endpoints associated with the GroupMember.</p>
</td>
</tr>
<tr>
<td>
<code>ports</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NamedPort">
[]NamedPort
</a>
</em>
</td>
<td>
<p>Ports is the list NamedPort of the GroupMember.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.GroupMemberSet">GroupMemberSet
(<code>map[github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2.groupMemberKey]*github.com/vmware-tanzu/antrea/pkg/apis/controlplane/v1beta2.GroupMember</code> alias)</p></h3>
<p>
<p>GroupMemberSet is a set of GroupMembers.</p>
</p>
<h3 id="controlplane.antrea.io/v1beta2.GroupReference">GroupReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.GroupAssociation">GroupAssociation</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>Namespace of the Group. Empty for ClusterGroup.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name of the Group.</p>
</td>
</tr>
<tr>
<td>
<code>uid</code></br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/types#UID">
k8s.io/apimachinery/pkg/types.UID
</a>
</em>
</td>
<td>
<p>UID of the Group.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.IPAddress">IPAddress
(<code>[]byte</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">GroupMember</a>, 
<a href="#controlplane.antrea.io/v1beta2.IPNet">IPNet</a>)
</p>
<p>
<p>IPAddress describes a single IP address. Either an IPv4 or IPv6 address must be set.</p>
</p>
<h3 id="controlplane.antrea.io/v1beta2.IPBlock">IPBlock
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyPeer">NetworkPolicyPeer</a>)
</p>
<p>
<p>IPBlock describes a particular CIDR (Ex. &ldquo;192.168.1.<sup>1</sup>&frasl;<sub>24</sub>&rdquo;). The except entry describes CIDRs that should
not be included within this rule.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>cidr</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.IPNet">
IPNet
</a>
</em>
</td>
<td>
<p>CIDR is an IPNet represents the IP Block.</p>
</td>
</tr>
<tr>
<td>
<code>except</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.IPNet">
[]IPNet
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Except is a slice of IPNets that should not be included within an IP Block.
Except values will be rejected if they are outside the CIDR range.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.IPNet">IPNet
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.IPBlock">IPBlock</a>)
</p>
<p>
<p>IPNet describes an IP network.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>ip</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.IPAddress">
IPAddress
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>prefixLength</code></br>
<em>
int32
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.NamedPort">NamedPort
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">GroupMember</a>)
</p>
<p>
<p>NamedPort represents a Port with a name on Pod.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>port</code></br>
<em>
int32
</em>
</td>
<td>
<p>Port represents the Port number.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name represents the associated name with this Port number.</p>
</td>
</tr>
<tr>
<td>
<code>protocol</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.Protocol">
Protocol
</a>
</em>
</td>
<td>
<p>Protocol for port. Must be UDP, TCP, or SCTP.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.NetworkPolicy">NetworkPolicy
</h3>
<p>
<p>NetworkPolicy is the message format of antrea/pkg/controller/types.NetworkPolicy in an API response.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>rules</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyRule">
[]NetworkPolicyRule
</a>
</em>
</td>
<td>
<p>Rules is a list of rules to be applied to the selected GroupMembers.</p>
</td>
</tr>
<tr>
<td>
<code>appliedToGroups</code></br>
<em>
[]string
</em>
</td>
<td>
<p>AppliedToGroups is a list of names of AppliedToGroups to which this policy applies.
Cannot be set in conjunction with any NetworkPolicyRule.AppliedToGroups in Rules.</p>
</td>
</tr>
<tr>
<td>
<code>priority</code></br>
<em>
float64
</em>
</td>
<td>
<p>Priority represents the relative priority of this Network Policy as compared to
other Network Policies. Priority will be unset (nil) for K8s NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>tierPriority</code></br>
<em>
int32
</em>
</td>
<td>
<p>TierPriority represents the priority of the Tier associated with this Network
Policy. The TierPriority will remain nil for K8s NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>sourceRef</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyReference">
NetworkPolicyReference
</a>
</em>
</td>
<td>
<p>Reference to the original NetworkPolicy that the internal NetworkPolicy is created for.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.NetworkPolicyNodeStatus">NetworkPolicyNodeStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyStatus">NetworkPolicyStatus</a>)
</p>
<p>
<p>NetworkPolicyNodeStatus is the status of a NetworkPolicy on a Node.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>nodeName</code></br>
<em>
string
</em>
</td>
<td>
<p>The name of the Node that produces the status.</p>
</td>
</tr>
<tr>
<td>
<code>generation</code></br>
<em>
int64
</em>
</td>
<td>
<p>The generation realized by the Node.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.NetworkPolicyPeer">NetworkPolicyPeer
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyRule">NetworkPolicyRule</a>)
</p>
<p>
<p>NetworkPolicyPeer describes a peer of NetworkPolicyRules.
It could be a list of names of AddressGroups and/or a list of IPBlock.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>addressGroups</code></br>
<em>
[]string
</em>
</td>
<td>
<p>A list of names of AddressGroups.</p>
</td>
</tr>
<tr>
<td>
<code>ipBlocks</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.IPBlock">
[]IPBlock
</a>
</em>
</td>
<td>
<p>A list of IPBlock.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.NetworkPolicyReference">NetworkPolicyReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicy">NetworkPolicy</a>, 
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyStats">NetworkPolicyStats</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>type</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyType">
NetworkPolicyType
</a>
</em>
</td>
<td>
<p>Type of the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>Namespace of the NetworkPolicy. It&rsquo;s empty for Antrea ClusterNetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name of the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>uid</code></br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/types#UID">
k8s.io/apimachinery/pkg/types.UID
</a>
</em>
</td>
<td>
<p>UID of the NetworkPolicy.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.NetworkPolicyRule">NetworkPolicyRule
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicy">NetworkPolicy</a>)
</p>
<p>
<p>NetworkPolicyRule describes a particular set of traffic that is allowed.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>direction</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.Direction">
Direction
</a>
</em>
</td>
<td>
<p>The direction of this rule.
If it&rsquo;s set to In, From must be set and To must not be set.
If it&rsquo;s set to Out, To must be set and From must not be set.</p>
</td>
</tr>
<tr>
<td>
<code>from</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyPeer">
NetworkPolicyPeer
</a>
</em>
</td>
<td>
<p>From represents sources which should be able to access the GroupMembers selected by the policy.</p>
</td>
</tr>
<tr>
<td>
<code>to</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyPeer">
NetworkPolicyPeer
</a>
</em>
</td>
<td>
<p>To represents destinations which should be able to be accessed by the GroupMembers selected by the policy.</p>
</td>
</tr>
<tr>
<td>
<code>services</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.Service">
[]Service
</a>
</em>
</td>
<td>
<p>Services is a list of services which should be matched.</p>
</td>
</tr>
<tr>
<td>
<code>priority</code></br>
<em>
int32
</em>
</td>
<td>
<p>Priority defines the priority of the Rule as compared to other rules in the
NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>action</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.RuleAction">
RuleAction
</a>
</em>
</td>
<td>
<p>Action specifies the action to be applied on the rule. i.e. Allow/Drop. An empty
action “nil” defaults to Allow action, which would be the case for rules created for
K8s Network Policy.</p>
</td>
</tr>
<tr>
<td>
<code>enableLogging</code></br>
<em>
bool
</em>
</td>
<td>
<p>EnableLogging indicates whether or not to generate logs when rules are matched. Default to false.</p>
</td>
</tr>
<tr>
<td>
<code>appliedToGroups</code></br>
<em>
[]string
</em>
</td>
<td>
<p>AppliedToGroups is a list of names of AppliedToGroups to which this rule applies.
Cannot be set in conjunction with NetworkPolicy.AppliedToGroups of the NetworkPolicy
that this Rule is referred to.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name describes the intention of this rule.
Name should be unique within the policy.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.NetworkPolicyStats">NetworkPolicyStats
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NodeStatsSummary">NodeStatsSummary</a>)
</p>
<p>
<p>NetworkPolicyStats contains the information and traffic stats of a NetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>networkPolicy</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyReference">
NetworkPolicyReference
</a>
</em>
</td>
<td>
<p>The reference of the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>trafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.TrafficStats">
TrafficStats
</a>
</em>
</td>
<td>
<p>The stats of the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>ruleTrafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.RuleTrafficStats">
[]RuleTrafficStats
</a>
</em>
</td>
<td>
<p>The stats of the NetworkPolicy rules. It&rsquo;s empty for K8s NetworkPolicies as they don&rsquo;t have rule name to identify a rule.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.NetworkPolicyStatus">NetworkPolicyStatus
</h3>
<p>
<p>NetworkPolicyStatus is the status of a NetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>nodes</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyNodeStatus">
[]NetworkPolicyNodeStatus
</a>
</em>
</td>
<td>
<p>Nodes contains statuses produced on a list of Nodes.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.NetworkPolicyType">NetworkPolicyType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyReference">NetworkPolicyReference</a>)
</p>
<p>
</p>
<h3 id="controlplane.antrea.io/v1beta2.PodReference">PodReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.GroupMember">GroupMember</a>)
</p>
<p>
<p>PodReference represents a Pod Reference.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>The name of this Pod.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>The Namespace of this Pod.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.Protocol">Protocol
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NamedPort">NamedPort</a>, 
<a href="#controlplane.antrea.io/v1beta2.Service">Service</a>)
</p>
<p>
<p>Protocol defines network protocols supported for things like container ports.</p>
</p>
<h3 id="controlplane.antrea.io/v1beta2.Service">Service
</h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyRule">NetworkPolicyRule</a>)
</p>
<p>
<p>Service describes a port to allow traffic on.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>protocol</code></br>
<em>
<a href="#controlplane.antrea.io/v1beta2.Protocol">
Protocol
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The protocol (TCP, UDP, or SCTP) which traffic must match. If not specified, this
field defaults to TCP.</p>
</td>
</tr>
<tr>
<td>
<code>port</code></br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/util/intstr#IntOrString">
k8s.io/apimachinery/pkg/util/intstr.IntOrString
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The port name or number on the given protocol. If not specified, this matches all port numbers.</p>
</td>
</tr>
<tr>
<td>
<code>endPort</code></br>
<em>
int32
</em>
</td>
<td>
<em>(Optional)</em>
<p>EndPort defines the end of the port range, being the end included within the range.
It can only be specified when a numerical <code>port</code> is specified.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="controlplane.antrea.io/v1beta2.ServiceReference">ServiceReference
</h3>
<p>
<p>ServiceReference represents reference to a v1.Service.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>The name of this Service.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>The Namespace of this Service.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<h2 id="crd.antrea.io/v1alpha1">crd.antrea.io/v1alpha1</h2>
Resource Types:
<ul><li>
<a href="#crd.antrea.io/v1alpha1.ClusterNetworkPolicy">ClusterNetworkPolicy</a>
</li><li>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicy">NetworkPolicy</a>
</li><li>
<a href="#crd.antrea.io/v1alpha1.Tier">Tier</a>
</li></ul>
<h3 id="crd.antrea.io/v1alpha1.ClusterNetworkPolicy">ClusterNetworkPolicy
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
crd.antrea.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>ClusterNetworkPolicy</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<p>Standard metadata of the object.</p>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.ClusterNetworkPolicySpec">
ClusterNetworkPolicySpec
</a>
</em>
</td>
<td>
<p>Specification of the desired behavior of ClusterNetworkPolicy.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>tier</code></br>
<em>
string
</em>
</td>
<td>
<p>Tier specifies the tier to which this ClusterNetworkPolicy belongs to.
The ClusterNetworkPolicy order will be determined based on the
combination of the Tier&rsquo;s Priority and the ClusterNetworkPolicy&rsquo;s own
Priority. If not specified, this policy will be created in the Application
Tier right above the K8s NetworkPolicy which resides at the bottom.</p>
</td>
</tr>
<tr>
<td>
<code>priority</code></br>
<em>
float64
</em>
</td>
<td>
<p>Priority specfies the order of the ClusterNetworkPolicy relative to
other AntreaClusterNetworkPolicies.</p>
</td>
</tr>
<tr>
<td>
<code>appliedTo</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPeer">
[]NetworkPolicyPeer
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select workloads on which the rules will be applied to. Cannot be set in
conjunction with AppliedTo in each rule.</p>
</td>
</tr>
<tr>
<td>
<code>ingress</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Rule">
[]Rule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Set of ingress rules evaluated based on the order in which they are set.
Currently Ingress rule supports setting the <code>From</code> field but not the <code>To</code>
field within a Rule.</p>
</td>
</tr>
<tr>
<td>
<code>egress</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Rule">
[]Rule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Set of egress rules evaluated based on the order in which they are set.
Currently Egress rule supports setting the <code>To</code> field but not the <code>From</code>
field within a Rule.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyStatus">
NetworkPolicyStatus
</a>
</em>
</td>
<td>
<p>Most recently observed status of the NetworkPolicy.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.NetworkPolicy">NetworkPolicy
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
crd.antrea.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>NetworkPolicy</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<p>Standard metadata of the object.</p>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicySpec">
NetworkPolicySpec
</a>
</em>
</td>
<td>
<p>Specification of the desired behavior of NetworkPolicy.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>tier</code></br>
<em>
string
</em>
</td>
<td>
<p>Tier specifies the tier to which this NetworkPolicy belongs to.
The NetworkPolicy order will be determined based on the combination of the
Tier&rsquo;s Priority and the NetworkPolicy&rsquo;s own Priority. If not specified,
this policy will be created in the Application Tier right above the K8s
NetworkPolicy which resides at the bottom.</p>
</td>
</tr>
<tr>
<td>
<code>priority</code></br>
<em>
float64
</em>
</td>
<td>
<p>Priority specfies the order of the NetworkPolicy relative to other
NetworkPolicies.</p>
</td>
</tr>
<tr>
<td>
<code>appliedTo</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPeer">
[]NetworkPolicyPeer
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select workloads on which the rules will be applied to. Cannot be set in
conjunction with AppliedTo in each rule.</p>
</td>
</tr>
<tr>
<td>
<code>ingress</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Rule">
[]Rule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Set of ingress rules evaluated based on the order in which they are set.
Currently Ingress rule supports setting the <code>From</code> field but not the <code>To</code>
field within a Rule.</p>
</td>
</tr>
<tr>
<td>
<code>egress</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Rule">
[]Rule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Set of egress rules evaluated based on the order in which they are set.
Currently Egress rule supports setting the <code>To</code> field but not the <code>From</code>
field within a Rule.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyStatus">
NetworkPolicyStatus
</a>
</em>
</td>
<td>
<p>Most recently observed status of the NetworkPolicy.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.Tier">Tier
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
crd.antrea.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>Tier</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<p>Standard metadata of the object.</p>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.TierSpec">
TierSpec
</a>
</em>
</td>
<td>
<p>Specification of the desired behavior of Tier.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>priority</code></br>
<em>
int32
</em>
</td>
<td>
<p>Priority specfies the order of the Tier relative to other Tiers.</p>
</td>
</tr>
<tr>
<td>
<code>description</code></br>
<em>
string
</em>
</td>
<td>
<p>Description is an optional field to add more information regarding
the purpose of this Tier.</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.ClusterNetworkPolicySpec">ClusterNetworkPolicySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.ClusterNetworkPolicy">ClusterNetworkPolicy</a>)
</p>
<p>
<p>ClusterNetworkPolicySpec defines the desired state for ClusterNetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>tier</code></br>
<em>
string
</em>
</td>
<td>
<p>Tier specifies the tier to which this ClusterNetworkPolicy belongs to.
The ClusterNetworkPolicy order will be determined based on the
combination of the Tier&rsquo;s Priority and the ClusterNetworkPolicy&rsquo;s own
Priority. If not specified, this policy will be created in the Application
Tier right above the K8s NetworkPolicy which resides at the bottom.</p>
</td>
</tr>
<tr>
<td>
<code>priority</code></br>
<em>
float64
</em>
</td>
<td>
<p>Priority specfies the order of the ClusterNetworkPolicy relative to
other AntreaClusterNetworkPolicies.</p>
</td>
</tr>
<tr>
<td>
<code>appliedTo</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPeer">
[]NetworkPolicyPeer
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select workloads on which the rules will be applied to. Cannot be set in
conjunction with AppliedTo in each rule.</p>
</td>
</tr>
<tr>
<td>
<code>ingress</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Rule">
[]Rule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Set of ingress rules evaluated based on the order in which they are set.
Currently Ingress rule supports setting the <code>From</code> field but not the <code>To</code>
field within a Rule.</p>
</td>
</tr>
<tr>
<td>
<code>egress</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Rule">
[]Rule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Set of egress rules evaluated based on the order in which they are set.
Currently Egress rule supports setting the <code>To</code> field but not the <code>From</code>
field within a Rule.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.Destination">Destination
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.TraceflowSpec">TraceflowSpec</a>)
</p>
<p>
<p>Destination describes the destination spec of the traceflow.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>Namespace is the destination namespace.</p>
</td>
</tr>
<tr>
<td>
<code>pod</code></br>
<em>
string
</em>
</td>
<td>
<p>Pod is the destination pod, exclusive with destination service.</p>
</td>
</tr>
<tr>
<td>
<code>service</code></br>
<em>
string
</em>
</td>
<td>
<p>Service is the destination service, exclusive with destination pod.</p>
</td>
</tr>
<tr>
<td>
<code>ip</code></br>
<em>
string
</em>
</td>
<td>
<p>IP is the destination IPv4 or IPv6 address.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.ICMPEchoRequestHeader">ICMPEchoRequestHeader
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.TransportHeader">TransportHeader</a>)
</p>
<p>
<p>ICMPEchoRequestHeader describes spec of an ICMP echo request header.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>id</code></br>
<em>
int32
</em>
</td>
<td>
<p>ID is the ICMPEchoRequestHeader ID.</p>
</td>
</tr>
<tr>
<td>
<code>sequence</code></br>
<em>
int32
</em>
</td>
<td>
<p>Sequence is the ICMPEchoRequestHeader sequence.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.IPBlock">IPBlock
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.GroupSpec">GroupSpec</a>, 
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPeer">NetworkPolicyPeer</a>)
</p>
<p>
<p>IPBlock describes a particular CIDR (Ex. &ldquo;192.168.1.<sup>1</sup>&frasl;<sub>24</sub>&rdquo;) that is allowed
or denied to/from the workloads matched by a Spec.AppliedTo.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>cidr</code></br>
<em>
string
</em>
</td>
<td>
<p>CIDR is a string representing the IP Block
Valid examples are &ldquo;192.168.1.<sup>1</sup>&frasl;<sub>24</sub>&rdquo;.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.IPHeader">IPHeader
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.Packet">Packet</a>)
</p>
<p>
<p>IPHeader describes spec of an IPv4 header.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>srcIP</code></br>
<em>
string
</em>
</td>
<td>
<p>SrcIP is the source IP.</p>
</td>
</tr>
<tr>
<td>
<code>protocol</code></br>
<em>
int32
</em>
</td>
<td>
<p>Protocol is the IP protocol.</p>
</td>
</tr>
<tr>
<td>
<code>ttl</code></br>
<em>
int32
</em>
</td>
<td>
<p>TTL is the IP TTL.</p>
</td>
</tr>
<tr>
<td>
<code>flags</code></br>
<em>
int32
</em>
</td>
<td>
<p>Flags is the flags for IP.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.IPv6Header">IPv6Header
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.Packet">Packet</a>)
</p>
<p>
<p>IPv6Header describes spec of an IPv6 header.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>srcIP</code></br>
<em>
string
</em>
</td>
<td>
<p>SrcIP is the source IPv6.</p>
</td>
</tr>
<tr>
<td>
<code>nextHeader</code></br>
<em>
int32
</em>
</td>
<td>
<p>NextHeader is the IPv6 protocol.</p>
</td>
</tr>
<tr>
<td>
<code>hopLimit</code></br>
<em>
int32
</em>
</td>
<td>
<p>HopLimit is the IPv6 Hop Limit.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.NetworkPolicyPeer">NetworkPolicyPeer
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.ClusterNetworkPolicySpec">ClusterNetworkPolicySpec</a>, 
<a href="#crd.antrea.io/v1alpha1.NetworkPolicySpec">NetworkPolicySpec</a>, 
<a href="#crd.antrea.io/v1alpha1.Rule">Rule</a>)
</p>
<p>
<p>NetworkPolicyPeer describes the grouping selector of workloads.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>ipBlock</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.IPBlock">
IPBlock
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IPBlock describes the IPAddresses/IPBlocks that is matched in to/from.
IPBlock cannot be set as part of the AppliedTo field.
Cannot be set with any other selector.</p>
</td>
</tr>
<tr>
<td>
<code>podSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select Pods from NetworkPolicy&rsquo;s Namespace as workloads in
AppliedTo/To/From fields. If set with NamespaceSelector, Pods are
matched from Namespaces matched by the NamespaceSelector.
Cannot be set with any other selector except NamespaceSelector.</p>
</td>
</tr>
<tr>
<td>
<code>namespaceSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select all Pods from Namespaces matched by this selector, as
workloads in To/From fields. If set with PodSelector,
Pods are matched from Namespaces matched by the NamespaceSelector.
Cannot be set with any other selector except PodSelector or
ExternalEntitySelector.</p>
</td>
</tr>
<tr>
<td>
<code>externalEntitySelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select ExternalEntities from NetworkPolicy&rsquo;s Namespace as workloads
in AppliedTo/To/From fields. If set with NamespaceSelector,
ExternalEntities are matched from Namespaces matched by the
NamespaceSelector.
Cannot be set with any other selector except NamespaceSelector.</p>
</td>
</tr>
<tr>
<td>
<code>group</code></br>
<em>
string
</em>
</td>
<td>
<p>Group is the name of the ClusterGroup which can be set as an
AppliedTo or within an Ingress or Egress rule in place of
a stand-alone selector. A Group cannot be set with any other
selector.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.NetworkPolicyPhase">NetworkPolicyPhase
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyStatus">NetworkPolicyStatus</a>)
</p>
<p>
<p>NetworkPolicyPhase defines the phase in which a NetworkPolicy is.</p>
</p>
<h3 id="crd.antrea.io/v1alpha1.NetworkPolicyPort">NetworkPolicyPort
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.Rule">Rule</a>)
</p>
<p>
<p>NetworkPolicyPort describes the port and protocol to match in a rule.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>protocol</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#protocol-v1-core">
Kubernetes core/v1.Protocol
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The protocol (TCP, UDP, or SCTP) which traffic must match.
If not specified, this field defaults to TCP.</p>
</td>
</tr>
<tr>
<td>
<code>port</code></br>
<em>
<a href="https://godoc.org/k8s.io/apimachinery/pkg/util/intstr#IntOrString">
k8s.io/apimachinery/pkg/util/intstr.IntOrString
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The port on the given protocol. This can be either a numerical
or named port on a Pod. If this field is not provided, this
matches all port names and numbers.</p>
</td>
</tr>
<tr>
<td>
<code>endPort</code></br>
<em>
int32
</em>
</td>
<td>
<em>(Optional)</em>
<p>EndPort defines the end of the port range, being the end included within the range.
It can only be specified when a numerical <code>port</code> is specified.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.NetworkPolicySpec">NetworkPolicySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicy">NetworkPolicy</a>)
</p>
<p>
<p>NetworkPolicySpec defines the desired state for NetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>tier</code></br>
<em>
string
</em>
</td>
<td>
<p>Tier specifies the tier to which this NetworkPolicy belongs to.
The NetworkPolicy order will be determined based on the combination of the
Tier&rsquo;s Priority and the NetworkPolicy&rsquo;s own Priority. If not specified,
this policy will be created in the Application Tier right above the K8s
NetworkPolicy which resides at the bottom.</p>
</td>
</tr>
<tr>
<td>
<code>priority</code></br>
<em>
float64
</em>
</td>
<td>
<p>Priority specfies the order of the NetworkPolicy relative to other
NetworkPolicies.</p>
</td>
</tr>
<tr>
<td>
<code>appliedTo</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPeer">
[]NetworkPolicyPeer
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select workloads on which the rules will be applied to. Cannot be set in
conjunction with AppliedTo in each rule.</p>
</td>
</tr>
<tr>
<td>
<code>ingress</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Rule">
[]Rule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Set of ingress rules evaluated based on the order in which they are set.
Currently Ingress rule supports setting the <code>From</code> field but not the <code>To</code>
field within a Rule.</p>
</td>
</tr>
<tr>
<td>
<code>egress</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Rule">
[]Rule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Set of egress rules evaluated based on the order in which they are set.
Currently Egress rule supports setting the <code>To</code> field but not the <code>From</code>
field within a Rule.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.NetworkPolicyStatus">NetworkPolicyStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.ClusterNetworkPolicy">ClusterNetworkPolicy</a>, 
<a href="#crd.antrea.io/v1alpha1.NetworkPolicy">NetworkPolicy</a>)
</p>
<p>
<p>NetworkPolicyStatus represents information about the status of a NetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>phase</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPhase">
NetworkPolicyPhase
</a>
</em>
</td>
<td>
<p>The phase of a NetworkPolicy is a simple, high-level summary of the NetworkPolicy&rsquo;s status.</p>
</td>
</tr>
<tr>
<td>
<code>observedGeneration</code></br>
<em>
int64
</em>
</td>
<td>
<p>The generation observed by Antrea.</p>
</td>
</tr>
<tr>
<td>
<code>currentNodesRealized</code></br>
<em>
int32
</em>
</td>
<td>
<p>The number of nodes that have realized the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>desiredNodesRealized</code></br>
<em>
int32
</em>
</td>
<td>
<p>The total number of nodes that should realize the NetworkPolicy.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.NodeResult">NodeResult
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.TraceflowStatus">TraceflowStatus</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>node</code></br>
<em>
string
</em>
</td>
<td>
<p>Node is the node of the observation.</p>
</td>
</tr>
<tr>
<td>
<code>role</code></br>
<em>
string
</em>
</td>
<td>
<p>Role of the node like sender, receiver, etc.</p>
</td>
</tr>
<tr>
<td>
<code>timestamp</code></br>
<em>
int64
</em>
</td>
<td>
<p>Timestamp is the timestamp of the observations on the node.</p>
</td>
</tr>
<tr>
<td>
<code>observations</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Observation">
[]Observation
</a>
</em>
</td>
<td>
<p>Observations includes all observations from sender nodes, receiver ones, etc.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.Observation">Observation
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.NodeResult">NodeResult</a>)
</p>
<p>
<p>Observation describes those from sender nodes or receiver nodes.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>component</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.TraceflowComponent">
TraceflowComponent
</a>
</em>
</td>
<td>
<p>Component is the observation component.</p>
</td>
</tr>
<tr>
<td>
<code>componentInfo</code></br>
<em>
string
</em>
</td>
<td>
<p>ComponentInfo is the extension of Component field.</p>
</td>
</tr>
<tr>
<td>
<code>action</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.TraceflowAction">
TraceflowAction
</a>
</em>
</td>
<td>
<p>Action is the action to the observation.</p>
</td>
</tr>
<tr>
<td>
<code>pod</code></br>
<em>
string
</em>
</td>
<td>
<p>Pod is the combination of Pod name and Pod Namespace.</p>
</td>
</tr>
<tr>
<td>
<code>dstMAC</code></br>
<em>
string
</em>
</td>
<td>
<p>DstMAC is the destination MAC.</p>
</td>
</tr>
<tr>
<td>
<code>networkPolicy</code></br>
<em>
string
</em>
</td>
<td>
<p>NetworkPolicy is the combination of Namespace and NetworkPolicyName.</p>
</td>
</tr>
<tr>
<td>
<code>ttl</code></br>
<em>
int32
</em>
</td>
<td>
<p>TTL is the observation TTL.</p>
</td>
</tr>
<tr>
<td>
<code>translatedSrcIP</code></br>
<em>
string
</em>
</td>
<td>
<p>TranslatedSrcIP is the translated source IP.</p>
</td>
</tr>
<tr>
<td>
<code>translatedDstIP</code></br>
<em>
string
</em>
</td>
<td>
<p>TranslatedDstIP is the translated destination IP.</p>
</td>
</tr>
<tr>
<td>
<code>tunnelDstIP</code></br>
<em>
string
</em>
</td>
<td>
<p>TunnelDstIP is the tunnel destination IP.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.Packet">Packet
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.TraceflowSpec">TraceflowSpec</a>, 
<a href="#crd.antrea.io/v1alpha1.TraceflowStatus">TraceflowStatus</a>)
</p>
<p>
<p>Packet includes header info.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>srcIP</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>dstIP</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>length</code></br>
<em>
uint16
</em>
</td>
<td>
<p>Length is the IP packet length (includes the IPv4 or IPv6 header length).</p>
</td>
</tr>
<tr>
<td>
<code>ipHeader</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.IPHeader">
IPHeader
</a>
</em>
</td>
<td>
<p>TODO: change type IPHeader to *IPHeader and correct all internal references</p>
</td>
</tr>
<tr>
<td>
<code>ipv6Header</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.IPv6Header">
IPv6Header
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>transportHeader</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.TransportHeader">
TransportHeader
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.Rule">Rule
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.ClusterNetworkPolicySpec">ClusterNetworkPolicySpec</a>, 
<a href="#crd.antrea.io/v1alpha1.NetworkPolicySpec">NetworkPolicySpec</a>)
</p>
<p>
<p>Rule describes the traffic allowed to/from the workloads selected by
Spec.AppliedTo. Based on the action specified in the rule, traffic is either
allowed or denied which exactly match the specified ports and protocol.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>action</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.RuleAction">
RuleAction
</a>
</em>
</td>
<td>
<p>Action specifies the action to be applied on the rule.</p>
</td>
</tr>
<tr>
<td>
<code>ports</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPort">
[]NetworkPolicyPort
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Set of port and protocol allowed/denied by the rule. If this field is unset
or empty, this rule matches all ports.</p>
</td>
</tr>
<tr>
<td>
<code>from</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPeer">
[]NetworkPolicyPeer
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Rule is matched if traffic originates from workloads selected by
this field. If this field is empty, this rule matches all sources.</p>
</td>
</tr>
<tr>
<td>
<code>to</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPeer">
[]NetworkPolicyPeer
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Rule is matched if traffic is intended for workloads selected by
this field. If this field is empty or missing, this rule matches all
destinations.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Name describes the intention of this rule.
Name should be unique within the policy.</p>
</td>
</tr>
<tr>
<td>
<code>enableLogging</code></br>
<em>
bool
</em>
</td>
<td>
<p>EnableLogging is used to indicate if agent should generate logs
when rules are matched. Should be default to false.</p>
</td>
</tr>
<tr>
<td>
<code>appliedTo</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NetworkPolicyPeer">
[]NetworkPolicyPeer
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select workloads on which this rule will be applied to. Cannot be set in
conjunction with NetworkPolicySpec/ClusterNetworkPolicySpec.AppliedTo.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.RuleAction">RuleAction
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyRule">NetworkPolicyRule</a>, 
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyRule">NetworkPolicyRule</a>, 
<a href="#crd.antrea.io/v1alpha1.Rule">Rule</a>)
</p>
<p>
<p>RuleAction describes the action to be applied on traffic matching a rule.</p>
</p>
<h3 id="crd.antrea.io/v1alpha1.Source">Source
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.TraceflowSpec">TraceflowSpec</a>)
</p>
<p>
<p>Source describes the source spec of the traceflow.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>Namespace is the source namespace.</p>
</td>
</tr>
<tr>
<td>
<code>pod</code></br>
<em>
string
</em>
</td>
<td>
<p>Pod is the source pod.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.TCPHeader">TCPHeader
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.TransportHeader">TransportHeader</a>)
</p>
<p>
<p>TCPHeader describes spec of a TCP header.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>srcPort</code></br>
<em>
int32
</em>
</td>
<td>
<p>SrcPort is the source port.</p>
</td>
</tr>
<tr>
<td>
<code>dstPort</code></br>
<em>
int32
</em>
</td>
<td>
<p>DstPort is the destination port.</p>
</td>
</tr>
<tr>
<td>
<code>flags</code></br>
<em>
int32
</em>
</td>
<td>
<p>Flags are flags in the header.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.TierSpec">TierSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.Tier">Tier</a>)
</p>
<p>
<p>TierSpec defines the desired state for Tier.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>priority</code></br>
<em>
int32
</em>
</td>
<td>
<p>Priority specfies the order of the Tier relative to other Tiers.</p>
</td>
</tr>
<tr>
<td>
<code>description</code></br>
<em>
string
</em>
</td>
<td>
<p>Description is an optional field to add more information regarding
the purpose of this Tier.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.Traceflow">Traceflow
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.TraceflowSpec">
TraceflowSpec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>source</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Source">
Source
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>destination</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Destination">
Destination
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>packet</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Packet">
Packet
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>liveTraffic</code></br>
<em>
bool
</em>
</td>
<td>
<p>LiveTraffic indicates the Traceflow is to trace the live traffic
rather than an injected packet, when set to true. The first packet of
the first connection that matches the packet spec will be traced.</p>
</td>
</tr>
<tr>
<td>
<code>droppedOnly</code></br>
<em>
bool
</em>
</td>
<td>
<p>DroppedOnly indicates only the dropped packet should be captured in a
live-traffic Traceflow.</p>
</td>
</tr>
<tr>
<td>
<code>timeout</code></br>
<em>
uint16
</em>
</td>
<td>
<p>Timeout specifies the timeout of the Traceflow in seconds. Defaults
to 20 seconds if not set.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.TraceflowStatus">
TraceflowStatus
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.TraceflowAction">TraceflowAction
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.Observation">Observation</a>)
</p>
<p>
</p>
<h3 id="crd.antrea.io/v1alpha1.TraceflowComponent">TraceflowComponent
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.Observation">Observation</a>)
</p>
<p>
</p>
<h3 id="crd.antrea.io/v1alpha1.TraceflowPhase">TraceflowPhase
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.TraceflowStatus">TraceflowStatus</a>)
</p>
<p>
</p>
<h3 id="crd.antrea.io/v1alpha1.TraceflowSpec">TraceflowSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.Traceflow">Traceflow</a>)
</p>
<p>
<p>TraceflowSpec describes the spec of the traceflow.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>source</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Source">
Source
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>destination</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Destination">
Destination
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>packet</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Packet">
Packet
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>liveTraffic</code></br>
<em>
bool
</em>
</td>
<td>
<p>LiveTraffic indicates the Traceflow is to trace the live traffic
rather than an injected packet, when set to true. The first packet of
the first connection that matches the packet spec will be traced.</p>
</td>
</tr>
<tr>
<td>
<code>droppedOnly</code></br>
<em>
bool
</em>
</td>
<td>
<p>DroppedOnly indicates only the dropped packet should be captured in a
live-traffic Traceflow.</p>
</td>
</tr>
<tr>
<td>
<code>timeout</code></br>
<em>
uint16
</em>
</td>
<td>
<p>Timeout specifies the timeout of the Traceflow in seconds. Defaults
to 20 seconds if not set.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.TraceflowStatus">TraceflowStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.Traceflow">Traceflow</a>)
</p>
<p>
<p>TraceflowStatus describes current status of the traceflow.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>phase</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.TraceflowPhase">
TraceflowPhase
</a>
</em>
</td>
<td>
<p>Phase is the Traceflow phase.</p>
</td>
</tr>
<tr>
<td>
<code>reason</code></br>
<em>
string
</em>
</td>
<td>
<p>Reason is a message indicating the reason of the traceflow&rsquo;s current phase.</p>
</td>
</tr>
<tr>
<td>
<code>dataplaneTag</code></br>
<em>
byte
</em>
</td>
<td>
<p>DataplaneTag is a tag to identify a traceflow session across Nodes.</p>
</td>
</tr>
<tr>
<td>
<code>results</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.NodeResult">
[]NodeResult
</a>
</em>
</td>
<td>
<p>Results is the collection of all observations on different nodes.</p>
</td>
</tr>
<tr>
<td>
<code>capturedPacket</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.Packet">
Packet
</a>
</em>
</td>
<td>
<p>CapturedPacket is the captured packet in live-traffic Traceflow.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.TransportHeader">TransportHeader
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.Packet">Packet</a>)
</p>
<p>
<p>TransportHeader describes spec of a TransportHeader.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>icmp</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.ICMPEchoRequestHeader">
ICMPEchoRequestHeader
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>udp</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.UDPHeader">
UDPHeader
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>tcp</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.TCPHeader">
TCPHeader
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha1.UDPHeader">UDPHeader
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha1.TransportHeader">TransportHeader</a>)
</p>
<p>
<p>UDPHeader describes spec of a UDP header.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>srcPort</code></br>
<em>
int32
</em>
</td>
<td>
<p>SrcPort is the source port.</p>
</td>
</tr>
<tr>
<td>
<code>dstPort</code></br>
<em>
int32
</em>
</td>
<td>
<p>DstPort is the destination port.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<h2 id="crd.antrea.io/v1alpha2">crd.antrea.io/v1alpha2</h2>
Resource Types:
<ul><li>
<a href="#crd.antrea.io/v1alpha2.ClusterGroup">ClusterGroup</a>
</li><li>
<a href="#crd.antrea.io/v1alpha2.Egress">Egress</a>
</li><li>
<a href="#crd.antrea.io/v1alpha2.ExternalEntity">ExternalEntity</a>
</li></ul>
<h3 id="crd.antrea.io/v1alpha2.ClusterGroup">ClusterGroup
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
crd.antrea.io/v1alpha2
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>ClusterGroup</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<p>Standard metadata of the object.</p>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.GroupSpec">
GroupSpec
</a>
</em>
</td>
<td>
<p>Desired state of the group.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>podSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select Pods matching the labels set in the PodSelector in
AppliedTo/To/From fields. If set with NamespaceSelector, Pods are
matched from Namespaces matched by the NamespaceSelector.
Cannot be set with any other selector except NamespaceSelector.</p>
</td>
</tr>
<tr>
<td>
<code>namespaceSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select all Pods from Namespaces matched by this selector, as
workloads in AppliedTo/To/From fields. If set with PodSelector,
Pods are matched from Namespaces matched by the NamespaceSelector.
Cannot be set with any other selector except PodSelector.</p>
</td>
</tr>
<tr>
<td>
<code>ipBlock</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.IPBlock">
IPBlock
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IPBlock describes the IPAddresses/IPBlocks that is matched in to/from.
IPBlock cannot be set as part of the AppliedTo field.
Cannot be set with any other selector or ServiceReference.
Cannot be set with IPBlocks.</p>
</td>
</tr>
<tr>
<td>
<code>ipBlocks</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.IPBlock">
[]IPBlock
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IPBlocks is a list of IPAddresses/IPBlocks that is matched in to/from.
IPBlock cannot be set as part of the AppliedTo field.
Cannot be set with any other selector or ServiceReference.
Cannot be set with IPBlock.</p>
</td>
</tr>
<tr>
<td>
<code>serviceReference</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.ServiceReference">
ServiceReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select backend Pods of the referred Service.
Cannot be set with any other selector or ipBlock.</p>
</td>
</tr>
<tr>
<td>
<code>externalEntitySelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select ExternalEntities from all Namespaces as workloads
in AppliedTo/To/From fields. If set with NamespaceSelector,
ExternalEntities are matched from Namespaces matched by the
NamespaceSelector.
Cannot be set with any other selector except NamespaceSelector.</p>
</td>
</tr>
<tr>
<td>
<code>childGroups</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.ClusterGroupReference">
[]ClusterGroupReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select other ClusterGroups by name. The ClusterGroups must already
exist and must not contain ChildGroups themselves.
Cannot be set with any selector/IPBlock/ServiceReference.</p>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.GroupStatus">
GroupStatus
</a>
</em>
</td>
<td>
<p>Most recently observed status of the group.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.Egress">Egress
</h3>
<p>
<p>Egress defines which egress (SNAT) IP the traffic from the selected Pods to
the external network should use.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
crd.antrea.io/v1alpha2
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>Egress</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<p>Standard metadata of the object.</p>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.EgressSpec">
EgressSpec
</a>
</em>
</td>
<td>
<p>Specification of the desired behavior of Egress.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>appliedTo</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.AppliedTo">
AppliedTo
</a>
</em>
</td>
<td>
<p>AppliedTo selects Pods to which the Egress will be applied.</p>
</td>
</tr>
<tr>
<td>
<code>egressIP</code></br>
<em>
string
</em>
</td>
<td>
<p>EgressIP specifies the SNAT IP address for the selected workloads.</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.ExternalEntity">ExternalEntity
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
crd.antrea.io/v1alpha2
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>ExternalEntity</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
<p>Standard metadata of the object.</p>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.ExternalEntitySpec">
ExternalEntitySpec
</a>
</em>
</td>
<td>
<p>Desired state of the external entity.</p>
<br/>
<br/>
<table>
<tr>
<td>
<code>endpoints</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.Endpoint">
[]Endpoint
</a>
</em>
</td>
<td>
<p>Endpoints is a list of external endpoints associated with this entity.</p>
</td>
</tr>
<tr>
<td>
<code>ports</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.NamedPort">
[]NamedPort
</a>
</em>
</td>
<td>
<p>Ports maintain the list of named ports.</p>
</td>
</tr>
<tr>
<td>
<code>externalNode</code></br>
<em>
string
</em>
</td>
<td>
<p>ExternalNode is the opaque identifier of the agent/controller responsible
for additional processing or handling of this external entity.</p>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.AppliedTo">AppliedTo
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.EgressSpec">EgressSpec</a>)
</p>
<p>
<p>AppliedTo selects the entities to which a policy is applied.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>podSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select Pods matched by this selector. If set with NamespaceSelector,
Pods are matched from Namespaces matched by the NamespaceSelector;
otherwise, Pods are matched from all Namespaces.</p>
</td>
</tr>
<tr>
<td>
<code>namespaceSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select all Pods from Namespaces matched by this selector. If set with
PodSelector, Pods are matched from Namespaces matched by the
NamespaceSelector.</p>
</td>
</tr>
<tr>
<td>
<code>groups</code></br>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Groups is the set of ClusterGroup names.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.ClusterGroupReference">ClusterGroupReference
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.GroupSpec">GroupSpec</a>)
</p>
<p>
<p>ClusterGroupReference represent reference to a ClusterGroup.</p>
</p>
<h3 id="crd.antrea.io/v1alpha2.EgressSpec">EgressSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.Egress">Egress</a>)
</p>
<p>
<p>EgressSpec defines the desired state for Egress.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>appliedTo</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.AppliedTo">
AppliedTo
</a>
</em>
</td>
<td>
<p>AppliedTo selects Pods to which the Egress will be applied.</p>
</td>
</tr>
<tr>
<td>
<code>egressIP</code></br>
<em>
string
</em>
</td>
<td>
<p>EgressIP specifies the SNAT IP address for the selected workloads.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.Endpoint">Endpoint
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.ExternalEntitySpec">ExternalEntitySpec</a>)
</p>
<p>
<p>Endpoint refers to an endpoint associated with the ExternalEntity.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>ip</code></br>
<em>
string
</em>
</td>
<td>
<p>IP associated with this endpoint.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Name identifies this endpoint. Could be the network interface name in case of VMs.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.ExternalEntitySpec">ExternalEntitySpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.ExternalEntity">ExternalEntity</a>)
</p>
<p>
<p>ExternalEntitySpec defines the desired state for ExternalEntity.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>endpoints</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.Endpoint">
[]Endpoint
</a>
</em>
</td>
<td>
<p>Endpoints is a list of external endpoints associated with this entity.</p>
</td>
</tr>
<tr>
<td>
<code>ports</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.NamedPort">
[]NamedPort
</a>
</em>
</td>
<td>
<p>Ports maintain the list of named ports.</p>
</td>
</tr>
<tr>
<td>
<code>externalNode</code></br>
<em>
string
</em>
</td>
<td>
<p>ExternalNode is the opaque identifier of the agent/controller responsible
for additional processing or handling of this external entity.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.GroupCondition">GroupCondition
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.GroupStatus">GroupStatus</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>type</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.GroupConditionType">
GroupConditionType
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#conditionstatus-v1-core">
Kubernetes core/v1.ConditionStatus
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>lastTransitionTime</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.GroupConditionType">GroupConditionType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.GroupCondition">GroupCondition</a>)
</p>
<p>
</p>
<h3 id="crd.antrea.io/v1alpha2.GroupSpec">GroupSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.ClusterGroup">ClusterGroup</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>podSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select Pods matching the labels set in the PodSelector in
AppliedTo/To/From fields. If set with NamespaceSelector, Pods are
matched from Namespaces matched by the NamespaceSelector.
Cannot be set with any other selector except NamespaceSelector.</p>
</td>
</tr>
<tr>
<td>
<code>namespaceSelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select all Pods from Namespaces matched by this selector, as
workloads in AppliedTo/To/From fields. If set with PodSelector,
Pods are matched from Namespaces matched by the NamespaceSelector.
Cannot be set with any other selector except PodSelector.</p>
</td>
</tr>
<tr>
<td>
<code>ipBlock</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.IPBlock">
IPBlock
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IPBlock describes the IPAddresses/IPBlocks that is matched in to/from.
IPBlock cannot be set as part of the AppliedTo field.
Cannot be set with any other selector or ServiceReference.
Cannot be set with IPBlocks.</p>
</td>
</tr>
<tr>
<td>
<code>ipBlocks</code></br>
<em>
<a href="#crd.antrea.io/v1alpha1.IPBlock">
[]IPBlock
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IPBlocks is a list of IPAddresses/IPBlocks that is matched in to/from.
IPBlock cannot be set as part of the AppliedTo field.
Cannot be set with any other selector or ServiceReference.
Cannot be set with IPBlock.</p>
</td>
</tr>
<tr>
<td>
<code>serviceReference</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.ServiceReference">
ServiceReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select backend Pods of the referred Service.
Cannot be set with any other selector or ipBlock.</p>
</td>
</tr>
<tr>
<td>
<code>externalEntitySelector</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselector-v1-meta">
Kubernetes meta/v1.LabelSelector
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select ExternalEntities from all Namespaces as workloads
in AppliedTo/To/From fields. If set with NamespaceSelector,
ExternalEntities are matched from Namespaces matched by the
NamespaceSelector.
Cannot be set with any other selector except NamespaceSelector.</p>
</td>
</tr>
<tr>
<td>
<code>childGroups</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.ClusterGroupReference">
[]ClusterGroupReference
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Select other ClusterGroups by name. The ClusterGroups must already
exist and must not contain ChildGroups themselves.
Cannot be set with any selector/IPBlock/ServiceReference.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.GroupStatus">GroupStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.ClusterGroup">ClusterGroup</a>)
</p>
<p>
<p>GroupStatus represents information about the status of a Group.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>conditions</code></br>
<em>
<a href="#crd.antrea.io/v1alpha2.GroupCondition">
[]GroupCondition
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.NamedPort">NamedPort
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.ExternalEntitySpec">ExternalEntitySpec</a>)
</p>
<p>
<p>NamedPort describes the port and protocol to match in a rule.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>protocol</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#protocol-v1-core">
Kubernetes core/v1.Protocol
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>The protocol (TCP, UDP, or SCTP) which traffic must match.
If not specified, this field defaults to TCP.</p>
</td>
</tr>
<tr>
<td>
<code>port</code></br>
<em>
int32
</em>
</td>
<td>
<em>(Optional)</em>
<p>The port on the given protocol.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Name associated with the Port.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.ServiceReference">ServiceReference
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1alpha2.GroupSpec">GroupSpec</a>)
</p>
<p>
<p>ServiceReference represent reference to a v1.Service.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name of the Service</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<p>Namespace of the Service</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1alpha2.WebhookImpl">WebhookImpl
</h3>
<p>
<p>WebhookImpl implements webhook validator of a resource.</p>
</p>
<hr/>
<h2 id="crd.antrea.io/v1beta1">crd.antrea.io/v1beta1</h2>
Resource Types:
<ul></ul>
<h3 id="crd.antrea.io/v1beta1.AgentCondition">AgentCondition
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1beta1.AntreaAgentInfo">AntreaAgentInfo</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>type</code></br>
<em>
<a href="#crd.antrea.io/v1beta1.AgentConditionType">
AgentConditionType
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#conditionstatus-v1-core">
Kubernetes core/v1.ConditionStatus
</a>
</em>
</td>
<td>
<p>One of the AgentConditionType listed above</p>
</td>
</tr>
<tr>
<td>
<code>lastHeartbeatTime</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
</em>
</td>
<td>
<p>Mark certain type status, one of True, False, Unknown</p>
</td>
</tr>
<tr>
<td>
<code>reason</code></br>
<em>
string
</em>
</td>
<td>
<p>The timestamp when AntreaAgentInfo is created/updated, ideally heartbeat interval is 60s</p>
</td>
</tr>
<tr>
<td>
<code>message</code></br>
<em>
string
</em>
</td>
<td>
<p>Brief reason</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1beta1.AgentConditionType">AgentConditionType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1beta1.AgentCondition">AgentCondition</a>)
</p>
<p>
</p>
<h3 id="crd.antrea.io/v1beta1.AntreaAgentInfo">AntreaAgentInfo
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>podRef</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectreference-v1-core">
Kubernetes core/v1.ObjectReference
</a>
</em>
</td>
<td>
<p>Antrea binary version</p>
</td>
</tr>
<tr>
<td>
<code>nodeRef</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectreference-v1-core">
Kubernetes core/v1.ObjectReference
</a>
</em>
</td>
<td>
<p>The Pod that Antrea Agent is running in</p>
</td>
</tr>
<tr>
<td>
<code>nodeSubnets</code></br>
<em>
[]string
</em>
</td>
<td>
<p>The Node that Antrea Agent is running in</p>
</td>
</tr>
<tr>
<td>
<code>ovsInfo</code></br>
<em>
<a href="#crd.antrea.io/v1beta1.OVSInfo">
OVSInfo
</a>
</em>
</td>
<td>
<p>Node subnets</p>
</td>
</tr>
<tr>
<td>
<code>networkPolicyControllerInfo</code></br>
<em>
<a href="#crd.antrea.io/v1beta1.NetworkPolicyControllerInfo">
NetworkPolicyControllerInfo
</a>
</em>
</td>
<td>
<p>OVS Information</p>
</td>
</tr>
<tr>
<td>
<code>localPodNum</code></br>
<em>
int32
</em>
</td>
<td>
<p>Antrea Agent NetworkPolicy information</p>
</td>
</tr>
<tr>
<td>
<code>agentConditions</code></br>
<em>
<a href="#crd.antrea.io/v1beta1.AgentCondition">
[]AgentCondition
</a>
</em>
</td>
<td>
<p>The number of Pods which the agent is in charge of</p>
</td>
</tr>
<tr>
<td>
<code>apiPort</code></br>
<em>
int
</em>
</td>
<td>
<p>Agent condition contains types like AgentHealthy</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1beta1.AntreaControllerInfo">AntreaControllerInfo
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>podRef</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectreference-v1-core">
Kubernetes core/v1.ObjectReference
</a>
</em>
</td>
<td>
<p>Antrea binary version</p>
</td>
</tr>
<tr>
<td>
<code>nodeRef</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectreference-v1-core">
Kubernetes core/v1.ObjectReference
</a>
</em>
</td>
<td>
<p>The Pod that Antrea Controller is running in</p>
</td>
</tr>
<tr>
<td>
<code>serviceRef</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectreference-v1-core">
Kubernetes core/v1.ObjectReference
</a>
</em>
</td>
<td>
<p>The Node that Antrea Controller is running in</p>
</td>
</tr>
<tr>
<td>
<code>networkPolicyControllerInfo</code></br>
<em>
<a href="#crd.antrea.io/v1beta1.NetworkPolicyControllerInfo">
NetworkPolicyControllerInfo
</a>
</em>
</td>
<td>
<p>Antrea Controller Service</p>
</td>
</tr>
<tr>
<td>
<code>connectedAgentNum</code></br>
<em>
int32
</em>
</td>
<td>
<p>Antrea Controller NetworkPolicy information</p>
</td>
</tr>
<tr>
<td>
<code>controllerConditions</code></br>
<em>
<a href="#crd.antrea.io/v1beta1.ControllerCondition">
[]ControllerCondition
</a>
</em>
</td>
<td>
<p>Number of agents which are connected to this controller</p>
</td>
</tr>
<tr>
<td>
<code>apiPort</code></br>
<em>
int
</em>
</td>
<td>
<p>Controller condition contains types like ControllerHealthy</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1beta1.ControllerCondition">ControllerCondition
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1beta1.AntreaControllerInfo">AntreaControllerInfo</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>type</code></br>
<em>
<a href="#crd.antrea.io/v1beta1.ControllerConditionType">
ControllerConditionType
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#conditionstatus-v1-core">
Kubernetes core/v1.ConditionStatus
</a>
</em>
</td>
<td>
<p>One of the ControllerConditionType listed above, controllerHealthy</p>
</td>
</tr>
<tr>
<td>
<code>lastHeartbeatTime</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
</em>
</td>
<td>
<p>Mark certain type status, one of True, False, Unknown</p>
</td>
</tr>
<tr>
<td>
<code>reason</code></br>
<em>
string
</em>
</td>
<td>
<p>The timestamp when AntreaControllerInfo is created/updated, ideally heartbeat interval is 60s</p>
</td>
</tr>
<tr>
<td>
<code>message</code></br>
<em>
string
</em>
</td>
<td>
<p>Brief reason</p>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1beta1.ControllerConditionType">ControllerConditionType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1beta1.ControllerCondition">ControllerCondition</a>)
</p>
<p>
</p>
<h3 id="crd.antrea.io/v1beta1.NetworkPolicyControllerInfo">NetworkPolicyControllerInfo
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1beta1.AntreaAgentInfo">AntreaAgentInfo</a>, 
<a href="#crd.antrea.io/v1beta1.AntreaControllerInfo">AntreaControllerInfo</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>networkPolicyNum</code></br>
<em>
int32
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>addressGroupNum</code></br>
<em>
int32
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>appliedToGroupNum</code></br>
<em>
int32
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="crd.antrea.io/v1beta1.OVSInfo">OVSInfo
</h3>
<p>
(<em>Appears on:</em>
<a href="#crd.antrea.io/v1beta1.AntreaAgentInfo">AntreaAgentInfo</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>bridgeName</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>flowTable</code></br>
<em>
map[string]int32
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<hr/>
<h2 id="stats.antrea.io/v1alpha1">stats.antrea.io/v1alpha1</h2>
<p>
<p>Package v1alpha1 is the v1alpha1 version of the Antrea Stats API.</p>
</p>
Resource Types:
<ul><li>
<a href="#stats.antrea.io/v1alpha1.AntreaClusterNetworkPolicyStats">AntreaClusterNetworkPolicyStats</a>
</li><li>
<a href="#stats.antrea.io/v1alpha1.AntreaNetworkPolicyStats">AntreaNetworkPolicyStats</a>
</li><li>
<a href="#stats.antrea.io/v1alpha1.NetworkPolicyStats">NetworkPolicyStats</a>
</li></ul>
<h3 id="stats.antrea.io/v1alpha1.AntreaClusterNetworkPolicyStats">AntreaClusterNetworkPolicyStats
</h3>
<p>
<p>AntreaClusterNetworkPolicyStats is the statistics of a Antrea ClusterNetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
stats.antrea.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>AntreaClusterNetworkPolicyStats</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>trafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.TrafficStats">
TrafficStats
</a>
</em>
</td>
<td>
<p>The traffic stats of the Antrea ClusterNetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>ruleTrafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.RuleTrafficStats">
[]RuleTrafficStats
</a>
</em>
</td>
<td>
<p>The traffic stats of the Antrea ClusterNetworkPolicy, from rule perspective.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="stats.antrea.io/v1alpha1.AntreaNetworkPolicyStats">AntreaNetworkPolicyStats
</h3>
<p>
<p>AntreaNetworkPolicyStats is the statistics of a Antrea NetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
stats.antrea.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>AntreaNetworkPolicyStats</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>trafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.TrafficStats">
TrafficStats
</a>
</em>
</td>
<td>
<p>The traffic stats of the Antrea NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>ruleTrafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.RuleTrafficStats">
[]RuleTrafficStats
</a>
</em>
</td>
<td>
<p>The traffic stats of the Antrea NetworkPolicy, from rule perspective.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="stats.antrea.io/v1alpha1.NetworkPolicyStats">NetworkPolicyStats
</h3>
<p>
<p>NetworkPolicyStats is the statistics of a K8s NetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
stats.antrea.io/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>NetworkPolicyStats</code></td>
</tr>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>trafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.TrafficStats">
TrafficStats
</a>
</em>
</td>
<td>
<p>The traffic stats of the K8s NetworkPolicy.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="stats.antrea.io/v1alpha1.RuleTrafficStats">RuleTrafficStats
</h3>
<p>
(<em>Appears on:</em>
<a href="#stats.antrea.io/v1alpha1.AntreaClusterNetworkPolicyStats">AntreaClusterNetworkPolicyStats</a>, 
<a href="#stats.antrea.io/v1alpha1.AntreaNetworkPolicyStats">AntreaNetworkPolicyStats</a>, 
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyStats">NetworkPolicyStats</a>, 
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyStats">NetworkPolicyStats</a>)
</p>
<p>
<p>RuleTrafficStats contains TrafficStats of single rule inside a NetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>trafficStats</code></br>
<em>
<a href="#stats.antrea.io/v1alpha1.TrafficStats">
TrafficStats
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="stats.antrea.io/v1alpha1.TrafficStats">TrafficStats
</h3>
<p>
(<em>Appears on:</em>
<a href="#stats.antrea.io/v1alpha1.AntreaClusterNetworkPolicyStats">AntreaClusterNetworkPolicyStats</a>, 
<a href="#stats.antrea.io/v1alpha1.AntreaNetworkPolicyStats">AntreaNetworkPolicyStats</a>, 
<a href="#stats.antrea.io/v1alpha1.NetworkPolicyStats">NetworkPolicyStats</a>, 
<a href="#controlplane.antrea.io/v1beta2.NetworkPolicyStats">NetworkPolicyStats</a>, 
<a href="#controlplane.antrea.io/v1beta1.NetworkPolicyStats">NetworkPolicyStats</a>, 
<a href="#stats.antrea.io/v1alpha1.RuleTrafficStats">RuleTrafficStats</a>)
</p>
<p>
<p>TrafficStats contains the traffic stats of a NetworkPolicy.</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>packets</code></br>
<em>
int64
</em>
</td>
<td>
<p>Packets is the packets count hit by the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>bytes</code></br>
<em>
int64
</em>
</td>
<td>
<p>Bytes is the bytes count hit by the NetworkPolicy.</p>
</td>
</tr>
<tr>
<td>
<code>sessions</code></br>
<em>
int64
</em>
</td>
<td>
<p>Sessions is the sessions count hit by the NetworkPolicy.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<h2 id="system.antrea.io/v1beta1">system.antrea.io/v1beta1</h2>
<p>
<p>Package v1beta1 contains the v1beta1 version of the Antrea &ldquo;system&rdquo; API
group definitions.</p>
</p>
Resource Types:
<ul></ul>
<h3 id="system.antrea.io/v1beta1.BundleStatus">BundleStatus
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#system.antrea.io/v1beta1.SupportBundle">SupportBundle</a>)
</p>
<p>
</p>
<h3 id="system.antrea.io/v1beta1.SupportBundle">SupportBundle
</h3>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>status</code></br>
<em>
<a href="#system.antrea.io/v1beta1.BundleStatus">
BundleStatus
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>sum</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>size</code></br>
<em>
uint32
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>-</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <code>gen-crd-api-reference-docs</code>
on git commit <code>3f8c9ad2</code>.
</em></p>

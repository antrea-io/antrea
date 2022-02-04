# Copyright 2022 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This library is used to define Antrea Network Policy related CRDs in Python.
# Code structure is following the Kubernetes Python Client library (https://github.com/kubernetes-client/python).
# Could be improved by using openAPI generator in the future.

import six

class NetworkPolicy(object):
    attribute_types = {
        "kind": "string",
        "api_version": "string",
        "metadata": "kubernetes.client.V1ObjectMeta",
        "spec": "NetworkPolicySpec",
        "status": "NetworkPolicyStatus"
    }

    def __init__(self, kind=None, api_version=None, metadata=None, spec=None, status=None):
        self.kind = kind
        self.api_version = api_version
        self.metadata = metadata
        self.spec = spec
        self.status = status

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    
class NetworkPolicySpec(object):
    attribute_types = {
        "tier": "string",
        "priority": "float",
        "applied_to": "list[NetworkPolicyPeer]",
        "ingress": "list[Rule]",
        "egress": "list[Rule]"
    }

    def __init__(self, tier=None, priority=None, applied_to=None, ingress=None, egress=None):
        self.tier = tier
        self.priority = priority
        self.applied_to = applied_to
        self.ingress = ingress
        self.egress = egress
    
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class NetworkPolicyPeer(object):
    attribute_types = {
      "ip_block": "IPBlock",
      "pod_selector": "kubernete.client.V1LabelSelector",
      "namespace_selector": "kubernete.client.V1LabelSelector",
      "namespaces": "PeerNamespaces",
      "external_entity_selector": "kubernete.client.V1LabelSelector",
      "group": "string",
      "FQDN": "string"
    }

    def __init__(self, ip_block=None, pod_selector=None, namespace_selector=None, namespaces=None, external_entity_selector=None, group=None, FQDN=None):
        self.ip_block = ip_block
        self.pod_selector = pod_selector
        self.namespace_selector = namespace_selector
        self.namespaces = namespaces
        self.external_entity_selector = external_entity_selector
        self.group = group
        self.FQDN = FQDN
      
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result


class IPBlock(object):
    attribute_types = {
      "CIDR": "string"
    }

    def __init__(self, CIDR=None):
        self.CIDR = CIDR
    
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class PeerNamespaces(object):
    attribute_types = {
      "Match": "string"
    }

    def __init__(self, Match=None):
        self.Match = Match

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class Rule(object):
    attribute_types = {
      "action": "string",
      "ports": "list[NetworkPolicyPort]",
      "_from": "list[NetworkPolicyPeer]",
      "to": "list[NetworkPolicyPeer]",
      "name": "string",
      "enable_logging": "bool",
      "applied_to": "ist[NetworkPolicyPeer]"
    }

    def __init__(self, action=None, ports=None, _from=None, to=None, name=None, enable_logging=None, applied_to=None):
        self.action = action
        self.ports = ports
        self._from = _from
        self.to = to
        self.name = name
        self.enable_logging = enable_logging
        self.applied_to = applied_to
    
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class NetworkPolicyPort(object):
    attribute_types = {
      "protocol": "string",
      "port": "int or string",
      "endport": "int",
    }

    def __init__(self, protocol=None, port=None, endport=None):
        self.protocol = protocol
        self.port = port
        self.endport = endport
    
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class ClusterGroup(object):
    attribute_types = {
        "kind": "string",
        "api_version": "string",
        "metadata": "kubernetes.client.V1ObjectMeta",
        "spec": "GroupSpec",
        "status": "GroupStatus"
    }

    def __init__(self, kind=None, api_version=None, metadata=None, spec=None, status=None):
        self.kind = kind
        self.api_version = api_version
        self.metadata = metadata
        self.spec = spec
        self.status = status

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class GroupSpec(object):
    attribute_types = {
        "pod_selector": "kubernete.client.V1LabelSelector",
        "namespace_selector": "kubernete.client.V1LabelSelector",
        "ip_blocks": "list[IPBlock]",
        "service_reference": "ServiceReference",
        "external_entity_selector": "kubernete.client.V1LabelSelector",
        "child_groups": "list[string]"
    }

    def __init__(self, pod_selector=None, namespace_selector=None, ip_blocks=None, service_reference=None, external_entity_selector=None, child_groups=None):
        self.pod_selector = pod_selector
        self.namespace_selector = namespace_selector
        self.ip_blocks = ip_blocks
        self.service_reference = service_reference
        self.external_entity_selector = external_entity_selector
        self.child_groups = child_groups
    
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class ServiceReference(object):
    attribute_types = {
        "name": "string",
        "namespace": "string"
    }

    def __init__(self, name=None, namespace=None):
        self.name = name
        self.namespace = namespace
    
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class GroupStatus(object):
    attribute_types = {
        "conditions": "list[GroupCondition]"
    }

    def __init__(self, conditions=None):
        self.conditions = conditions
    
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class GroupCondition(object):
    attribute_types = {
      "type": "string",
      "status": "string",
      "last_transition_time": "datetime",
    }

    def __init__(self, type=None, status=None, last_transition_time=None):
        self.type = type
        self.status = status
        self.last_transition_time = last_transition_time
    
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class ClusterNetworkPolicy(object):
    attribute_types = {
        "kind": "string",
        "api_version": "string",
        "metadata": "kubernetes.client.V1ObjectMeta",
        "spec": "ClusterNetworkPolicySpec",
        "status": "NetworkPolicyStatus"
    }

    def __init__(self, kind=None, api_version=None, metadata=None, spec=None, status=None):
        self.kind = kind
        self.api_version = api_version
        self.metadata = metadata
        self.spec = spec
        self.status = status

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class ClusterNetworkPolicySpec(object):
    attribute_types = {
        "tier": "string",
        "priority": "float",
        "applied_to": "list[NetworkPolicyPeer]",
        "ingress": "list[Rule]",
        "egress": "list[Rule]"
    }

    def __init__(self, tier=None, priority=None, applied_to=None, ingress=None, egress=None):
        self.tier = tier
        self.priority = priority
        self.applied_to = applied_to
        self.ingress = ingress
        self.egress = egress
    
    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

class NetworkPolicyStatus(object):
    attribute_types = {
        "phase": "string",
        "observed_generation": "int",
        "current_nodes_realized": "int",
        "desired_nodes_realized": "int"
    }

    def __init__(self, phase=None, observed_generation=None, current_nodes_realized=None, desired_nodes_realized=None):
        self.phase = phase
        self.observed_generation = observed_generation
        self.current_nodes_realized = current_nodes_realized
        self.desired_nodes_realized = desired_nodes_realized

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.attribute_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result
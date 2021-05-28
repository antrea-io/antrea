require 'date'
# register accepts the hashmap passed to "script_params"
# it runs once at startup
def register(params)
    @@time_map = Hash.new
end

# filter runs for every event
# return the list of events to be passed forward
# returning empty list is equivalent to event.cancel
def filter(event)
    event.set("[ipfix][bytes]", event.get("[ipfix][octetTotalCount]").to_i)
    event.set("[ipfix][packets]", event.get("[ipfix][packetTotalCount]").to_i)
    if event.get("[ipfix][protocolIdentifier]") == 6
        event.remove("[ipfix][protocolIdentifier]")
        event.set("[ipfix][protocolIdentifier]", "TCP")
    end
    if event.get("[ipfix][protocolIdentifier]") == 17
        event.remove("[ipfix][protocolIdentifier]")
        event.set("[ipfix][protocolIdentifier]", "UDP")
    end

    flowType = event.get("[ipfix][flowType]")
    if flowType == 1
        event.set("[ipfix][flowTypeStr]", "Intra-Node")
    elsif flowType == 2
        event.set("[ipfix][flowTypeStr]", "Inter-Node")
    elsif flowType == 3
        event.set("[ipfix][flowTypeStr]", "To External")
    elsif flowType == 4
        event.set("[ipfix][flowTypeStr]", "From External")
    end

    ingressRuleAction = event.get("[ipfix][ingressNetworkPolicyRuleAction]")
    egressRuleAction = event.get("[ipfix][egressNetworkPolicyRuleAction]")
    if ingressRuleAction == 0
        event.set("[ipfix][ingressNetworkPolicyRuleActionStr]", "No Action")
    elsif ingressRuleAction == 1
        event.set("[ipfix][ingressNetworkPolicyRuleActionStr]", "Allow")
    elsif ingressRuleAction == 2
        event.set("[ipfix][ingressNetworkPolicyRuleActionStr]", "Drop")
    elsif ingressRuleAction == 3
        event.set("[ipfix][ingressNetworkPolicyRuleActionStr]", "Reject")
    end
    if egressRuleAction == 0
        event.set("[ipfix][egressNetworkPolicyRuleActionStr]", "No Action")
    elsif egressRuleAction == 1
        event.set("[ipfix][egressNetworkPolicyRuleActionStr]", "Allow")
    elsif egressRuleAction == 2
        event.set("[ipfix][egressNetworkPolicyRuleActionStr]", "Drop")
    elsif egressRuleAction == 3
        event.set("[ipfix][egressNetworkPolicyRuleActionStr]", "Reject")
    end

    if event.get("[ipfix][destinationIPv6Address]").nil?
        event.set("[ipfix][destinationIP]", event.get("[ipfix][destinationIPv4Address]"))
    else
        event.set("[ipfix][destinationIP]", event.get("[ipfix][destinationIPv6Address]"))
    end
    if event.get("[ipfix][sourceIPv6Address]").nil?
        event.set("[ipfix][sourceIP]", event.get("[ipfix][sourceIPv4Address]"))
    else
        event.set("[ipfix][sourceIP]", event.get("[ipfix][sourceIPv6Address]"))
    end
    if event.get("[ipfix][sourcePodName]") != ""
        if event.get("[ipfix][destinationServicePortName]") != ""
            flowkey = ""
            flowkey << event.get("[ipfix][sourcePodName]")
            flowkey << ":"
            flowkey << event.get("[ipfix][sourceTransportPort]").to_s
            flowkey << "->"
            flowkey << event.get("[ipfix][destinationServicePortName]")
            flowkey << event.get("[ipfix][destinationServicePort]").to_s
            flowkey << " "
            flowkey << event.get("[ipfix][protocolIdentifier]").to_s
            event.set("[ipfix][flowKeyPodToService]", flowkey)
        end
        if event.get("[ipfix][flowType]") != 3
            flowkey = ""
            flowkey << event.get("[ipfix][sourcePodName]")
            flowkey << ":"
            flowkey << event.get("[ipfix][sourceTransportPort]").to_s
            flowkey << "->"
            flowkey << event.get("[ipfix][destinationPodName]")
            flowkey << ":"
            flowkey << event.get("[ipfix][destinationTransportPort]").to_s
            flowkey << " "
            flowkey << event.get("[ipfix][protocolIdentifier]").to_s
            event.set("[ipfix][flowKey]", flowkey)
            event.set("[ipfix][flowKeyPodToPod]", flowkey)
        else
            flowkey = ""
            flowkey << event.get("[ipfix][sourcePodName]")
            flowkey << ":"
            flowkey << event.get("[ipfix][sourceTransportPort]").to_s
            flowkey << "->"
            flowkey << event.get("[ipfix][destinationIP]")
            flowkey << ":"
            flowkey << event.get("[ipfix][destinationTransportPort]").to_s
            flowkey << " "
            flowkey << event.get("[ipfix][protocolIdentifier]").to_s
            event.set("[ipfix][flowKey]", flowkey)
            event.set("[ipfix][flowKeyPodToExternal]", flowkey)
        end
    end
    if event.get("[ipfix][ingressNetworkPolicyName]") == ""
        event.remove("[ipfix][ingressNetworkPolicyName]")
        event.set("[ipfix][ingressNetworkPolicyName]", "N/A")
    end
    if event.get("[ipfix][ingressNetworkPolicyNamespace]") == ""
        event.remove("[ipfix][ingressNetworkPolicyNamespace]")
        event.set("[ipfix][ingressNetworkPolicyNamespace]", "N/A")
    end
    if event.get("[ipfix][egressNetworkPolicyName]") == ""
        event.remove("[ipfix][egressNetworkPolicyName]")
        event.set("[ipfix][egressNetworkPolicyName]", "N/A")
    end
    if event.get("[ipfix][egressNetworkPolicyNamespace]") == ""
        event.remove("[ipfix][egressNetworkPolicyNamespace]")
        event.set("[ipfix][egressNetworkPolicyNamespace]", "N/A")
    end
    ingressNetworkPolicyType = event.get("[ipfix][ingressNetworkPolicyType]")
    if ingressNetworkPolicyType == 1
        event.set("[ipfix][ingressNetworkPolicyTypeStr]", "K8s NetworkPolicy")
    elsif ingressNetworkPolicyType == 2
        event.set("[ipfix][ingressNetworkPolicyTypeStr]", "Antrea NetworkPolicy")
    elsif ingressNetworkPolicyType == 3
        event.set("[ipfix][ingressNetworkPolicyTypeStr]", "Antrea ClusterNetworkPolicy")
    end
    egressNetworkPolicyType = event.get("[ipfix][egressNetworkPolicyType]")
    if egressNetworkPolicyType == 1
        event.set("[ipfix][egressNetworkPolicyTypeStr]", "K8s NetworkPolicy")
    elsif egressNetworkPolicyType == 2
        event.set("[ipfix][egressNetworkPolicyTypeStr]", "Antrea NetworkPolicy")
    elsif egressNetworkPolicyType == 3
        event.set("[ipfix][egressNetworkPolicyTypeStr]", "Antrea ClusterNetworkPolicy")
    end
    key = event.get("[ipfix][flowKey]")
    if @@time_map.has_key?(key)
       t = DateTime.strptime(event.get("[ipfix][flowEndSeconds]").to_s, '%Y-%m-%dT%H:%M:%S').to_time.to_i
       duration = t - @@time_map[key]
       event.set("[ipfix][throughput]", event.get("[ipfix][octetDeltaCountFromSourceNode]").to_i / duration.to_i)
       event.set("[ipfix][reverseThroughput]", event.get("[ipfix][reverseOctetDeltaCountFromSourceNode]").to_i / duration.to_i)
       @@time_map[key] = t
    else
       startTime = DateTime.strptime(event.get("[ipfix][flowStartSeconds]").to_s, '%Y-%m-%dT%H:%M:%S').to_time.to_i
       endTime = DateTime.strptime(event.get("[ipfix][flowEndSeconds]").to_s, '%Y-%m-%dT%H:%M:%S').to_time.to_i
       duration = endTime-startTime
       event.set("[ipfix][throughput]", event.get("[ipfix][octetDeltaCountFromSourceNode]").to_i / duration.to_i)
       event.set("[ipfix][reverseThroughput]", event.get("[ipfix][reverseOctetDeltaCountFromSourceNode]").to_i / duration.to_i)
       @@time_map[key] = endTime
    end
    return [event]
end

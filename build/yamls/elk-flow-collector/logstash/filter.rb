require 'date'
# register accepts the hashmap passed to "script_params"
# it runs once at startup
def register(params)
    @interval = params["interval"]
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
        if event.get("[ipfix][destinationPodName]") != ""
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
            event.set("[ipfix][flowKeyPodToPod]", flowkey)
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
    key = event.get("[ipfix][flowKeyPodToPod]")
     if @@time_map.has_key?(key)
        t = DateTime.strptime(event.get("[ipfix][flowEndSeconds]").to_s, '%Y-%m-%dT%H:%M:%S').to_time.to_i
        duration = t - @@time_map[key]
        event.set("[ipfix][throughput]", event.get("[ipfix][octetDeltaCountFromSourceNode]").to_i / duration.to_i)
        event.set("[ipfix][reverseThroughput]", event.get("[ipfix][reverseOctetDeltaCountFromSourceNode]").to_i / duration.to_i)
        @@time_map[key] = t
     else
        @@time_map[key] = DateTime.strptime(event.get("[ipfix][flowEndSeconds]").to_s, '%Y-%m-%dT%H:%M:%S').to_time.to_i
        event.set("[ipfix][throughput]", event.get("[ipfix][octetDeltaCountFromSourceNode]").to_i / @interval.to_i)
        event.set("[ipfix][reverseThroughput]", event.get("[ipfix][reverseOctetDeltaCountFromSourceNode]").to_i / @interval.to_i)
     end
    return [event]
end

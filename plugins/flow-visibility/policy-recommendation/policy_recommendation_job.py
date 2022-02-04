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

import antrea_crd
import datetime
import getopt
import json
import kubernetes.client
import os
import random
import string
import sys
import uuid

from policy_recommendation_utils import *
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf
from pyspark.sql.types import StringType

# Column names of flow record table in Clickhouse database used in recommendation job 
FLOW_TABLE_COLUMNS = [
    'sourcePodNamespace',
    'sourcePodLabels',
    'destinationIP',
    'destinationPodNamespace',
    'destinationPodLabels',
    'destinationServicePortName',
    'destinationTransportPort',
    'protocolIdentifier',
]

NAMESPACE_ALLOW_LIST = [
    'kube-system',
    'flow-aggregator',
    'flow-visibility'
]

ROW_DELIMITER = "#"
PEER_DELIMITER = "|"

def get_flow_type(destinationServicePortName, destinationPodLabels):
    if destinationServicePortName != "":
        return "pod_to_svc"
    elif destinationPodLabels != "":
        return "pod_to_pod"
    else:
        return "pod_to_external"

def get_protocol_string(protocolIdentifier):
    if protocolIdentifier == 6:
        return "TCP"
    elif protocolIdentifier == 17:
        return "UDP"
    else:
        return "UNKNOWN"

def map_flow_to_egress(flow):
    src = ROW_DELIMITER.join([flow.sourcePodNamespace, flow.sourcePodLabels])
    if flow.flowType == "pod_to_external":
        dst = ROW_DELIMITER.join([flow.destinationIP, str(flow.destinationTransportPort), get_protocol_string(flow.protocolIdentifier)])
    else:
        dst = ROW_DELIMITER.join([flow.destinationPodNamespace, flow.destinationPodLabels, str(flow.destinationTransportPort), get_protocol_string(flow.protocolIdentifier)])
    return (src, ("", dst))

def map_flow_to_egress_svc(flow):
    src = ROW_DELIMITER.join([flow.sourcePodNamespace, flow.sourcePodLabels])
    dst = ROW_DELIMITER.join([flow.destinationServicePortName, str(flow.destinationTransportPort), get_protocol_string(flow.protocolIdentifier)])
    return (src, dst)

def map_flow_to_ingress(flow):
    src = ROW_DELIMITER.join([flow.sourcePodNamespace, flow.sourcePodLabels, str(flow.destinationTransportPort), get_protocol_string(flow.protocolIdentifier)])
    dst = ROW_DELIMITER.join([flow.destinationPodNamespace, flow.destinationPodLabels])
    return (dst, (src, ""))

def combine_network_peers(a, b):
    if a[0] != "":
        new_src = a[0]
    else:
        new_src = b[0]
    if a[1] != "":
        new_dst = a[1]
    else:
        new_dst = b[1]
    return (new_src, new_dst)

def generate_k8s_egress_rule(egress):
    if len(egress.split(ROW_DELIMITER)) == 4:
        ns, labels, port, protocolIdentifier = egress.split(ROW_DELIMITER)
        egress_peer = kubernetes.client.V1NetworkPolicyPeer(
            namespace_selector = kubernetes.client.V1LabelSelector(
                match_labels = {
                    "name":ns
                }
            ),
            pod_selector = kubernetes.client.V1LabelSelector(
                match_labels = json.loads(labels)
            ),    
        )
    elif len(egress.split(ROW_DELIMITER)) == 3:
        destinationIP, port, protocolIdentifier = egress.split(ROW_DELIMITER)
        if get_IP_version(destinationIP) == "v4":
            cidr = destinationIP + "/32"
        else:
            cidr = destinationIP + "/128"
        egress_peer = kubernetes.client.V1NetworkPolicyPeer(
            ip_block = kubernetes.client.V1IPBlock(
                cidr = cidr,
            )
        )
    else:
        print("Warning: egress tuple {} has wrong format".format(egress))
        return ""
    ports = kubernetes.client.V1NetworkPolicyPort(
        port = int(port),
        protocol = protocolIdentifier
    )
    egress_rule = kubernetes.client.V1NetworkPolicyEgressRule(
        to = [egress_peer],
        ports = [ports]
    )
    return egress_rule

def generate_k8s_ingress_rule(ingress):
    ns, labels, port, protocolIdentifier = ingress.split(ROW_DELIMITER)
    ingress_peer = kubernetes.client.V1NetworkPolicyPeer(
        namespace_selector = kubernetes.client.V1LabelSelector(
            match_labels = {
                "name":ns
            }
        ),
        pod_selector = kubernetes.client.V1LabelSelector(
            match_labels = json.loads(labels)
        ),    
    )
    ports = kubernetes.client.V1NetworkPolicyPort(
        port = int(port),
        protocol = protocolIdentifier
    )
    ingress_rule = kubernetes.client.V1NetworkPolicyIngressRule(
        _from = [ingress_peer],
        ports = [ports]
    )
    return ingress_rule

def generate_policy_name(info):
    return "-".join([info, "".join(random.sample(string.ascii_letters + string.digits, 5))])

def generate_k8s_np(x):
    applied_to, (ingresses, egresses) = x
    ingress_list = ingresses.split(PEER_DELIMITER)
    egress_list = egresses.split(PEER_DELIMITER)
    egressRules = []
    for egress in egress_list:
        if ROW_DELIMITER in egress:
            egressRules.append(generate_k8s_egress_rule(egress))
    ingressRules = []
    for ingress in ingress_list:
        if ROW_DELIMITER in ingress:
            ingressRules.append(generate_k8s_ingress_rule(ingress))
    if egressRules or ingressRules:
        policy_types = []
        if egressRules:
            policy_types.append("Egress")
        if ingressRules:
            policy_types.append("Ingress")
        ns, labels = applied_to.split(ROW_DELIMITER)
        np_name = generate_policy_name("recommend-k8s-np")
        np = kubernetes.client.V1NetworkPolicy(
            api_version = "networking.k8s.io/v1",
            kind = "NetworkPolicy",
            metadata = kubernetes.client.V1ObjectMeta(
                name = np_name,
                namespace = ns
            ),
            spec = kubernetes.client.V1NetworkPolicySpec(
                egress = egressRules,
                ingress = ingressRules,
                pod_selector = kubernetes.client.V1LabelSelector(
                    match_labels = json.loads(labels)
                ),
                policy_types = policy_types    
            )
        )
    return dict_to_yaml(np.to_dict())

def generate_anp_egress_rule(egress):
    if len(egress.split(ROW_DELIMITER)) == 4:
        ns, labels, port, protocolIdentifier = egress.split(ROW_DELIMITER)
        egress_peer = antrea_crd.NetworkPolicyPeer(
            namespace_selector = kubernetes.client.V1LabelSelector(
                match_labels = {
                    "kubernetes.io/metadata.name":ns
                }
            ),
            pod_selector = kubernetes.client.V1LabelSelector(
                match_labels = json.loads(labels)
            ),    
        )
    elif len(egress.split(ROW_DELIMITER)) == 3:
        destinationIP, port, protocolIdentifier = egress.split(ROW_DELIMITER)
        if get_IP_version(destinationIP) == "v4":
            cidr = destinationIP + "/32"
        else:
            cidr = destinationIP + "/128"
        egress_peer = antrea_crd.NetworkPolicyPeer(
            ip_block = antrea_crd.IPBlock(
                CIDR = cidr,
            )
        )
    else:
        print("Warning: egress tuple {} has wrong format".format(egress))
    ports = antrea_crd.NetworkPolicyPort(
        protocol = protocolIdentifier,
        port = int(port)
    )
    egress_rule = antrea_crd.Rule(
        action = "Allow",
        to = [egress_peer],
        ports = [ports]
    )
    return egress_rule

def generate_anp_ingress_rule(ingress):
    ns, labels, port, protocolIdentifier = ingress.split(ROW_DELIMITER)
    ingress_peer = antrea_crd.NetworkPolicyPeer(
        namespace_selector = kubernetes.client.V1LabelSelector(
            match_labels = {
                "kubernetes.io/metadata.name":ns
            }
        ),
        pod_selector = kubernetes.client.V1LabelSelector(
            match_labels = json.loads(labels)
        ),    
    )
    ports = antrea_crd.NetworkPolicyPort(
        protocol = protocolIdentifier,
        port = int(port)
    )
    ingress_rule = antrea_crd.Rule(
        action = "Allow",
        _from = [ingress_peer],
        ports = [ports]
    )
    return ingress_rule

def generate_anp(network_peers):
    applied_to, (ingresses, egresses) = network_peers
    ingress_list = ingresses.split(PEER_DELIMITER)
    egress_list = egresses.split(PEER_DELIMITER)
    egressRules = []
    for egress in egress_list:
        if ROW_DELIMITER in egress:
            egressRules.append(generate_anp_egress_rule(egress))
    ingressRules = []
    for ingress in ingress_list:
        if ROW_DELIMITER in ingress:
            ingressRules.append(generate_anp_ingress_rule(ingress))
    if egressRules or ingressRules:
        ns, labels = applied_to.split(ROW_DELIMITER)
        np_name = generate_policy_name("recommend-allow-anp")
        np = antrea_crd.NetworkPolicy(
            kind = "NetworkPolicy",
            api_version = "crd.antrea.io/v1alpha1",
            metadata = kubernetes.client.V1ObjectMeta(
                name = np_name,
                namespace = ns,
            ),
            spec = antrea_crd.NetworkPolicySpec(
                tier = "Application",
                priority = 5,
                applied_to = [antrea_crd.NetworkPolicyPeer(
                    pod_selector = kubernetes.client.V1LabelSelector(
                        match_labels = json.loads(labels)
                    ),    
                )],
                egress = egressRules,
                ingress = ingressRules, 
            )
        )
        return dict_to_yaml(np.to_dict())

def get_svc_cg_name(namespace, name):
    return "-".join(["cg", namespace, name])

def generate_svc_cg(destinationServicePortNameRow):
    namespace, name = destinationServicePortNameRow.destinationServicePortName.partition(':')[0].split('/')
    svc_cg = antrea_crd.ClusterGroup(
        kind = "ClusterGroup",
        api_version = "crd.antrea.io/v1alpha2",
        metadata = kubernetes.client.V1ObjectMeta(
            name = get_svc_cg_name(namespace, name)
        ),
        spec = antrea_crd.GroupSpec(
            service_reference = antrea_crd.ServiceReference(
                name = name,
                namespace = namespace
            )
        )
    )
    return dict_to_yaml(svc_cg.to_dict())

def generate_acnp_svc_egress_rule(egress):
    svcPortName, port, protocolIdentifier = egress.split(ROW_DELIMITER)
    ns, svc = svcPortName.partition(':')[0].split('/')
    egress_peer = antrea_crd.NetworkPolicyPeer(
        group = get_svc_cg_name(ns, svc)
    )
    ports = antrea_crd.NetworkPolicyPort(
        protocol = protocolIdentifier,
        port = int(port)
    )
    egress_rule = antrea_crd.Rule(
        action = "Allow",
        to = [egress_peer],
        ports = [ports]
    )
    return egress_rule

def generate_svc_acnp(x):
    applied_to, egresses = x
    egress_list = egresses.split(PEER_DELIMITER)
    egressRules = []
    for egress in egress_list:
        egressRules.append(generate_acnp_svc_egress_rule(egress))
    if egressRules:
        ns, labels = applied_to.split(ROW_DELIMITER)
        np_name = generate_policy_name("recommend-svc-allow-acnp")
        np = antrea_crd.ClusterNetworkPolicy(
            kind = "ClusterNetworkPolicy",
            api_version = "crd.antrea.io/v1alpha1",
            metadata = kubernetes.client.V1ObjectMeta(
                name = np_name,
            ),
            spec = antrea_crd.NetworkPolicySpec(
                tier = "Application",
                priority = 5,
                applied_to = [antrea_crd.NetworkPolicyPeer(
                    pod_selector = kubernetes.client.V1LabelSelector(
                        match_labels = json.loads(labels)
                    ),
                    namespace_selector = kubernetes.client.V1LabelSelector(
                        match_labels = {
                            "kubernetes.io/metadata.name":ns
                        }
                    )
                )],
                egress = egressRules,
            )
        )
    return dict_to_yaml(np.to_dict())

def generate_reject_acnp(applied_to):
    if not applied_to:
        np_name = "recommend-reject-all-acnp"
        applied_to = antrea_crd.NetworkPolicyPeer(
            pod_selector = kubernetes.client.V1LabelSelector(),
            namespace_selector = kubernetes.client.V1LabelSelector()
        )
    else:
        np_name = generate_policy_name("recommend-reject-acnp")
        ns, labels = applied_to.split(ROW_DELIMITER)
        applied_to = antrea_crd.NetworkPolicyPeer(
            pod_selector = kubernetes.client.V1LabelSelector(
                match_labels = json.loads(labels)
            ),
            namespace_selector = kubernetes.client.V1LabelSelector(
                match_labels = {
                    "kubernetes.io/metadata.name":ns
                }
            )
        )
    np = antrea_crd.ClusterNetworkPolicy(
        kind = "ClusterNetworkPolicy",
        api_version = "crd.antrea.io/v1alpha1",
        metadata = kubernetes.client.V1ObjectMeta(
            name = np_name,
        ),
        spec = antrea_crd.NetworkPolicySpec(
            tier = "Baseline",
            priority = 5,
            applied_to = [applied_to],
            egress = [antrea_crd.Rule(
                action = "Reject",
                to = [antrea_crd.NetworkPolicyPeer(
                    pod_selector = kubernetes.client.V1LabelSelector())]
            )],
            ingress = [antrea_crd.Rule(
                action = "Reject",
                _from = [antrea_crd.NetworkPolicyPeer(
                    pod_selector = kubernetes.client.V1LabelSelector())]
            )],      
        )
    )
    return dict_to_yaml(np.to_dict())

def recommend_k8s_policies(flows_df):
    egress_rdd = flows_df.rdd.map(map_flow_to_egress)\
        .reduceByKey(lambda a, b: ("", a[1]+PEER_DELIMITER+b[1]))
    ingress_rdd = flows_df.filter(flows_df.flowType != "pod_to_external")\
        .rdd.map(map_flow_to_ingress)\
        .reduceByKey(lambda a, b: (a[0]+PEER_DELIMITER+b[0], ""))
    network_peers_rdd = ingress_rdd.union(egress_rdd)\
                    .reduceByKey(combine_network_peers)
    k8s_np_rdd = network_peers_rdd.map(generate_k8s_np)
    k8s_np_list = k8s_np_rdd.collect()
    return k8s_np_list

def recommend_antrea_policies(flows_df, option=1, deny_rules=True):
    # Recommend allow Antrea Network Policies for unprotected Pod-to-Pod & Pod-to-External flows
    unprotected_not_svc_flows_df = flows_df.filter(flows_df.flowType != "pod_to_svc")
    egress_rdd = unprotected_not_svc_flows_df.rdd.map(map_flow_to_egress)\
        .reduceByKey(lambda a, b: ("", a[1]+PEER_DELIMITER+b[1]))
    ingress_rdd = unprotected_not_svc_flows_df.filter(unprotected_not_svc_flows_df.flowType != "pod_to_external")\
        .rdd.map(map_flow_to_ingress)\
        .reduceByKey(lambda a, b: (a[0]+PEER_DELIMITER+b[0], ""))
    network_peers_rdd = ingress_rdd.union(egress_rdd)\
                    .reduceByKey(combine_network_peers)
    anp_rdd = network_peers_rdd.map(generate_anp)
    anp_list = anp_rdd.collect()
    # Recommend allow Antrea Cluster Network Policies for unprotected Pod-to-Svc flows
    unprotected_svc_flows_df = flows_df.filter(flows_df.flowType == "pod_to_svc")
    svc_df = unprotected_svc_flows_df.groupBy(["destinationServicePortName"]).agg({})
    svc_cg_list = svc_df.rdd.map(generate_svc_cg).collect()
    egress_svc_rdd = unprotected_svc_flows_df.rdd.map(map_flow_to_egress_svc)\
        .reduceByKey(lambda a, b: a+PEER_DELIMITER+b)
    svc_acnp_rdd = egress_svc_rdd.map(generate_svc_acnp)
    svc_acnp_list = svc_acnp_rdd.collect()
    if deny_rules:
        if option == 1:
            # Recommend deny ANPs for the applied to groups of allow policies
            applied_groups_rdd = network_peers_rdd.map(lambda x: x[0])\
                .union(egress_svc_rdd.map(lambda x: x[0]))\
                .distinct()
            deny_anp_rdd = applied_groups_rdd.map(generate_reject_acnp)
            deny_anp_list = deny_anp_rdd.collect()
            return anp_list + svc_cg_list + svc_acnp_list + deny_anp_list
        else:
            # Recommend deny ACNP for whole cluster
            deny_all_policy = generate_reject_acnp("")
            return anp_list + svc_cg_list + svc_acnp_list + [deny_all_policy]
    else:
        return anp_list + svc_cg_list + svc_acnp_list

def recommend_policies_for_unprotected_flows(unprotected_flows_df, option=1):
    if option not in [1, 2, 3]:
        print("Error: option {} is not valid".format(option))
        return []
    if option == 3:
        # Recommend k8s native network policies for unprotected flows
        return recommend_k8s_policies(unprotected_flows_df)
    else:
        return recommend_antrea_policies(unprotected_flows_df, option, True)

def recommend_policies_for_trusted_denied_flows(trusted_denied_flows_df):
    return recommend_antrea_policies(trusted_denied_flows_df, deny_rules=False)

def recommend_policies_for_ns_allow_list(ns_allow_list):
    policies = []
    for ns in ns_allow_list:
        np_name = generate_policy_name("recommend-allow-acnp-{}".format(ns))
        acnp = antrea_crd.ClusterNetworkPolicy(
            kind = "ClusterNetworkPolicy",
            api_version = "crd.antrea.io/v1alpha1",
            metadata = kubernetes.client.V1ObjectMeta(
                name = np_name,
            ),
            spec = antrea_crd.NetworkPolicySpec(
                tier = "Platform",
                priority = 5,
                applied_to = [antrea_crd.NetworkPolicyPeer(
                    namespace_selector = kubernetes.client.V1LabelSelector(
                        match_labels = {
                            "kubernetes.io/metadata.name":ns
                        }
                    )
                )],
                egress = [antrea_crd.Rule(
                    action = "Allow",
                    to = [antrea_crd.NetworkPolicyPeer(
                        pod_selector = kubernetes.client.V1LabelSelector())]
                )],
                ingress = [antrea_crd.Rule(
                    action = "Allow",
                    _from = [antrea_crd.NetworkPolicyPeer(
                        pod_selector = kubernetes.client.V1LabelSelector())]
                )], 
            )
        )
        policies.append(dict_to_yaml(acnp.to_dict()))
    return policies

def generate_sql_query(table_name, limit, start_time, end_time, unprotected):
    sql_query = "SELECT {} FROM {}".format(", ".join(FLOW_TABLE_COLUMNS), table_name)
    if unprotected:
        sql_query += " WHERE ingressNetworkPolicyName == '' AND egressNetworkPolicyName == ''"
    else:
        # Select user trusted denied flows when unprotected equals False
        sql_query += " WHERE trusted == 1"
    if start_time:
        sql_query += " AND flowEndSeconds >= '{}'".format(start_time)
    if end_time:
        sql_query += " AND flowEndSeconds < '{}'".format(end_time)
    sql_query += " GROUP BY {}".format(", ".join(FLOW_TABLE_COLUMNS))
    if limit:
        sql_query += " LIMIT {}".format(limit)
    return sql_query

def read_flow_df(spark, db_jdbc_address, sql_query):
    flow_df = spark.read \
        .format("jdbc") \
        .option("driver", "ru.yandex.clickhouse.ClickHouseDriver") \
        .option("url", db_jdbc_address) \
        .option("user", os.getenv("CH_USERNAME")) \
        .option("password", os.getenv("CH_PASSWORD")) \
        .option("query",  sql_query)\
        .load()
    return flow_df.withColumn('flowType', udf(get_flow_type, StringType())("destinationServicePortName", "destinationPodLabels"))

def write_recommendation_result(spark, result, recommendation_type, db_jdbc_address, table_name):
    result_dict = {
        'id': str(uuid.uuid4()),
        'type': recommendation_type,
        'timeCreated': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'yamls': '---\n'.join(result)
    }
    result_df = spark.createDataFrame([result_dict])
    result_df.write\
        .mode("append") \
        .format("jdbc") \
        .option("driver", "ru.yandex.clickhouse.ClickHouseDriver") \
        .option("url", db_jdbc_address) \
        .option("user", os.getenv("CH_USERNAME")) \
        .option("password", os.getenv("CH_PASSWORD")) \
        .option("dbtable", table_name) \
        .save()

def initial_recommendation_job(spark, db_jdbc_address, table_name, limit=0, option=1, start_time=None, end_time=None, ns_allow_list=NAMESPACE_ALLOW_LIST):
    """
    Start an initial policy recommendation Spark job on a cluster having no recommendation before.

    Args:
        spark: Current SparkSession.
        db_jdbc_address: Database address to fetch the flow records.
        table_name: Name of the table storing flow records in database.
        limit: Limit on the number of flow records fetched in database. Default value is 100, setting to 0 means unlimited.
        option: Option of network isolation preference in policy recommendation. Currently we have 3 options and default value is 1:
            1: Recommending allow ANP/ACNP policies, with default deny rules only on applied to Pod labels which have allow rules recommended.
            2: Recommending allow ANP/ACNP policies, with default deny rules for whole cluster.
            3: Recommending allow K8s network policies, with no deny rules at all.
        start_time: The start time of the flow records considered for the policy recommendation. Default value is None, which means no limit of the start time of flow records.
        end_time: The end time of the flow records considered for the policy recommendation. Default value is None, which means no limit of the end time of flow records.
        ns_allow_list: List of default traffic allow namespaces. Default value is Antrea CNI related namespaces.

    Returns:
        A list of recommended policies, each recommended policy is a string of YAML format.
    """
    sql_query = generate_sql_query(table_name, limit, start_time, end_time, True)
    unprotected_flows_df = read_flow_df(spark, db_jdbc_address, sql_query)
    return recommend_policies_for_ns_allow_list(ns_allow_list) + recommend_policies_for_unprotected_flows(unprotected_flows_df, option)

def subsequent_recommendation_job(spark, db_jdbc_address, table_name, limit=0, option=1, start_time=None, end_time=None):
    """
    Start a subsequent policy recommendation Spark job on a cluster having recommendation before.

    Args:
        spark: Current SparkSession.
        db_jdbc_address: Database address to fetch the flow records.
        table_name: Name of the table storing flow records in database.
        limit: Limit on the number of flow records fetched in database. Default value is 100, setting to 0 means unlimited.
        option: Option of network isolation preference in policy recommendation. Currently we have 3 options and default value is 1:
            1: Recommending allow ANP/ACNP policies, with default deny rules only on applied to Pod labels which have allow rules recommended.
            2: Recommending allow ANP/ACNP policies, with default deny rules for whole cluster.
            3: Recommending allow K8s network policies, with no deny rules at all.
        start_time: The start time of the flow records considered for the policy recommendation. Default value is None, which means no limit of the start time of flow records.
        end_time: The end time of the flow records considered for the policy recommendation. Default value is None, which means no limit of the end time of flow records.

    Returns:
        A list of recommended policies, each recommended policy is a string of YAML format.
    """    
    recommend_policies = []
    sql_query = generate_sql_query(table_name, limit, start_time, end_time, True)
    unprotected_flows_df = read_flow_df(spark, db_jdbc_address, sql_query)
    recommend_policies += recommend_policies_for_unprotected_flows(unprotected_flows_df, option)
    if option in [1, 2]:
        sql_query = generate_sql_query(table_name, limit, start_time, end_time, False)
        trusted_denied_flows_df = read_flow_df(spark, db_jdbc_address, sql_query)
        recommend_policies += recommend_policies_for_trusted_denied_flows(trusted_denied_flows_df)
    return recommend_policies

def is_intstring(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def main(argv):
    db_jdbc_address = "jdbc:clickhouse://clickhouse-clickhouse.flow-visibility.svc:8123"
    flow_table_name = "default.flows"
    result_table_name = "default.recommendations"
    recommendation_type = 'initial'
    limit = 0
    option = 1
    start_time = ""
    end_time = ""
    ns_allow_list = NAMESPACE_ALLOW_LIST
    help_message = """
    Start the policy recommendation spark job.

    Options:
    -h, --help: Show help message.
    -t, --type=initial: {initial|subsequent} Indicates this recommendation is an initial recommendion or a subsequent recommendation job.
    -l, --limit=0: The limit on the number of flow records read from the database. 0 means no limit.
    -o, --option=1: Option of network isolation preference in policy recommendation.
        Currently we have 3 options:
        1: Recommending allow ANP/ACNP policies, with default deny rules only on applied to Pod labels which have allow rules recommended.
        2: Recommending allow ANP/ACNP policies, with default deny rules for whole cluster.
        3: Recommending allow K8s network policies, with no deny rules at all.
    -s, --start_time=None: The start time of the flow records considered for the policy recommendation. 
        Format is YYYY-MM-DD hh:mm:ss in UTC timezone. Default value is None, which means no limit of the start time of flow records.
    -e, --end_time=None: The end time of the flow records considered for the policy recommendation.
        Format is YYYY-MM-DD hh:mm:ss in UTC timezone. Default value is None, which means no limit of the end time of flow records.
    -n, --ns_allow_list=[]: List of default traffic allow namespaces.
        Default value is a list of Antrea CNI related namespaces: ['kube-system', 'flow-aggregator', 'flow-visibility'].
    
    Usage Example:
    python3 policy_recommendation_job.py -t initial -l 1000 -o 1 -s '2021-01-01 00:00:00' -e '2021-12-31 00:00:00' -n '["kube-system","flow-aggregator","flow-visibility"]'
    """

    try:
        opts, _ = getopt.getopt(argv, "ht:l:o:s:e:n:", ["help", "type=", "limit=", "option=", "start_time=", "end_time=", "ns_allow_list="])
    except getopt.GetoptError as e:
        print("getopt.getopt ERROR: {}".format(e))
        print(help_message)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(help_message)
            sys.exit()
        elif opt in ("-t", "--type"):
            if arg not in ["initial", "subsequent"]:
                print("Recommendation type should be 'initial' or 'subsequent'.")
                print(help_message)
                sys.exit(2)
            recommendation_type = arg
        elif opt in ("-l", "--limit"):
            if not is_intstring(arg) or int(arg) < 0:
                print("Limit should be an integer >= 0.")
                print(help_message)
                sys.exit(2)
            limit = int(arg)
        elif opt in ("-o", "--option"):
            if not is_intstring(arg) or int(arg) not in [1, 2, 3]:
                print("Option of network isolation preference should be 1 or 2 or 3.")
                print(help_message)
                sys.exit(2)
            option = int(arg)
        elif opt in ("-s", "--start_time"):
            try:
                datetime.datetime.strptime(arg, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                print("start_time should be in 'YYYY-MM-DD hh:mm:ss' format.")
                print(help_message)
                sys.exit(2)
            start_time = arg
        elif opt in ("-e", "--end_time"):
            try:
                datetime.datetime.strptime(arg, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                print("end_time should be in 'YYYY-MM-DD hh:mm:ss' format.")
                print(help_message)
                sys.exit(2)
            end_time = arg
        elif opt in ("-n", "--ns_allow_list"):
            arg_list = json.loads(arg)
            if not isinstance(arg_list, list):
                print("ns_allow_list should be a list.")
                print(help_message)
                sys.exit(2)
            ns_allow_list = arg_list
    
    spark = SparkSession.builder.getOrCreate()
    if recommendation_type == 'initial':
        result = initial_recommendation_job(spark, db_jdbc_address, flow_table_name, limit, option, start_time, end_time, ns_allow_list)
        print("Initial recommended completed, policy number: {}".format(len(result)))
        write_recommendation_result(spark, result, 'initial', db_jdbc_address, result_table_name)
    else:
        result = subsequent_recommendation_job(spark, db_jdbc_address, flow_table_name, limit, option, start_time, end_time)
        print("Subsequent recommended completed, policy number: {}".format(len(result)))
        write_recommendation_result(spark, result, 'subsequent', db_jdbc_address, result_table_name)
    spark.stop()

if __name__ == '__main__':
    main(sys.argv[1:])

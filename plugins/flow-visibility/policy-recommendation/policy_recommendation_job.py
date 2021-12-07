import antrea_crd
import json
import kubernetes.client
import random
import string
import yaml
from ipaddress import ip_address, IPv4Address
from pyspark.sql import SparkSession
from pyspark.sql.functions import udf
from pyspark.sql.types import *
from re import sub

# Column names of flow record table in Clickhouse database used in recommendation job 
FLOW_TABLE_COLUMNS = [
    'src_ip',
    'src_pod_ns',
    'src_pod_labels',
    'dst_ip',
    'dst_pod_ns',
    'dst_pod_labels',
    'dst_svc_name',
    'dst_svc_ns',
    'dst_port',
    'proto',
    'ingress_policy',
    'egress_policy',
    'trusted',
]

def get_flow_type(dst_svc_name, dst_pod_labels):
    if dst_svc_name != "":
        return "pod_to_svc"
    elif dst_pod_labels != "":
        return "pod_to_pod"
    else:
        return "pod_to_external"

def map_flow_to_egress(flow):
    src = "#".join([flow.src_pod_ns, flow.src_pod_labels])
    if flow.flow_type == "pod_to_external":
        dst = "#".join([flow.dst_ip, str(flow.dst_port), flow.proto])
    else:
        dst = "#".join([flow.dst_pod_ns, flow.dst_pod_labels, str(flow.dst_port), flow.proto])
    return (src, ("", dst))

def map_flow_to_egress_svc(flow):
    src = "#".join([flow.src_pod_ns, flow.src_pod_labels])
    dst = "#".join([flow.dst_svc_ns, flow.dst_svc_name, str(flow.dst_port), flow.proto])
    return (src, dst)

def map_flow_to_ingress(flow):
    src = "#".join([flow.src_pod_ns, flow.src_pod_labels, str(flow.dst_port), flow.proto])
    dst = "#".join([flow.dst_pod_ns, flow.dst_pod_labels])
    return (dst, (src, ""))

def combine_network_peers(a, b):
    if a[0] != "" and b[0] != "":
        new_src = '|'.join([a[0], b[0]])
    elif a[0] != "":
        new_src = a[0]
    else:
        new_src = b[0]
    if a[1] != "" and b[1] != "":
        new_dst = '|'.join([a[1], b[1]])
    elif a[1] != "":
        new_dst = a[1]
    else:
        new_dst = b[1]
    return (new_src, new_dst)

def get_IP_version(IP):
    return "v4" if type(ip_address(IP)) is IPv4Address else "v6"

def camel(s):
    s = sub(r"(_|-)+", " ", s).title().replace(" ", "")
    if not s: return s
    return s[0].lower() + s[1:]

def camel_dict(d):
    result = {}
    for key, value in d.items():
        if isinstance(value, list):
            result[camel(key)] = list(map(
                lambda x: camel_dict(x) if isinstance(x, dict) else x, value
            ))
        elif isinstance(value, dict) and key != "match_labels":
            result[camel(key)] = camel_dict(value)
        elif value != None:
            result[camel(key)] = value
    return result

def dict_to_yaml(d):
    return yaml.dump(yaml.load(json.dumps(camel_dict(d)), Loader=yaml.FullLoader))

def generate_k8s_egress_rule(egress):
    if len(egress.split("#")) == 4:
        ns, labels, port, proto = egress.split("#")
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
    elif len(egress.split("#")) == 3:
        dst_ip, port, proto = egress.split("#")
        if get_IP_version(dst_ip) == "v4":
            cidr = dst_ip + "/32"
        else:
            cidr = dst_ip + "/128"
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
        protocol = proto
    )
    egress_rule = kubernetes.client.V1NetworkPolicyEgressRule(
        to = [egress_peer],
        ports = [ports]
    )
    return egress_rule

def generate_k8s_ingress_rule(ingress):
    ns, labels, port, proto = ingress.split("#")
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
        protocol = proto
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
    ingress_list = ingresses.split('|')
    egress_list = egresses.split('|')
    egressRules = []
    for egress in egress_list:
        if '#' in egress:
            egressRules.append(generate_k8s_egress_rule(egress))
    ingressRules = []
    for ingress in ingress_list:
        if '#' in ingress:
            ingressRules.append(generate_k8s_ingress_rule(ingress))
    if egressRules or ingressRules:
        policy_types = []
        if egressRules:
            policy_types.append("Egress")
        if ingressRules:
            policy_types.append("Ingress")
        ns, labels = applied_to.split("#")
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
    if len(egress.split("#")) == 4:
        ns, labels, port, proto = egress.split("#")
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
    elif len(egress.split("#")) == 3:
        dst_ip, port, proto = egress.split("#")
        if get_IP_version(dst_ip) == "v4":
            cidr = dst_ip + "/32"
        else:
            cidr = dst_ip + "/128"
        egress_peer = antrea_crd.NetworkPolicyPeer(
            ip_block = antrea_crd.IPBlock(
                CIDR = cidr,
            )
        )
    else:
        print("Warning: egress tuple {} has wrong format".format(egress))
    ports = antrea_crd.NetworkPolicyPort(
        protocol = proto,
        port = int(port)
    )
    egress_rule = antrea_crd.Rule(
        action = "Allow",
        to = [egress_peer],
        ports = [ports]
    )
    return egress_rule

def generate_anp_ingress_rule(ingress):
    ns, labels, port, proto = ingress.split("#")
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
        protocol = proto,
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
    ingress_list = ingresses.split('|')
    egress_list = egresses.split('|')
    egressRules = []
    for egress in egress_list:
        if '#' in egress:
            egressRules.append(generate_anp_egress_rule(egress))
    ingressRules = []
    for ingress in ingress_list:
        if '#' in ingress:
            ingressRules.append(generate_anp_ingress_rule(ingress))
    if egressRules or ingressRules:
        ns, labels = applied_to.split("#")
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

def generate_svc_cg(x):
    namespace, name = x
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
    ns, svc, port, proto = egress.split("#")
    egress_peer = antrea_crd.NetworkPolicyPeer(
        group = get_svc_cg_name(ns, svc)
    )
    ports = antrea_crd.NetworkPolicyPort(
        protocol = proto,
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
    egress_list = egresses.split('|')
    egressRules = []
    for egress in egress_list:
        egressRules.append(generate_acnp_svc_egress_rule(egress))
    if egressRules:
        ns, labels = applied_to.split("#")
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
        ns, labels = applied_to.split("#")
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
        .reduceByKey(lambda a, b: ("", a[1]+"|"+b[1]))
    ingress_rdd = flows_df.filter(flows_df.flow_type != "pod_to_external")\
        .rdd.map(map_flow_to_ingress)\
        .reduceByKey(lambda a, b: (a[0]+"|"+b[0], ""))
    network_peers_rdd = ingress_rdd.union(egress_rdd)\
                    .reduceByKey(combine_network_peers)
    k8s_np_rdd = network_peers_rdd.map(generate_k8s_np)
    k8s_np_list = k8s_np_rdd.collect()
    return k8s_np_list

def recommend_antrea_policies(flows_df, option=1, deny_rules=True):
    # Recommend allow Antrea Network Policies for unprotected Pod-to-Pod & Pod-to-External flows
    unprotected_not_svc_flows_df = flows_df.filter(flows_df.flow_type != "pod_to_svc")
    egress_rdd = unprotected_not_svc_flows_df.rdd.map(map_flow_to_egress)\
        .reduceByKey(lambda a, b: ("", a[1]+"|"+b[1]))
    ingress_rdd = unprotected_not_svc_flows_df.filter(unprotected_not_svc_flows_df.flow_type != "pod_to_external")\
        .rdd.map(map_flow_to_ingress)\
        .reduceByKey(lambda a, b: (a[0]+"|"+b[0], ""))
    network_peers_rdd = ingress_rdd.union(egress_rdd)\
                    .reduceByKey(combine_network_peers)
    anp_rdd = network_peers_rdd.map(generate_anp)
    anp_list = anp_rdd.collect()
    # Recommend allow Antrea Cluster Network Policies for unprotected Pod-to-Svc flows
    unprotected_svc_flows_df = flows_df.filter(flows_df.flow_type == "pod_to_svc")
    svc_df = unprotected_svc_flows_df.groupBy(["dst_svc_ns", "dst_svc_name"]).agg({})
    svc_cg_list = svc_df.rdd.map(generate_svc_cg).collect()
    egress_svc_rdd = unprotected_svc_flows_df.rdd.map(map_flow_to_egress_svc)\
        .reduceByKey(lambda a, b: a+"|"+b)
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

def generate_sql_query(table_name, limit, start_time, end_time):
    sql_query = "SELECT {} FROM {}".format(", ".join(FLOW_TABLE_COLUMNS), table_name)
    if start_time and end_time:
        sql_query += " WHERE flow_end_seconds >= '{}' AND flow_end_seconds < '{}'".format(start_time, end_time)
    elif start_time:
        sql_query += " WHERE flow_end_seconds >= '{}'".format(start_time)
    elif end_time:
        sql_query += " WHERE flow_end_seconds < '{}'".format(end_time)
    if limit:
        sql_query += " LIMIT {}".format(limit)
    return sql_query

def read_flow_df(spark, db_jdbc_address, sql_query):
    return spark.read \
        .format("jdbc") \
        .option("url", db_jdbc_address) \
        .option("query",  sql_query)\
        .load()

def aggregate_and_fill_type(flow_df):
    return flow_df.groupBy(FLOW_TABLE_COLUMNS[:-3])\
                    .agg({})\
                    .withColumn('flow_type', udf(get_flow_type, StringType())("dst_svc_name", "dst_pod_labels"))

def initial_recommendation_job(spark, db_jdbc_address, table_name, limit=100, option=1, start_time=None, end_time=None):
    sql_query = generate_sql_query(table_name, limit, start_time, end_time)
    flow_df = read_flow_df(spark, db_jdbc_address, sql_query)
    unprotected_flows_df = aggregate_and_fill_type(flow_df.filter((flow_df.ingress_policy == "") & (flow_df.egress_policy == "")))
    return recommend_policies_for_unprotected_flows(unprotected_flows_df, option)

def subsequent_recommendation_job(spark, db_jdbc_address, table_name, limit=100, option=1, start_time=None, end_time=None):
    recommend_policies = []
    sql_query = generate_sql_query(table_name, limit, start_time, end_time)
    flow_df = read_flow_df(spark, db_jdbc_address, sql_query)
    unprotected_flows_df = aggregate_and_fill_type(flow_df.filter((flow_df.ingress_policy == "") & (flow_df.egress_policy == "")))
    recommend_policies += recommend_policies_for_unprotected_flows(unprotected_flows_df, option)
    if option in [1, 2]:
        trusted_denied_flows_df = aggregate_and_fill_type(flow_df.filter(flow_df.trusted == 1))
        recommend_policies += recommend_policies_for_trusted_denied_flows(trusted_denied_flows_df)
    return recommend_policies

def main():
    spark = SparkSession.builder.getOrCreate()
    # Argument values for development use only
    db_jdbc_address = "jdbc:clickhouse://localhost:8123"
    table_name = "default.flow_record"
    # result = initial_recommendation_job(spark, db_jdbc_address, table_name, option=1)
    # print("Initial recommended completed, policy number: {}".format(len(result)))
    result = subsequent_recommendation_job(spark, db_jdbc_address, table_name, option=1, start_time="2021-12-01 00:00:00", end_time=None)
    print("Subsequent recommended completed, policy number: {}".format(len(result)))
    for policy in result:
        print(policy)

if __name__ == '__main__':
    main()

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

import pytest
import yaml
from policy_recommendation_job import *
from pyspark.sql import SparkSession

table_name = "default.flows"

@pytest.mark.parametrize("test_input, expected_sql_query", [
    (
        (0, "", "", True), 
        "SELECT {} FROM {} WHERE ingressNetworkPolicyName == '' AND egressNetworkPolicyName == '' GROUP BY {}".format(", ".join(FLOW_TABLE_COLUMNS), table_name, ", ".join(FLOW_TABLE_COLUMNS))
    ),
    (
        (0, "", "", False), 
        "SELECT {} FROM {} WHERE trusted == 1 GROUP BY {}".format(", ".join(FLOW_TABLE_COLUMNS), table_name, ", ".join(FLOW_TABLE_COLUMNS))
    ),
    (
        (100, "", "", True), 
        "SELECT {} FROM {} WHERE ingressNetworkPolicyName == '' AND egressNetworkPolicyName == '' GROUP BY {} LIMIT 100".format(", ".join(FLOW_TABLE_COLUMNS), table_name, ", ".join(FLOW_TABLE_COLUMNS))
    ),
    (
        (100, "2022-01-01 00:00:00", "", True), 
        "SELECT {} FROM {} WHERE ingressNetworkPolicyName == '' AND egressNetworkPolicyName == '' AND flowEndSeconds >= '2022-01-01 00:00:00' GROUP BY {} LIMIT 100".format(", ".join(FLOW_TABLE_COLUMNS), table_name, ", ".join(FLOW_TABLE_COLUMNS))
    ),
    (
        (100, "", "2022-01-01 23:59:59", True), 
        "SELECT {} FROM {} WHERE ingressNetworkPolicyName == '' AND egressNetworkPolicyName == '' AND flowEndSeconds < '2022-01-01 23:59:59' GROUP BY {} LIMIT 100".format(", ".join(FLOW_TABLE_COLUMNS), table_name, ", ".join(FLOW_TABLE_COLUMNS))
    ),
    (
        (100, "2022-01-01 00:00:00", "2022-01-01 23:59:59", True), 
        "SELECT {} FROM {} WHERE ingressNetworkPolicyName == '' AND egressNetworkPolicyName == '' AND flowEndSeconds >= '2022-01-01 00:00:00' AND flowEndSeconds < '2022-01-01 23:59:59' GROUP BY {} LIMIT 100".format(", ".join(FLOW_TABLE_COLUMNS), table_name, ", ".join(FLOW_TABLE_COLUMNS))
    ),
])
def test_generate_sql_query(test_input, expected_sql_query):
    limit, start_time, end_time, unprotected = test_input
    sql_query = generate_sql_query(table_name, limit, start_time, end_time, unprotected)
    assert sql_query == expected_sql_query

@pytest.mark.parametrize("test_input, expected_policies", [
    (
        NAMESPACE_ALLOW_LIST,
        {
            ns:{
                "apiVersion": "crd.antrea.io/v1alpha1",
                "kind": "ClusterNetworkPolicy",
                "metadata": {
                    "name": "recommend-allow-acnp-{}-74D9G".format(ns)
                },
                "spec": {
                    "priority": 5, 
                    "tier": "Platform",
                    "appliedTo": [{
                        "namespaceSelector": {
                            "matchLabels": {
                                "kubernetes.io/metadata.name": "{}".format(ns)
                            }
                        }
                    }],
                    "egress": [{
                        "action": "Allow",
                        "to": [{
                            "podSelector": {}
                        }]
                    }],
                    "ingress": [{
                        "action": "Allow",
                        "from": [{
                            "podSelector": {}
                        }]
                    }],
                }
            }
        for ns in NAMESPACE_ALLOW_LIST
        }
    ),
])
def test_recommend_policies_for_ns_allow_list(test_input, expected_policies):
    recommend_polices_yamls = recommend_policies_for_ns_allow_list(test_input)
    recommend_polices_dicts = [
        yaml.load(i, Loader=yaml.FullLoader) for i in recommend_polices_yamls
    ]
    assert len(recommend_polices_dicts) == len(expected_policies)
    for policy in recommend_polices_dicts:
        assert (
            "spec" in policy
            and "appliedTo" in policy["spec"]
            and len(policy["spec"]["appliedTo"]) == 1
            and "namespaceSelector" in policy["spec"]["appliedTo"][0]
            and "matchLabels" in policy["spec"]["appliedTo"][0]["namespaceSelector"]
            and "kubernetes.io/metadata.name" in policy["spec"]["appliedTo"][0]["namespaceSelector"]["matchLabels"]
        )
        namespace = policy["spec"]["appliedTo"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"]
        expect_policy = expected_policies[namespace]
        assert (
            "metadata" in policy
            and "name" in policy["metadata"]
            and policy["metadata"]["name"].startswith("recommend-allow-acnp-{}".format(namespace)) == True
        )
        policy["metadata"]["name"] = expect_policy["metadata"]["name"]
        assert policy == expect_policy

@pytest.fixture(scope="session")
def spark_session(request):
    spark_session = (
        SparkSession.builder.master("local")
        .appName("policy_recommendation_job_test")
        .getOrCreate()
    )
    request.addfinalizer(lambda: spark_session.sparkContext.stop())
    return spark_session
 
flows_input = [
    (
        "antrea-test",
        '{"podname":"perftest-a"}',
        "10.10.0.5",
        "antrea-test",
        '{"podname":"perftest-b"}',
        "",
        5201,
        6,
        "pod_to_pod",
    ),
    (
        "antrea-test",
        '{"podname":"perftest-a"}',
        "10.10.0.6",
        "antrea-test",
        '{"podname":"perftest-c"}',
        "antrea-e2e/perftestsvc:5201",
        5201,
        6,
        "pod_to_svc",
    ),
    (
        "antrea-test",
        '{"podname":"perftest-a"}',
        "192.168.0.1",
        "",
        "",
        "",
        80,
        6,
        "pod_to_external",
    ),
]

@pytest.mark.parametrize("flows_input, expected_policies", [
    (
        flows_input,
        {
            "perftest-b": {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": "recommend-k8s-np-BzeCA", "namespace": "antrea-test"},
                "spec": {
                    "egress": [],
                    "ingress": [
                        {
                            "from": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {"name": "antrea-test"}
                                    },
                                    "podSelector": {"matchLabels": {"podname": "perftest-a"}},
                                }
                            ],
                            "ports": [{"port": 5201, "protocol": "TCP"}],
                        }
                    ],
                    "podSelector": {"matchLabels": {"podname": "perftest-b"}},
                    "policyTypes": ["Ingress"],
                },
            },
            "perftest-c": {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": "recommend-k8s-np-j5c1d", "namespace": "antrea-test"},
                "spec": {
                    "egress": [],
                    "ingress": [
                        {
                            "from": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {"name": "antrea-test"}
                                    },
                                    "podSelector": {"matchLabels": {"podname": "perftest-a"}},
                                }
                            ],
                            "ports": [{"port": 5201, "protocol": "TCP"}],
                        },
                    ],
                    "podSelector": {"matchLabels": {"podname": "perftest-c"}},
                    "policyTypes": ["Ingress"],
                },
            },
            "perftest-a": {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": "recommend-k8s-np-OiBQn", "namespace": "antrea-test"},
                "spec": {
                    "egress": [
                        {
                            "ports": [{"port": 5201, "protocol": "TCP"}],
                            "to": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {"name": "antrea-test"}
                                    },
                                    "podSelector": {"matchLabels": {"podname": "perftest-b"}},
                                }
                            ],
                        },
                        {
                            "ports": [{"port": 5201, "protocol": "TCP"}],
                            "to": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {"name": "antrea-test"}
                                    },
                                    "podSelector": {"matchLabels": {"podname": "perftest-c"}},
                                }
                            ],
                        },
                        {
                            "ports": [{"port": 80, "protocol": "TCP"}],
                            "to": [{"ipBlock": {"cidr": "192.168.0.1/32"}}],
                        },
                    ],
                    "ingress": [],
                    "podSelector": {"matchLabels": {"podname": "perftest-a"}},
                    "policyTypes": ["Egress"],
                },
            },
        }
    )
])
def test_recommend_k8s_policies(spark_session, flows_input, expected_policies):
    test_df = spark_session.createDataFrame(
        flows_input, FLOW_TABLE_COLUMNS + ["flowType"]
    )
    recommend_k8s_polices_yamls = recommend_k8s_policies(test_df)
    recommend_k8s_polices_dicts = [
        yaml.load(i, Loader=yaml.FullLoader) for i in recommend_k8s_polices_yamls
    ]
    assert len(recommend_k8s_polices_dicts) == len(expected_policies)
    for policy in recommend_k8s_polices_dicts:
        assert (
            "spec" in policy
            and "podSelector" in policy["spec"]
            and "matchLabels" in policy["spec"]["podSelector"]
            and "podname" in policy["spec"]["podSelector"]["matchLabels"]
        )
        podname = policy["spec"]["podSelector"]["matchLabels"]["podname"]
        expect_policy = expected_policies[podname]
        assert (
            "metadata" in policy 
            and "name" in policy["metadata"]
            and policy["metadata"]["name"].startswith("recommend-k8s-np-") == True
        )
        policy["metadata"]["name"] = expect_policy["metadata"]["name"]
        assert policy == expect_policy


@pytest.mark.parametrize("test_input, expected_policies", [
    (
        (flows_input, 1, True),
        {
            "NetworkPolicy": {
                "perftest-b": {
                    "apiVersion": "crd.antrea.io/v1alpha1",
                    "kind": "NetworkPolicy",
                    "metadata": {
                        "name": "recommend-allow-anp-53JbG",
                        "namespace": "antrea-test",
                    },
                    "spec": {
                        "appliedTo": [
                            {"podSelector": {"matchLabels": {"podname": "perftest-b"}}}
                        ],
                        "egress": [],
                        "ingress": [
                            {
                                "action": "Allow",
                                "from": [
                                    {
                                        "namespaceSelector": {
                                            "matchLabels": {
                                                "kubernetes.io/metadata.name": "antrea-test"
                                            }
                                        },
                                        "podSelector": {
                                            "matchLabels": {"podname": "perftest-a"}
                                        },
                                    }
                                ],
                                "ports": [{"port": 5201, "protocol": "TCP"}],
                            }
                        ],
                        "priority": 5,
                        "tier": "Application",
                    },
                },
                "perftest-a": {
                    "apiVersion": "crd.antrea.io/v1alpha1",
                    "kind": "NetworkPolicy",
                    "metadata": {
                        "name": "recommend-allow-anp-eDJzR",
                        "namespace": "antrea-test",
                    },
                    "spec": {
                        "appliedTo": [
                            {"podSelector": {"matchLabels": {"podname": "perftest-a"}}}
                        ],
                        "egress": [
                            {
                                "action": "Allow",
                                "ports": [{"port": 5201, "protocol": "TCP"}],
                                "to": [
                                    {
                                        "namespaceSelector": {
                                            "matchLabels": {
                                                "kubernetes.io/metadata.name": "antrea-test"
                                            }
                                        },
                                        "podSelector": {
                                            "matchLabels": {"podname": "perftest-b"}
                                        },
                                    }
                                ],
                            },
                            {
                                "action": "Allow",
                                "ports": [{"port": 80, "protocol": "TCP"}],
                                "to": [{"ipBlock": {"cidr": "192.168.0.1/32"}}],
                            },
                        ],
                        "ingress": [],
                        "priority": 5,
                        "tier": "Application",
                    },
                },
            },
            "ClusterGroup": {
                "apiVersion": "crd.antrea.io/v1alpha2",
                "kind": "ClusterGroup",
                "metadata": {"name": "cg-antrea-e2e-perftestsvc"},
                "spec": {
                    "serviceReference": {"name": "perftestsvc", "namespace": "antrea-e2e"}
                },
            },
            "ClusterNetworkPolicy": {
                "Application": {
                    "perftest-a": {
                        "apiVersion": "crd.antrea.io/v1alpha1",
                        "kind": "ClusterNetworkPolicy",
                        "metadata": {"name": "recommend-svc-allow-acnp-sGSj9"},
                        "spec": {
                            "appliedTo": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {
                                            "kubernetes.io/metadata.name": "antrea-test"
                                        }
                                    },
                                    "podSelector": {"matchLabels": {"podname": "perftest-a"}},
                                }
                            ],
                            "egress": [
                                {
                                    "action": "Allow",
                                    "ports": [{"port": 5201, "protocol": "TCP"}],
                                    "to": [{"group": "cg-antrea-e2e-perftestsvc"}],
                                }
                            ],
                            "priority": 5,
                            "tier": "Application",
                        },
                    },
                },
                "Baseline": {
                    "perftest-a": {
                        "apiVersion": "crd.antrea.io/v1alpha1",
                        "kind": "ClusterNetworkPolicy",
                        "metadata": {"name": "recommend-reject-acnp-OpeDq"},
                        "spec": {
                            "appliedTo": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {
                                            "kubernetes.io/metadata.name": "antrea-test"
                                        }
                                    },
                                    "podSelector": {
                                        "matchLabels": {"podname": "perftest-a"}
                                    },
                                }
                            ],
                            "egress": [{"action": "Reject", "to": [{"podSelector": {}}]}],
                            "ingress": [
                                {"action": "Reject", "from": [{"podSelector": {}}]}
                            ],
                            "priority": 5,
                            "tier": "Baseline",
                        },
                    },
                    "perftest-b": {
                        "apiVersion": "crd.antrea.io/v1alpha1",
                        "kind": "ClusterNetworkPolicy",
                        "metadata": {"name": "recommend-reject-acnp-trSQN"},
                        "spec": {
                            "appliedTo": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {
                                            "kubernetes.io/metadata.name": "antrea-test"
                                        }
                                    },
                                    "podSelector": {
                                        "matchLabels": {"podname": "perftest-b"}
                                    },
                                }
                            ],
                            "egress": [{"action": "Reject", "to": [{"podSelector": {}}]}],
                            "ingress": [
                                {"action": "Reject", "from": [{"podSelector": {}}]}
                            ],
                            "priority": 5,
                            "tier": "Baseline",
                        },
                    },
                },
            },
        },
    ),
])
def test_recommend_antrea_policies(spark_session, test_input, expected_policies):
    flows_input, option, deny_rules = test_input
    test_df = spark_session.createDataFrame(
        flows_input, FLOW_TABLE_COLUMNS + ["flowType"]
    )
    recommend_polices_yamls = recommend_antrea_policies(test_df, option, deny_rules)
    recommend_polices_dicts = [
        yaml.load(i, Loader=yaml.FullLoader) for i in recommend_polices_yamls
    ]
    for policy in recommend_polices_dicts:
        assert "kind" in policy and policy["kind"] in expected_policies
        if policy["kind"] == "NetworkPolicy":
            assert (
                "spec" in policy
                and "appliedTo" in policy["spec"]
                and len(policy["spec"]["appliedTo"]) == 1
                and "podSelector" in policy["spec"]["appliedTo"][0]
                and "matchLabels" in policy["spec"]["appliedTo"][0]["podSelector"]
                and "podname" in policy["spec"]["appliedTo"][0]["podSelector"]["matchLabels"]
            )
            podname = policy["spec"]["appliedTo"][0]["podSelector"]["matchLabels"]["podname"]
            expect_policy = expected_policies[policy["kind"]][podname]
            assert (
                "metadata" in policy
                and "name" in policy["metadata"]
                and policy["metadata"]["name"].startswith("recommend-allow-anp-") == True
            )
            policy["metadata"]["name"] = expect_policy["metadata"]["name"]
            assert policy == expect_policy
        elif policy["kind"] == "ClusterGroup":
            assert policy == expected_policies[policy["kind"]]
        else:
            assert "spec" in policy and "tier" in policy["spec"]
            policy_tier = policy["spec"]["tier"]
            assert policy_tier in expected_policies[policy["kind"]]
            assert (
                "appliedTo" in policy["spec"]
                and len(policy["spec"]["appliedTo"]) == 1
                and "podSelector" in policy["spec"]["appliedTo"][0]
                and "matchLabels" in policy["spec"]["appliedTo"][0]["podSelector"]
                and "podname" in policy["spec"]["appliedTo"][0]["podSelector"]["matchLabels"]
            )
            podname = policy["spec"]["appliedTo"][0]["podSelector"]["matchLabels"]["podname"]
            expect_policy = expected_policies[policy["kind"]][policy_tier][podname]
            assert "metadata" in policy and "name" in policy["metadata"]
            if policy_tier == "Application":
                assert policy["metadata"]["name"].startswith("recommend-svc-allow-acnp-") == True
            else:
                assert policy["metadata"]["name"].startswith("recommend-reject-acnp-") == True
            policy["metadata"]["name"] = expect_policy["metadata"]["name"]
            assert policy == expect_policy

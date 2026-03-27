# Third-party IPAM packages

Packages below have been copied from
[k8s.io/kubernetes](https://github.com/kubernetes/kubernetes) to avoid
importing the whole kubernetes repo. They were originally imported from
v1.21.1, and the `range_allocator.go` file has since been synced with
upstream changes up to v1.32 (see below).

| Upstream                                             | Local                                        |
|------------------------------------------------------|----------------------------------------------|
| `pkg/controller/util/node/controller_utils.go`       | `controller_util_node/controller_utils.go`   |
| `pkg/controller/nodeipam/ipam/cidrset/cidr_set.go`   | `nodeipam/ipam/cidrset/cidr_set.go`          |
| `pkg/controller/nodeipam/ipam/cidrset/metrics.go`    | `nodeipam/ipam/cidrset/metrics.go`           |
| `pkg/controller/nodeipam/ipam/cidr_allocator.go`     | `nodeipam/ipam/cidr_allocator.go`            |
| `pkg/controller/nodeipam/ipam/range_allocator.go`    | `nodeipam/ipam/range_allocator.go`           |
| `pkg/controller/nodeipam/node_ipam_controller.go`    | `nodeipam/node_ipam_controller.go`           |
| `pkg/util/node/node.go`                              | `util_node/node.go`                          |

## Notable upstream syncs

- `range_allocator.go`: ported
  [K8s PR #123238](https://github.com/kubernetes/kubernetes/pull/123238)
  (replace channel with workqueue, fix infinite loop) and
  [K8s PR #128305](https://github.com/kubernetes/kubernetes/pull/128305)
  (release CIDRs only on actual node deletion).

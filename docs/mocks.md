# Mocks

Antrea uses the [GoMock](https://github.com/golang/mock) framework for its unit
tests.

The following interfaces are mocked at the moment:
 * `github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig.OVSBridgeClient` is mocked as
   `github.com/vmware-tanzu/antrea/pkg/ovs/ovsconfig/testing.MockOVSBridgeClient`
 * `github.com/vmware-tanzu/antrea/pkg/agent/cniserver/ipam.IPAMDriver` is mocked as
   `github.com/vmware-tanzu/antrea/pkg/agent/cniserver/ipam/testing.MockIPAMDriver`
 * `github.com/vmware-tanzu/antrea/pkg/agent/openflow.Client` is mocked as
   `github.com/vmware-tanzu/antrea/pkg/agent/openflow/testing.MockClient`
 * `github.com/vmware-tanzu/antrea/pkg/ovs/openflow.Bridge` is mocked as
   `github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing.MockBridge`
 * `github.com/vmware-tanzu/antrea/pkg/ovs/openflow.Table` is mocked as
   `github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing.MockTable`
 * `github.com/vmware-tanzu/antrea/pkg/ovs/openflow.Flow` is mocked as
   `github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing.MockFlow`
 * `github.com/vmware-tanzu/antrea/pkg/ovs/openflow.Action` is mocked as
   `github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing.MockAction`
 * `github.com/vmware-tanzu/antrea/pkg/ovs/openflow.FlowBuilder` is mocked as
   `github.com/vmware-tanzu/antrea/pkg/ovs/openflow/testing.MockFlowBuilder`

If you add or modify interfaces that need to be mocked, please add or update
the `go:generate` comment (to invoke mockgen) right above the interface
definition. All the mocks for a given package must be generated in a
sub-package called `testing`. For example, to mock interface `Iface` defined in
`pkg/foo/example.go`, use the following `go:generate` comment above the `Iface`
definition:

```
//go:generate mockgen -copyright_file <RELATIVE PATH TO>/hack/boilerplate/license_header.raw.txt -destination testing/mock_example.go -package=testing github.com/vmware-tanzu/antrea/pkg/foo Iface
```

You can then re-generate the mock source code (with `mockgen`) by invoking
`make mocks` from the top-level directory.

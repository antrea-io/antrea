# Mocks

OKN uses the [GoMock](https://github.com/golang/mock) framework for its unit
tests.

The following interfaces are mocked at the moment:
 * `okn/pkg/ovs/ovsconfig.OVSBridgeClient` is mocked as
   `okn/pkg/ovs/ovsconfig/testing.MockOVSBridgeClient`
 * `okn/pkg/agent/cniserver/ipam.IPAMDriver` is mocked as
   `okn/pkg/agent/cniserver/ipam/testing.MockIPAMDriver`
 * `okn/pkg/agent/openflow.Client` is mocked as
   `okn/pkg/agent/openflow/testing.MockClient`

If you add or modify interfaces that need to be mocked, please add or update
the `go:generate` comment (to invoke mockgen) right above the interface
definition. All the mocks for a given package must be generated in a
sub-package called `testing`. For example, to mock interface `Iface` defined in
`pkg/foo/example.go`, use the following `go:generate` comment above the `Iface`
definition:

```
//go:generate mockgen -copyright_file <RELATIVE PATH TO>/hack/boilerplate/license_header.go.txt -destination testing/mock_example.go -package=testing okn/pkg/foo Iface
```

You can then re-generate the mock source code (with `mockgen`) by invoking
`make mocks` from the top-level directory.

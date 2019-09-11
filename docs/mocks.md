# Mocks

OKN uses the [GoMock](https://github.com/golang/mock)
https://github.com/golang/mock for its unit tests.

The following interfaces are mocked at the moment:
 * `OVSBridgeClient` from the `okn/pkg/ovs/ovsconfig` package is mocked as
   `MockOVSdbClient`
 * `IPAMDriver` from the `okn/pkg/agent/cniserver/ipam` package is mocked as
   `MockIPAMDriver`
  * `Client` from the `okn/pkg/agent/openflow` package is mocked as
    `MockOFClient`  

If you modify one or more interfaces, you can re-generate the mock source code
(with `mockgen`) by invoking `make mocks` from the top-level directory.

## Description
Fixes #7673

This PR introduces support for configuring BGP Timers and BFD (Bidirectional Forwarding Detection) in the `BGPPolicy` CRD.

### Changes
- **BGP Timers**: Added `BGPTimers` struct to `BGPPeer` to allow configuration of `KeepaliveTimeSeconds`, `HoldTimeSeconds`, and `ConnectRetryTimeSeconds`.
- **BFD Configuration**: Added `BFDConfig` struct to `BGPPeer` with an explicit `Enabled` field and descriptive parameters (`MinTransmitInterval`, `MinReceiveInterval`, `Multiplier`).
- **GoBGP Integration**: Updated `gobgp.go` to map the new Timer configurations to the GoBGP API. (BFD mapping is prepared but deferred pending GoBGP v3 API support).

### Comparison with Alternatives
This implementation improves upon previous proposals (e.g., #7725) by:
1.  Using a nested `BGPTimers` struct for cleaner API design.
2.  Adopting descriptive naming for BFD fields (`MinTransmitInterval` etc.).
3.  Adding the `Enabled` field for explicit BFD control.
4.  Including `ConnectRetryTimeSeconds` for better robustness.

## Testing
- Verified code compilation and structure.
- Implementation logic verified against GoBGP documentation and requirements.

## Checklist
- [x] Code compiles correctly
- [x] API changes are backward compatible (new fields are optional)

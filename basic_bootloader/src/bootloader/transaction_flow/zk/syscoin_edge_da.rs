// SYSCOIN: consensus constants for compact Gateway DA and gas-tank fee policy.
// Released application and verifier artifacts bind these values; the server validates its
// runtime configuration against them before execution.
use ruint::aliases::B160;

/// SYSCOIN: only the canonical Gateway chain executes child-chain settlement commits whose
/// baked-relay messages enter the proven Edge-DA root.
pub const SYSCOIN_GATEWAY_CHAIN_ID: u64 = 57_001;

#[inline(always)]
pub fn syscoin_compact_edge_da_enabled_on_chain(chain_id: u64) -> bool {
    chain_id == SYSCOIN_GATEWAY_CHAIN_ID
}

pub fn syscoin_compact_edge_da_commit_target() -> B160 {
    B160::from_be_bytes([
        0xab, 0xb6, 0x9e, 0x8e, 0x89, 0x9c, 0x06, 0xe5, 0x14, 0x14, 0xef, 0xde, 0x62, 0xd4, 0x42,
        0x3d, 0xe4, 0xf3, 0x50, 0x04,
    ])
}

/// SYSCOIN: canonical `SyscoinRelayedSLDAValidator` derived from the frozen universal-factory
/// deployment whose L2-to-L1 messages may enter the proven compact Edge-DA root.
pub fn syscoin_compact_edge_da_relay_emitter() -> B160 {
    B160::from_be_bytes([
        0x75, 0x8b, 0x06, 0xcd, 0xa8, 0x0b, 0xdd, 0x01, 0x6f, 0x79, 0xaf, 0xd0, 0xdf, 0x1a, 0x98,
        0x40, 0x39, 0x06, 0x7a, 0x21,
    ])
}

pub fn syscoin_gas_tank_address() -> B160 {
    B160::from_be_bytes([
        0xb4, 0x99, 0x43, 0xea, 0x23, 0x26, 0x24, 0xdd, 0x4a, 0xa6, 0x3e, 0x18, 0x18, 0x60, 0x76,
        0xc6, 0xc9, 0x9a, 0x68, 0xef,
    ])
}

#[cfg(test)]
// SYSCOIN: keep same-address commit calls on direct/edge chains out of Gateway-only admission.
mod tests {
    use super::{syscoin_compact_edge_da_enabled_on_chain, SYSCOIN_GATEWAY_CHAIN_ID};

    #[test]
    fn compact_edge_da_admission_is_gateway_chain_only() {
        assert!(syscoin_compact_edge_da_enabled_on_chain(
            SYSCOIN_GATEWAY_CHAIN_ID
        ));
        assert!(!syscoin_compact_edge_da_enabled_on_chain(57));
        assert!(!syscoin_compact_edge_da_enabled_on_chain(57_002));
    }
}

mod guardian_set_update;
pub use guardian_set_update::*;

mod set_message_fee;
pub use set_message_fee::*;

mod transfer_fees;
pub use transfer_fees::*;

mod upgrade_contract;
pub use upgrade_contract::*;
use wormhole_solana_vaas::zero_copy::VaaAccount;

use crate::{error::CoreBridgeError, state::Config};
use anchor_lang::prelude::*;
use wormhole_raw_vaas::core::{CoreBridgeDecree, CoreBridgeGovPayload};

/// Validate a posted VAA as a Core Bridge governance decree. Specifically for the Core Bridge, the
/// guardian set used to attest for this governance decree must be the latest guardian set (found in
/// the [Config] account).
pub fn require_valid_governance_vaa<'ctx>(
    config: &'ctx Config,
    vaa: &'ctx VaaAccount<'ctx>,
) -> Result<CoreBridgeDecree<'ctx>> {
    // Make sure the VAA was attested for by the latest guardian set.
    require_eq!(
        config.guardian_set_index,
        vaa.guardian_set_index(),
        CoreBridgeError::LatestGuardianSetRequired
    );

    // The emitter must be the hard-coded governance emitter.
    let emitter = vaa.emitter_info();
    require!(
        emitter.chain == crate::constants::GOVERNANCE_CHAIN
            && emitter.address == crate::constants::GOVERNANCE_EMITTER,
        CoreBridgeError::InvalidGovernanceEmitter
    );

    // Finally attempt to parse the governance decree.
    CoreBridgeGovPayload::try_from(vaa.payload())
        .map(|msg| msg.decree())
        .map_err(|_| error!(CoreBridgeError::InvalidGovernanceVaa))
}

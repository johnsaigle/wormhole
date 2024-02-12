use crate::{
    constants::UPGRADE_SEED_PREFIX,
    error::CoreBridgeError,
    legacy::{instruction::EmptyArgs, utils::LegacyAnchorized},
    state::Config,
    utils,
};
use anchor_lang::prelude::*;
use wormhole_solana_utils::cpi::bpf_loader_upgradeable::{self, BpfLoaderUpgradeable};
use wormhole_solana_vaas::zero_copy::VaaAccount;

#[derive(Accounts)]
pub struct UpgradeContract<'info> {
    #[account(mut)]
    payer: Signer<'info>,

    /// For governance VAAs, we need to make sure that the current guardian set was used to attest
    /// for this governance decree.
    #[account(
        mut,
        address = wormhole_solana_consts::CORE_BRIDGE_CONFIG,
    )]
    config: Account<'info, LegacyAnchorized<Config>>,

    /// VAA account, which may either be the new EncodedVaa account or legacy PostedVaaV1
    /// account.
    ///
    /// CHECK: This account will be read via zero-copy deserialization in the instruction
    /// handler, which will determine which type of VAA account is being used. If this account
    /// is the legacy PostedVaaV1 account, its PDA address will be verified by this zero-copy
    /// reader.
    #[account(owner = crate::ID)]
    vaa: AccountInfo<'info>,

    /// Claim account (mut), which acts as replay protection after consuming data from the VAA
    /// account.
    ///
    /// Seeds: [emitter_address, emitter_chain, sequence],
    /// seeds::program = core_bridge_program.
    ///
    /// CHECK: This account is created via [claim_vaa](crate::utils::vaa::claim_vaa).
    /// This account can only be created once for this VAA.
    #[account(mut)]
    claim: AccountInfo<'info>,

    /// CHECK: We need this upgrade authority to invoke the BPF Loader Upgradeable program to
    /// upgrade this program's executable. We verify this PDA address here out of convenience to get
    /// the PDA bump seed to invoke the upgrade.
    #[account(
        seeds = [UPGRADE_SEED_PREFIX],
        bump,
    )]
    upgrade_authority: AccountInfo<'info>,

    /// Spill account to collect excess lamports.
    ///
    /// CHECK: This account receives any lamports after the result of the upgrade.
    #[account(mut)]
    spill: AccountInfo<'info>,

    /// Deployed implementation.
    ///
    /// CHECK: The pubkey of this account is checked in access control against the one encoded in
    /// the governance VAA.
    #[account(mut)]
    buffer: AccountInfo<'info>,

    /// Core Bridge program data needed for BPF Loader Upgradable program.
    ///
    /// CHECK: BPF Loader Upgradeable program needs this account to upgrade the program's
    /// implementation.
    #[account(
        mut,
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = solana_program::bpf_loader_upgradeable::id(),
    )]
    program_data: AccountInfo<'info>,

    /// CHECK: This must equal the Core Bridge program ID for the BPF Loader Upgradeable program.
    #[account(
        mut,
        address = crate::ID
    )]
    this_program: AccountInfo<'info>,

    /// CHECK: BPF Loader Upgradeable program needs this sysvar.
    #[account(address = solana_program::sysvar::rent::id())]
    rent: AccountInfo<'info>,

    /// CHECK: BPF Loader Upgradeable program needs this sysvar.
    #[account(address = solana_program::sysvar::clock::id())]
    clock: AccountInfo<'info>,

    /// BPF Loader Upgradeable program.
    ///
    /// CHECK: In order to upgrade the program, we need to invoke the BPF Loader Upgradeable
    /// program.
    bpf_loader_upgradeable_program: Program<'info, BpfLoaderUpgradeable>,

    system_program: Program<'info, System>,
}

impl<'info> crate::legacy::utils::ProcessLegacyInstruction<'info, EmptyArgs>
    for UpgradeContract<'info>
{
    const LOG_IX_NAME: &'static str = "LegacyUpgradeContract";

    const ANCHOR_IX_FN: fn(Context<Self>, EmptyArgs) -> Result<()> = upgrade_contract;
}

impl<'info> UpgradeContract<'info> {
    fn constraints(ctx: &Context<Self>) -> Result<()> {
        let vaa = VaaAccount::load(&ctx.accounts.vaa)?;
        let gov_payload = super::require_valid_governance_vaa(&ctx.accounts.config, &vaa)?;

        let decree = gov_payload
            .contract_upgrade()
            .ok_or(error!(CoreBridgeError::InvalidGovernanceAction))?;

        // Make sure that the contract upgrade is intended for this network.
        require_eq!(
            decree.chain(),
            wormhole_solana_consts::SOLANA_CHAIN,
            CoreBridgeError::GovernanceForAnotherChain
        );

        // Read the implementation pubkey and check against the buffer in our account context.
        require_keys_eq!(
            Pubkey::from(decree.implementation()),
            ctx.accounts.buffer.key(),
            CoreBridgeError::ImplementationMismatch
        );

        // Done.
        Ok(())
    }
}

/// Processor for contract upgrade governance decrees. This instruction handler invokes the BPF
/// Loader Upgradeable program to upgrade this program's executable to the provided buffer.
#[access_control(UpgradeContract::constraints(&ctx))]
fn upgrade_contract(ctx: Context<UpgradeContract>, _args: EmptyArgs) -> Result<()> {
    let vaa = VaaAccount::load_unchecked(&ctx.accounts.vaa);

    // Create the claim account to provide replay protection. Because this instruction creates this
    // account every time it is executed, this account cannot be created again with this emitter
    // address, chain and sequence combination.
    utils::vaa::claim_vaa(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            utils::vaa::ClaimVaa {
                claim: ctx.accounts.claim.to_account_info(),
                payer: ctx.accounts.payer.to_account_info(),
            },
        ),
        &crate::ID,
        &vaa,
        None,
    )?;

    // Finally upgrade.
    bpf_loader_upgradeable::upgrade(CpiContext::new_with_signer(
        ctx.accounts
            .bpf_loader_upgradeable_program
            .to_account_info(),
        bpf_loader_upgradeable::Upgrade {
            program: ctx.accounts.this_program.to_account_info(),
            program_data: ctx.accounts.program_data.to_account_info(),
            buffer: ctx.accounts.buffer.to_account_info(),
            authority: ctx.accounts.upgrade_authority.to_account_info(),
            spill: ctx.accounts.spill.to_account_info(),
            rent: ctx.accounts.rent.to_account_info(),
            clock: ctx.accounts.clock.to_account_info(),
        },
        &[&[UPGRADE_SEED_PREFIX, &[ctx.bumps["upgrade_authority"]]]],
    ))
}

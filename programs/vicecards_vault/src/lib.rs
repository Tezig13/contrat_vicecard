//! VICECARDS reward vault.
//!
//! The VICECARDS coin is created on pump.fun with this program's `vault` PDA as its creator and
//! TTWO (Take-Two Interactive, tokenized by Backpack Securities, Token-2022) as its quote, so every
//! creator fee belongs to the vault, in TTWO. pump.fun's collect instructions are permissionless:
//! anyone can move the fees into the vault's TTWO account (`sweep_creator_fee` +
//! `collect_creator_fee_v2` on the bonding curve; `sweep_creator_fee` + `collect_coin_creator_fee`
//! on PumpSwap after graduation).
//!
//! Every hour the backend (operator) computes each collector's share off-chain and publishes the
//! root of a merkle tree of cumulative entitlements in TTWO (`set_root`). The program refuses a
//! root that commits more TTWO than the vault holds. `claim` is permissionless: anyone (the payout
//! crank or the player) pays a wallet the difference between its cumulative entitlement and what
//! it was already paid. The TTWO goes to the leaf's wallet, never to the caller.
//!
//! No withdrawal instruction: TTWO only leaves the vault through `claim`. (TTWO's issuer keeps,
//! like on every account of that token, the power to pause transfers, freeze accounts and move
//! tokens as permanent delegate: this program cannot remove that.)
//!
//! Merkle tree: leaf = sha256(0x00 || wallet || cumulative u64 LE), node = sha256(0x01 || min || max).

use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_interface::{transfer_checked, Mint, TokenAccount, TokenInterface, TransferChecked};
use solana_sha256_hasher::hashv;

declare_id!("D1MRTECLfpTN6tNUTeAXwZ8t8FZ2WNzPSf9K5CDukweE");

/// Deepest proof `claim` accepts (2^32 leaves); bounds the instruction's compute.
pub const MAX_PROOF_LEN: usize = 32;

/// The only wallet allowed to call `initialize` (it becomes the admin): the user's dev wallet.
#[cfg(not(feature = "test-initializer"))]
pub const INITIALIZER: Pubkey = pubkey!("HUv25kpB16CcBfWwx2BApSYqMpfGFWafLaB34ZzT1i8P");
/// Tests: the key derived from the seed [9; 32].
#[cfg(feature = "test-initializer")]
pub const INITIALIZER: Pubkey = pubkey!("J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf");

pub const CONFIG_SEED: &[u8] = b"config";
pub const VAULT_SEED: &[u8] = b"vault";
pub const CLAIM_SEED: &[u8] = b"claim";

#[program]
pub mod vicecards_vault {
    use super::*;

    /// Creates the config and the vault's account of `quote_mint` (TTWO) once. `mint` is the
    /// pump.fun coin, recorded for reference (the coin may be launched after this instruction).
    pub fn initialize(ctx: Context<Initialize>, operator: Pubkey, mint: Pubkey) -> Result<()> {
        require_keys_neq!(operator, Pubkey::default(), VaultError::ZeroAddress);
        require_keys_neq!(operator, ctx.accounts.admin.key(), VaultError::OperatorIsAdmin);
        require_keys_neq!(mint, Pubkey::default(), VaultError::ZeroAddress);

        let config = &mut ctx.accounts.config;
        config.admin = ctx.accounts.admin.key();
        config.pending_admin = Pubkey::default();
        config.operator = operator;
        config.mint = mint;
        config.quote_mint = ctx.accounts.quote_mint.key();
        config.epoch = 0;
        config.root = [0u8; 32];
        config.total_committed = 0;
        config.total_claimed = 0;
        config.paused = false;
        config.bump = ctx.bumps.config;
        config.vault_bump = ctx.bumps.vault;

        emit!(OperatorUpdated { previous: Pubkey::default(), new: operator });
        Ok(())
    }

    /// Publishes the hourly root. `total_committed` is the sum of every cumulative entitlement in
    /// the tree; what is not yet claimed of it must be covered by the vault's TTWO.
    pub fn set_root(ctx: Context<SetRoot>, epoch: u64, root: [u8; 32], total_committed: u64) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require!(epoch == config.epoch.checked_add(1).ok_or(VaultError::MathOverflow)?, VaultError::WrongEpoch);
        require!(root != [0u8; 32], VaultError::ZeroRoot);
        require!(total_committed >= config.total_committed, VaultError::CommittedDecreased);

        let owed = total_committed.checked_sub(config.total_claimed).ok_or(VaultError::MathOverflow)?;
        require!(owed <= ctx.accounts.vault_quote_account.amount, VaultError::Insolvent);

        config.epoch = epoch;
        config.root = root;
        config.total_committed = total_committed;
        emit!(RootSet { epoch, root, total_committed });
        Ok(())
    }

    /// Pays `wallet` what it is owed under the current root: `cumulative` minus what it was
    /// already paid. Anyone may call it; `payer` funds the wallet's claim status and TTWO account
    /// on first use.
    /// A claim with nothing left to pay succeeds and moves nothing.
    pub fn claim(ctx: Context<Claim>, cumulative: u64, proof: Vec<[u8; 32]>) -> Result<()> {
        let config = &ctx.accounts.config;
        require!(!config.paused, VaultError::Paused);
        require!(config.root != [0u8; 32], VaultError::InvalidProof);
        require!(proof.len() <= MAX_PROOF_LEN, VaultError::InvalidProof);
        let wallet = ctx.accounts.wallet.key();
        require!(verify(&proof, config.root, leaf_hash(&wallet, cumulative)), VaultError::InvalidProof);

        let status = &mut ctx.accounts.claim_status;
        if status.wallet == Pubkey::default() {
            status.wallet = wallet;
            status.bump = ctx.bumps.claim_status;
        }
        // cumulative entitlements only grow from one root to the next
        let amount = cumulative.checked_sub(status.claimed).ok_or(VaultError::MathOverflow)?;
        if amount == 0 {
            return Ok(());
        }

        // Effects before the transfer.
        status.claimed = cumulative;
        let config = &mut ctx.accounts.config;
        config.total_claimed = config.total_claimed.checked_add(amount).ok_or(VaultError::MathOverflow)?;
        // set_root's solvency check guarantees this; kept as a last line of defence
        require!(config.total_claimed <= config.total_committed, VaultError::Insolvent);

        let vault_bump = config.vault_bump;
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.quote_token_program.key(),
                TransferChecked {
                    from: ctx.accounts.vault_quote_account.to_account_info(),
                    mint: ctx.accounts.quote_mint.to_account_info(),
                    to: ctx.accounts.wallet_quote_account.to_account_info(),
                    authority: ctx.accounts.vault.to_account_info(),
                },
                &[&[VAULT_SEED, &[vault_bump]]],
            ),
            amount,
            ctx.accounts.quote_mint.decimals,
        )?;

        emit!(Claimed { wallet, amount, cumulative });
        Ok(())
    }

    pub fn set_operator(ctx: Context<AdminOnly>, operator: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require_keys_neq!(operator, Pubkey::default(), VaultError::ZeroAddress);
        require_keys_neq!(operator, config.admin, VaultError::OperatorIsAdmin);
        emit!(OperatorUpdated { previous: config.operator, new: operator });
        config.operator = operator;
        Ok(())
    }

    /// Pausing stops `claim` only; roots keep being published so nobody's share is lost.
    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        ctx.accounts.config.paused = paused;
        emit!(PausedSet { paused });
        Ok(())
    }

    /// Step 1 of the admin transfer. `Pubkey::default()` cancels a pending transfer.
    pub fn propose_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require_keys_neq!(new_admin, config.operator, VaultError::OperatorIsAdmin);
        config.pending_admin = new_admin;
        Ok(())
    }

    /// Step 2 of the admin transfer, signed by the new admin.
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        emit!(AdminTransferred { previous: config.admin, new: config.pending_admin });
        config.admin = config.pending_admin;
        config.pending_admin = Pubkey::default();
        Ok(())
    }
}

pub fn leaf_hash(wallet: &Pubkey, cumulative: u64) -> [u8; 32] {
    hashv(&[&[0u8], wallet.as_ref(), &cumulative.to_le_bytes()]).to_bytes()
}

fn node_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    hashv(&[&[1u8], lo, hi]).to_bytes()
}

/// Sorted-pair merkle proof: no position bits, the order of each pair is fixed by its bytes.
pub fn verify(proof: &[[u8; 32]], root: [u8; 32], leaf: [u8; 32]) -> bool {
    proof.iter().fold(leaf, |acc, sibling| node_hash(&acc, sibling)) == root
}

// -------------------------------------------------------------------------
// Accounts
// -------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut, address = INITIALIZER @ VaultError::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(init, payer = admin, space = 8 + Config::INIT_SPACE, seeds = [CONFIG_SEED], bump)]
    pub config: Account<'info, Config>,
    /// CHECK: PDA without data: the coin's creator on pump.fun, owner of the vault's TTWO account.
    #[account(seeds = [VAULT_SEED], bump)]
    pub vault: UncheckedAccount<'info>,
    /// TTWO: the coin's quote on pump.fun, the creator fees and the rewards.
    pub quote_mint: InterfaceAccount<'info, Mint>,
    /// It may already exist and hold fees: the coin can be launched before this instruction.
    #[account(
        init_if_needed,
        payer = admin,
        associated_token::mint = quote_mint,
        associated_token::authority = vault,
        associated_token::token_program = quote_token_program,
    )]
    pub vault_quote_account: InterfaceAccount<'info, TokenAccount>,
    pub quote_token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetRoot<'info> {
    #[account(address = config.operator @ VaultError::Unauthorized)]
    pub operator: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: the vault PDA.
    #[account(seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(
        associated_token::mint = config.quote_mint,
        associated_token::authority = vault,
        associated_token::token_program = quote_token_program,
    )]
    pub vault_quote_account: InterfaceAccount<'info, TokenAccount>,
    pub quote_token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: the vault PDA, signs the transfer out.
    #[account(seeds = [VAULT_SEED], bump = config.vault_bump)]
    pub vault: UncheckedAccount<'info>,
    #[account(
        mut,
        associated_token::mint = quote_mint,
        associated_token::authority = vault,
        associated_token::token_program = quote_token_program,
    )]
    pub vault_quote_account: InterfaceAccount<'info, TokenAccount>,
    #[account(address = config.quote_mint)]
    pub quote_mint: InterfaceAccount<'info, Mint>,
    /// CHECK: any wallet; it is the leaf's wallet (checked by the proof) and owns the account paid.
    pub wallet: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = quote_mint,
        associated_token::authority = wallet,
        associated_token::token_program = quote_token_program,
    )]
    pub wallet_quote_account: InterfaceAccount<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + ClaimStatus::INIT_SPACE,
        seeds = [CLAIM_SEED, wallet.key().as_ref()],
        bump,
    )]
    pub claim_status: Account<'info, ClaimStatus>,
    pub quote_token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(address = config.admin @ VaultError::Unauthorized)]
    pub admin: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    #[account(address = config.pending_admin @ VaultError::Unauthorized)]
    pub new_admin: Signer<'info>,
    #[account(mut, seeds = [CONFIG_SEED], bump = config.bump)]
    pub config: Account<'info, Config>,
}

// -------------------------------------------------------------------------
// State
// -------------------------------------------------------------------------

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    pub pending_admin: Pubkey,
    /// Publishes the hourly roots.
    pub operator: Pubkey,
    /// The pump.fun coin.
    pub mint: Pubkey,
    /// TTWO: the coin's quote, the creator fees and the rewards.
    pub quote_mint: Pubkey,
    /// Last published epoch (0 = none yet).
    pub epoch: u64,
    pub root: [u8; 32],
    /// Sum of the cumulative entitlements of the current root, in TTWO base units.
    pub total_committed: u64,
    /// TTWO paid out by `claim` so far.
    pub total_claimed: u64,
    pub paused: bool,
    pub bump: u8,
    pub vault_bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct ClaimStatus {
    pub wallet: Pubkey,
    /// TTWO already paid to `wallet`.
    pub claimed: u64,
    pub bump: u8,
}

// -------------------------------------------------------------------------
// Events & errors
// -------------------------------------------------------------------------

#[event]
pub struct RootSet {
    pub epoch: u64,
    pub root: [u8; 32],
    pub total_committed: u64,
}

#[event]
pub struct Claimed {
    pub wallet: Pubkey,
    pub amount: u64,
    pub cumulative: u64,
}

#[event]
pub struct OperatorUpdated {
    pub previous: Pubkey,
    pub new: Pubkey,
}

#[event]
pub struct PausedSet {
    pub paused: bool,
}

#[event]
pub struct AdminTransferred {
    pub previous: Pubkey,
    pub new: Pubkey,
}

#[error_code]
pub enum VaultError {
    #[msg("Zero address")]
    ZeroAddress,
    #[msg("The operator cannot be the admin")]
    OperatorIsAdmin,
    #[msg("Signer is not allowed")]
    Unauthorized,
    #[msg("Epoch must be the previous one + 1")]
    WrongEpoch,
    #[msg("Empty root")]
    ZeroRoot,
    #[msg("Total committed cannot decrease")]
    CommittedDecreased,
    #[msg("The vault does not hold what this root commits")]
    Insolvent,
    #[msg("Invalid merkle proof")]
    InvalidProof,
    #[msg("Claims paused")]
    Paused,
    #[msg("Math overflow")]
    MathOverflow,
}

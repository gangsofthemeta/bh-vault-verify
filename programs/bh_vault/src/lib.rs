//! bh_vault - Bloodhound Manual LP Terminal, Phase 2 milestones M1 + M2 (bounded automation).
//!
//! One program in which three things proven separately in Phase 1 work together:
//!   * a per-user vault PDA owns token accounts and Meteora DLMM positions (DLMM CPIs hand-built
//!     from the published IDL, idl/dlmm.json);
//!   * the performance-fee rate (750 bps, or 500 bps for a holder of an NFT from an allowlisted,
//!     verified Token Metadata collection) is decided on chain, identically for owner and keeper;
//!   * the keeper pays the network fee and the vault's SOL reserve repays exactly that fee, computed
//!     by the program from the Instructions sysvar, inside limits only the owner can set.
//!
//! Design rules enforced here (see README.md):
//!   R3 fees are OWED, never sent: every claim path measures the vault token balance immediately
//!      before and after the DLMM claim_fee2 CPI, books floor(claimed * rate / 10_000) per mint in
//!      Vault.fees_owed and leaves the tokens in the vault's own token account. Only the
//!      permissionless `collect_fees` moves them, and only to the treasury's associated token
//!      account. No owner-signed or keeper-signed instruction takes a treasury account.
//!   R4 keeper cost repayment: sole signer, explicit compute-unit limit, base and priority parts
//!      computed here, five owner-set limits, one repayment per transaction, never by CPI.
//!   R6 PositionRecord.version increments on every state-changing instruction on a position; keeper
//!      instructions must quote it, user instructions never do.
//!
//! M2 (policy.rs + the keeper section below): the owner-signed per-position Policy, the out-of-range
//! mark, keeper_rebalance, compound protection, exit rules. Not in M2: swaps.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{
    instruction::{get_stack_height, AccountMeta, Instruction, TRANSACTION_LEVEL_STACK_HEIGHT},
    program::invoke_signed,
};
use anchor_lang::system_program;
use solana_sha256_hasher::hashv;

pub mod migrate;
pub mod oracle;
pub mod policy;
pub use migrate::RECORD_LAYOUT;
pub use oracle::*;
pub use policy::*;

// M2.11: a SEPARATE devnet program. M2.10 at 7PQF3EkH8Ccyh6ydPaWh7guLqxdo9Rzcwqke64XBPoor stays frozen.
declare_id!("8vmMdR5ibh7Er3QUENpvfX8u8vfUssCezzec6EjZnNtu");

pub const DLMM_ID: Pubkey = pubkey!("LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo");
pub const TOKEN_ID: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN22_ID: Pubkey = pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_ID: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const MEMO_ID: Pubkey = pubkey!("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
pub const TM_ID: Pubkey = pubkey!("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");
pub const IX_SYSVAR_ID: Pubkey = pubkey!("Sysvar1nstructions1111111111111111111111111");
pub const COMPUTE_BUDGET_ID: Pubkey = pubkey!("ComputeBudget111111111111111111111111111111");
pub const LOADER_V3_ID: Pubkey = pubkey!("BPFLoaderUpgradeab1e11111111111111111111111");

pub const RATE_STANDARD_BPS: u16 = 750;
pub const RATE_HOLDER_BPS: u16 = 500;
pub const MAX_ALLOWLIST: usize = 16;

/// Protocol constants the program cannot read on chain.
pub const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
pub const MAX_CU_LIMIT: u64 = 1_400_000;
pub const SECONDS_PER_DAY: i64 = 86_400;

pub const FLAG_COMPOUND: u8 = 1;
pub const FLAG_CLOSE: u8 = 2;
pub const FLAG_REBALANCE: u8 = 4;
const FLAG_MASK: u8 = 7;
/// fees_owed slots an owner can pre-pay for (`reserve_owed_slots`).
pub const MAX_OWED_SLOTS: usize = 64;

/// Keeper action kinds (KeeperRepaid.kind). Exits may take the reserve below `exit_floor`.
pub const KIND_COMPOUND: u8 = 0;
pub const KIND_EXIT: u8 = 1;
pub const KIND_REBALANCE: u8 = 2;
pub const KIND_MARK: u8 = 3;

/// Which claim path booked the fee (FeeBooked.path).
pub const PATH_USER_CLAIM: u8 = 0;
pub const PATH_COMPOUND: u8 = 1;
pub const PATH_KEEPER_CLOSE: u8 = 2;
pub const PATH_EMERGENCY: u8 = 3;
pub const PATH_REBALANCE: u8 = 4;
/// M2.11: the owner's price-protected normal close (`close_position`).
pub const PATH_CLOSE: u8 = 5;

/// M2.11: a proposed treasury takes effect no earlier than this after the proposal. Compiled in;
/// the admin cannot change it.
pub const TREASURY_DELAY_S: i64 = 172_800;
/// M2.11: the Config layout this program writes.
pub const CONFIG_VERSION: u8 = 1;

// DLMM instruction discriminators, copied from idl/dlmm.json.
const IX_INIT_POSITION2: [u8; 8] = [143, 19, 242, 145, 213, 15, 104, 115];
const IX_ADD_BY_STRATEGY2: [u8; 8] = [3, 221, 149, 218, 111, 141, 118, 213];
const IX_REMOVE_BY_RANGE2: [u8; 8] = [204, 2, 195, 145, 53, 145, 145, 205];
const IX_CLAIM_FEE2: [u8; 8] = [112, 191, 101, 171, 28, 144, 127, 187];
const IX_CLOSE_POSITION2: [u8; 8] = [174, 90, 35, 115, 186, 40, 147, 226];
const IX_INIT_POSITION_PDA: [u8; 8] = [46, 82, 125, 146, 85, 141, 228, 153];
const IX_INIT_BIN_ARRAY: [u8; 8] = [35, 86, 19, 185, 78, 212, 75, 211];

#[program]
pub mod bh_vault {
    use super::*;

    // ================================================================ admin

    /// NOT first-caller-wins: the signer must be this program's upgrade authority, read from the
    /// program's ProgramData account. The signer becomes Config.admin.
    pub fn initialize_config(ctx: Context<InitializeConfig>, keeper: Pubkey, treasury: Pubkey) -> Result<()> {
        let pd = &ctx.accounts.program_data;
        let (expected, _) = Pubkey::find_program_address(&[crate::ID.as_ref()], &LOADER_V3_ID);
        require_keys_eq!(pd.key(), expected, VaultError::NotUpgradeAuthority);
        require_keys_eq!(*pd.owner, LOADER_V3_ID, VaultError::NotUpgradeAuthority);
        {
            // UpgradeableLoaderState::ProgramData = u32 tag (3) | slot u64 | Option<Pubkey>
            let d = pd.try_borrow_data()?;
            require!(
                d.len() >= 45 && d[0..4] == [3, 0, 0, 0] && d[12] == 1 && d[13..45] == ctx.accounts.authority.key().to_bytes(),
                VaultError::NotUpgradeAuthority
            );
        }
        let c = &mut ctx.accounts.config;
        c.admin = ctx.accounts.authority.key();
        c.keeper = keeper;
        c.treasury = treasury;
        c.paused = false;
        c.bump = ctx.bumps.config;
        c.pending_treasury = Pubkey::default();
        c.treasury_eta = 0;
        c.pending_admin = Pubkey::default();
        c.version = CONFIG_VERSION;
        c.allowlist = Vec::new();
        Ok(())
    }

    pub fn set_keeper(ctx: Context<AdminOnly>, keeper: Pubkey) -> Result<()> {
        let c = &mut ctx.accounts.config;
        let old = c.keeper;
        c.keeper = keeper;
        emit!(KeeperChanged { old, new: keeper });
        Ok(())
    }

    // M2.11: `set_treasury` is removed. A treasury change is proposed by the admin and takes effect
    // only through `execute_treasury`, no earlier than TREASURY_DELAY_S after the proposal.

    /// Admin. Replaces any earlier proposal and restarts the delay.
    pub fn propose_treasury(ctx: Context<AdminOnly>, treasury: Pubkey) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let c = &mut ctx.accounts.config;
        c.pending_treasury = treasury;
        c.treasury_eta = now.checked_add(TREASURY_DELAY_S).ok_or(VaultError::Math)?;
        emit!(TreasuryProposed { old: c.treasury, new: treasury, eta: c.treasury_eta });
        Ok(())
    }

    /// Admin. Drops the pending proposal.
    pub fn cancel_treasury(ctx: Context<AdminOnly>) -> Result<()> {
        let c = &mut ctx.accounts.config;
        require!(c.treasury_eta != 0, VaultError::NoPendingTreasury);
        let new = c.pending_treasury;
        c.pending_treasury = Pubkey::default();
        c.treasury_eta = 0;
        emit!(TreasuryProposalCancelled { new });
        Ok(())
    }

    /// Anyone, once the delay has passed: the proposed treasury becomes the treasury.
    pub fn execute_treasury(ctx: Context<ConfigAnyone>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let c = &mut ctx.accounts.config;
        require!(c.treasury_eta != 0, VaultError::NoPendingTreasury);
        require!(now >= c.treasury_eta, VaultError::TreasuryNotDue);
        let old = c.treasury;
        c.treasury = c.pending_treasury;
        c.pending_treasury = Pubkey::default();
        c.treasury_eta = 0;
        emit!(TreasuryChanged { old, new: c.treasury });
        Ok(())
    }

    /// Admin. Step one of the handover: names the next admin, who must accept by signing.
    pub fn propose_admin(ctx: Context<AdminOnly>, admin: Pubkey) -> Result<()> {
        let c = &mut ctx.accounts.config;
        c.pending_admin = admin;
        emit!(AdminProposed { old: c.admin, new: admin });
        Ok(())
    }

    /// Step two: signed by the proposed admin only. A mistyped address can never sign this.
    pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
        let c = &mut ctx.accounts.config;
        let new = ctx.accounts.new_admin.key();
        require!(c.pending_admin != Pubkey::default() && c.pending_admin == new, VaultError::NotPendingAdmin);
        let old = c.admin;
        c.admin = new;
        c.pending_admin = Pubkey::default();
        emit!(AdminChanged { old, new });
        Ok(())
    }

    /// Pause blocks entry (open_position, add_liquidity) and every keeper instruction. It never
    /// blocks an exit, a remove, a claim or a withdrawal.
    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        ctx.accounts.config.paused = paused;
        emit!(PausedSet { paused });
        Ok(())
    }

    pub fn add_collection(ctx: Context<AdminOnly>, collection: Pubkey) -> Result<()> {
        let c = &mut ctx.accounts.config;
        require!(!c.allowlist.contains(&collection), VaultError::AlreadyListed);
        require!(c.allowlist.len() < MAX_ALLOWLIST, VaultError::AllowlistFull);
        c.allowlist.push(collection);
        emit!(CollectionAdded { collection });
        Ok(())
    }

    pub fn remove_collection(ctx: Context<AdminOnly>, collection: Pubkey) -> Result<()> {
        let c = &mut ctx.accounts.config;
        let before = c.allowlist.len();
        c.allowlist.retain(|k| k != &collection);
        require!(c.allowlist.len() < before, VaultError::NotListed);
        emit!(CollectionRemoved { collection });
        Ok(())
    }

    // ================================================================ owner: vault and funds

    /// The owner signs. All cost limits start at zero, so the keeper can spend nothing until the
    /// owner sets them.
    pub fn init_vault(ctx: Context<InitVault>) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.owner = ctx.accounts.owner.key();
        v.bump = ctx.bumps.vault;
        v.reserve_bump = ctx.bumps.sol_reserve;
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let a = &ctx.accounts;
        check_vault_ata(&a.vault_token, a.mint.key, &a.vault.key(), a.token_program.key)?;
        reject_transfer_fee_mint(&a.mint)?;
        token_transfer(&a.token_program, &a.owner_token, &a.mint, &a.vault_token, &a.owner, amount, &[])
    }

    /// Vault -> a token account whose SPL owner is the vault owner's wallet. At most
    /// (balance - fees_owed) of the mint can leave. amount = u64::MAX means "everything available".
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let a = &ctx.accounts;
        check_vault_ata(&a.vault_token, a.mint.key, &a.vault.key(), a.token_program.key)?;
        check_token(&a.destination, a.mint.key, a.owner.key).map_err(|_| error!(VaultError::DestinationNotOwner))?;
        let available = token_amount(&a.vault_token)?.checked_sub(a.vault.owed(a.mint.key)).ok_or(VaultError::FeesOwedLocked)?;
        let amount = if amount == u64::MAX { available } else { amount };
        require!(amount <= available, VaultError::FeesOwedLocked);
        if amount > 0 {
            let owner = a.vault.owner;
            let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[a.vault.bump]];
            token_transfer(&a.token_program, &a.vault_token, &a.mint, &a.destination, &a.vault.to_account_info(), amount, &[seeds])?;
        }
        Ok(())
    }

    /// Owner only (seeds bind the vault to the signer). Each limit is in lamports.
    pub fn set_cost_limits(
        ctx: Context<OwnerVault>,
        per_action_cap: u64,
        priority_fee_cap: u64,
        daily_cap: u64,
        budget_total: u64,
        exit_floor: u64,
    ) -> Result<()> {
        let v = &mut ctx.accounts.vault;
        v.per_action_cap = per_action_cap;
        v.priority_fee_cap = priority_fee_cap;
        v.daily_cap = daily_cap;
        v.budget_total = budget_total;
        v.exit_floor = exit_floor;
        Ok(())
    }

    /// Anyone may add SOL to a vault's reserve.
    pub fn fund_reserve(ctx: Context<FundReserve>, amount: u64) -> Result<()> {
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer { from: ctx.accounts.funder.to_account_info(), to: ctx.accounts.sol_reserve.to_account_info() },
            ),
            amount,
        )
    }

    /// Owner only, and only to the owner.
    pub fn withdraw_reserve(ctx: Context<WithdrawReserve>, amount: u64) -> Result<()> {
        let vault_key = ctx.accounts.vault.key();
        let seeds: &[&[u8]] = &[b"reserve", vault_key.as_ref(), &[ctx.accounts.vault.reserve_bump]];
        system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                system_program::Transfer { from: ctx.accounts.sol_reserve.to_account_info(), to: ctx.accounts.owner.to_account_info() },
                &[seeds],
            ),
            amount,
        )
    }

    // ================================================================ NFT fee tier

    /// Permissionless: the program verifies everything, the caller only finds the accounts.
    pub fn register_nft(ctx: Context<RegisterNft>) -> Result<()> {
        let mint_ai = ctx.accounts.nft_mint.to_account_info();
        let token_ai = ctx.accounts.nft_token.to_account_info();
        let md_ai = ctx.accounts.nft_metadata.to_account_info();
        let mint = mint_ai.key();

        // The mint itself: a token-program mint with supply 1 and 0 decimals.
        require!(is_token_program(mint_ai.owner), VaultError::NftMintInvalid);
        {
            let d = mint_ai.try_borrow_data()?;
            require!(d.len() >= 82 && d[45] == 1, VaultError::NftMintInvalid);
            let supply = u64::from_le_bytes(d[36..44].try_into().unwrap());
            require!(supply == 1 && d[44] == 0, VaultError::NftMintInvalid);
        }
        require!(*token_ai.owner == *mint_ai.owner, VaultError::TokenWrongProgram);

        // Metadata address must be THE canonical PDA for this mint.
        let (expected_md, md_bump) = Pubkey::find_program_address(&[b"metadata", TM_ID.as_ref(), mint.as_ref()], &TM_ID);
        require_keys_eq!(md_ai.key(), expected_md, VaultError::WrongNftMetadataAccount);

        let v = &mut ctx.accounts.vault;
        let collection = live_check(&token_ai, &md_ai, &mint, &v.owner, &ctx.accounts.config.allowlist)?;
        v.has_nft = true;
        v.nft_mint = mint;
        v.nft_token = token_ai.key();
        v.nft_md_bump = md_bump;
        emit!(NftRegistered { vault: v.key(), nft_mint: mint, collection });
        Ok(())
    }

    pub fn clear_nft(ctx: Context<OwnerVault>) -> Result<()> {
        ctx.accounts.vault.clear_nft();
        Ok(())
    }

    // ================================================================ owner: positions

    /// Owner signs. DLMM position (a fresh keypair) is created by CPI, owned by the vault PDA; its
    /// rent is paid by the owner wallet. Liquidity comes from the vault's own token accounts.
    #[allow(clippy::too_many_arguments)]
    pub fn open_position<'info>(
        ctx: Context<'_, '_, '_, 'info, OpenPosition<'info>>,
        lower_bin_id: i32,
        width: i32,
        amount_x: u64,
        amount_y: u64,
        active_id: i32,
        max_slippage: i32,
        strategy: u8,
        flags: u8,
    ) -> Result<()> {
        require!(!ctx.accounts.config.paused, VaultError::ConfigPaused);
        let a = &ctx.accounts;
        let vault_key = a.vault.key();
        check_vault_ata(&a.vault_x, a.mint_x.key, &vault_key, a.token_program_x.key)?;
        check_vault_ata(&a.vault_y, a.mint_y.key, &vault_key, a.token_program_y.key)?;
        // M2.1: no position in a pool with a transfer-fee mint until the accounting for it exists.
        reject_transfer_fee_mint(&a.mint_x)?;
        reject_transfer_fee_mint(&a.mint_y)?;
        let owner = a.vault.owner;
        let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[a.vault.bump]];
        let d = Dx {
            vault: a.vault.to_account_info(),
            position: a.position.to_account_info(),
            lb_pair: a.lb_pair.to_account_info(),
            bitmap_ext: a.bitmap_ext.to_account_info(),
            vault_x: a.vault_x.to_account_info(),
            vault_y: a.vault_y.to_account_info(),
            reserve_x: a.reserve_x.to_account_info(),
            reserve_y: a.reserve_y.to_account_info(),
            mint_x: a.mint_x.to_account_info(),
            mint_y: a.mint_y.to_account_info(),
            token_program_x: a.token_program_x.to_account_info(),
            token_program_y: a.token_program_y.to_account_info(),
            event_authority: a.event_authority.to_account_info(),
            dlmm_program: a.dlmm_program.to_account_info(),
        };
        let mut infos = d.infos();
        infos.push(a.owner.to_account_info());
        infos.push(a.system_program.to_account_info());
        infos.extend_from_slice(ctx.remaining_accounts);

        // CPI 1: initialize_position2 - payer = owner wallet, position owner = vault PDA.
        let mut data = IX_INIT_POSITION2.to_vec();
        data.extend_from_slice(&lower_bin_id.to_le_bytes());
        data.extend_from_slice(&width.to_le_bytes());
        let metas = vec![
            AccountMeta::new(a.owner.key(), true),
            AccountMeta::new(d.position.key(), true),
            AccountMeta::new_readonly(d.lb_pair.key(), false),
            AccountMeta::new_readonly(vault_key, true),
            AccountMeta::new_readonly(a.system_program.key(), false),
            AccountMeta::new_readonly(d.event_authority.key(), false),
            AccountMeta::new_readonly(DLMM_ID, false),
        ];
        invoke_signed(&Instruction { program_id: DLMM_ID, accounts: metas, data }, &infos, &[seeds])?;

        // CPI 2: add_liquidity_by_strategy2 from the vault's own token accounts.
        let upper = lower_bin_id.checked_add(width).and_then(|v| v.checked_sub(1)).ok_or(VaultError::Math)?;
        cpi_add_by_strategy(&d, &infos, ctx.remaining_accounts, amount_x, amount_y, active_id, max_slippage, lower_bin_id, upper, strategy, seeds)?;

        // Liquidity may only come out of the owner's part: what is owed must still be there.
        require_covered(&a.vault, &d.vault_x, d.mint_x.key)?;
        require_covered(&a.vault, &d.vault_y, d.mint_y.key)?;

        let v = &mut ctx.accounts.vault;
        v.positions_opened = v.positions_opened.checked_add(1).ok_or(VaultError::Math)?;
        let start_version = v.positions_opened << 32;
        let r = &mut ctx.accounts.record;
        r.vault = vault_key;
        r.lb_pair = ctx.accounts.lb_pair.key();
        r.position = ctx.accounts.position.key();
        r.flags = flags & FLAG_MASK;
        r.paused = false;
        // A record never starts at a version an earlier record of this vault could have had, so a
        // keeper transaction signed for a closed position can never match a re-opened one.
        r.version = start_version;
        r.bump = ctx.bumps.record;
        r.origin = ctx.accounts.position.key();
        r.layout = RECORD_LAYOUT;
        r.reserved = [0u8; migrate::RECORD_RESERVED];
        // Nothing automatic can run under an all-zero policy: the owner must sign one (set_policy).
        r.policy = Policy::default();
        r.st = AutoState::default();
        Ok(())
    }

    /// Owner only. The whole rebalance / compound / exit policy of one position. Bumps the version
    /// (every keeper transaction signed before this is dead) and drops any out-of-range mark, which
    /// was made under the old rules.
    pub fn set_policy(ctx: Context<OwnerRecord>, policy: Policy) -> Result<()> {
        policy.validate()?;
        let r = &mut ctx.accounts.record;
        r.policy = policy;
        r.st.clear_mark();
        r.bump_version()?;
        emit!(PolicySet { vault: r.vault, record: r.key(), version: r.version });
        Ok(())
    }

    /// Owner only: pre-pays room for `slots` fee mints in Vault.fees_owed, so keeper-signed claims
    /// in pools with new mints do not stop at OwedTableFull. Never shrinks.
    pub fn reserve_owed_slots(ctx: Context<GrowVault>, slots: u16) -> Result<()> {
        require!((slots as usize) <= MAX_OWED_SLOTS, VaultError::OwedTableFull);
        let vault_ai = ctx.accounts.vault.to_account_info();
        let need = Vault::space(slots as usize);
        if vault_ai.data_len() < need {
            let short = Rent::get()?.minimum_balance(need).saturating_sub(vault_ai.lamports());
            if short > 0 {
                system_program::transfer(
                    CpiContext::new(ctx.accounts.system_program.to_account_info(), system_program::Transfer { from: ctx.accounts.owner.to_account_info(), to: vault_ai.clone() }),
                    short,
                )?;
            }
            vault_ai.resize(need)?;
        }
        Ok(())
    }

    /// Anyone, unpaid: if the program sees the active bin back inside the range (plus margin), the
    /// out-of-range mark is dropped. A keeper that "forgets" to clear a mark cannot stop this.
    /// M2.8: dropping the mark no longer ends the owner's exit run. The run ends only on a CONFIRMED
    /// recovery (`return_evidence`): in a pool with an open gate, fresh verified Pyth prices that put
    /// the whole external band back inside the range (remaining accounts: the gate, then the price
    /// accounts of token X and token Y); in a pool without an open gate (remaining accounts: the gate
    /// PDA address, existing or not), a second in-range observation at least RECOVERY_CONFIRM_S after
    /// the first. Refused when it would change nothing.
    pub fn clear_mark<'info>(ctx: Context<'_, '_, '_, 'info, ClearMark<'info>>) -> Result<()> {
        let rest = ctx.remaining_accounts;
        let a = ctx.accounts;
        let now = Clock::get()?.unix_timestamp;
        let (pair, lower, upper, side) = observe(&a.record, &a.position, &a.lb_pair)?;
        require!(side == 0 && (a.record.st.mark_time != 0 || a.record.st.oor_since != 0), VaultError::NotOutOfRange);
        let ev = return_evidence(&a.record, &pair, a.lb_pair.key, (lower, upper), rest, now)?;
        let before = a.record.st;
        let pol = a.record.policy;
        on_return(&mut a.record.st, &pol, now, ev);
        require!(a.record.st != before, VaultError::MarkUnchanged);
        a.record.bump_version()?;
        emit!(RangeObserved { record: a.record.key(), active_id: pair.active_id, lower, upper, side, mark_time: 0, own_bin: 0, version: a.record.version, oracle: false, oor_since: a.record.st.oor_since });
        Ok(())
    }

    /// bit 0 allow_compound, bit 1 allow_close, bit 2 allow_rebalance.
    pub fn set_flags(ctx: Context<OwnerRecord>, flags: u8) -> Result<()> {
        let r = &mut ctx.accounts.record;
        r.flags = flags & FLAG_MASK;
        r.bump_version()
    }

    pub fn set_position_paused(ctx: Context<OwnerRecord>, paused: bool) -> Result<()> {
        let r = &mut ctx.accounts.record;
        r.paused = paused;
        r.bump_version()
    }

    /// Owner claims swap fees into the vault. The performance fee is booked as owed.
    pub fn user_claim<'info>(ctx: Context<'_, '_, '_, 'info, UserClaim<'info>>, min_bin_id: i32, max_bin_id: i32) -> Result<()> {
        let owner_ai = ctx.accounts.owner.to_account_info();
        let system_ai = ctx.accounts.system_program.to_account_info();
        let p = &mut ctx.accounts.p;
        require_keys_eq!(owner_ai.key(), p.vault.owner, VaultError::NotOwner);
        p.validate()?;
        let (d, infos) = p.bundle(ctx.remaining_accounts, &[]);
        claim_and_book(p, &d, &infos, ctx.remaining_accounts, min_bin_id, max_bin_id, PATH_USER_CLAIM, Some((&owner_ai, &system_ai)))?;
        p.record.bump_version()
    }

    /// Owner alone. Reads neither Config.paused, the position pause flag, the keeper nor any
    /// treasury account: remove all liquidity, claim (fee booked as owed), close the position, send
    /// (balance - fees_owed) of both mints to the owner's token accounts. What is owed stays in the
    /// vault's token account until `collect_fees`.
    pub fn emergency_exit<'info>(ctx: Context<'_, '_, '_, 'info, EmergencyExit<'info>>, min_bin_id: i32, max_bin_id: i32) -> Result<()> {
        let owner_ai = ctx.accounts.owner.to_account_info();
        let system_ai = ctx.accounts.system_program.to_account_info();
        let dest_x = ctx.accounts.owner_token_x.to_account_info();
        let dest_y = ctx.accounts.owner_token_y.to_account_info();
        let p = &mut ctx.accounts.p;
        require_keys_eq!(owner_ai.key(), p.vault.owner, VaultError::NotOwner);
        p.validate()?;
        check_token(&dest_x, p.mint_x.key, owner_ai.key).map_err(|_| error!(VaultError::DestinationNotOwner))?;
        check_token(&dest_y, p.mint_y.key, owner_ai.key).map_err(|_| error!(VaultError::DestinationNotOwner))?;
        let (d, infos) = p.bundle(ctx.remaining_accounts, &[owner_ai.clone(), dest_x.clone(), dest_y.clone()]);
        let owner = p.vault.owner;
        let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[p.vault.bump]];

        cpi_remove_all(&d, &infos, ctx.remaining_accounts, min_bin_id, max_bin_id, seeds)?;
        claim_and_book(p, &d, &infos, ctx.remaining_accounts, min_bin_id, max_bin_id, PATH_EMERGENCY, Some((&owner_ai, &system_ai)))?;
        cpi_close(&d, &infos, &owner_ai, seeds)?;

        let out_x = token_amount(&d.vault_x)?.checked_sub(p.vault.owed(d.mint_x.key)).ok_or(VaultError::FeesOwedLocked)?;
        let out_y = token_amount(&d.vault_y)?.checked_sub(p.vault.owed(d.mint_y.key)).ok_or(VaultError::FeesOwedLocked)?;
        if out_x > 0 {
            token_transfer(&d.token_program_x, &d.vault_x, &d.mint_x, &dest_x, &d.vault, out_x, &[seeds])?;
        }
        if out_y > 0 {
            token_transfer(&d.token_program_y, &d.vault_y, &d.mint_y, &dest_y, &d.vault, out_y, &[seeds])?;
        }
        p.record.bump_version()?;
        p.record.close(owner_ai)
    }

    // ================================================================ M2.11: owner liquidity

    /// Owner only. Adds liquidity from the vault's token accounts to the position over its OWN
    /// range (read from the position account; no range argument, so nothing can widen or move it).
    /// Refused while the protocol is paused (Config.paused); allowed while only this position's
    /// automation is paused (record.paused stops keepers, not the owner). The remaining accounts must
    /// be exactly the bin arrays of the position's range, in order. The UI funds the vault with
    /// `deposit` in the same transaction; what DLMM does not place stays in the vault.
    #[allow(clippy::too_many_arguments)]
    pub fn add_liquidity<'info>(
        ctx: Context<'_, '_, '_, 'info, OwnerLiquidity<'info>>,
        amount_x: u64,
        amount_y: u64,
        active_id: i32,
        max_active_bin_slippage: i32,
        strategy: u8,
    ) -> Result<()> {
        let owner_ai = ctx.accounts.owner.to_account_info();
        let p = &mut ctx.accounts.p;
        require_keys_eq!(owner_ai.key(), p.vault.owner, VaultError::NotOwner);
        require!(!p.config.paused, VaultError::ConfigPaused);
        reject_transfer_fee_mint(&p.mint_x)?;
        reject_transfer_fee_mint(&p.mint_y)?;
        p.validate()?;
        require!(strategy <= 8, VaultError::BadPolicy);
        let vault_key = p.vault.key();
        let (lower, upper) = parse_position(p.position.owner, &p.position.try_borrow_data()?, &p.record.lb_pair, &vault_key)?;
        require_range_arrays(&p.record.lb_pair, lower, upper, ctx.remaining_accounts)?;
        let (d, infos) = p.bundle(ctx.remaining_accounts, &[]);
        let owner = p.vault.owner;
        let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[p.vault.bump]];

        let before_x = token_amount(&d.vault_x)?;
        let before_y = token_amount(&d.vault_y)?;
        cpi_add_by_strategy(&d, &infos, ctx.remaining_accounts, amount_x, amount_y, active_id, max_active_bin_slippage, lower, upper, strategy, seeds)?;
        let in_x = before_x.checked_sub(token_amount(&d.vault_x)?).ok_or(VaultError::Math)?;
        let in_y = before_y.checked_sub(token_amount(&d.vault_y)?).ok_or(VaultError::Math)?;

        require_covered(&p.vault, &d.vault_x, d.mint_x.key)?;
        require_covered(&p.vault, &d.vault_y, d.mint_y.key)?;
        p.record.bump_version()?;
        let pair = parse_pair(d.lb_pair.owner, &d.lb_pair.try_borrow_data()?)?;
        emit!(LiquidityAdded { vault: vault_key, position: d.position.key(), in_x, in_y, active_id: pair.active_id, version: p.record.version });
        Ok(())
    }

    /// Owner only. Removes `bps` (1..=9,999) of the position's liquidity over its whole range into the
    /// vault's token accounts. No fee claim: pending swap fees stay in the position for
    /// `claim_and_book`. Price protection: the pool's active bin must be within `max_active_bin_move`
    /// of `expected_active_id`, and the measured amounts must reach `min_out_x/y`. Allowed while the
    /// protocol or the position is paused. The UI adds `withdraw` in the same transaction.
    pub fn remove_liquidity<'info>(
        ctx: Context<'_, '_, '_, 'info, OwnerLiquidity<'info>>,
        bps: u16,
        expected_active_id: i32,
        max_active_bin_move: u16,
        min_out_x: u64,
        min_out_y: u64,
    ) -> Result<()> {
        let owner_ai = ctx.accounts.owner.to_account_info();
        let p = &mut ctx.accounts.p;
        require_keys_eq!(owner_ai.key(), p.vault.owner, VaultError::NotOwner);
        p.validate()?;
        require!((1..=9_999).contains(&bps), VaultError::BadBps);
        let active = require_active_window(&p.lb_pair, expected_active_id, max_active_bin_move)?;
        let vault_key = p.vault.key();
        let (lower, upper) = parse_position(p.position.owner, &p.position.try_borrow_data()?, &p.record.lb_pair, &vault_key)?;
        require_range_arrays(&p.record.lb_pair, lower, upper, ctx.remaining_accounts)?;
        let principal = held_total(&p.position, &p.record.lb_pair, &vault_key, lower, upper, ctx.remaining_accounts)?;
        let (d, infos) = p.bundle(ctx.remaining_accounts, &[]);
        let owner = p.vault.owner;
        let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[p.vault.bump]];

        let (out_x, out_y) = remove_measured(&d, &infos, ctx.remaining_accounts, lower, upper, bps, seeds)?;
        require!(out_x >= min_out_x && out_y >= min_out_y, VaultError::SlippageExceeded);
        // finding M211-F1: the bound is the removed share of the principal, not the whole position
        let (bound_x, bound_y) = (share_bound_up(principal.0, bps)?, share_bound_up(principal.1, bps)?);
        msg!("remove: out {} {} principal {} {}", out_x, out_y, bound_x, bound_y);
        require!(out_x as u128 <= bound_x && out_y as u128 <= bound_y, VaultError::FeesLeftWithPrincipal);
        {
            let pd = d.position.try_borrow_data()?;
            require!((lower..=upper).any(|b| position_share(&pd, lower, b) > 0), VaultError::PositionWouldBeEmpty);
        }
        require_covered(&p.vault, &d.vault_x, d.mint_x.key)?;
        require_covered(&p.vault, &d.vault_y, d.mint_y.key)?;
        p.record.bump_version()?;
        emit!(LiquidityRemoved { vault: vault_key, position: d.position.key(), bps, out_x, out_y, active_id: active, version: p.record.version });
        Ok(())
    }

    /// Owner only: the normal, price-protected full close. Window check first, then remove 100%
    /// (measured, at least `min_out_x/y`), claim and book the fee exactly as a user claim
    /// (PATH_CLOSE), close the DLMM position (rent to the owner), send (balance - owed) of both mints
    /// to the owner's own token accounts, close the record. Allowed while paused. If the price
    /// protection refuses, `emergency_exit` is always available.
    pub fn close_position<'info>(
        ctx: Context<'_, '_, '_, 'info, EmergencyExit<'info>>,
        expected_active_id: i32,
        max_active_bin_move: u16,
        min_out_x: u64,
        min_out_y: u64,
    ) -> Result<()> {
        let owner_ai = ctx.accounts.owner.to_account_info();
        let system_ai = ctx.accounts.system_program.to_account_info();
        let dest_x = ctx.accounts.owner_token_x.to_account_info();
        let dest_y = ctx.accounts.owner_token_y.to_account_info();
        let p = &mut ctx.accounts.p;
        require_keys_eq!(owner_ai.key(), p.vault.owner, VaultError::NotOwner);
        p.validate()?;
        check_token(&dest_x, p.mint_x.key, owner_ai.key).map_err(|_| error!(VaultError::DestinationNotOwner))?;
        check_token(&dest_y, p.mint_y.key, owner_ai.key).map_err(|_| error!(VaultError::DestinationNotOwner))?;
        let active = require_active_window(&p.lb_pair, expected_active_id, max_active_bin_move)?;
        let vault_key = p.vault.key();
        let (lower, upper) = parse_position(p.position.owner, &p.position.try_borrow_data()?, &p.record.lb_pair, &vault_key)?;
        require_range_arrays(&p.record.lb_pair, lower, upper, ctx.remaining_accounts)?;
        let principal = held_total(&p.position, &p.record.lb_pair, &vault_key, lower, upper, ctx.remaining_accounts)?;
        let (d, infos) = p.bundle(ctx.remaining_accounts, &[owner_ai.clone(), dest_x.clone(), dest_y.clone()]);
        let owner = p.vault.owner;
        let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[p.vault.bump]];

        let (out_x, out_y) = remove_measured(&d, &infos, ctx.remaining_accounts, lower, upper, 10_000, seeds)?;
        require!(out_x >= min_out_x && out_y >= min_out_y, VaultError::SlippageExceeded);
        // the same fee isolation as a partial remove: only claim_and_book may move swap fees
        msg!("remove: out {} {} principal {} {}", out_x, out_y, principal.0, principal.1);
        require!(out_x as u128 <= principal.0 && out_y as u128 <= principal.1, VaultError::FeesLeftWithPrincipal);
        claim_and_book(p, &d, &infos, ctx.remaining_accounts, lower, upper, PATH_CLOSE, Some((&owner_ai, &system_ai)))?;
        cpi_close(&d, &infos, &owner_ai, seeds)?;

        let paid_x = token_amount(&d.vault_x)?.checked_sub(p.vault.owed(d.mint_x.key)).ok_or(VaultError::FeesOwedLocked)?;
        let paid_y = token_amount(&d.vault_y)?.checked_sub(p.vault.owed(d.mint_y.key)).ok_or(VaultError::FeesOwedLocked)?;
        if paid_x > 0 {
            token_transfer(&d.token_program_x, &d.vault_x, &d.mint_x, &dest_x, &d.vault, paid_x, &[seeds])?;
        }
        if paid_y > 0 {
            token_transfer(&d.token_program_y, &d.vault_y, &d.mint_y, &dest_y, &d.vault, paid_y, &[seeds])?;
        }
        require_covered(&p.vault, &d.vault_x, d.mint_x.key)?;
        require_covered(&p.vault, &d.vault_y, d.mint_y.key)?;
        p.record.bump_version()?;
        emit!(PositionClosed { vault: vault_key, position: d.position.key(), out_x, out_y, paid_x, paid_y, active_id: active, version: p.record.version });
        p.record.close(owner_ai)
    }

    // ================================================================ M2.3: record migration

    /// Converts a PositionRecord written by M2, M2.1 or M2.2 (279, 327 or 347 bytes of account
    /// data) to the current layout, in place (rules: migrate.rs). The position is not closed and no
    /// token moves.
    ///   * who: the owner of the vault the record names, or the Config admin. Nobody else, not the keeper
    ///   * what is checked: the record is the PDA of this program for its own `origin`, and the vault
    ///     passed is the vault the record names. No address, amount or limit is taken as an argument
    ///   * lamports: only the extra rent of the larger record, from `payer` (a signer), and only up
    ///     to `max_lamports`. Never from the vault, its SOL reserve or a token account
    ///   * once: a converted record has another length and is refused
    /// Every limit the old layout does not have is zero afterwards: the automatic actions that need
    /// it stay refused until the owner signs a new policy. An owner can put this in front of any
    /// other instruction of the same transaction (for example emergency_exit).
    pub fn migrate_record(ctx: Context<MigrateRecord>, max_lamports: u64) -> Result<()> {
        let a = &ctx.accounts;
        let who = a.authority.key();
        require!(who == a.vault.owner || who == a.config.admin, VaultError::NotMigrationAuthority);
        let ai = a.record.to_account_info();
        require!(*ai.owner == crate::ID, VaultError::RecordNotMigratable);
        let old = ai.try_borrow_data()?.to_vec();
        require!(old.len() >= migrate::PREFIX && old[0..8] == *PositionRecord::DISCRIMINATOR, VaultError::RecordNotMigratable);
        // the record is the PDA of its own `origin` (the same bytes in every layout) ...
        let expected = Pubkey::create_program_address(&[b"pos", &old[115..147], &[old[114]]], &crate::ID).map_err(|_| error!(VaultError::RecordNotMigratable))?;
        require_keys_eq!(ai.key(), expected, VaultError::RecordNotMigratable);
        // ... and belongs to the vault whose owner (or the admin) signed
        require!(old[8..40] == a.vault.key().to_bytes(), VaultError::NotMigrationAuthority);
        let new = migrate::convert(&old, Clock::get()?.unix_timestamp).ok_or(VaultError::RecordNotMigratable)?;
        let short = Rent::get()?.minimum_balance(new.len()).saturating_sub(ai.lamports());
        require!(short <= max_lamports, VaultError::MigrationRentExceeded);
        if short > 0 {
            system_program::transfer(
                CpiContext::new(a.system_program.to_account_info(), system_program::Transfer { from: a.payer.to_account_info(), to: ai.clone() }),
                short,
            )?;
        }
        ai.resize(new.len())?;
        ai.try_borrow_mut_data()?.copy_from_slice(&new);
        emit!(RecordMigrated { record: ai.key(), from_len: old.len() as u32, to_len: new.len() as u32, layout: RECORD_LAYOUT, rent_paid: short, payer: a.payer.key(), authority: who });
        Ok(())
    }

    // ================================================================ M2.3: pool gates (admin / guardian)
    // No keeper instruction and no owner instruction can write a gate or the guardian.

    /// Admin only, once: creates the guardian record. The guardian can disable or revoke a gate,
    /// nothing else.
    pub fn init_guardian(ctx: Context<InitGuardian>, guardian: Pubkey) -> Result<()> {
        let g = &mut ctx.accounts.guardian_set;
        g.guardian = guardian;
        g.bump = ctx.bumps.guardian_set;
        g.reserved = [0u8; 32];
        Ok(())
    }

    pub fn set_guardian(ctx: Context<SetGuardian>, guardian: Pubkey) -> Result<()> {
        ctx.accounts.guardian_set.guardian = guardian;
        Ok(())
    }

    /// Admin only. A new gate is DISABLED: it authorises nothing until `enable_gate`.
    /// The pool, its two mints, their decimals and the bin step are read from the accounts; the
    /// admin supplies the two Pyth feed ids (token X in USD, token Y in USD) and the limits.
    pub fn create_gate(ctx: Context<CreateGate>, feed_x: [u8; 32], feed_y: [u8; 32], limits: GateLimits) -> Result<()> {
        let a = &ctx.accounts;
        let pair = parse_pair(a.lb_pair.owner, &a.lb_pair.try_borrow_data()?)?;
        require!(a.mint_x.key() == pair.mint_x && a.mint_y.key() == pair.mint_y, VaultError::BadGate);
        limits.validate(pair.bin_step)?;
        require!(feed_x != feed_y && feed_x != [0u8; 32] && feed_y != [0u8; 32], VaultError::BadGate);
        let decimals_x = mint_decimals(&a.mint_x)?;
        let decimals_y = mint_decimals(&a.mint_y)?;
        let bump = ctx.bumps.gate;
        let g = &mut ctx.accounts.gate;
        g.layout = GATE_LAYOUT;
        g.bump = bump;
        g.lb_pair = ctx.accounts.lb_pair.key();
        g.mint_x = pair.mint_x;
        g.mint_y = pair.mint_y;
        g.decimals_x = decimals_x;
        g.decimals_y = decimals_y;
        g.bin_step = pair.bin_step;
        g.feed_x = feed_x;
        g.feed_y = feed_y;
        g.enabled = false;
        g.revoked = false;
        g.valid_until = 0;
        g.limits = limits;
        g.reserved = [0u8; oracle::GATE_RESERVED];
        emit_gate(g, ctx.accounts.admin.key())
    }

    /// Admin only: enables the gate, or renews it, up to `valid_until` (at most 7 days ahead).
    /// A revoked gate cannot be enabled.
    pub fn enable_gate(ctx: Context<GateAdmin>, valid_until: i64) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let g = &mut ctx.accounts.gate;
        require!(!g.revoked, VaultError::GateRevoked);
        require!(valid_until > now && valid_until <= now + MAX_GATE_VALIDITY, VaultError::BadGate);
        g.limits.validate(g.bin_step)?;
        g.enabled = true;
        g.valid_until = valid_until;
        emit_gate(g, ctx.accounts.admin.key())
    }

    /// Admin only: new limits and / or feed ids. The gate is disabled by the change and must be
    /// enabled again explicitly.
    pub fn set_gate(ctx: Context<GateAdmin>, feed_x: [u8; 32], feed_y: [u8; 32], limits: GateLimits) -> Result<()> {
        let g = &mut ctx.accounts.gate;
        limits.validate(g.bin_step)?;
        require!(feed_x != feed_y && feed_x != [0u8; 32] && feed_y != [0u8; 32], VaultError::BadGate);
        g.feed_x = feed_x;
        g.feed_y = feed_y;
        g.limits = limits;
        g.enabled = false;
        g.valid_until = 0;
        emit_gate(g, ctx.accounts.admin.key())
    }

    /// Admin only: lifts a revocation. The gate stays disabled.
    pub fn reset_gate(ctx: Context<GateAdmin>) -> Result<()> {
        let g = &mut ctx.accounts.gate;
        g.revoked = false;
        g.enabled = false;
        g.valid_until = 0;
        emit_gate(g, ctx.accounts.admin.key())
    }

    /// Admin or guardian. Takes effect in the same slot: the next keeper mark or rebalance of the
    /// pool is refused. Owner actions and automated exits do not read the gate and are not affected.
    pub fn disable_gate(ctx: Context<GateStop>) -> Result<()> {
        ctx.accounts.authorise()?;
        let g = &mut ctx.accounts.gate;
        g.enabled = false;
        emit_gate(g, ctx.accounts.authority.key())
    }

    /// Admin or guardian. Like disable, and the gate cannot be enabled again until the admin resets it.
    pub fn revoke_gate(ctx: Context<GateStop>) -> Result<()> {
        ctx.accounts.authorise()?;
        let g = &mut ctx.accounts.gate;
        g.enabled = false;
        g.revoked = true;
        g.valid_until = 0;
        emit_gate(g, ctx.accounts.authority.key())
    }

    // ================================================================ keeper
    // Token flows reachable from here: vault token accounts <-> DLMM pool reserves. Nothing else.
    // SOL flows reachable from here: vault SOL reserve -> Config.keeper (the network fee of this
    // transaction, inside the owner's limits), DLMM position rent -> the owner wallet on close,
    // and on a rebalance: old position rent -> SOL reserve -> new position rent.

    /// Records what the program itself sees: the active bin of the position's pool is out of the
    /// position's range by the owner's margin (mark set, with the time), or it is back (mark
    /// dropped). A rebalance or an out-of-range exit needs a mark of the required age.
    ///
    /// M2.1: a mark also stores a fingerprint of DLMM's swap-fee counters of every bin of the range
    /// (remaining accounts: the range's bin arrays, in order). A rebalance or an out-of-range exit
    /// needs that fingerprint unchanged: no swap traded inside the range since the mark. If it has
    /// changed, a new mark starts the wait again.
    ///
    /// M2.2: one more remaining account after the range's bin arrays: the bin array of the pool's
    /// ACTIVE bin (it may be one of the range's arrays again). No mark while the active bin holds no
    /// liquidity at all: a bin nobody provides liquidity in is not a price. And the position must
    /// hold liquidity of its own in at least one bin of the range (the nearest one to the price is
    /// reported), no longer necessarily in the edge bin.
    ///
    /// M2.3 (Mode P): three more remaining accounts make it an ORACLE-CHECKED mark: the pool's gate
    /// and the two Pyth price accounts the gate names. The gate must be open and the pool's price
    /// inside the external price band. Only such a mark can lead to a keeper rebalance. Without
    /// them the mark is a plain one, set only for a position whose owner signed the out-of-range
    /// exit rule; a plain mark can only lead to an automated exit, which needs no gate.
    ///
    /// M2.5: the owner's out-of-range exit wait counts from `oor_since`, the time of the first mark
    /// of an unbroken run. Making a live plain mark into an oracle-checked one (the only way a live,
    /// unchanged mark can be replaced) starts the REBALANCE wait again and leaves `oor_since` where
    /// it was: a keeper cannot push an exit the owner signed further away by marking.
    pub fn keeper_mark<'info>(ctx: Context<'_, '_, '_, 'info, KeeperMark<'info>>, expected_version: u64) -> Result<()> {
        let arrays = ctx.remaining_accounts;
        let a = ctx.accounts;
        let (quote, now) = keeper_gate(&a.keeper, &a.config, &mut a.vault, &mut a.record, &a.sol_reserve, &a.instructions, FLAG_REBALANCE | FLAG_CLOSE, KIND_MARK, expected_version)?;
        let (pair, lower, upper, side) = observe(&a.record, &a.position, &a.lb_pair)?;
        let r = &mut a.record;
        let pol = r.policy;
        require!(r.st.marks_today < pol.max_marks_per_day, VaultError::OverDailyMarks);
        r.st.marks_today += 1;
        let mut own_bin = 0i32;
        if side == 0 {
            // M2.8: drops the rebalance mark; the exit run ends only on a confirmed recovery (clear_mark).
            require!(r.st.mark_time != 0 || r.st.oor_since != 0, VaultError::NotOutOfRange);
            let ev = return_evidence(r, &pair, a.lb_pair.key, (lower, upper), arrays, now)?;
            let before = r.st;
            on_return(&mut r.st, &pol, now, ev);
            require!(r.st != before, VaultError::MarkUnchanged);
        } else {
            require!(recent_move(&pair, now) <= pol.max_slippage_bins as u32, VaultError::SlippageExceeded);
            let n = bin_arrays_spanned(lower, upper);
            let with_oracle = arrays.len() == n + 4;
            require!(with_oracle || arrays.len() == n + 1, VaultError::MissingBinArrays);
            let fp = range_fingerprint(a.lb_pair.key, lower, upper, &arrays[..n])?;
            require_active_bin_liquidity(a.lb_pair.key, pair.active_id, &arrays[n])?;
            if with_oracle {
                mode_p(&arrays[n + 1], &arrays[n + 2], &arrays[n + 3], a.lb_pair.key, &pair, &pol, now)?;
            } else {
                require!(r.flags & FLAG_CLOSE != 0 && pol.exit_on_oor, VaultError::MarkNeedsOracle);
            }
            // The proof is about the position's own liquidity: it must hold some in the range. The
            // nearest such bin to the price is the first one a returning price would trade against.
            own_bin = nearest_own_bin(&a.position.try_borrow_data()?, lower, upper, side).ok_or(VaultError::EdgeBinEmpty)?;
            // a mark that can still be used is never moved: its time is the proof of the wait.
            // Unless a swap has traded inside the range since: then the wait starts again.
            let live = r.st.mark_time != 0 && now <= mark_last_use(&pol, r.flags, r.st.mark_time);
            // The one exception: an oracle-checked mark may replace a plain one. The wait starts again.
            let same = live && r.st.mark_side == side && r.st.mark_fp == fp;
            require!(!(same && (r.st.mark_oracle == 1 || !with_oracle)), VaultError::MarkUnchanged);
            // M2.8: the exit run goes on through a swap inside the range, a replaced or retried mark
            // and a plain mark made into a checked one; only the other side or a gap in observations
            // starts a new one (run_on_mark). The REBALANCE wait still starts again with any new mark.
            let flags = r.flags;
            run_on_mark(&mut r.st, &pol, flags, side, now);
            r.st.mark_time = now;
            r.st.mark_active_id = pair.active_id;
            r.st.mark_side = side;
            r.st.mark_fp = fp;
            r.st.mark_oracle = with_oracle as u8;
        }
        emit!(RangeObserved { record: r.key(), active_id: pair.active_id, lower, upper, side, mark_time: r.st.mark_time, version: r.version, own_bin, oracle: r.st.mark_oracle == 1, oor_since: r.st.oor_since });
        let position = a.position.key();
        keeper_repay(&a.keeper, &a.vault, &a.record, &a.sol_reserve, &a.system_program, position, KIND_MARK, &quote)
    }

    /// Claim, check the owner's minimum and cost ratio against what DLMM really paid, book the fee
    /// as owed, re-add exactly claimed-minus-fee to the same position at the pool's own active bin,
    /// repay the keeper the network fee of this transaction. The keeper passes no amount, no bin,
    /// no price and no slippage. If any check fails the whole transaction fails: nothing is repaid.
    pub fn keeper_compound<'info>(ctx: Context<'_, '_, '_, 'info, KeeperCompound<'info>>, expected_version: u64) -> Result<()> {
        let k = &mut ctx.accounts.k;
        let (quote, now) = k.gate(FLAG_COMPOUND, KIND_COMPOUND, expected_version)?;
        let (pair, lower, upper, _) = observe(&k.p.record, &k.p.position, &k.p.lb_pair)?;
        let pol = k.p.record.policy;
        let st = k.p.record.st;
        require!(pol.min_claim_x > 0 || pol.min_claim_y > 0, VaultError::ThresholdNotSet);
        // M2.1: no automatic compounding without the economic check, and that check needs a wrapped-SOL leg.
        require!(pol.max_cost_bps > 0, VaultError::CostRatioNotSet);
        require!(pair.mint_x == WSOL_MINT || pair.mint_y == WSOL_MINT, VaultError::CostRatioNeedsSolLeg);
        require!(st.last_compound == 0 || now.saturating_sub(st.last_compound) >= pol.compound_cooldown as i64, VaultError::CompoundCooldown);
        require!(st.compounds_today < pol.max_compounds_per_day, VaultError::OverDailyCompounds);
        require!(recent_move(&pair, now) <= pol.max_slippage_bins as u32, VaultError::SlippageExceeded);

        let p = &mut k.p;
        let (d, infos) = p.bundle(ctx.remaining_accounts, &[]);
        let owner = p.vault.owner;
        let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[p.vault.bump]];
        let x0 = token_amount(&d.vault_x)?;
        let y0 = token_amount(&d.vault_y)?;
        let c = claim_and_book(p, &d, &infos, ctx.remaining_accounts, lower, upper, PATH_COMPOUND, None)?;
        require!(min_claim_met(c.claimed_x, c.claimed_y, pol.min_claim_x, pol.min_claim_y), VaultError::BelowMinClaim);
        let cost = quote.base + quote.priority;
        let v = claim_value_lamports(&pair, c.claimed_x, c.claimed_y).ok_or(VaultError::CostRatioNeedsSolLeg)??;
        require!(cost_ratio_ok(cost, v, pol.max_cost_bps), VaultError::CostRatioExceeded);
        let value = v.min(u64::MAX as u128) as u64;
        let (net_x, net_y) = (c.claimed_x - c.fee_x, c.claimed_y - c.fee_y);
        if net_x > 0 || net_y > 0 {
            cpi_add_by_strategy(&d, &infos, ctx.remaining_accounts, net_x, net_y, pair.active_id, 0, lower, upper, pol.strategy, seeds)?;
        }
        // The re-add can only use what was just claimed: the vault's other funds and the fee just booked are still there.
        require!(
            token_amount(&d.vault_x)? >= x0.checked_add(c.fee_x).ok_or(VaultError::Math)? && token_amount(&d.vault_y)? >= y0.checked_add(c.fee_y).ok_or(VaultError::Math)?,
            VaultError::IdleFundsUsed
        );
        require_covered(&p.vault, &d.vault_x, d.mint_x.key)?;
        require_covered(&p.vault, &d.vault_y, d.mint_y.key)?;
        p.record.st.last_compound = now;
        p.record.st.compounds_today += 1;
        emit!(Compounded { record: p.record.key(), active_id: pair.active_id, lower, upper, claimed_x: c.claimed_x, claimed_y: c.claimed_y, value_lamports: value, cost_lamports: cost, compounds_today: p.record.st.compounds_today });
        k.repay(KIND_COMPOUND, &quote)
    }

    /// ONE keeper transaction: remove all liquidity, claim (performance fee booked on the claimed
    /// swap fees only, as everywhere), close the old DLMM position, open a new one whose range the
    /// PROGRAM checks against the owner's policy and (M2.7) the VERIFIED external price, and deposit
    /// what came out of the old position (no swap, nothing from the vault's idle funds).
    /// M2.7: the new range is one-sided and never contains the active bin: bids (token Y) wholly below
    /// it and at or below the external price less its uncertainty, asks (token X) wholly above it and
    /// at or above the external price plus its uncertainty (`check_placement`). Nothing goes into the
    /// active bin, so DLMM charges no composition fee. Only the token of that side is deposited.
    /// Needs an out-of-range mark of the required age AND the program seeing it still out of range.
    /// Position rent: old position -> SOL reserve -> new position (a DLMM PDA whose base is the
    /// PositionRecord); the keeper never receives rent.
    /// Remaining accounts: the bin arrays of the old range, then the bin arrays of the new range, then
    /// (M2.7, only when those do not hold it) the bin array of the pool's active bin.
    ///
    /// M2.3: the range may move only inside the owner's ROLLING 24-hour limits (bins and price
    /// movement). Mode P: the pool's gate must be open and the two Pyth price accounts it names are
    /// validated again here, whatever an earlier transaction did. The pool's price must be inside
    /// the external price band before anything moves; after the deposit the program reads what the
    /// new position really holds and checks the outcome of the whole rebalance: the effective price
    /// of all its bids and of all its asks against the band, and that what the vault owns afterwards
    /// is worth, at the external price, what came out of the old position (fees claimed included).
    /// The DLMM instructions called from here are remove, claim, close, initialise and add: no swap.
    pub fn keeper_rebalance<'info>(
        ctx: Context<'_, '_, '_, 'info, KeeperRebalance<'info>>,
        expected_version: u64,
        new_lower_bin_id: i32,
        new_width: i32,
    ) -> Result<()> {
        let new_pos = ctx.accounts.new_position.to_account_info();
        let rent_ai = ctx.accounts.rent.to_account_info();
        let gate_ai = ctx.accounts.gate.to_account_info();
        let price_x_ai = ctx.accounts.price_x.to_account_info();
        let price_y_ai = ctx.accounts.price_y.to_account_info();
        let k = &mut ctx.accounts.k;
        let (quote, now) = k.gate(FLAG_REBALANCE, KIND_REBALANCE, expected_version)?;
        let (pair, lower, upper, side) = observe(&k.p.record, &k.p.position, &k.p.lb_pair)?;
        // Every check that can refuse the rebalance before anything moves (its own function: stack space).
        let plan = rebalance_plan(&k.p.record, &pair, (lower, upper, side), now, (new_lower_bin_id, new_width), k.p.lb_pair.key, ctx.remaining_accounts, [&gate_ai, &price_x_ai, &price_y_ai])?;
        let (new_upper, shift_bins, ring_slot) = (plan.new_upper, plan.shift_bins, plan.ring_slot);
        let (old_bins, rest) = ctx.remaining_accounts.split_at(plan.n_old);
        let new_bins = &rest[..plan.n_new];
        let (rent_budget, strategy, max_loss_bps) = (k.p.record.policy.rent_budget, k.p.record.policy.strategy, k.p.record.policy.max_loss_bps);

        let reserve_ai = k.sol_reserve.to_account_info();
        let system_ai = k.system_program.to_account_info();
        let p = &mut k.p;
        let record_ai = p.record.to_account_info();
        let (d, infos) = p.bundle(ctx.remaining_accounts, &[reserve_ai.clone(), record_ai.clone(), new_pos.clone(), system_ai.clone(), rent_ai.clone()]);
        let owner = p.vault.owner;
        let vault_key = p.vault.key();
        let origin = p.record.origin;
        let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[p.vault.bump]];
        let reserve_seeds: &[&[u8]] = &[b"reserve", vault_key.as_ref(), &[p.vault.reserve_bump]];
        let record_seeds: &[&[u8]] = &[b"pos", origin.as_ref(), &[p.record.bump]];

        // M2.1: bin arrays of the new range. An existing one is used as it is. A missing one is created
        // only inside the owner's rent budget, paid by the vault's SOL reserve. Never by the keeper.
        let rent = Rent::get()?;
        let first_new = bin_array_index(new_lower_bin_id);
        for (i, ba) in new_bins.iter().enumerate() {
            let index = first_new + i as i64;
            let (expected, _) = Pubkey::find_program_address(&[b"bin_array", d.lb_pair.key.as_ref(), &index.to_le_bytes()], &DLMM_ID);
            require_keys_eq!(ba.key(), expected, VaultError::WrongBinArray);
            if *ba.owner == DLMM_ID {
                check_bin_array(ba.owner, &ba.try_borrow_data()?, d.lb_pair.key, index)?;
                continue;
            }
            require!(*ba.owner == system_program::ID && ba.data_is_empty(), VaultError::WrongBinArray);
            require!(rent_budget > 0, VaultError::MissingBinArrays);
            let need = rent.minimum_balance(BIN_ARRAY_LEN).saturating_sub(ba.lamports());
            require!(need <= rent_budget.saturating_sub(p.record.st.rent_spent), VaultError::RentBudgetExceeded);
            let before = reserve_ai.lamports();
            let keep = rent.minimum_balance(0).checked_add(p.vault.exit_floor).ok_or(VaultError::Math)?;
            require!(before >= need.checked_add(keep).ok_or(VaultError::Math)?, VaultError::ReserveEmpty);
            let mut data = IX_INIT_BIN_ARRAY.to_vec();
            data.extend_from_slice(&index.to_le_bytes());
            let metas = vec![
                AccountMeta::new_readonly(d.lb_pair.key(), false),
                AccountMeta::new(ba.key(), false),
                AccountMeta::new(reserve_ai.key(), true),
                AccountMeta::new_readonly(system_ai.key(), false),
            ];
            invoke_signed(&Instruction { program_id: DLMM_ID, accounts: metas, data }, &infos, &[reserve_seeds])?;
            let paid = before.checked_sub(reserve_ai.lamports()).ok_or(VaultError::Math)?;
            require!(paid <= need, VaultError::RentLeak);
            check_bin_array(ba.owner, &ba.try_borrow_data()?, d.lb_pair.key, index)?;
            p.record.st.rent_spent = p.record.st.rent_spent.checked_add(paid).ok_or(VaultError::Math)?;
            emit!(BinArrayCreated { record: p.record.key(), lb_pair: d.lb_pair.key(), bin_array: ba.key(), index, lamports: paid, payer: reserve_ai.key(), recoverable: false, rent_spent: p.record.st.rent_spent, rent_budget });
        }

        let x0 = token_amount(&d.vault_x)?;
        let y0 = token_amount(&d.vault_y)?;
        cpi_remove_all(&d, &infos, old_bins, lower, upper, seeds)?;
        let removed_x = token_amount(&d.vault_x)?.checked_sub(x0).ok_or(VaultError::Math)?;
        let removed_y = token_amount(&d.vault_y)?.checked_sub(y0).ok_or(VaultError::Math)?;
        let c = claim_and_book(p, &d, &infos, old_bins, lower, upper, PATH_REBALANCE, None)?;

        let lam0 = reserve_ai.lamports();
        cpi_close(&d, &infos, &reserve_ai, seeds)?;
        let rent_in = reserve_ai.lamports().checked_sub(lam0).ok_or(VaultError::Math)?;
        let mut data = IX_INIT_POSITION_PDA.to_vec();
        data.extend_from_slice(&new_lower_bin_id.to_le_bytes());
        data.extend_from_slice(&new_width.to_le_bytes());
        let metas = vec![
            AccountMeta::new(reserve_ai.key(), true),
            AccountMeta::new_readonly(record_ai.key(), true),
            AccountMeta::new(new_pos.key(), false),
            AccountMeta::new_readonly(d.lb_pair.key(), false),
            AccountMeta::new_readonly(vault_key, true),
            AccountMeta::new_readonly(system_ai.key(), false),
            AccountMeta::new_readonly(rent_ai.key(), false),
            AccountMeta::new_readonly(d.event_authority.key(), false),
            AccountMeta::new_readonly(DLMM_ID, false),
        ];
        invoke_signed(&Instruction { program_id: DLMM_ID, accounts: metas, data }, &infos, &[seeds, reserve_seeds, record_seeds])?;
        let rent_out = (lam0 + rent_in).checked_sub(reserve_ai.lamports()).ok_or(VaultError::Math)?;
        // the reserve never ends a rebalance with less rent money than it started with
        require!(rent_out <= rent_in, VaultError::RentLeak);

        let dep_x = removed_x.checked_add(c.claimed_x - c.fee_x).ok_or(VaultError::Math)?;
        let dep_y = removed_y.checked_add(c.claimed_y - c.fee_y).ok_or(VaultError::Math)?;
        let mut d2 = d.clone();
        d2.position = new_pos.clone();
        // M2.7: the new range is wholly below the active bin (bids, token Y) or wholly above it (asks,
        // token X): DLMM can place only that token there. The other token (claimed swap fees only: the
        // old range was wholly on one side) stays in the vault's token account and counts against
        // `min_placed_bps` like anything else not placed.
        let (add_x, add_y) = if side > 0 { (0, dep_y) } else { (dep_x, 0) };
        if add_x > 0 || add_y > 0 {
            cpi_add_by_strategy(&d2, &infos, new_bins, add_x, add_y, pair.active_id, 0, new_lower_bin_id, new_upper, strategy, seeds)?;
        }
        // Only what came out of the old position can go into the new one: the vault's other funds
        // and the fee just booked are still there.
        let x1 = token_amount(&d.vault_x)?;
        let y1 = token_amount(&d.vault_y)?;
        require!(x1 >= x0.checked_add(c.fee_x).ok_or(VaultError::Math)? && y1 >= y0.checked_add(c.fee_y).ok_or(VaultError::Math)?, VaultError::IdleFundsUsed);
        require_covered(&p.vault, &d.vault_x, d.mint_x.key)?;
        require_covered(&p.vault, &d.vault_y, d.mint_y.key)?;

        // M2.3: the outcome of the whole rebalance, from what the new position really holds now.
        let before = (removed_x as u128 + c.claimed_x as u128, removed_y as u128 + c.claimed_y as u128);
        let flows = Flows { out: before, net: (dep_x as u128, dep_y as u128), kept: ((x1 - x0) as u128, (y1 - y0) as u128) };
        let (held_x, held_y) = check_outcome(&new_pos, d.lb_pair.key, &vault_key, new_lower_bin_id, new_upper, new_bins, pair.bin_step, &plan.mp, (max_loss_bps, plan.min_placed_bps), &flows)?;

        let r = &mut p.record;
        let old_position = r.position;
        r.position = new_pos.key();
        r.st.clear_mark();
        r.st.last_rebalance = now;
        r.st.rebalances_today += 1;
        r.st.ring[ring_slot] = ShiftEntry { time: now, bins: shift_bins };
        emit!(Rebalanced {
            record: r.key(), old_position, new_position: r.position, active_id: pair.active_id, side,
            old_lower: lower, old_upper: upper, new_lower: new_lower_bin_id, new_upper,
            removed_x, removed_y, deposited_x: x0 + removed_x + c.claimed_x - x1, deposited_y: y0 + removed_y + c.claimed_y - y1,
            rent_in, rent_out, rebalances_today: r.st.rebalances_today,
            held_x, held_y, shift_bins,
        });
        k.repay(KIND_REBALANCE, &quote)
    }

    /// Remove all liquidity, claim, book the fee as owed, close the position. Tokens stay in the
    /// vault's token accounts; position rent and record rent go to the owner wallet. Exit kind.
    /// Runs only when an exit rule the owner signed is satisfied on chain.
    pub fn keeper_close<'info>(ctx: Context<'_, '_, '_, 'info, KeeperClose<'info>>, expected_version: u64) -> Result<()> {
        let owner_ai = ctx.accounts.owner_wallet.to_account_info();
        let k = &mut ctx.accounts.k;
        let (quote, now) = k.gate(FLAG_CLOSE, KIND_EXIT, expected_version)?;
        let (pair, lower, upper, side) = observe(&k.p.record, &k.p.position, &k.p.lb_pair)?;
        let (pol, st) = (k.p.record.policy, k.p.record.st);
        require!(exit_rule_met(&pol, &st, now, side), VaultError::ExitRuleNotMet);
        // M2.9 (owner's decisions 1 and 2): a keeper exit needs the pool's own open gate (none, disabled,
        // revoked or expired: ExitNeedsGate; the owner's withdrawal and emergency exit never look at it).
        // An out-of-range exit also needs fresh, fully verified Pyth prices whose WHOLE band (both feeds'
        // uncertainty and the rounding allowance) is still out of the range on the marked side by the
        // owner's margin; anything less is ExitOracleNotOut, a bad price account fails with its oracle
        // error, and Meteora's active bin is never enough on its own. A time exit (exit_after) the owner
        // signed reads no price: it does not depend on where the price is.
        // M2.10 (owner's decision 1): once the owner's signed exit_after deadline has passed, the exit
        // needs no open gate either (the gate account must still be this pool's gate address). Only the
        // owner's set_policy can set exit_after; keeper_close takes no parameter but the version; it only
        // removes liquidity into the vault's own token accounts. Before the deadline the price path
        // above applies unchanged, whatever else is configured.
        let timed = pol.exit_after > 0 && now >= pol.exit_after;
        let band = exit_oracle(&ctx.accounts.gate, &ctx.accounts.price_x, &ctx.accounts.price_y, k.p.lb_pair.key, &pair, now, !timed)?;
        if let Some(b) = band {
            require!(oracle_out(side, lower, upper, pol.oor_margin_bins, pair.bin_step, &b)?, VaultError::ExitOracleNotOut);
        }
        // M2.8: no "no swap inside the range since the mark" condition any more (M2.1's RangeTraded):
        // an exit only removes liquidity, it never swaps, and that condition let any trade inside the
        // range, however small, push the owner's exit back. The run itself (`oor_since`) carries the
        // proof of how long the position has been out of range. The range's bin arrays are still checked the way the
        // fingerprint reads them (owner, size, pool, index, address, order, exact count): only the comparison is gone.
        range_fingerprint(k.p.lb_pair.key, lower, upper, ctx.remaining_accounts)?;
        let p = &mut k.p;
        let (d, infos) = p.bundle(ctx.remaining_accounts, &[owner_ai.clone()]);
        let owner = p.vault.owner;
        let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[p.vault.bump]];
        cpi_remove_all(&d, &infos, ctx.remaining_accounts, lower, upper, seeds)?;
        claim_and_book(p, &d, &infos, ctx.remaining_accounts, lower, upper, PATH_KEEPER_CLOSE, None)?;
        cpi_close(&d, &infos, &owner_ai, seeds)?;
        p.record.close(owner_ai)?;
        k.repay(KIND_EXIT, &quote)
    }

    // ================================================================ anyone

    /// Permissionless settlement of what a vault owes for one mint: transfers exactly
    /// fees_owed[mint] (never more) from the vault's token account to the associated token account
    /// of Config.treasury and zeroes the entry. Moves nothing when nothing is owed.
    /// M2.11: refused when nothing is owed (NothingToCollect). There is no amount argument, the
    /// source is the vault's own token account and the destination is the associated token account
    /// of the EFFECTIVE treasury (a proposed treasury receives nothing before `execute_treasury`).
    /// The entry is removed in the same instruction, so a second call finds nothing.
    pub fn collect_fees(ctx: Context<CollectFees>) -> Result<()> {
        let a = &ctx.accounts;
        let vault_key = a.vault.key();
        check_vault_ata(&a.vault_token, a.mint.key, &vault_key, a.token_program.key)?;
        let treasury = a.config.treasury;
        require_keys_eq!(a.treasury_token.key(), ata_address(&treasury, a.token_program.key, a.mint.key), VaultError::WrongTreasuryAccount);
        let amount = a.vault.owed(a.mint.key);
        require!(amount > 0, VaultError::NothingToCollect);
        require!(token_amount(&a.vault_token)? >= amount, VaultError::FeesOwedLocked);
        let owner = a.vault.owner;
        let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[a.vault.bump]];
        token_transfer(&a.token_program, &a.vault_token, &a.mint, &a.treasury_token, &a.vault.to_account_info(), amount, &[seeds])?;
        let mint = a.mint.key();
        let treasury_token = a.treasury_token.key();
        let caller = a.caller.key();
        let v = &mut ctx.accounts.vault;
        v.fees_owed.retain(|e| e.mint != mint);
        v.fee_seq = v.fee_seq.checked_add(1).ok_or(VaultError::Math)?;
        emit!(FeesCollected { vault: vault_key, mint, amount, treasury, treasury_token, caller, owed_after: 0, fee_seq: v.fee_seq, slot: Clock::get()?.slot });
        Ok(())
    }
}

// ====================================================================== token helpers

fn is_token_program(k: &Pubkey) -> bool {
    *k == TOKEN_ID || *k == TOKEN22_ID
}

pub fn ata_address(wallet: &Pubkey, token_program: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[wallet.as_ref(), token_program.as_ref(), mint.as_ref()], &ATA_ID).0
}

/// An SPL token account (either token program) of `mint` whose SPL owner is `owner`.
fn check_token(ai: &AccountInfo, mint: &Pubkey, owner: &Pubkey) -> Result<()> {
    require!(is_token_program(ai.owner), VaultError::BadTokenAccount);
    let data = ai.try_borrow_data()?;
    require!(data.len() >= 165, VaultError::BadTokenAccount);
    require!(data[0..32] == mint.to_bytes(), VaultError::BadTokenAccount);
    require!(data[32..64] == owner.to_bytes(), VaultError::BadTokenAccount);
    Ok(())
}

/// A vault holds each mint in exactly ONE token account: the associated token account of the vault
/// PDA. fees_owed[mint] and "balance - owed" always refer to that account.
fn check_vault_ata(ai: &AccountInfo, mint: &Pubkey, vault: &Pubkey, token_program: &Pubkey) -> Result<()> {
    require!(is_token_program(token_program) && ai.owner == token_program, VaultError::BadTokenAccount);
    check_token(ai, mint, vault)?;
    require_keys_eq!(ai.key(), ata_address(vault, token_program, mint), VaultError::BadTokenAccount);
    Ok(())
}

fn token_amount(ai: &AccountInfo) -> Result<u64> {
    let data = ai.try_borrow_data()?;
    require!(data.len() >= 72, VaultError::BadTokenAccount);
    Ok(u64::from_le_bytes(data[64..72].try_into().unwrap()))
}

/// Invariant: fees_owed[mint] <= balance of the vault's token account for that mint.
fn require_covered(vault: &Vault, token_ai: &AccountInfo, mint: &Pubkey) -> Result<()> {
    require!(token_amount(token_ai)? >= vault.owed(mint), VaultError::FeesOwedLocked);
    Ok(())
}

/// SPL `TransferChecked` (same wire format in Token and Token-2022).
fn token_transfer<'info>(
    program: &AccountInfo<'info>,
    from: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    amount: u64,
    seeds: &[&[&[u8]]],
) -> Result<()> {
    require!(is_token_program(program.key), VaultError::BadTokenAccount);
    require_keys_eq!(*mint.owner, *program.key, VaultError::BadTokenAccount);
    let decimals = mint.try_borrow_data()?[44];
    let mut data = Vec::with_capacity(10);
    data.push(12);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    let ix = Instruction {
        program_id: *program.key,
        accounts: vec![
            AccountMeta::new(from.key(), false),
            AccountMeta::new_readonly(mint.key(), false),
            AccountMeta::new(to.key(), false),
            AccountMeta::new_readonly(authority.key(), true),
        ],
        data,
    };
    invoke_signed(&ix, &[from.clone(), mint.clone(), to.clone(), authority.clone(), program.clone()], seeds)?;
    Ok(())
}

// ====================================================================== DLMM CPIs

/// The accounts every DLMM CPI needs, as plain AccountInfos.
#[derive(Clone)]
pub struct Dx<'info> {
    pub vault: AccountInfo<'info>,
    pub position: AccountInfo<'info>,
    pub lb_pair: AccountInfo<'info>,
    pub bitmap_ext: AccountInfo<'info>,
    pub vault_x: AccountInfo<'info>,
    pub vault_y: AccountInfo<'info>,
    pub reserve_x: AccountInfo<'info>,
    pub reserve_y: AccountInfo<'info>,
    pub mint_x: AccountInfo<'info>,
    pub mint_y: AccountInfo<'info>,
    pub token_program_x: AccountInfo<'info>,
    pub token_program_y: AccountInfo<'info>,
    pub event_authority: AccountInfo<'info>,
    pub dlmm_program: AccountInfo<'info>,
}

impl<'info> Dx<'info> {
    fn infos(&self) -> Vec<AccountInfo<'info>> {
        vec![
            self.vault.clone(), self.position.clone(), self.lb_pair.clone(), self.bitmap_ext.clone(),
            self.vault_x.clone(), self.vault_y.clone(), self.reserve_x.clone(), self.reserve_y.clone(),
            self.mint_x.clone(), self.mint_y.clone(), self.token_program_x.clone(), self.token_program_y.clone(),
            self.event_authority.clone(), self.dlmm_program.clone(),
        ]
    }

    /// position, lb_pair, bitmap_ext, user tokens, reserves, mints, sender, token programs.
    fn liquidity_metas(&self) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(self.position.key(), false),
            AccountMeta::new(self.lb_pair.key(), false),
            // Anchor optional-account convention: the DLMM program id stands for "None".
            if self.bitmap_ext.is_writable { AccountMeta::new(self.bitmap_ext.key(), false) } else { AccountMeta::new_readonly(self.bitmap_ext.key(), false) },
            AccountMeta::new(self.vault_x.key(), false),
            AccountMeta::new(self.vault_y.key(), false),
            AccountMeta::new(self.reserve_x.key(), false),
            AccountMeta::new(self.reserve_y.key(), false),
            AccountMeta::new_readonly(self.mint_x.key(), false),
            AccountMeta::new_readonly(self.mint_y.key(), false),
            AccountMeta::new_readonly(self.vault.key(), true),
            AccountMeta::new_readonly(self.token_program_x.key(), false),
            AccountMeta::new_readonly(self.token_program_y.key(), false),
        ]
    }
}

fn dlmm_invoke<'info>(mut metas: Vec<AccountMeta>, with_memo: bool, bins: &[AccountInfo<'info>], data: Vec<u8>, infos: &[AccountInfo<'info>], seeds: &[&[u8]], event_authority: &Pubkey) -> Result<()> {
    if with_memo {
        metas.push(AccountMeta::new_readonly(MEMO_ID, false));
    }
    metas.push(AccountMeta::new_readonly(*event_authority, false));
    metas.push(AccountMeta::new_readonly(DLMM_ID, false));
    for b in bins {
        metas.push(AccountMeta::new(b.key(), false));
    }
    invoke_signed(&Instruction { program_id: DLMM_ID, accounts: metas, data }, infos, &[seeds])?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cpi_add_by_strategy<'info>(
    d: &Dx<'info>, infos: &[AccountInfo<'info>], bins: &[AccountInfo<'info>],
    amount_x: u64, amount_y: u64, active_id: i32, max_slippage: i32, min_bin_id: i32, max_bin_id: i32, strategy: u8,
    seeds: &[&[u8]],
) -> Result<()> {
    let mut data = IX_ADD_BY_STRATEGY2.to_vec();
    data.extend_from_slice(&amount_x.to_le_bytes());
    data.extend_from_slice(&amount_y.to_le_bytes());
    data.extend_from_slice(&active_id.to_le_bytes());
    data.extend_from_slice(&max_slippage.to_le_bytes());
    data.extend_from_slice(&min_bin_id.to_le_bytes());
    data.extend_from_slice(&max_bin_id.to_le_bytes());
    data.push(strategy);
    data.extend_from_slice(&[0u8; 64]);
    data.extend_from_slice(&0u32.to_le_bytes()); // RemainingAccountsInfo.slices = []
    dlmm_invoke(d.liquidity_metas(), false, bins, data, infos, seeds, d.event_authority.key)
}

/// remove_liquidity_by_range2 at 100%. Moves principal only: DLMM leaves pending swap fees in the
/// position until claim_fee2, and this is never measured for the performance fee.
fn cpi_remove_all<'info>(d: &Dx<'info>, infos: &[AccountInfo<'info>], bins: &[AccountInfo<'info>], min_bin_id: i32, max_bin_id: i32, seeds: &[&[u8]]) -> Result<()> {
    let mut data = IX_REMOVE_BY_RANGE2.to_vec();
    data.extend_from_slice(&min_bin_id.to_le_bytes());
    data.extend_from_slice(&max_bin_id.to_le_bytes());
    data.extend_from_slice(&10_000u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    dlmm_invoke(d.liquidity_metas(), true, bins, data, infos, seeds, d.event_authority.key)
}

/// M2.11: remove_liquidity_by_range2 at `bps` over `lower..=upper` into the vault's token accounts,
/// returning the measured increase of both (never the arguments).
fn remove_measured<'info>(d: &Dx<'info>, infos: &[AccountInfo<'info>], bins: &[AccountInfo<'info>], lower: i32, upper: i32, bps: u16, seeds: &[&[u8]]) -> Result<(u64, u64)> {
    let before_x = token_amount(&d.vault_x)?;
    let before_y = token_amount(&d.vault_y)?;
    let mut data = IX_REMOVE_BY_RANGE2.to_vec();
    data.extend_from_slice(&lower.to_le_bytes());
    data.extend_from_slice(&upper.to_le_bytes());
    data.extend_from_slice(&bps.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes()); // RemainingAccountsInfo.slices = []
    dlmm_invoke(d.liquidity_metas(), true, bins, data, infos, seeds, d.event_authority.key)?;
    let out_x = token_amount(&d.vault_x)?.checked_sub(before_x).ok_or(VaultError::Math)?;
    let out_y = token_amount(&d.vault_y)?.checked_sub(before_y).ok_or(VaultError::Math)?;
    Ok((out_x, out_y))
}

/// M2.11: `arrays` must be EXACTLY the bin-array PDAs covering `lower..=upper`, in order, and each a
/// genuine DLMM bin array of the pool. Nothing missing, nothing extra.
fn require_range_arrays(lb_pair: &Pubkey, lower: i32, upper: i32, arrays: &[AccountInfo]) -> Result<()> {
    require!(arrays.len() == bin_arrays_spanned(lower, upper), VaultError::WrongPositionBinArrays);
    let first = bin_array_index(lower);
    for (i, ba) in arrays.iter().enumerate() {
        let index = first + i as i64;
        let (expected, _) = Pubkey::find_program_address(&[b"bin_array", lb_pair.as_ref(), &index.to_le_bytes()], &DLMM_ID);
        require_keys_eq!(ba.key(), expected, VaultError::WrongPositionBinArrays);
        check_bin_array(ba.owner, &ba.try_borrow_data()?, lb_pair, index).map_err(|_| error!(VaultError::WrongPositionBinArrays))?;
    }
    Ok(())
}

/// M2.11: the pool's active bin must be within `max_move` bins of `expected`. Returns the active bin.
fn require_active_window(lb_pair: &AccountInfo, expected: i32, max_move: u16) -> Result<i32> {
    let pair = parse_pair(lb_pair.owner, &lb_pair.try_borrow_data()?)?;
    require!((pair.active_id as i64 - expected as i64).abs() <= max_move as i64, VaultError::ActiveBinMoved);
    Ok(pair.active_id)
}

/// M2.11: an UPPER bound of the position's principal (token X, token Y), summed over its range, from
/// DLMM's own accounts. DLMM pays floor(amount * share / supply) per bin on a remove; this bound is never
/// below that (`pro_rata_up`), so a remove that returns more than it moved something other than
/// principal. (`position_holdings` rounds the other way on purpose: the keeper's checks must never
/// overstate what a position holds.)
fn held_total(position: &AccountInfo, lb_pair: &Pubkey, vault: &Pubkey, lower: i32, upper: i32, arrays: &[AccountInfo]) -> Result<(u128, u128)> {
    let pd = position.try_borrow_data()?;
    let (pl, pu) = parse_position(position.owner, &pd, lb_pair, vault)?;
    require!(pl == lower && pu == upper, VaultError::WrongPositionAccount);
    let first = bin_array_index(lower);
    let (mut x, mut y, mut n) = (0u128, 0u128, 0i32);
    for (i, ba) in arrays.iter().enumerate() {
        let index = first + i as i64;
        let d = ba.try_borrow_data()?;
        check_bin_array(ba.owner, &d, lb_pair, index)?;
        let from = (index * BINS_PER_ARRAY as i64).max(lower as i64) as i32;
        let to = ((index + 1) * BINS_PER_ARRAY as i64 - 1).min(upper as i64) as i32;
        for bin in from..=to {
            let o = BIN_ARRAY_HEADER + BIN_SIZE * (bin as i64 - index * BINS_PER_ARRAY as i64) as usize;
            let amount_x = u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
            let amount_y = u64::from_le_bytes(d[o + 8..o + 16].try_into().unwrap());
            let supply = u128::from_le_bytes(d[o + 32..o + 48].try_into().unwrap());
            let share = position_share(&pd, lower, bin);
            x += pro_rata_up(amount_x, share, supply) as u128;
            y += pro_rata_up(amount_y, share, supply) as u128;
            n += 1;
        }
    }
    require!(n == upper - lower + 1, VaultError::MissingBinArrays);
    Ok((x, y))
}

/// M2.11: amount * share / supply rounded UP, without overflow, never below the exact floor value:
/// share and supply are cut to 64 significant bits together with the cut share rounded up and the cut
/// supply rounded down. At most `amount` (a position never holds more than the bin). The overstatement
/// is a few base units at most per bin.
pub fn pro_rata_up(amount: u64, share: u128, supply: u128) -> u64 {
    if share == 0 || supply == 0 || amount == 0 {
        return 0;
    }
    if share >= supply {
        return amount;
    }
    let s = (128 - supply.leading_zeros()).saturating_sub(64);
    let (sh, su) = if s == 0 { (share, supply) } else { ((share >> s) + 1, supply >> s) };
    let num = amount as u128 * sh; // amount < 2^64 and sh <= 2^64: fits
    let q = num / su + if num % su != 0 { 1 } else { 0 };
    q.min(amount as u128) as u64
}

/// M2.11 (finding M211-F1): the fee-isolation bound for removing `bps` of a position: principal * bps / 10,000
/// rounded UP. DLMM removes floor(share * bps / 10,000) of each bin's share and pays the floor of the pro rata
/// amount, which is at most pro_rata_up(bin) * bps / 10,000; the sum is therefore at most this bound.
pub fn share_bound_up(principal: u128, bps: u16) -> Result<u128> {
    let n = principal.checked_mul(bps as u128).ok_or(VaultError::Math)?;
    Ok(n / 10_000 + if n % 10_000 != 0 { 1 } else { 0 })
}

fn cpi_claim<'info>(d: &Dx<'info>, infos: &[AccountInfo<'info>], bins: &[AccountInfo<'info>], min_bin_id: i32, max_bin_id: i32, seeds: &[&[u8]]) -> Result<()> {
    let mut data = IX_CLAIM_FEE2.to_vec();
    data.extend_from_slice(&min_bin_id.to_le_bytes());
    data.extend_from_slice(&max_bin_id.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    let metas = vec![
        AccountMeta::new(d.lb_pair.key(), false),
        AccountMeta::new(d.position.key(), false),
        AccountMeta::new_readonly(d.vault.key(), true),
        AccountMeta::new(d.reserve_x.key(), false),
        AccountMeta::new(d.reserve_y.key(), false),
        AccountMeta::new(d.vault_x.key(), false),
        AccountMeta::new(d.vault_y.key(), false),
        AccountMeta::new_readonly(d.mint_x.key(), false),
        AccountMeta::new_readonly(d.mint_y.key(), false),
        AccountMeta::new_readonly(d.token_program_x.key(), false),
        AccountMeta::new_readonly(d.token_program_y.key(), false),
    ];
    dlmm_invoke(metas, true, bins, data, infos, seeds, d.event_authority.key)
}

fn cpi_close<'info>(d: &Dx<'info>, infos: &[AccountInfo<'info>], rent_receiver: &AccountInfo<'info>, seeds: &[&[u8]]) -> Result<()> {
    let metas = vec![
        AccountMeta::new(d.position.key(), false),
        AccountMeta::new_readonly(d.vault.key(), true),
        AccountMeta::new(rent_receiver.key(), false),
    ];
    dlmm_invoke(metas, false, &[], IX_CLOSE_POSITION2.to_vec(), infos, seeds, d.event_authority.key)
}

/// The ONLY place a performance fee is computed.
///   rate   = NFT check (500 / 750), decided before the claim from on-chain accounts only
///   before = vault token balances
///   DLMM claim_fee2 CPI            <- nothing else between the two reads
///   after  = vault token balances;  claimed = after - before
///   fee    = floor(claimed * rate / 10_000) per token, ADDED to Vault.fees_owed, not transferred.
/// Returns what was claimed and the fee booked on it.
/// `grow` = (payer, system program) when the owner signs: the owner pays for extra fees_owed slots.
#[allow(clippy::too_many_arguments)]
fn claim_and_book<'info>(
    p: &mut Pos<'info>, d: &Dx<'info>, infos: &[AccountInfo<'info>], bins: &[AccountInfo<'info>],
    min_bin_id: i32, max_bin_id: i32, path: u8, grow: Option<(&AccountInfo<'info>, &AccountInfo<'info>)>,
) -> Result<Claimed> {
    let (rate, lapse_code) = resolve_rate(&mut p.vault, &p.config.allowlist, &p.nft_token, &p.nft_metadata)?;
    let owner = p.vault.owner;
    let seeds: &[&[u8]] = &[b"vault", owner.as_ref(), &[p.vault.bump]];

    let before_x = token_amount(&d.vault_x)?;
    let before_y = token_amount(&d.vault_y)?;
    cpi_claim(d, infos, bins, min_bin_id, max_bin_id, seeds)?;
    let claimed_x = token_amount(&d.vault_x)?.checked_sub(before_x).ok_or(VaultError::Math)?;
    let claimed_y = token_amount(&d.vault_y)?.checked_sub(before_y).ok_or(VaultError::Math)?;

    let fee_x = fee_of(claimed_x, rate);
    let fee_y = fee_of(claimed_y, rate);

    let vault_ai = p.vault.to_account_info();
    if let Some((payer, system)) = grow {
        let missing = [(d.mint_x.key, fee_x), (d.mint_y.key, fee_y)].iter().filter(|(m, f)| *f > 0 && !p.vault.has_entry(m)).count();
        let need = Vault::space(p.vault.fees_owed.len() + missing);
        if vault_ai.data_len() < need {
            let short = Rent::get()?.minimum_balance(need).saturating_sub(vault_ai.lamports());
            if short > 0 {
                system_program::transfer(CpiContext::new(system.clone(), system_program::Transfer { from: payer.clone(), to: vault_ai.clone() }), short)?;
            }
            vault_ai.resize(need)?;
        }
    }
    let slots = (vault_ai.data_len().saturating_sub(Vault::BASE)) / Vault::ENTRY;
    let owed_x = p.vault.book(d.mint_x.key, fee_x, slots)?;
    let owed_y = p.vault.book(d.mint_y.key, fee_y, slots)?;
    // M2.11: every fee event on a vault carries the next sequence number (gap and duplicate check)
    p.vault.fee_seq = p.vault.fee_seq.checked_add(1).ok_or(VaultError::Math)?;

    emit!(FeeBooked {
        vault: p.vault.key(),
        position: d.position.key(),
        path,
        rate_bps: rate,
        lapse_code,
        claimed_x,
        claimed_y,
        fee_x,
        fee_y,
        owed_x,
        owed_y,
        fee_seq: p.vault.fee_seq,
    });
    Ok(Claimed { claimed_x, claimed_y, fee_x, fee_y })
}

pub fn fee_of(claimed: u64, rate_bps: u16) -> u64 {
    ((claimed as u128) * (rate_bps as u128) / 10_000) as u64
}

/// What one claim_fee2 CPI delivered to the vault, and the performance fee booked on it.
pub struct Claimed {
    pub claimed_x: u64,
    pub claimed_y: u64,
    pub fee_x: u64,
    pub fee_y: u64,
}

// ====================================================================== M2: what the program sees

/// The pool's state and the position's range, read from the two DLMM accounts the PositionRecord
/// names. Returns (pool view, lower bin, upper bin, side: +1 above / -1 below / 0 not out).
fn observe(record: &PositionRecord, position: &AccountInfo, lb_pair: &AccountInfo) -> Result<(PairView, i32, i32, i8)> {
    let pair = parse_pair(lb_pair.owner, &lb_pair.try_borrow_data()?)?;
    let (lower, upper) = parse_position(position.owner, &position.try_borrow_data()?, &record.lb_pair, &record.vault)?;
    let side = side_of(pair.active_id, lower, upper, record.policy.oor_margin_bins);
    Ok((pair, lower, upper, side))
}

/// sha256 over (bin id, fee_x_per_token_stored, fee_y_per_token_stored) of every bin lower..=upper,
/// read from DLMM's own bin arrays. `arrays` must be exactly the range's bin arrays, in order: each is
/// checked for owner, size, discriminator, pool, index and address.
fn range_fingerprint(lb_pair: &Pubkey, lower: i32, upper: i32, arrays: &[AccountInfo]) -> Result<[u8; 32]> {
    require!(arrays.len() == bin_arrays_spanned(lower, upper), VaultError::MissingBinArrays);
    let first = bin_array_index(lower);
    let mut buf: Vec<u8> = Vec::with_capacity(36 * (upper - lower + 1) as usize);
    for (i, ba) in arrays.iter().enumerate() {
        let index = first + i as i64;
        let (expected, _) = Pubkey::find_program_address(&[b"bin_array", lb_pair.as_ref(), &index.to_le_bytes()], &DLMM_ID);
        require_keys_eq!(ba.key(), expected, VaultError::WrongBinArray);
        let d = ba.try_borrow_data()?;
        check_bin_array(ba.owner, &d, lb_pair, index)?;
        fingerprint_feed(&mut buf, &d, index, lower, upper);
    }
    Ok(hashv(&[&buf]).to_bytes())
}

/// M2.2: `account` must be the genuine bin array of the pool's active bin, and that bin must hold
/// liquidity (liquidity_supply > 0). A missing array counts as an empty bin.
fn require_active_bin_liquidity(lb_pair: &Pubkey, active: i32, account: &AccountInfo) -> Result<()> {
    let index = bin_array_index(active);
    let (expected, _) = Pubkey::find_program_address(&[b"bin_array", lb_pair.as_ref(), &index.to_le_bytes()], &DLMM_ID);
    require_keys_eq!(account.key(), expected, VaultError::WrongBinArray);
    require!(*account.owner == DLMM_ID, VaultError::ActiveBinEmpty);
    let d = account.try_borrow_data()?;
    check_bin_array(account.owner, &d, lb_pair, index)?;
    require!(bin_liquidity_supply(&d, index, active) > 0, VaultError::ActiveBinEmpty);
    Ok(())
}

fn emit_gate(g: &Account<PoolGate>, by: Pubkey) -> Result<()> {
    emit!(GateChanged { gate: g.key(), lb_pair: g.lb_pair, enabled: g.enabled, revoked: g.revoked, valid_until: g.valid_until, limits: g.limits, by });
    Ok(())
}

/// Decimals of a mint of either token program (byte 44 of the mint in both).
fn mint_decimals(mint: &AccountInfo) -> Result<u8> {
    require!(is_token_program(mint.owner), VaultError::BadGate);
    let d = mint.try_borrow_data()?;
    require!(d.len() >= 82, VaultError::BadGate);
    Ok(d[44])
}

/// M2.3 Mode P, everything that must hold BEFORE a keeper mark or rebalance may rely on the pool's
/// price: the gate is this program's gate of this pool, open (enabled, not revoked, not expired);
/// both price accounts are genuine, fully verified, of the gate's feeds, fresh, tight and near their
/// moving average; and the pool's active-bin price is within the stricter of the owner's and the
/// gate's deviation limit of the external price, the confidence of both feeds counted INSIDE that
/// limit (M2.4: uncertainty uses the limit up, it does not widen it). Returns the price and that limit.
#[inline(never)]
fn mode_p(gate_ai: &AccountInfo, price_x: &AccountInfo, price_y: &AccountInfo, lb_pair: &Pubkey, pair: &PairView, pol: &Policy, now: i64) -> Result<Box<ModeP>> {
    require!(*gate_ai.owner == crate::ID, VaultError::GateMissing);
    let gate = {
        let d = gate_ai.try_borrow_data()?;
        PoolGate::try_deserialize(&mut &d[..]).map_err(|_| error!(VaultError::GateMissing))?
    };
    let expected = Pubkey::create_program_address(&[b"gate", lb_pair.as_ref(), &[gate.bump]], &crate::ID).map_err(|_| error!(VaultError::GateWrongPool))?;
    require!(gate_ai.key() == expected && gate.lb_pair == *lb_pair, VaultError::GateWrongPool);
    require!(gate.mint_x == pair.mint_x && gate.mint_y == pair.mint_y && gate.bin_step == pair.bin_step, VaultError::GateWrongPool);
    gate.check_open(now)?;
    require!(pol.max_dev_bps > 0, VaultError::OracleLimitNotSet);
    let dev = pol.max_dev_bps.min(gate.limits.max_dev_bps);
    let px = parse_price(price_x.owner, &price_x.try_borrow_data()?, &gate.feed_x)?;
    let py = parse_price(price_y.owner, &price_y.try_borrow_data()?, &gate.feed_y)?;
    let band = oracle_band(&px, &py, gate.decimals_x, gate.decimals_y, &gate.limits, now)?;
    let active = bin_price_q64(pair.bin_step, pair.active_id).ok_or(VaultError::OracleMath)?;
    require!(price_in_band(active, &band, dev)?, VaultError::OracleDeviation);
    Ok(Box::new(ModeP { band, dev, min_width: gate.limits.min_width, min_placed_bps: gate.limits.min_placed_bps }))
}

/// M2.9: the gate and price check of a KEEPER EXIT. The gate is found by its address (PDA
/// ["gate", lb_pair]): any other account there is GateWrongPool (another pool's gate included). No
/// open gate of this pool (no account, disabled, revoked, expired, older layout) is ExitNeedsGate:
/// keeper exits are not allowed in a pool without an approved independent price. Without `need_price`
/// (M2.10: the owner's exit_after deadline has passed) only the address is checked. With `need_price`
/// the two price accounts are checked exactly as for a keeper mark or rebalance (the upgraded
/// receiver as owner, full verification, the gate's feeds, age, future, feed gap, confidence, moving
/// average) and the band comes back. Unlike mode_p, the pool's active bin is NOT required to be near
/// the external price: an exit only removes liquidity, and that requirement would let anyone hold an
/// exit back by moving the pool away from the price.
#[inline(never)]
fn exit_oracle(gate_ai: &AccountInfo, price_x: &AccountInfo, price_y: &AccountInfo, lb_pair: &Pubkey, pair: &PairView, now: i64, need_price: bool) -> Result<Option<Band>> {
    let (gate_key, _) = Pubkey::find_program_address(&[b"gate", lb_pair.as_ref()], &crate::ID);
    require_keys_eq!(gate_ai.key(), gate_key, VaultError::GateWrongPool);
    // M2.10: a passed, owner-signed exit_after deadline needs neither an open gate nor prices. The
    // gate is only located (above) so no other account can stand in its place.
    if !need_price {
        return Ok(None);
    }
    require!(*gate_ai.owner == crate::ID && !gate_ai.data_is_empty(), VaultError::ExitNeedsGate);
    let gate = {
        let d = gate_ai.try_borrow_data()?;
        PoolGate::try_deserialize(&mut &d[..]).map_err(|_| error!(VaultError::ExitNeedsGate))?
    };
    require!(gate.lb_pair == *lb_pair && gate.mint_x == pair.mint_x && gate.mint_y == pair.mint_y && gate.bin_step == pair.bin_step, VaultError::GateWrongPool);
    gate.check_open(now).map_err(|_| error!(VaultError::ExitNeedsGate))?;
    let px = parse_price(price_x.owner, &price_x.try_borrow_data()?, &gate.feed_x)?;
    let py = parse_price(price_y.owner, &price_y.try_borrow_data()?, &gate.feed_y)?;
    Ok(Some(oracle_band(&px, &py, gate.decimals_x, gate.decimals_y, &gate.limits, now)?))
}

/// What `mode_p` hands back: the external price, the deviation limit in force, and the gate's two
/// minimums for a keeper rebalance (M2.5).
#[derive(Clone, Copy)]
pub struct ModeP {
    pub band: Band,
    pub dev: u16,
    pub min_width: u16,
    pub min_placed_bps: u16,
}

/// What `rebalance_plan` hands back to keeper_rebalance.
pub struct RebalancePlan {
    pub new_upper: i32,
    /// number of bin arrays of the OLD range at the front of the remaining accounts
    pub n_old: usize,
    /// M2.7: number of bin arrays of the NEW range, right after them (an optional last account is the
    /// active bin's array, read only)
    pub n_new: usize,
    pub shift_bins: u32,
    pub ring_slot: usize,
    /// the external price band and the deviation limit in force (Mode P)
    pub mp: (Band, u16),
    /// M2.5: the least share of what came out that the new position must hold (the higher of the
    /// gate's and the owner's)
    pub min_placed_bps: u16,
}

/// Everything that can refuse a keeper rebalance before any token or lamport moves: the mark (set
/// with the oracle check, aged, not expired, same side), the pool's own filter window, cooldown and
/// daily count, where the new range may be, no swap inside the old range since the mark, the
/// owner's rolling movement limits, liquidity in the active bin, and Mode P (gate + both prices).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn rebalance_plan(
    record: &PositionRecord, pair: &PairView, (lower, upper, side): (i32, i32, i8), now: i64, (new_lower, new_width): (i32, i32), lb_pair: &Pubkey,
    remaining: &[AccountInfo], [gate, price_x, price_y]: [&AccountInfo; 3],
) -> Result<Box<RebalancePlan>> {
    let (pol, st) = (&record.policy, &record.st);
    require!(st.mark_time != 0, VaultError::NoMark);
    require!(st.mark_oracle == 1, VaultError::MarkNotOracle);
    require!(side != 0, VaultError::BackInRange);
    require!(side == st.mark_side, VaultError::MarkSideChanged);
    let age = now.saturating_sub(st.mark_time);
    require!(age >= pol.oor_wait as i64, VaultError::MarkTooYoung);
    require!(age <= pol.oor_wait as i64 + pol.mark_ttl as i64, VaultError::MarkExpired);
    require!(recent_move(pair, now) <= pol.max_slippage_bins as u32, VaultError::SlippageExceeded);
    require!(st.last_rebalance == 0 || now.saturating_sub(st.last_rebalance) >= pol.rebalance_cooldown as i64, VaultError::RebalanceCooldown);
    require!(st.rebalances_today < pol.max_rebalances_per_day, VaultError::OverDailyRebalances);
    let new_upper = check_new_range(pol, side, lower, upper, new_lower, new_width)?;
    let n_old = bin_arrays_spanned(lower, upper);
    let n_new = bin_arrays_spanned(new_lower, new_upper);
    // Remaining accounts: the old range's bin arrays, the new range's, and (M2.7) the bin array of the
    // active bin when the new range's arrays do not hold it: the new range no longer contains it.
    let at = bin_array_index(pair.active_id) - bin_array_index(new_lower);
    let active_inside = at >= 0 && (at as usize) < n_new;
    require!(remaining.len() == n_old + n_new + usize::from(!active_inside), VaultError::MissingBinArrays);
    let (old_bins, rest) = remaining.split_at(n_old);
    let new_bins = &rest[..n_new];
    // M2.1: no swap has traded inside the old range since the mark.
    require!(range_fingerprint(lb_pair, lower, upper, old_bins)? == st.mark_fp, VaultError::RangeTraded);
    // M2.3: the owner's movement limits, per rebalance and over the rolling 24 hours.
    let (shift_bins, ring_slot) = check_rolling(pol, &st.ring, now, pair.bin_step, (lower, upper), (new_lower, new_upper))?;
    // M2.2: the active bin must hold liquidity. Its bin array must exist.
    let active_array = if active_inside { &new_bins[at as usize] } else { &rest[n_new] };
    require_active_bin_liquidity(lb_pair, pair.active_id, active_array)?;
    // M2.3 Mode P: gate and both price accounts, checked by this instruction itself.
    let mp = mode_p(gate, price_x, price_y, lb_pair, pair, pol, now)?;
    // M2.7: the new liquidity sits on the right side of the VERIFIED external price and outside the
    // active bin (no composition fee): bids at or below the price, asks at or above it.
    check_placement(side, pair.active_id, new_lower, new_upper, pol.edge_slack, pair.bin_step, &mp.band)?;
    // M2.8: the new position must not meet the owner's own exit rule the moment it exists. A correctly
    // placed position sits outside the active bin, so with a small margin the very next mark would start
    // an exit (M2.7 finding 1). Checked against the pool's active bin AND the far end of the verified
    // external band (`oracle_within`, the test that confirms a recovery), with the owner's margin as
    // signed: it is never widened here. Incompatible = the rebalance is refused as a whole.
    if record.flags & FLAG_CLOSE != 0 {
        require!(!(pol.exit_after > 0 && now >= pol.exit_after), VaultError::ExitMarginConflict);
        if pol.exit_on_oor {
            require!(side_of(pair.active_id, new_lower, new_upper, pol.oor_margin_bins) == 0, VaultError::ExitMarginConflict);
            require!(oracle_within(side, new_lower, new_upper, pol.oor_margin_bins, pair.bin_step, &mp.band)?, VaultError::ExitMarginConflict);
        }
    }
    // M2.5: the gate's own minimums. Zero in the gate means "no keeper rebalance in this pool". The
    // owner's policy was applied above (check_new_range) and can only ask for more.
    require!(mp.min_width > 0, VaultError::GateWidthNotSet);
    require!(new_width >= mp.min_width as i32, VaultError::WidthBelowGate);
    require!(mp.min_placed_bps > 0, VaultError::PlacedNotSet);
    Ok(Box::new(RebalancePlan { new_upper, n_old, n_new, shift_bins, ring_slot, mp: (mp.band, mp.dev), min_placed_bps: mp.min_placed_bps.max(pol.min_placed_bps) }))
}

/// M2.3: the outcome of a whole keeper rebalance, judged on what the new position really holds
/// after the deposit (read from DLMM's accounts, not from what was asked for):
///   1. the effective price of all its bids and of all its asks against the external band;
///   2. value at the external mid price: holdings + what stayed in the vault's token accounts
///      (`vault_delta`, the booked performance fee included) >= what came out of the old position
///      (`before`: removed + claimed), less the owner's `max_loss_bps`;
///   3. M2.5: the position is not empty and not dust: what it holds is worth at least
///      `min_placed_bps` of what came out net of the performance fee (`net`). A rebalance that
///      would leave the money sitting in the vault's token accounts is refused as a whole: the
///      transaction fails, the old position is untouched and the keeper is not repaid.
/// Returns the holdings (token X, token Y).
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn check_outcome(
    new_pos: &AccountInfo, lb_pair: &Pubkey, vault: &Pubkey, lower: i32, upper: i32, new_bins: &[AccountInfo], bin_step: u16, mp: &(Band, u16), (max_loss_bps, min_placed_bps): (u16, u16),
    f: &Flows,
) -> Result<(u64, u64)> {
    let (before, vault_delta) = (f.out, f.kept);
    let held = position_holdings(new_pos, lb_pair, vault, lower, upper, new_bins)?;
    let (held_x, held_y) = held.iter().fold((0u128, 0u128), |s, h| (s.0 + h.0 as u128, s.1 + h.1 as u128));
    let first = bin_price_q64(bin_step, lower).ok_or(VaultError::OracleMath)?;
    let first_inv = bin_price_q64(bin_step, lower.checked_neg().ok_or(VaultError::Math)?).ok_or(VaultError::OracleMath)?;
    let base_inv = bin_price_q64(bin_step, -1).ok_or(VaultError::OracleMath)?;
    require!(outcome_prices_ok(first, first_inv, base_q64(bin_step), base_inv, &held, &mp.0, mp.1)?, VaultError::OutcomePrice);
    // Attribution rounds down and DLMM rounds a deposit in the pool's favour: 2 base units per bin of dust.
    let dust = 2 * held.len() as u128;
    let after = (held_x + vault_delta.0 + dust, held_y + vault_delta.1 + dust);
    // one log line, so a refusal can be checked by hand: token X, token Y of each side and the external mid price
    msg!("outcome: out {} {} held {} {} kept {} {} mid {}/{} net {} {} min_placed {}", before.0, before.1, held_x, held_y, vault_delta.0, vault_delta.1, mp.0.mid_num, mp.0.mid_den, f.net.0, f.net.1, min_placed_bps);
    require!(value_conserved(before, after, &mp.0, max_loss_bps)?, VaultError::OutcomeLoss);
    require!(placed_enough(f.net, (held_x, held_y), &mp.0, min_placed_bps)?, VaultError::PlacedTooLittle);
    Ok((held_x.min(u64::MAX as u128) as u64, held_y.min(u64::MAX as u128) as u64))
}

/// Token X, token Y of one keeper rebalance: `out` = removed from the old position plus the swap
/// fees claimed; `net` = `out` less the performance fee booked (what was handed to the deposit);
/// `kept` = what the vault's token accounts gained over the whole rebalance (the fee included).
pub struct Flows {
    pub out: (u128, u128),
    pub net: (u128, u128),
    pub kept: (u128, u128),
}

/// What a DLMM position holds, bin by bin (lowest first), from DLMM's own accounts: the bin's token
/// amounts times the position's share of the bin's liquidity, rounded down. `arrays` are the range's
/// bin arrays in order (already checked by the caller's loop, checked again here).
#[inline(never)]
fn position_holdings(position: &AccountInfo, lb_pair: &Pubkey, vault: &Pubkey, lower: i32, upper: i32, arrays: &[AccountInfo]) -> Result<Holdings> {
    let pd = position.try_borrow_data()?;
    let (pl, pu) = parse_position(position.owner, &pd, lb_pair, vault)?;
    require!(pl == lower && pu == upper, VaultError::WrongPositionAccount);
    let first = bin_array_index(lower);
    let mut out = Vec::with_capacity((upper - lower + 1) as usize);
    for (i, ba) in arrays.iter().enumerate() {
        let index = first + i as i64;
        let d = ba.try_borrow_data()?;
        check_bin_array(ba.owner, &d, lb_pair, index)?;
        let from = (index * BINS_PER_ARRAY as i64).max(lower as i64) as i32;
        let to = ((index + 1) * BINS_PER_ARRAY as i64 - 1).min(upper as i64) as i32;
        for bin in from..=to {
            let o = BIN_ARRAY_HEADER + BIN_SIZE * (bin as i64 - index * BINS_PER_ARRAY as i64) as usize;
            let amount_x = u64::from_le_bytes(d[o..o + 8].try_into().unwrap());
            let amount_y = u64::from_le_bytes(d[o + 8..o + 16].try_into().unwrap());
            let supply = u128::from_le_bytes(d[o + 32..o + 48].try_into().unwrap());
            let share = position_share(&pd, lower, bin);
            out.push((pro_rata(amount_x, share, supply), pro_rata(amount_y, share, supply)));
        }
    }
    require!(out.len() == (upper - lower + 1) as usize, VaultError::MissingBinArrays);
    Ok(out)
}

/// M2.1: mints with the Token-2022 transfer-fee extension are refused at every entry (deposit, open).
fn reject_transfer_fee_mint(mint: &AccountInfo) -> Result<()> {
    if *mint.owner == TOKEN22_ID {
        require!(!has_transfer_fee_ext(&mint.try_borrow_data()?), VaultError::TransferFeeTokenUnsupported);
    }
    Ok(())
}

/// Last second at which a mark made at `mark_time` can still be used by an enabled action.
pub fn mark_last_use(pol: &Policy, flags: u8, mark_time: i64) -> i64 {
    let mut wait = 0i64;
    if flags & FLAG_REBALANCE != 0 {
        wait = pol.oor_wait as i64;
    }
    if flags & FLAG_CLOSE != 0 && pol.exit_on_oor {
        wait = wait.max(pol.exit_wait as i64);
    }
    mark_time.saturating_add(wait).saturating_add(pol.mark_ttl as i64)
}

/// The two exit rules an owner can sign: a time, or an out-of-range mark of a given age that the
/// program still sees out of range on the same side.
pub fn exit_rule_met(pol: &Policy, st: &AutoState, now: i64, side: i8) -> bool {
    if pol.exit_after > 0 && now >= pol.exit_after {
        return true;
    }
    if pol.exit_on_oor && st.mark_time != 0 && side != 0 && side == st.mark_side {
        // M2.5: the wait counts from the first mark of the run (never later than the mark itself; a
        // record without it falls back to the mark's own time). The mark must still be fresh.
        // M2.8: only a run on the mark's own side counts; a record without a run side falls back to the mark.
        let since = if st.oor_since != 0 && st.oor_side == st.mark_side { st.oor_since.min(st.mark_time) } else { st.mark_time };
        return now.saturating_sub(since) >= pol.exit_wait as i64 && now.saturating_sub(st.mark_time) <= pol.exit_wait as i64 + pol.mark_ttl as i64;
    }
    false
}

/// M2.8: seconds between the two in-range observations that confirm a recovery in a pool WITHOUT an
/// open gate. The weaker rule: it shows only that the pool's own price was seen back twice that far
/// apart, with no out-of-range mark in between. A gated pool uses the verified Pyth price instead.
pub const RECOVERY_CONFIRM_S: i64 = 300;

/// M2.8: what an in-range observation can prove about the owner's exit run.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Evidence {
    /// Nothing: no run, no gate account passed, or an open gate without price accounts.
    None,
    /// The pool has no open gate (none, disabled, revoked or expired): the two-observation rule.
    NoOpenGate,
    /// An open gate and fresh verified Pyth prices: true = the whole band is back inside the range.
    Oracle(bool),
}

/// M2.8: an out-of-range observation on `side`. The run continues when it is on the same side and its
/// last observation could still have been used (no unobserved gap); otherwise a new run starts now.
/// A recovery that was pending is cancelled: the price was seen out again.
pub fn run_on_mark(st: &mut AutoState, pol: &Policy, flags: u8, side: i8, now: i64) {
    let goes_on = st.oor_since != 0 && st.oor_side == side && st.oor_seen != 0 && now <= mark_last_use(pol, flags, st.oor_seen);
    if !goes_on {
        st.oor_since = now;
        st.oor_side = side;
    }
    st.back_since = 0;
    st.oor_seen = now;
}

/// M2.8: an in-range observation: the rebalance mark is dropped; the exit run is kept only while the
/// owner has an out-of-range exit rule signed (there is nothing else it protects), and then ends only
/// as `run_on_return` says.
pub fn on_return(st: &mut AutoState, pol: &Policy, now: i64, ev: Evidence) {
    st.drop_mark();
    if pol.exit_on_oor {
        run_on_return(st, now, ev);
    } else {
        st.end_run();
    }
}

/// M2.8: an in-range observation of the pool. Returns true when it ended the run.
///   Oracle(true)  -> confirmed: the run ends
///   Oracle(false) -> the verified price says still out: counts as an observation of the run
///   NoOpenGate    -> first: back_since = now; a later one at least RECOVERY_CONFIRM_S on: the run ends
///   None          -> nothing (an unconfirmed return is never an observation of the run)
pub fn run_on_return(st: &mut AutoState, now: i64, ev: Evidence) -> bool {
    if st.oor_since == 0 {
        return false;
    }
    let ended = match ev {
        Evidence::Oracle(back) => {
            if !back {
                st.back_since = 0;
                st.oor_seen = now;
            }
            back
        }
        Evidence::NoOpenGate => {
            if st.back_since == 0 {
                st.back_since = now;
                false
            } else {
                now.saturating_sub(st.back_since) >= RECOVERY_CONFIRM_S
            }
        }
        Evidence::None => false,
    };
    if ended {
        st.end_run();
    }
    ended
}

/// M2.8: what the accounts passed to an in-range observation say. The gate is found by its ADDRESS
/// (PDA ["gate", lb_pair]), never by its place, so bin arrays passed for another reason are never
/// mistaken for it, and in a pool with an open gate the weaker two-observation rule cannot be chosen
/// by leaving the price accounts out: that only gives `None`. Price accounts, when passed, follow the
/// gate and must be valid (any oracle error fails the instruction).
fn return_evidence(record: &PositionRecord, pair: &PairView, lb_pair: &Pubkey, (lower, upper): (i32, i32), rest: &[AccountInfo], now: i64) -> Result<Evidence> {
    if record.st.oor_since == 0 || record.st.oor_side == 0 {
        return Ok(Evidence::None);
    }
    let (gate_key, _) = Pubkey::find_program_address(&[b"gate", lb_pair.as_ref()], &crate::ID);
    let Some(i) = rest.iter().position(|ai| ai.key() == gate_key) else {
        return Ok(Evidence::None);
    };
    let g = &rest[i];
    if *g.owner != crate::ID || g.data_is_empty() {
        return Ok(Evidence::NoOpenGate);
    }
    let gate = {
        let d = g.try_borrow_data()?;
        PoolGate::try_deserialize(&mut &d[..]).map_err(|_| error!(VaultError::GateMissing))?
    };
    require!(gate.lb_pair == *lb_pair && gate.mint_x == pair.mint_x && gate.mint_y == pair.mint_y && gate.bin_step == pair.bin_step, VaultError::GateWrongPool);
    if gate.check_open(now).is_err() {
        return Ok(Evidence::NoOpenGate);
    }
    if rest.len() < i + 3 {
        return Ok(Evidence::None);
    }
    let px = parse_price(rest[i + 1].owner, &rest[i + 1].try_borrow_data()?, &gate.feed_x)?;
    let py = parse_price(rest[i + 2].owner, &rest[i + 2].try_borrow_data()?, &gate.feed_y)?;
    let band = oracle_band(&px, &py, gate.decimals_x, gate.decimals_y, &gate.limits, now)?;
    Ok(Evidence::Oracle(oracle_within(record.st.oor_side, lower, upper, record.policy.oor_margin_bins, pair.bin_step, &band)?))
}

// ====================================================================== NFT fee tier

/// Decides the rate for this claim. A registered vault MUST be given its exact token account and
/// metadata account: anything else is an error, never a silent 750. If the accounts are the right
/// ones but the NFT no longer qualifies, the rate is 750 and the registration is cleared.
fn resolve_rate(v: &mut Vault, allowlist: &[Pubkey], token_ai: &AccountInfo, md_ai: &AccountInfo) -> Result<(u16, u32)> {
    if !v.has_nft {
        return Ok((RATE_STANDARD_BPS, 0));
    }
    require_keys_eq!(token_ai.key(), v.nft_token, VaultError::WrongNftTokenAccount);
    let expected_md = Pubkey::create_program_address(&[b"metadata", TM_ID.as_ref(), v.nft_mint.as_ref(), &[v.nft_md_bump]], &TM_ID)
        .map_err(|_| error!(VaultError::WrongNftMetadataAccount))?;
    require_keys_eq!(md_ai.key(), expected_md, VaultError::WrongNftMetadataAccount);
    // The addresses are pinned, so what they contain is chain truth, not the caller's choice.
    match live_check(token_ai, md_ai, &v.nft_mint, &v.owner, allowlist) {
        Ok(_) => Ok((RATE_HOLDER_BPS, 0)),
        Err(e) => {
            v.clear_nft();
            Ok((RATE_STANDARD_BPS, e as u32 + anchor_lang::error::ERROR_CODE_OFFSET))
        }
    }
}

/// Every check that decides "this wallet holds an NFT of an allowlisted verified collection".
/// The caller has already pinned the ADDRESSES (token account, metadata PDA).
fn live_check(token_ai: &AccountInfo, md_ai: &AccountInfo, mint: &Pubkey, owner: &Pubkey, allowlist: &[Pubkey]) -> std::result::Result<Pubkey, VaultError> {
    if !is_token_program(token_ai.owner) {
        return Err(VaultError::TokenWrongProgram);
    }
    {
        let d = token_ai.try_borrow_data().map_err(|_| VaultError::TokenInvalid)?;
        // 165 = classic layout. Token-2022 may append extensions; byte 165 is then AccountType::Account (2).
        if d.len() < 165 || (d.len() > 165 && d[165] != 2) {
            return Err(VaultError::TokenInvalid);
        }
        if d[0..32] != mint.to_bytes() {
            return Err(VaultError::TokenMintMismatch);
        }
        if d[32..64] != owner.to_bytes() {
            return Err(VaultError::TokenOwnerMismatch);
        }
        if u64::from_le_bytes(d[64..72].try_into().unwrap()) != 1 {
            return Err(VaultError::TokenAmountNotOne);
        }
        // state: 0 uninitialised, 1 initialised, 2 frozen. pNFTs are ALWAYS frozen: counts as held.
        // The delegate (bytes 72..108) is deliberately ignored: pNFT staking / listing sets one.
        if d[108] != 1 && d[108] != 2 {
            return Err(VaultError::TokenInvalid);
        }
    }
    if *md_ai.owner != TM_ID {
        return Err(VaultError::MetadataWrongOwner);
    }
    let d = md_ai.try_borrow_data().map_err(|_| VaultError::MetadataInvalid)?;
    let c = parse_collection(&d, mint).ok_or(VaultError::MetadataInvalid)?;
    let (verified, key) = c.ok_or(VaultError::NoCollection)?;
    if !verified {
        return Err(VaultError::CollectionNotVerified);
    }
    if !allowlist.contains(&key) {
        return Err(VaultError::CollectionNotAllowlisted);
    }
    Ok(key)
}

/// Manual, length-independent parse of Token Metadata `Metadata` (key = 4, MetadataV1).
/// Outer None = not a metadata account for this mint. Inner None = no collection set.
/// Layout: key u8 | update_authority 32 | mint 32 | name str | symbol str | uri str |
/// seller_fee u16 | creators Option<Vec<34>> | primary_sale bool | is_mutable bool |
/// edition_nonce Option<u8> | token_standard Option<u8> | collection Option<{verified bool, key 32}> | ...
pub fn parse_collection(d: &[u8], mint: &Pubkey) -> Option<Option<(bool, Pubkey)>> {
    if d.len() < 65 || d[0] != 4 || d[33..65] != mint.to_bytes() {
        return None;
    }
    let mut o = 65usize;
    for _ in 0..3 {
        let n = u32::from_le_bytes(d.get(o..o.checked_add(4)?)?.try_into().ok()?) as usize;
        o = o.checked_add(4)?.checked_add(n)?;
    }
    o = o.checked_add(2)?; // seller_fee_basis_points
    match *d.get(o)? {
        0 => o += 1,
        1 => {
            let n = u32::from_le_bytes(d.get(o + 1..o + 5)?.try_into().ok()?) as usize;
            o = o.checked_add(5)?.checked_add(n.checked_mul(34)?)?;
        }
        _ => return None,
    }
    o = o.checked_add(2)?; // primary_sale_happened, is_mutable
    for _ in 0..2 {
        // edition_nonce, token_standard
        match *d.get(o)? {
            0 => o += 1,
            1 => o += 2,
            // Very old accounts can hold junk past this point: treat as "no collection".
            _ => return Some(None),
        }
    }
    match *d.get(o)? {
        1 => {
            let verified = match *d.get(o + 1)? {
                0 => false,
                1 => true,
                _ => return Some(None),
            };
            let key = Pubkey::new_from_array(d.get(o + 2..o + 34)?.try_into().ok()?);
            Some(Some((verified, key)))
        }
        _ => Some(None),
    }
}

// ====================================================================== keeper cost repayment

/// The network fee of the current transaction, split the way the cluster charges it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TxQuote {
    /// 5_000 lamports x signatures
    pub base: u64,
    /// ceil(cu_limit x micro-lamport price / 1_000_000)
    pub priority: u64,
    pub cu_limit: u32,
    pub cu_price: u64,
}

fn rd16(d: &[u8], o: usize) -> Result<usize> {
    let b = d.get(o..o.checked_add(2).ok_or(VaultError::BadInstructionsSysvar)?).ok_or(VaultError::BadInstructionsSysvar)?;
    Ok(u16::from_le_bytes([b[0], b[1]]) as usize)
}

/// Rebuilds the fee of the current transaction from the Instructions sysvar and enforces the shape
/// a keeper transaction must have:
///   * every signer any instruction refers to is the keeper (so there is exactly one signature the
///     program can see, and the keeper is the fee payer);
///   * the only instructions are ComputeBudget instructions and ONE instruction of this program,
///     the one running now (no second keeper instruction, no precompile signatures to pay for);
///   * SetComputeUnitLimit is present, so the priority fee is a known number.
pub fn quote_keeper_tx(d: &[u8], keeper: &Pubkey, program_id: &Pubkey) -> Result<TxQuote> {
    let bad = VaultError::BadInstructionsSysvar;
    require!(d.len() >= 4, VaultError::BadInstructionsSysvar);
    let n = rd16(d, 0)?;
    let current = rd16(d, d.len() - 2)?;
    let mut limit: Option<u32> = None;
    let mut price: u64 = 0;
    let mut own = 0usize;

    for i in 0..n {
        let mut o = rd16(d, 2 + 2 * i)?;
        let n_acc = rd16(d, o)?;
        o += 2;
        for _ in 0..n_acc {
            let m = d.get(o..o + 33).ok_or(bad)?;
            // bit 0 = is_signer (message level), bit 1 = is_writable
            if m[0] & 1 != 0 {
                require!(m[1..33] == keeper.to_bytes(), VaultError::KeeperNotSoleSigner);
            }
            o += 33;
        }
        let pid = Pubkey::new_from_array(d.get(o..o + 32).ok_or(bad)?.try_into().unwrap());
        o += 32;
        let len = rd16(d, o)?;
        o += 2;
        let data = d.get(o..o + len).ok_or(bad)?;

        if pid == COMPUTE_BUDGET_ID {
            match data.first() {
                // RequestHeapFrame, SetLoadedAccountsDataSizeLimit: no effect on the fee
                Some(1) | Some(4) => {}
                Some(2) if data.len() >= 5 => limit = Some(u32::from_le_bytes(data[1..5].try_into().unwrap())),
                Some(3) if data.len() >= 9 => price = u64::from_le_bytes(data[1..9].try_into().unwrap()),
                _ => return Err(VaultError::KeeperTxShape.into()),
            }
        } else if pid == *program_id && i == current {
            own += 1;
        } else {
            return Err(VaultError::KeeperTxShape.into());
        }
    }
    require!(own == 1, VaultError::KeeperTxShape);
    let cu_limit = (limit.ok_or(VaultError::MissingCuLimit)? as u64).min(MAX_CU_LIMIT);
    let priority = ((cu_limit as u128 * price as u128 + 999_999) / 1_000_000).min(u64::MAX as u128) as u64;
    Ok(TxQuote { base: LAMPORTS_PER_SIGNATURE, priority, cu_limit: cu_limit as u32, cu_price: price })
}

/// UTC day number of a unix timestamp. The daily counter belongs to one such bucket.
pub fn day_bucket(unix_timestamp: i64) -> i64 {
    unix_timestamp.div_euclid(SECONDS_PER_DAY)
}

// ====================================================================== state

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub keeper: Pubkey,
    /// Wallet whose associated token accounts receive collected fees.
    pub treasury: Pubkey,
    pub paused: bool,
    pub bump: u8,
    // --- M2.11: treasury change with a delay, two-step admin handover
    /// Proposed treasury (default = none). Receives nothing until `execute_treasury`.
    pub pending_treasury: Pubkey,
    /// Earliest time `execute_treasury` may run (0 = no proposal).
    pub treasury_eta: i64,
    /// Proposed next admin (default = none); becomes admin only by signing `accept_admin`.
    pub pending_admin: Pubkey,
    /// Layout version (CONFIG_VERSION).
    pub version: u8,
    pub allowlist: Vec<Pubkey>,
}
impl Config {
    pub const SPACE: usize = 8 + 32 * 3 + 1 + 1 + 32 + 8 + 32 + 1 + 4 + 32 * MAX_ALLOWLIST;
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct FeeOwed {
    pub mint: Pubkey,
    pub amount: u64,
}

#[account]
#[derive(Default)]
pub struct Vault {
    pub owner: Pubkey,
    pub bump: u8,
    pub reserve_bump: u8,
    // --- registered NFT (fee tier)
    pub has_nft: bool,
    pub nft_mint: Pubkey,
    pub nft_token: Pubkey,
    pub nft_md_bump: u8,
    // --- keeper cost limits (lamports), set only by the owner
    pub per_action_cap: u64,
    pub priority_fee_cap: u64,
    pub daily_cap: u64,
    pub budget_total: u64,
    pub exit_floor: u64,
    // --- keeper cost counters
    pub spent_today: u64,
    pub day: i64,
    pub spent_total: u64,
    pub positions_opened: u64,
    /// M2.11: counts every fee event on this vault (FeeBooked and FeesCollected).
    pub fee_seq: u64,
    /// Performance fees booked but not yet collected, per mint. The tokens are in the vault's own
    /// token account for that mint. Entries are removed by collect_fees.
    pub fees_owed: Vec<FeeOwed>,
}
impl Vault {
    pub const BASE: usize = 8 + 32 + 3 + 32 + 32 + 1 + 8 * 10 + 4;
    pub const ENTRY: usize = 40;
    pub const INITIAL_SLOTS: usize = 4;
    pub const fn space(slots: usize) -> usize {
        Self::BASE + Self::ENTRY * slots
    }

    pub fn owed(&self, mint: &Pubkey) -> u64 {
        self.fees_owed.iter().find(|e| e.mint == *mint).map(|e| e.amount).unwrap_or(0)
    }

    pub fn has_entry(&self, mint: &Pubkey) -> bool {
        self.fees_owed.iter().any(|e| e.mint == *mint)
    }

    /// Adds `fee` to what is owed for `mint`; returns the new total owed for that mint.
    pub fn book(&mut self, mint: &Pubkey, fee: u64, slots: usize) -> Result<u64> {
        if let Some(e) = self.fees_owed.iter_mut().find(|e| e.mint == *mint) {
            e.amount = e.amount.checked_add(fee).ok_or(VaultError::Math)?;
            return Ok(e.amount);
        }
        if fee == 0 {
            return Ok(0);
        }
        require!(self.fees_owed.len() < slots, VaultError::OwedTableFull);
        self.fees_owed.push(FeeOwed { mint: *mint, amount: fee });
        Ok(fee)
    }

    pub fn clear_nft(&mut self) {
        self.has_nft = false;
        self.nft_mint = Pubkey::default();
        self.nft_token = Pubkey::default();
        self.nft_md_bump = 0;
    }

    /// All five owner-set limits, in one pure function. Updates the counters and returns the
    /// reserve balance after the repayment. `reserve_lamports` and `rent_min` are read by the caller.
    pub fn charge(&mut self, now: i64, q: &TxQuote, kind: u8, reserve_lamports: u64, rent_min: u64) -> Result<u64> {
        let total = q.base.checked_add(q.priority).ok_or(VaultError::Math)?;
        require!(q.priority <= self.priority_fee_cap, VaultError::PriorityOverCap);
        require!(total <= self.per_action_cap, VaultError::OverPerActionCap);
        let day = day_bucket(now);
        if day != self.day {
            // New UTC day: the daily counter starts again. spent_total never resets.
            self.day = day;
            self.spent_today = 0;
        }
        let today = self.spent_today.checked_add(total).ok_or(VaultError::Math)?;
        require!(today <= self.daily_cap, VaultError::OverDailyCap);
        let lifetime = self.spent_total.checked_add(total).ok_or(VaultError::Math)?;
        require!(lifetime <= self.budget_total, VaultError::OverBudget);
        let after = reserve_lamports.checked_sub(total).ok_or(VaultError::ReserveEmpty)?;
        require!(after >= rent_min, VaultError::ReserveEmpty);
        if kind != KIND_EXIT {
            require!(after >= rent_min.checked_add(self.exit_floor).ok_or(VaultError::Math)?, VaultError::BelowExitFloor);
        }
        self.spent_today = today;
        self.spent_total = lifetime;
        Ok(after)
    }
}

#[account]
pub struct PositionRecord {
    pub vault: Pubkey,
    pub lb_pair: Pubkey,
    pub position: Pubkey,
    /// bit 0 allow_compound, bit 1 allow_close, bit 2 allow_rebalance
    pub flags: u8,
    pub paused: bool,
    /// Incremented by every state-changing instruction on this position, user or keeper.
    pub version: u64,
    pub bump: u8,
    // --- M2
    /// The DLMM position this record was opened with: the record's PDA seed, for life. `position`
    /// changes on a keeper rebalance, the record's address does not.
    pub origin: Pubkey,
    // --- M2.3
    /// Which release wrote this layout (migrate.rs). Older records have no such byte and a
    /// different length; they are converted by `migrate_record`.
    pub layout: u8,
    pub policy: Policy,
    pub st: AutoState,
    /// Room for later releases, so the record does not have to grow again.
    pub reserved: [u8; migrate::RECORD_RESERVED],
}
impl PositionRecord {
    pub const SPACE: usize = migrate::LEN_M23;
    pub fn bump_version(&mut self) -> Result<()> {
        self.version = self.version.checked_add(1).ok_or(VaultError::Math)?;
        Ok(())
    }
}

// ====================================================================== events

#[event]
pub struct NftRegistered {
    pub vault: Pubkey,
    pub nft_mint: Pubkey,
    pub collection: Pubkey,
}

#[event]
pub struct FeeBooked {
    pub vault: Pubkey,
    pub position: Pubkey,
    pub path: u8,
    pub rate_bps: u16,
    /// 0, or the error code that ended the NFT registration in this instruction
    pub lapse_code: u32,
    pub claimed_x: u64,
    pub claimed_y: u64,
    pub fee_x: u64,
    pub fee_y: u64,
    /// total owed for each mint after this booking
    pub owed_x: u64,
    pub owed_y: u64,
    /// M2.11: Vault.fee_seq after this event
    pub fee_seq: u64,
}

#[event]
pub struct FeesCollected {
    pub vault: Pubkey,
    pub mint: Pubkey,
    pub amount: u64,
    // --- M2.11
    pub treasury: Pubkey,
    pub treasury_token: Pubkey,
    pub caller: Pubkey,
    pub owed_after: u64,
    pub fee_seq: u64,
    pub slot: u64,
}

// --- M2.11: owner liquidity
#[event]
pub struct LiquidityAdded {
    pub vault: Pubkey,
    pub position: Pubkey,
    /// measured decrease of the vault's token accounts
    pub in_x: u64,
    pub in_y: u64,
    pub active_id: i32,
    pub version: u64,
}

#[event]
pub struct LiquidityRemoved {
    pub vault: Pubkey,
    pub position: Pubkey,
    pub bps: u16,
    /// measured increase of the vault's token accounts
    pub out_x: u64,
    pub out_y: u64,
    pub active_id: i32,
    pub version: u64,
}

#[event]
pub struct PositionClosed {
    pub vault: Pubkey,
    pub position: Pubkey,
    /// measured principal removed from the position
    pub out_x: u64,
    pub out_y: u64,
    /// sent to the owner's token accounts (balance less what is owed)
    pub paid_x: u64,
    pub paid_y: u64,
    pub active_id: i32,
    pub version: u64,
}

// --- M2.11: admin actions
#[event]
pub struct TreasuryProposed {
    pub old: Pubkey,
    pub new: Pubkey,
    pub eta: i64,
}

#[event]
pub struct TreasuryProposalCancelled {
    pub new: Pubkey,
}

#[event]
pub struct TreasuryChanged {
    pub old: Pubkey,
    pub new: Pubkey,
}

#[event]
pub struct AdminProposed {
    pub old: Pubkey,
    pub new: Pubkey,
}

#[event]
pub struct AdminChanged {
    pub old: Pubkey,
    pub new: Pubkey,
}

#[event]
pub struct KeeperChanged {
    pub old: Pubkey,
    pub new: Pubkey,
}

#[event]
pub struct PausedSet {
    pub paused: bool,
}

#[event]
pub struct CollectionAdded {
    pub collection: Pubkey,
}

#[event]
pub struct CollectionRemoved {
    pub collection: Pubkey,
}

#[event]
pub struct KeeperRepaid {
    pub vault: Pubkey,
    pub position: Pubkey,
    pub kind: u8,
    pub base: u64,
    pub priority: u64,
    pub total: u64,
    pub cu_limit: u32,
    pub cu_price: u64,
    pub reserve_after: u64,
    pub day: i64,
    pub spent_today: u64,
    pub spent_total: u64,
    /// PositionRecord.version after this action
    pub version: u64,
}

#[event]
pub struct PolicySet {
    pub vault: Pubkey,
    pub record: Pubkey,
    pub version: u64,
}

/// What the program read from the DLMM accounts in keeper_mark / clear_mark.
#[event]
pub struct RangeObserved {
    pub record: Pubkey,
    pub active_id: i32,
    pub lower: i32,
    pub upper: i32,
    pub side: i8,
    /// 0 = no mark after this instruction
    pub mark_time: i64,
    pub version: u64,
    /// M2.2: the bin of the range nearest to the price in which the position holds liquidity (0 when no mark was set)
    pub own_bin: i32,
    /// M2.3: the mark was set with the pool gate and the external price check
    pub oracle: bool,
    /// M2.5: the time the owner's out-of-range exit wait counts from (0 = no mark)
    pub oor_since: i64,
}

#[event]
pub struct Compounded {
    pub record: Pubkey,
    pub active_id: i32,
    pub lower: i32,
    pub upper: i32,
    pub claimed_x: u64,
    pub claimed_y: u64,
    /// lamport value of the claimed fees at the pool's active-bin price (0 when max_cost_bps is 0)
    pub value_lamports: u64,
    pub cost_lamports: u64,
    pub compounds_today: u16,
}

#[event]
pub struct Rebalanced {
    pub record: Pubkey,
    pub old_position: Pubkey,
    pub new_position: Pubkey,
    pub active_id: i32,
    pub side: i8,
    pub old_lower: i32,
    pub old_upper: i32,
    pub new_lower: i32,
    pub new_upper: i32,
    pub removed_x: u64,
    pub removed_y: u64,
    pub deposited_x: u64,
    pub deposited_y: u64,
    /// lamports the closed position returned to the SOL reserve / the reserve paid for the new one
    pub rent_in: u64,
    pub rent_out: u64,
    pub rebalances_today: u16,
    /// M2.3: what the new position holds after the deposit, read from DLMM's accounts
    pub held_x: u64,
    pub held_y: u64,
    /// M2.3: bins this rebalance moved the range (recorded in the rolling 24-hour window)
    pub shift_bins: u32,
}

/// M2.3: an older PositionRecord was converted to the current layout.
#[event]
pub struct RecordMigrated {
    pub record: Pubkey,
    pub from_len: u32,
    pub to_len: u32,
    pub layout: u8,
    pub rent_paid: u64,
    pub payer: Pubkey,
    /// the vault owner or the Config admin
    pub authority: Pubkey,
}

/// M2.3: a pool gate was created or changed. `by` is the admin or the guardian.
#[event]
pub struct GateChanged {
    pub gate: Pubkey,
    pub lb_pair: Pubkey,
    pub enabled: bool,
    pub revoked: bool,
    pub valid_until: i64,
    pub limits: GateLimits,
    pub by: Pubkey,
}

/// M2.1: the vault's SOL reserve paid the rent of a DLMM bin array a rebalance needed. DLMM never
/// closes a bin array, so this rent does not come back.
#[event]
pub struct BinArrayCreated {
    pub record: Pubkey,
    pub lb_pair: Pubkey,
    pub bin_array: Pubkey,
    pub index: i64,
    pub lamports: u64,
    pub payer: Pubkey,
    pub recoverable: bool,
    pub rent_spent: u64,
    pub rent_budget: u64,
}

// ====================================================================== accounts

#[derive(Accounts)]
pub struct InitializeConfig<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(init, payer = authority, space = Config::SPACE, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    /// CHECK: must be this program's ProgramData account; address, owner and upgrade authority checked in the handler
    pub program_data: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    pub admin: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump, has_one = admin @ VaultError::NotAdmin)]
    pub config: Account<'info, Config>,
}

/// M2.11: no signer requirement beyond the fee payer (execute_treasury checks the delay itself).
#[derive(Accounts)]
pub struct ConfigAnyone<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
}

/// M2.11: signed by the proposed admin (checked in the handler).
#[derive(Accounts)]
pub struct AcceptAdmin<'info> {
    pub new_admin: Signer<'info>,
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct InitVault<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(init, payer = owner, space = Vault::space(Vault::INITIAL_SLOTS), seeds = [b"vault", owner.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: system-owned zero-data PDA that holds only SOL; only its bump is recorded here
    #[account(seeds = [b"reserve", vault.key().as_ref()], bump)]
    pub sol_reserve: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// Seeds bind the vault to the signer: nobody but the owner can derive a matching vault.
#[derive(Accounts)]
pub struct OwnerVault<'info> {
    pub owner: Signer<'info>,
    #[account(mut, seeds = [b"vault", owner.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [b"vault", owner.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: token program validates source + authority
    #[account(mut)]
    pub owner_token: UncheckedAccount<'info>,
    /// CHECK: check_vault_ata
    #[account(mut)]
    pub vault_token: UncheckedAccount<'info>,
    /// CHECK: owner program checked in token_transfer
    pub mint: UncheckedAccount<'info>,
    /// CHECK: id checked in check_vault_ata
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [b"vault", owner.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: check_vault_ata
    #[account(mut)]
    pub vault_token: UncheckedAccount<'info>,
    /// CHECK: check_token (mint, SPL owner = signer wallet)
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    /// CHECK: owner program checked in token_transfer
    pub mint: UncheckedAccount<'info>,
    /// CHECK: id checked in check_vault_ata
    pub token_program: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct FundReserve<'info> {
    #[account(mut)]
    pub funder: Signer<'info>,
    #[account(seeds = [b"vault", vault.owner.as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: system-owned SOL-only PDA of this vault
    #[account(mut, seeds = [b"reserve", vault.key().as_ref()], bump = vault.reserve_bump)]
    pub sol_reserve: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawReserve<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(seeds = [b"vault", owner.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: system-owned SOL-only PDA of this vault
    #[account(mut, seeds = [b"reserve", vault.key().as_ref()], bump = vault.reserve_bump)]
    pub sol_reserve: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterNft<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"vault", vault.owner.as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: verified in the handler
    pub nft_mint: UncheckedAccount<'info>,
    /// CHECK: verified in the handler
    pub nft_token: UncheckedAccount<'info>,
    /// CHECK: verified in the handler
    pub nft_metadata: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct OwnerRecord<'info> {
    pub owner: Signer<'info>,
    #[account(seeds = [b"vault", owner.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut, seeds = [b"pos", record.origin.as_ref()], bump = record.bump, has_one = vault)]
    pub record: Account<'info, PositionRecord>,
}

#[derive(Accounts)]
pub struct OpenPosition<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"vault", owner.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    #[account(init, payer = owner, space = PositionRecord::SPACE, seeds = [b"pos", position.key().as_ref()], bump)]
    pub record: Account<'info, PositionRecord>,
    /// CHECK: fresh keypair, created by DLMM initialize_position2
    #[account(mut)]
    pub position: Signer<'info>,
    /// CHECK: validated by DLMM
    #[account(mut)]
    pub lb_pair: UncheckedAccount<'info>,
    /// CHECK: optional in DLMM; pass the DLMM program id for None
    pub bitmap_ext: UncheckedAccount<'info>,
    /// CHECK: check_vault_ata
    #[account(mut)]
    pub vault_x: UncheckedAccount<'info>,
    /// CHECK: check_vault_ata
    #[account(mut)]
    pub vault_y: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM against lb_pair
    #[account(mut)]
    pub reserve_x: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM against lb_pair
    #[account(mut)]
    pub reserve_y: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM against lb_pair
    pub mint_x: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM against lb_pair
    pub mint_y: UncheckedAccount<'info>,
    /// CHECK: id checked in check_vault_ata
    pub token_program_x: UncheckedAccount<'info>,
    /// CHECK: id checked in check_vault_ata
    pub token_program_y: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM
    pub event_authority: UncheckedAccount<'info>,
    /// CHECK: address constraint
    #[account(address = DLMM_ID)]
    pub dlmm_program: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// One position of one vault, with everything a DLMM claim needs and the two NFT accounts.
/// Shared by user_claim, emergency_exit, keeper_compound and keeper_close; who may sign is decided
/// by the instruction that embeds it. There is NO treasury account and NO destination in here.
#[derive(Accounts)]
pub struct Pos<'info> {
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"vault", vault.owner.as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut, seeds = [b"pos", record.origin.as_ref()], bump = record.bump, has_one = vault, has_one = position, has_one = lb_pair)]
    pub record: Account<'info, PositionRecord>,
    /// CHECK: bound by record.position
    #[account(mut)]
    pub position: UncheckedAccount<'info>,
    /// CHECK: bound by record.lb_pair
    #[account(mut)]
    pub lb_pair: UncheckedAccount<'info>,
    /// CHECK: optional in DLMM; pass the DLMM program id for None
    pub bitmap_ext: UncheckedAccount<'info>,
    /// CHECK: validate()
    #[account(mut)]
    pub vault_x: UncheckedAccount<'info>,
    /// CHECK: validate()
    #[account(mut)]
    pub vault_y: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM against lb_pair
    #[account(mut)]
    pub reserve_x: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM against lb_pair
    #[account(mut)]
    pub reserve_y: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM against lb_pair
    pub mint_x: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM against lb_pair
    pub mint_y: UncheckedAccount<'info>,
    /// CHECK: id checked in validate()
    pub token_program_x: UncheckedAccount<'info>,
    /// CHECK: id checked in validate()
    pub token_program_y: UncheckedAccount<'info>,
    /// CHECK: address constraint
    #[account(address = MEMO_ID)]
    pub memo_program: UncheckedAccount<'info>,
    /// CHECK: validated by DLMM
    pub event_authority: UncheckedAccount<'info>,
    /// CHECK: address constraint
    #[account(address = DLMM_ID)]
    pub dlmm_program: UncheckedAccount<'info>,
    /// CHECK: must be Vault.nft_token when an NFT is registered (resolve_rate); ignored otherwise
    pub nft_token: UncheckedAccount<'info>,
    /// CHECK: must be the registered mint's metadata PDA when an NFT is registered; ignored otherwise
    pub nft_metadata: UncheckedAccount<'info>,
}

impl<'info> Pos<'info> {
    fn validate(&self) -> Result<()> {
        let v = self.vault.key();
        check_vault_ata(&self.vault_x, self.mint_x.key, &v, self.token_program_x.key)?;
        check_vault_ata(&self.vault_y, self.mint_y.key, &v, self.token_program_y.key)
    }

    fn bundle(&self, remaining: &[AccountInfo<'info>], extra: &[AccountInfo<'info>]) -> (Dx<'info>, Vec<AccountInfo<'info>>) {
        let d = Dx {
            vault: self.vault.to_account_info(),
            position: self.position.to_account_info(),
            lb_pair: self.lb_pair.to_account_info(),
            bitmap_ext: self.bitmap_ext.to_account_info(),
            vault_x: self.vault_x.to_account_info(),
            vault_y: self.vault_y.to_account_info(),
            reserve_x: self.reserve_x.to_account_info(),
            reserve_y: self.reserve_y.to_account_info(),
            mint_x: self.mint_x.to_account_info(),
            mint_y: self.mint_y.to_account_info(),
            token_program_x: self.token_program_x.to_account_info(),
            token_program_y: self.token_program_y.to_account_info(),
            event_authority: self.event_authority.to_account_info(),
            dlmm_program: self.dlmm_program.to_account_info(),
        };
        let mut infos = d.infos();
        infos.push(self.memo_program.to_account_info());
        infos.extend_from_slice(extra);
        infos.extend_from_slice(remaining);
        (d, infos)
    }
}

#[derive(Accounts)]
pub struct UserClaim<'info> {
    /// Pays for an extra fees_owed slot if the vault needs one.
    #[account(mut)]
    pub owner: Signer<'info>,
    pub p: Pos<'info>,
    pub system_program: Program<'info, System>,
}

/// M2.11: add_liquidity and remove_liquidity. The owner signs; tokens move only between the pool
/// and the vault's own token accounts (no destination account exists here).
#[derive(Accounts)]
pub struct OwnerLiquidity<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    pub p: Pos<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct EmergencyExit<'info> {
    /// Receives the position rent and the record rent.
    #[account(mut)]
    pub owner: Signer<'info>,
    pub p: Pos<'info>,
    /// CHECK: check_token - SPL owner must be the vault owner
    #[account(mut)]
    pub owner_token_x: UncheckedAccount<'info>,
    /// CHECK: check_token - SPL owner must be the vault owner
    #[account(mut)]
    pub owner_token_y: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// Everything a keeper instruction needs. The keeper passes no rate, no fee and no destination.
#[derive(Accounts)]
pub struct KeeperCtx<'info> {
    /// Fee payer and sole signer; receives the repayment.
    #[account(mut)]
    pub keeper: Signer<'info>,
    pub p: Pos<'info>,
    /// CHECK: system-owned SOL-only PDA of this vault
    #[account(mut, seeds = [b"reserve", p.vault.key().as_ref()], bump = p.vault.reserve_bump)]
    pub sol_reserve: UncheckedAccount<'info>,
    /// CHECK: address-checked Instructions sysvar
    #[account(address = IX_SYSVAR_ID @ VaultError::BadInstructionsSysvar)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

impl<'info> KeeperCtx<'info> {
    fn gate(&mut self, flag: u8, kind: u8, expected_version: u64) -> Result<(TxQuote, i64)> {
        let out = keeper_gate(&self.keeper, &self.p.config, &mut self.p.vault, &mut self.p.record, &self.sol_reserve, &self.instructions, flag, kind, expected_version)?;
        self.p.validate()?;
        Ok(out)
    }

    fn repay(&mut self, kind: u8, q: &TxQuote) -> Result<()> {
        let position = self.p.position.key();
        keeper_repay(&self.keeper, &self.p.vault, &self.p.record, &self.sol_reserve, &self.system_program, position, kind, q)
    }
}

/// Everything that can refuse a keeper instruction before any token moves: who signs, top level
/// only, version, pauses, flag, transaction shape, the position's own cost caps (which can only
/// tighten the vault's), the vault's five cost limits. Returns the fee quote and the cluster time.
#[allow(clippy::too_many_arguments)]
fn keeper_gate<'info>(
    keeper: &Signer<'info>, config: &Account<'info, Config>, vault: &mut Account<'info, Vault>, record: &mut Account<'info, PositionRecord>,
    sol_reserve: &UncheckedAccount<'info>, instructions: &UncheckedAccount<'info>, flag: u8, kind: u8, expected_version: u64,
) -> Result<(TxQuote, i64)> {
    require_keys_eq!(keeper.key(), config.keeper, VaultError::NotKeeper);
    // Top level only: a wrapper program must not be able to call this N times in one transaction.
    require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, VaultError::NotTopLevel);
    // Version first among the state checks: a stale or duplicated keeper transaction always dies here.
    require!(record.version == expected_version, VaultError::StaleVersion);
    require!(record.layout == RECORD_LAYOUT, VaultError::RecordLayout);
    require!(!config.paused, VaultError::ConfigPaused);
    require!(!record.paused, VaultError::PositionPaused);
    require!(record.flags & flag != 0, VaultError::ActionNotAllowed);
    let quote = {
        let data = instructions.try_borrow_data()?;
        quote_keeper_tx(&data, keeper.key, &crate::ID)?
    };
    let pol = &record.policy;
    if pol.max_priority_fee > 0 {
        require!(quote.priority <= pol.max_priority_fee, VaultError::PriorityOverCap);
    }
    if pol.max_action_cost > 0 {
        require!(quote.base.saturating_add(quote.priority) <= pol.max_action_cost, VaultError::OverPerActionCap);
    }
    let rent_min = Rent::get()?.minimum_balance(0);
    let now = Clock::get()?.unix_timestamp;
    vault.charge(now, &quote, kind, sol_reserve.lamports(), rent_min)?;
    record.bump_version()?;
    record.st.roll_day(now);
    Ok((quote, now))
}

/// The transfer itself: vault SOL reserve -> Config.keeper, exactly base + priority.
#[allow(clippy::too_many_arguments)]
fn keeper_repay<'info>(
    keeper: &Signer<'info>, vault: &Account<'info, Vault>, record: &Account<'info, PositionRecord>, sol_reserve: &UncheckedAccount<'info>,
    system_program: &Program<'info, System>, position: Pubkey, kind: u8, q: &TxQuote,
) -> Result<()> {
    let total = q.base + q.priority;
    let vault_key = vault.key();
    let seeds: &[&[u8]] = &[b"reserve", vault_key.as_ref(), &[vault.reserve_bump]];
    system_program::transfer(
        CpiContext::new_with_signer(
            system_program.to_account_info(),
            system_program::Transfer { from: sol_reserve.to_account_info(), to: keeper.to_account_info() },
            &[seeds],
        ),
        total,
    )?;
    emit!(KeeperRepaid {
        vault: vault_key,
        position,
        kind,
        base: q.base,
        priority: q.priority,
        total,
        cu_limit: q.cu_limit,
        cu_price: q.cu_price,
        reserve_after: sol_reserve.lamports(),
        day: vault.day,
        spent_today: vault.spent_today,
        spent_total: vault.spent_total,
        version: record.version,
    });
    Ok(())
}

/// keeper_mark needs no token account: the keeper, the position's record and the two DLMM
/// accounts the record names.
#[derive(Accounts)]
pub struct KeeperMark<'info> {
    #[account(mut)]
    pub keeper: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"vault", vault.owner.as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    #[account(mut, seeds = [b"pos", record.origin.as_ref()], bump = record.bump, has_one = vault, has_one = position, has_one = lb_pair)]
    pub record: Account<'info, PositionRecord>,
    /// CHECK: bound by record.position; owner and layout checked in observe()
    pub position: UncheckedAccount<'info>,
    /// CHECK: bound by record.lb_pair; owner and layout checked in observe()
    pub lb_pair: UncheckedAccount<'info>,
    /// CHECK: system-owned SOL-only PDA of this vault
    #[account(mut, seeds = [b"reserve", vault.key().as_ref()], bump = vault.reserve_bump)]
    pub sol_reserve: UncheckedAccount<'info>,
    /// CHECK: address-checked Instructions sysvar
    #[account(address = IX_SYSVAR_ID @ VaultError::BadInstructionsSysvar)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// No signer: anyone can make the program look at the pool and drop a mark that no longer holds.
#[derive(Accounts)]
pub struct ClearMark<'info> {
    #[account(mut, seeds = [b"pos", record.origin.as_ref()], bump = record.bump, has_one = position, has_one = lb_pair)]
    pub record: Account<'info, PositionRecord>,
    /// CHECK: bound by record.position; owner and layout checked in observe()
    pub position: UncheckedAccount<'info>,
    /// CHECK: bound by record.lb_pair; owner and layout checked in observe()
    pub lb_pair: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct GrowVault<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(mut, seeds = [b"vault", owner.key().as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct KeeperRebalance<'info> {
    pub k: KeeperCtx<'info>,
    /// CHECK: created by DLMM initialize_position_pda, which derives and checks the address
    /// (seeds "position", lb_pair, base = the PositionRecord, lower bin, width)
    #[account(mut)]
    pub new_position: UncheckedAccount<'info>,
    pub rent: Sysvar<'info, Rent>,
    /// CHECK: mode_p() - this program's gate PDA of the position's pool; read only
    pub gate: UncheckedAccount<'info>,
    /// CHECK: mode_p() - Pyth receiver account of the gate's X feed; read only
    pub price_x: UncheckedAccount<'info>,
    /// CHECK: mode_p() - Pyth receiver account of the gate's Y feed; read only
    pub price_y: UncheckedAccount<'info>,
}

/// The vault owner or the Config admin signs; `payer` (may be the same wallet) pays the extra rent.
/// The record is checked by hand: an older layout cannot be read as the struct.
#[derive(Accounts)]
pub struct MigrateRecord<'info> {
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(seeds = [b"vault", vault.owner.as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: owner, discriminator, PDA address and length checked in the handler
    #[account(mut)]
    pub record: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitGuardian<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump, has_one = admin @ VaultError::NotAdmin)]
    pub config: Account<'info, Config>,
    #[account(init, payer = admin, space = GuardianSet::SPACE, seeds = [b"guardian"], bump)]
    pub guardian_set: Account<'info, GuardianSet>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetGuardian<'info> {
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump, has_one = admin @ VaultError::NotAdmin)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"guardian"], bump = guardian_set.bump)]
    pub guardian_set: Account<'info, GuardianSet>,
}

#[derive(Accounts)]
pub struct CreateGate<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump, has_one = admin @ VaultError::NotAdmin)]
    pub config: Account<'info, Config>,
    /// CHECK: owner and layout checked by parse_pair
    pub lb_pair: UncheckedAccount<'info>,
    /// CHECK: must be the pool's token X mint
    pub mint_x: UncheckedAccount<'info>,
    /// CHECK: must be the pool's token Y mint
    pub mint_y: UncheckedAccount<'info>,
    #[account(init, payer = admin, space = PoolGate::SPACE, seeds = [b"gate", lb_pair.key().as_ref()], bump)]
    pub gate: Account<'info, PoolGate>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GateAdmin<'info> {
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump, has_one = admin @ VaultError::NotAdmin)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"gate", gate.lb_pair.as_ref()], bump = gate.bump)]
    pub gate: Account<'info, PoolGate>,
}

/// disable / revoke: the admin, or the guardian named in the guardian record.
#[derive(Accounts)]
pub struct GateStop<'info> {
    pub authority: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(seeds = [b"guardian"], bump = guardian_set.bump)]
    pub guardian_set: Option<Account<'info, GuardianSet>>,
    #[account(mut, seeds = [b"gate", gate.lb_pair.as_ref()], bump = gate.bump)]
    pub gate: Account<'info, PoolGate>,
}

impl<'info> GateStop<'info> {
    fn authorise(&self) -> Result<()> {
        let who = self.authority.key();
        let guardian = self.guardian_set.as_ref().map_or(false, |g| g.guardian == who);
        require!(who == self.config.admin || guardian, VaultError::NotGateAuthority);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct KeeperCompound<'info> {
    pub k: KeeperCtx<'info>,
}

#[derive(Accounts)]
pub struct KeeperClose<'info> {
    pub k: KeeperCtx<'info>,
    /// CHECK: must be the vault owner; receives the position rent and the record rent
    #[account(mut, address = k.p.vault.owner @ VaultError::NotOwner)]
    pub owner_wallet: UncheckedAccount<'info>,
    /// CHECK: M2.9 exit_oracle() - this program's gate PDA of the position's pool (checked by address); read only
    pub gate: UncheckedAccount<'info>,
    /// CHECK: M2.9 exit_oracle() - Pyth receiver account of the gate's X feed; read only (not read for a time exit)
    pub price_x: UncheckedAccount<'info>,
    /// CHECK: M2.9 exit_oracle() - Pyth receiver account of the gate's Y feed; read only (not read for a time exit)
    pub price_y: UncheckedAccount<'info>,
}

/// Anyone can settle a vault's debt to the treasury. M2.11: the caller signs only so the event can
/// name it; it gains nothing and chooses no amount, source or destination.
#[derive(Accounts)]
pub struct CollectFees<'info> {
    pub caller: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"vault", vault.owner.as_ref()], bump = vault.bump)]
    pub vault: Account<'info, Vault>,
    /// CHECK: check_vault_ata
    #[account(mut)]
    pub vault_token: UncheckedAccount<'info>,
    /// CHECK: must be the associated token account of Config.treasury for this mint
    #[account(mut)]
    pub treasury_token: UncheckedAccount<'info>,
    /// CHECK: owner program checked in token_transfer
    pub mint: UncheckedAccount<'info>,
    /// CHECK: id checked in check_vault_ata
    pub token_program: UncheckedAccount<'info>,
}

// ====================================================================== errors

#[error_code]
#[derive(PartialEq)]
pub enum VaultError {
    NotAdmin,                 // 6000
    NotOwner,                 // 6001
    NotKeeper,                // 6002
    NotUpgradeAuthority,      // 6003
    ConfigPaused,             // 6004
    PositionPaused,           // 6005
    ActionNotAllowed,         // 6006
    StaleVersion,             // 6007
    DestinationNotOwner,      // 6008
    BadTokenAccount,          // 6009
    FeesOwedLocked,           // 6010
    WrongTreasuryAccount,     // 6011
    OwedTableFull,            // 6012
    Math,                     // 6013
    AlreadyListed,            // 6014
    AllowlistFull,            // 6015
    NotListed,                // 6016
    WrongNftTokenAccount,     // 6017
    WrongNftMetadataAccount,  // 6018
    NftMintInvalid,           // 6019
    TokenWrongProgram,        // 6020
    TokenInvalid,             // 6021
    TokenMintMismatch,        // 6022
    TokenOwnerMismatch,       // 6023
    TokenAmountNotOne,        // 6024
    MetadataWrongOwner,       // 6025
    MetadataInvalid,          // 6026
    NoCollection,             // 6027
    CollectionNotVerified,    // 6028
    CollectionNotAllowlisted, // 6029
    NotTopLevel,              // 6030
    KeeperNotSoleSigner,      // 6031
    KeeperTxShape,            // 6032
    MissingCuLimit,           // 6033
    BadInstructionsSysvar,    // 6034
    PriorityOverCap,          // 6035
    OverPerActionCap,         // 6036
    OverDailyCap,             // 6037
    OverBudget,               // 6038
    BelowExitFloor,           // 6039
    ReserveEmpty,             // 6040
    // ---- M2
    BadPolicy,                // 6041
    WrongPairAccount,         // 6042
    WrongPositionAccount,     // 6043
    ThresholdNotSet,          // 6044
    BelowMinClaim,            // 6045
    CostRatioExceeded,        // 6046
    CostRatioNeedsSolLeg,     // 6047
    CompoundCooldown,         // 6048
    OverDailyCompounds,       // 6049
    SlippageExceeded,         // 6050
    NotOutOfRange,            // 6051
    MarkUnchanged,            // 6052
    OverDailyMarks,           // 6053
    NoMark,                   // 6054
    MarkTooYoung,             // 6055
    MarkExpired,              // 6056
    BackInRange,              // 6057
    MarkSideChanged,          // 6058
    RebalanceCooldown,        // 6059
    OverDailyRebalances,      // 6060
    WidthOutOfPolicy,         // 6061
    RangeOutOfBounds,         // 6062
    DirectionNotAllowed,      // 6063
    WrongDirection,           // 6064
    RangeNotAtActive,         // 6065
    MissingBinArrays,         // 6066
    RentLeak,                 // 6067
    IdleFundsUsed,            // 6068
    ExitRuleNotMet,           // 6069
    // ---- M2.1
    RangeTraded,              // 6070
    EdgeBinEmpty,             // 6071
    WrongBinArray,            // 6072
    RentBudgetExceeded,       // 6073
    TransferFeeTokenUnsupported, // 6074
    CostRatioNotSet,          // 6075
    // ---- M2.2
    ShiftNotSet,              // 6076
    ShiftExceeded,            // 6077
    DailyShiftExceeded,       // 6078
    ActiveBinEmpty,           // 6079
    // ---- M2.3
    MoveExceeded,             // 6080
    DailyMoveExceeded,        // 6081
    ShiftRingFull,            // 6082
    RecordNotMigratable,      // 6083
    RecordLayout,             // 6084
    BadGate,                  // 6085
    NotGateAuthority,         // 6086
    GateMissing,              // 6087
    GateWrongPool,            // 6088
    GateDisabled,             // 6089
    GateRevoked,              // 6090
    GateExpired,              // 6091
    OracleLimitNotSet,        // 6092
    OracleWrongOwner,         // 6093
    OracleBadAccount,         // 6094
    OracleNotFull,            // 6095
    OracleWrongFeed,          // 6096
    OraclePriceInvalid,       // 6097
    OracleStale,              // 6098
    OracleFromFuture,         // 6099
    OracleFeedGap,            // 6100
    OracleConfidence,         // 6101
    OracleEmaDeviation,       // 6102
    OracleMath,               // 6103
    OracleDeviation,          // 6104
    MarkNeedsOracle,          // 6105
    MarkNotOracle,            // 6106
    OutcomePrice,             // 6107
    OutcomeLoss,              // 6108
    NotMigrationAuthority,    // 6109
    MigrationRentExceeded,    // 6110
    // ---- M2.5
    GateWidthNotSet,          // 6111
    WidthBelowGate,           // 6112
    PlacedNotSet,             // 6113
    PlacedTooLittle,          // 6114
    // ---- M2.7
    RangeIncludesActive,      // 6115
    PlacementVsReference,     // 6116
    PlacementTooFar,          // 6117
    // ---- M2.8
    ExitMarginConflict,       // 6118
    // ---- M2.9
    ExitOracleNotOut,         // 6119 keeper exit: the verified price band is not wholly out of the range (recovered or unsure)
    ExitNeedsGate,            // 6120 keeper exit: the pool has no open gate (no keeper exits without an independent price)
    // --- M2.11
    BadBps,                   // 6121 remove_liquidity: bps must be 1..=9,999 (a full exit closes the position)
    ActiveBinMoved,           // 6122 the pool's active bin left the owner's signed window
    WrongPositionBinArrays,   // 6123 the remaining accounts are not exactly the bin arrays of the position's range
    PositionWouldBeEmpty,     // 6124 a partial remove would leave an open position with no liquidity
    FeesLeftWithPrincipal,    // 6125 a remove returned more than the position's principal (fees may only leave by claim)
    NothingToCollect,         // 6126 collect_fees: nothing is owed for this mint
    TreasuryNotDue,           // 6127 execute_treasury before the delay has passed
    NoPendingTreasury,        // 6128 no treasury change is proposed
    NotPendingAdmin,          // 6129 accept_admin not signed by the proposed admin
    NeedsMigration,           // 6130 reserved (layout migration; unused while the program has no older accounts)
}

// ====================================================================== native unit tests
// `cargo test -p bh_vault` on the host. Pure functions only: the fee quote, the day bucket and the
// five cost limits. The on-chain behaviour is tested in tests/ against a validator.

#[cfg(test)]
mod tests {
    /// exact floor(a * sh / su) for su < 2^127 (test only: 192-bit long division)
    fn exact_floor(a: u64, sh: u128, su: u128) -> u128 {
        let (hi, lo64) = (sh >> 64, sh & u64::MAX as u128);
        let prod_hi = a as u128 * hi;
        let prod_lo = a as u128 * lo64;
        let low = prod_lo & u64::MAX as u128;
        let carry_mid = (prod_lo >> 64) + (prod_hi & u64::MAX as u128);
        let mid = carry_mid & u64::MAX as u128;
        let top = (prod_hi >> 64) + (carry_mid >> 64);
        let (mut rem, mut q) = (0u128, 0u128);
        for word in [top, mid, low] {
            for bit in (0..64).rev() {
                rem = (rem << 1) | ((word >> bit) & 1);
                q <<= 1;
                if rem >= su {
                    rem -= su;
                    q |= 1;
                }
            }
        }
        q
    }

    /// M2.11 fee-rounding boundaries (owner item 6): zero, dust, the 64-bit cut edges, share = supply - 1,
    /// and a deterministic fuzz of 20,000 cases. pro_rata_up is never below the exact floor DLMM pays and never
    /// more than 5 units above it (under 2 for amounts below 2^62); pro_rata (the keeper's) is never above it.
    #[test]
    fn pro_rata_up_boundaries_and_fuzz() {
        let check = |a: u64, sh: u128, su: u128| {
            let ex = exact_floor(a, sh.min(su), su);
            let up = crate::pro_rata_up(a, sh, su) as u128;
            let lo = crate::pro_rata(a, sh, su) as u128;
            assert!(up >= ex && up <= ex + 5 && up <= a as u128, "up({a},{sh},{su}) = {up}, exact {ex}");
            assert!(lo <= ex, "lo({a},{sh},{su}) = {lo}, exact {ex}");
        };
        // zero and dust
        assert_eq!(crate::pro_rata_up(0, 5, 9), 0);
        assert_eq!(crate::pro_rata_up(9, 0, 9), 0);
        assert_eq!(crate::pro_rata_up(9, 5, 0), 0);
        assert_eq!(crate::pro_rata_up(1, 1, 2), 1); // exact 0.5 -> 1 (an upper bound may round up)
        assert_eq!(crate::pro_rata_up(1, 2, 2), 1);
        assert_eq!(crate::pro_rata_up(1, 3, 2), 1); // share > supply cannot happen in DLMM; capped at the bin amount
        assert_eq!(crate::pro_rata_up(10, 1, 10), 1);
        for (a, sh, su) in [(1u64, 1u128, 3u128), (2, 1, 3), (70, 1, 70), (69, 1, 70)] {
            check(a, sh, su);
        }
        // the 64-bit cut: supply just below, at and just above 2^64, and near 2^126
        let p64 = 1u128 << 64;
        for su in [p64 - 1, p64, p64 + 1, (p64 << 1) - 1, 1u128 << 100, (1u128 << 126) - 1, 1u128 << 126] {
            for sh in [1u128, 2, su / 3, su / 2, su - 1, su] {
                for a in [1u64, 2, 7, 1_000_000, 551_749_081, u64::MAX / 2, u64::MAX] {
                    check(a, sh, su);
                }
            }
        }
        // deterministic fuzz
        let mut x: u128 = 0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C834;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let su = (next() >> (next() % 120) as u32).max(1) & ((1u128 << 126) - 1);
            let su = su.max(1);
            let sh = next() % (su + 1);
            let a = (next() >> (next() % 64) as u32) as u64;
            check(a, sh, su);
        }
    }

    /// M211-F1: the bps-scaled bound rounds up and never overflows for any held total of a 70-bin position
    #[test]
    fn share_bound_up_boundaries() {
        assert_eq!(crate::share_bound_up(0, 9_999).unwrap(), 0);
        assert_eq!(crate::share_bound_up(1, 1).unwrap(), 1);
        assert_eq!(crate::share_bound_up(10_000, 1).unwrap(), 1);
        assert_eq!(crate::share_bound_up(10_001, 1).unwrap(), 2);
        assert_eq!(crate::share_bound_up(300_000_000, 5_000).unwrap(), 150_000_000);
        assert_eq!(crate::share_bound_up(300_000_001, 5_000).unwrap(), 150_000_001);
        let big = u64::MAX as u128 * 70;
        assert!(crate::share_bound_up(big, 9_999).unwrap() <= big);
        assert_eq!(crate::share_bound_up(big, 10_000).unwrap(), big);
    }

    /// fee_of boundaries at both rates: zero, the largest claim that books nothing, the first that books one unit, u64::MAX
    #[test]
    fn fee_of_boundaries() {
        assert_eq!(crate::fee_of(0, 750), 0);
        assert_eq!(crate::fee_of(13, 750), 0);
        assert_eq!(crate::fee_of(14, 750), 1);
        assert_eq!(crate::fee_of(19, 500), 0);
        assert_eq!(crate::fee_of(20, 500), 1);
        assert_eq!(crate::fee_of(7_029, 750), 527);
        assert_eq!(crate::fee_of(7_027, 500), 351);
        assert_eq!(crate::fee_of(u64::MAX, 750), ((u64::MAX as u128 * 750) / 10_000) as u64);
        assert_eq!(crate::fee_of(u64::MAX, 10_000), u64::MAX);
    }

    #[test]
    fn pro_rata_up_never_understates() {
        // exact floor computed in u128 where it fits, against the 64-bit cut used for large DLMM liquidity values
        let cases: [(u64, u128, u128); 7] = [
            (1_000, 1, 3),
            (551_749_081, 123_456_789_012_345_678_901_234_567, 998_877_665_544_332_211_009_988_776_655),
            (u64::MAX, 1u128 << 100, (1u128 << 101) + 7),
            (7, 5, 9),
            (1_000_000_000, (1u128 << 90) / 3, 1u128 << 90),
            (999, 0, 5),
            (999, 5, 5),
        ];
        for (a, sh, su) in cases {
            let up = crate::pro_rata_up(a, sh, su) as u128;
            let lo = crate::pro_rata(a, sh, su) as u128;
            // exact floor via 256-bit long multiplication split: a * sh = a * (hi * 2^64 + lo)
            let exact = {
                let (hi, lo64) = (sh >> 64, sh & u64::MAX as u128);
                // floor((a*hi*2^64 + a*lo64) / su), computed bit by bit (test only)
                let mut rem: u128 = 0;
                let mut q: u128 = 0;
                let prod_hi = a as u128 * hi; // < 2^128
                let prod_lo = a as u128 * lo64; // < 2^128
                // value = prod_hi * 2^64 + prod_lo, as 192-bit: [top 64 | mid 64 | low 64]
                let low = prod_lo & u64::MAX as u128;
                let carry_mid = (prod_lo >> 64) + (prod_hi & u64::MAX as u128);
                let mid = carry_mid & u64::MAX as u128;
                let top = (prod_hi >> 64) + (carry_mid >> 64);
                for word in [top, mid, low] {
                    for bit in (0..64).rev() {
                        rem = (rem << 1) | ((word >> bit) & 1);
                        q <<= 1;
                        if rem >= su {
                            rem -= su;
                            q |= 1;
                        }
                    }
                }
                q
            };
            assert!(up >= exact, "pro_rata_up({a},{sh},{su}) = {up} < exact {exact}");
            assert!(up <= exact + 3, "pro_rata_up({a},{sh},{su}) = {up} overstates exact {exact} by more than 3");
            assert!(lo <= exact, "pro_rata understates as designed");
            assert!(up <= a as u128);
        }
    }

    use super::*;

    const D: i64 = SECONDS_PER_DAY;

    fn q(base: u64, priority: u64) -> TxQuote {
        TxQuote { base, priority, cu_limit: 0, cu_price: 0 }
    }

    fn limits() -> Vault {
        Vault { per_action_cap: 20_000, priority_fee_cap: 10_000, daily_cap: 30_000, budget_total: 70_000, exit_floor: 50_000, ..Default::default() }
    }

    #[test]
    fn day_bucket_boundaries() {
        assert_eq!(day_bucket(0), 0);
        assert_eq!(day_bucket(D - 1), 0);
        assert_eq!(day_bucket(D), 1);
        assert_eq!(day_bucket(1_791_763_199), 20_737); // 2026-10-11 23:59:59 UTC
        assert_eq!(day_bucket(1_791_763_200), 20_738); // 2026-10-12 00:00:00 UTC
        assert_eq!(day_bucket(-1), -1);
    }

    #[test]
    fn daily_counter_resets_at_utc_midnight_but_budget_does_not() {
        let mut v = limits();
        let rent = 890_880;
        let big = 10_000_000;
        let t = 20_000 * D + D - 5; // five seconds before midnight
        assert_eq!(v.charge(t, &q(5_000, 10_000), KIND_COMPOUND, big, rent).unwrap(), big - 15_000);
        assert_eq!(v.charge(t + 1, &q(5_000, 10_000), KIND_COMPOUND, big, rent).unwrap(), big - 15_000);
        assert_eq!((v.spent_today, v.spent_total, v.day), (30_000, 30_000, 20_000));
        // same day: the daily cap is full
        assert_eq!(v.charge(t + 2, &q(5_000, 0), KIND_COMPOUND, big, rent).unwrap_err(), VaultError::OverDailyCap.into());
        assert_eq!((v.spent_today, v.spent_total), (30_000, 30_000));
        // five seconds later it is a new UTC day: the daily counter starts again
        v.charge(t + 5, &q(5_000, 10_000), KIND_COMPOUND, big, rent).unwrap();
        assert_eq!((v.spent_today, v.spent_total, v.day), (15_000, 45_000, 20_001));
        v.charge(t + 6, &q(5_000, 10_000), KIND_COMPOUND, big, rent).unwrap();
        assert_eq!((v.spent_today, v.spent_total), (30_000, 60_000));
        // next day: daily is fresh, but budget_total (70_000) is lifetime and does NOT reset
        assert_eq!(v.charge(t + 5 + D, &q(5_000, 10_000), KIND_COMPOUND, big, rent).unwrap_err(), VaultError::OverBudget.into());
        v.charge(t + 5 + D, &q(5_000, 5_000), KIND_COMPOUND, big, rent).unwrap();
        assert_eq!((v.spent_today, v.spent_total, v.day), (10_000, 70_000, 20_002));
        assert_eq!(v.charge(t + 5 + 9 * D, &q(5_000, 0), KIND_EXIT, big, rent).unwrap_err(), VaultError::OverBudget.into());
    }

    #[test]
    fn caps_and_exit_floor() {
        let rent = 890_880;
        let mut v = limits();
        assert_eq!(v.charge(0, &q(5_000, 10_001), KIND_COMPOUND, 10_000_000, rent).unwrap_err(), VaultError::PriorityOverCap.into());
        v.priority_fee_cap = 1_000_000;
        assert_eq!(v.charge(0, &q(5_000, 15_001), KIND_COMPOUND, 10_000_000, rent).unwrap_err(), VaultError::OverPerActionCap.into());
        // reserve = rent + floor + 4_999 after paying 5_000 would be below the floor
        let reserve = rent + 50_000 + 4_999;
        assert_eq!(v.charge(0, &q(5_000, 0), KIND_COMPOUND, reserve, rent).unwrap_err(), VaultError::BelowExitFloor.into());
        assert_eq!(v.charge(0, &q(5_000, 0), KIND_EXIT, reserve, rent).unwrap(), reserve - 5_000);
        // never below rent-exemption, even for an exit
        assert_eq!(v.charge(0, &q(5_000, 0), KIND_EXIT, rent + 4_999, rent).unwrap_err(), VaultError::ReserveEmpty.into());
        assert_eq!(v.charge(0, &q(5_000, 0), KIND_EXIT, 4_999, rent).unwrap_err(), VaultError::ReserveEmpty.into());
        assert_eq!(v.spent_total, 5_000);
    }

    /// Serialises instructions the way the Instructions sysvar does.
    fn sysvar(ixs: &[(Pubkey, Vec<(Pubkey, bool)>, Vec<u8>)], current: u16) -> Vec<u8> {
        let mut out = (ixs.len() as u16).to_le_bytes().to_vec();
        out.extend(std::iter::repeat(0u8).take(2 * ixs.len()));
        for (i, (pid, accs, data)) in ixs.iter().enumerate() {
            let start = out.len() as u16;
            out[2 + 2 * i..4 + 2 * i].copy_from_slice(&start.to_le_bytes());
            out.extend((accs.len() as u16).to_le_bytes());
            for (k, signer) in accs {
                out.push(if *signer { 1 } else { 0 } | 2);
                out.extend(k.to_bytes());
            }
            out.extend(pid.to_bytes());
            out.extend((data.len() as u16).to_le_bytes());
            out.extend(data);
        }
        out.extend(current.to_le_bytes());
        out
    }
    fn cu_limit(n: u32) -> (Pubkey, Vec<(Pubkey, bool)>, Vec<u8>) {
        let mut d = vec![2u8];
        d.extend(n.to_le_bytes());
        (COMPUTE_BUDGET_ID, vec![], d)
    }
    fn cu_price(n: u64) -> (Pubkey, Vec<(Pubkey, bool)>, Vec<u8>) {
        let mut d = vec![3u8];
        d.extend(n.to_le_bytes());
        (COMPUTE_BUDGET_ID, vec![], d)
    }

    #[test]
    fn quote_matches_cluster_formula_and_shape_rules() {
        let keeper = Pubkey::new_unique();
        let other = Pubkey::new_unique();
        let own = |signer: Pubkey| (crate::ID, vec![(signer, true), (Pubkey::new_unique(), false)], vec![1, 2, 3]);

        let d = sysvar(&[cu_limit(300_000), cu_price(12_345), own(keeper)], 2);
        let got = quote_keeper_tx(&d, &keeper, &crate::ID).unwrap();
        assert_eq!(got, TxQuote { base: 5_000, priority: 3_704, cu_limit: 300_000, cu_price: 12_345 }); // ceil(3_703.5)

        // 1 micro-lamport on 1 CU still costs 1 lamport (ceil); limit above 1.4M is clamped
        let d = sysvar(&[cu_limit(1), cu_price(1), own(keeper)], 2);
        assert_eq!(quote_keeper_tx(&d, &keeper, &crate::ID).unwrap().priority, 1);
        let d = sysvar(&[cu_limit(2_000_000), cu_price(1_000_000), own(keeper)], 2);
        assert_eq!(quote_keeper_tx(&d, &keeper, &crate::ID).unwrap().priority, 1_400_000);

        let d = sysvar(&[cu_price(5), own(keeper)], 1);
        assert_eq!(quote_keeper_tx(&d, &keeper, &crate::ID).unwrap_err(), VaultError::MissingCuLimit.into());
        let d = sysvar(&[cu_limit(1), own(keeper), own(keeper)], 1);
        assert_eq!(quote_keeper_tx(&d, &keeper, &crate::ID).unwrap_err(), VaultError::KeeperTxShape.into());
        let d = sysvar(&[cu_limit(1), own(keeper), (MEMO_ID, vec![], vec![])], 1);
        assert_eq!(quote_keeper_tx(&d, &keeper, &crate::ID).unwrap_err(), VaultError::KeeperTxShape.into());
        let d = sysvar(&[cu_limit(1), own(other)], 1);
        assert_eq!(quote_keeper_tx(&d, &keeper, &crate::ID).unwrap_err(), VaultError::KeeperNotSoleSigner.into());
        let d = sysvar(&[cu_limit(1), (crate::ID, vec![(keeper, true), (other, true)], vec![])], 1);
        assert_eq!(quote_keeper_tx(&d, &keeper, &crate::ID).unwrap_err(), VaultError::KeeperNotSoleSigner.into());
    }

    #[test]
    fn position_day_counters_roll_at_utc_midnight() {
        let mut st = AutoState { day: 20_000, compounds_today: 3, rebalances_today: 2, marks_today: 5, last_compound: 7, last_rebalance: 8, mark_time: 9, mark_active_id: 4, mark_side: 1, mark_fp: [7u8; 32], rent_spent: 11, ..Default::default() };
        st.roll_day(20_000 * D + D - 1); // 23:59:59 the same day
        assert_eq!((st.compounds_today, st.rebalances_today, st.marks_today), (3, 2, 5));
        st.roll_day(20_001 * D); // 00:00:00
        assert_eq!((st.day, st.compounds_today, st.rebalances_today, st.marks_today), (20_001, 0, 0, 0));
        // cooldown clocks and the mark are NOT reset by the day change
        assert_eq!((st.last_compound, st.last_rebalance, st.mark_time, st.mark_side), (7, 8, 9, 1));
    }

    #[test]
    fn exit_rules_and_mark_window() {
        let pol = Policy { exit_on_oor: true, exit_wait: 600, mark_ttl: 300, oor_wait: 100, ..Default::default() };
        let st = AutoState { mark_time: 1_000, mark_side: 1, ..Default::default() };
        assert!(!exit_rule_met(&pol, &st, 1_599, 1)); // too young
        assert!(exit_rule_met(&pol, &st, 1_600, 1));
        assert!(exit_rule_met(&pol, &st, 1_900, 1));
        assert!(!exit_rule_met(&pol, &st, 1_901, 1)); // mark expired
        assert!(!exit_rule_met(&pol, &st, 1_700, 0)); // price is back in range now
        assert!(!exit_rule_met(&pol, &st, 1_700, -1)); // other side than the mark
        assert!(!exit_rule_met(&pol, &AutoState::default(), 1_700, 1)); // no mark
        assert!(!exit_rule_met(&Policy { exit_on_oor: false, ..pol }, &st, 1_700, 1)); // rule not signed
        assert!(!exit_rule_met(&Policy::default(), &st, i64::MAX, 1)); // nothing signed: never
        // M2.5: the wait counts from the first mark of the run. A plain mark of 1_000 made into an
        // oracle-checked one at 1_590 (mark_time moves, oor_since does not): the exit is due at
        // 1_600 as before, not at 2_190, and the newer mark keeps it usable until 2_490.
        let conv = AutoState { mark_time: 1_590, mark_side: 1, mark_oracle: 1, oor_since: 1_000, oor_side: 1, ..Default::default() };
        assert!(!exit_rule_met(&pol, &conv, 1_599, 1));
        assert!(exit_rule_met(&pol, &conv, 1_600, 1));
        assert!(exit_rule_met(&pol, &conv, 2_490, 1));
        assert!(!exit_rule_met(&pol, &conv, 2_491, 1));
        assert!(!exit_rule_met(&pol, &conv, 1_700, 0));
        assert!(!exit_rule_met(&pol, &conv, 1_700, -1));
        // oor_since can never make the exit due before the mark itself exists, and a value later
        // than the mark is not believed
        let odd = AutoState { mark_time: 1_000, mark_side: 1, oor_since: 5_000, oor_side: 1, ..Default::default() };
        assert!(!exit_rule_met(&pol, &odd, 1_599, 1));
        assert!(exit_rule_met(&pol, &odd, 1_600, 1));
        // M2.8: a run on the other side, or no run side (a record from before M2.8), does not count
        assert!(!exit_rule_met(&pol, &AutoState { oor_side: -1, ..conv }, 1_600, 1));
        assert!(!exit_rule_met(&pol, &AutoState { oor_side: 0, ..conv }, 1_600, 1));
        assert!(exit_rule_met(&pol, &AutoState { oor_side: 0, ..conv }, 2_190, 1));
        // clear_mark drops both; drop_mark only the mark
        let mut c = AutoState { back_since: 7, oor_seen: 1_590, ..conv };
        c.drop_mark();
        assert_eq!((c.mark_time, c.mark_side, c.mark_oracle, c.oor_since, c.oor_side, c.oor_seen), (0, 0, 0, 1_000, 1, 1_590));
        c.clear_mark();
        assert_eq!((c.mark_time, c.oor_since, c.mark_oracle, c.oor_side, c.back_since, c.oor_seen), (0, 0, 0, 0, 0, 0));
        let timed = Policy { exit_after: 5_000, ..Default::default() };
        assert!(!exit_rule_met(&timed, &AutoState::default(), 4_999, 0));
        assert!(exit_rule_met(&timed, &AutoState::default(), 5_000, 0));
        // a mark stays "live" until the last enabled action can no longer use it
        assert_eq!(mark_last_use(&pol, FLAG_REBALANCE, 1_000), 1_400);
        assert_eq!(mark_last_use(&pol, FLAG_CLOSE, 1_000), 1_900);
        assert_eq!(mark_last_use(&pol, FLAG_REBALANCE | FLAG_CLOSE, 1_000), 1_900);
        assert_eq!(mark_last_use(&Policy { exit_on_oor: false, ..pol }, FLAG_CLOSE, 1_000), 1_300);
    }

    /// M2.8: the exit run through marks, retries, trades, returns and gaps.
    #[test]
    fn exit_run_survives_noise_and_ends_on_confirmed_recovery() {
        let pol = Policy { exit_on_oor: true, exit_wait: 600, mark_ttl: 300, oor_wait: 100, ..Default::default() };
        let f = FLAG_CLOSE;
        let mut st = AutoState::default();
        run_on_mark(&mut st, &pol, f, 1, 1_000);
        assert_eq!((st.oor_since, st.oor_side, st.oor_seen), (1_000, 1, 1_000));
        // a later mark (a dust trade changed the fingerprint, a retry, a conversion): the run goes on
        run_on_mark(&mut st, &pol, f, 1, 1_400);
        assert_eq!((st.oor_since, st.oor_seen), (1_000, 1_400));
        // an unconfirmed return (no gate account, or an open gate without prices) changes nothing
        let keep = st;
        assert!(!run_on_return(&mut st, 1_450, Evidence::None));
        assert_eq!(st, keep);
        // the verified price says still out: an observation of the run
        assert!(!run_on_return(&mut st, 1_500, Evidence::Oracle(false)));
        assert_eq!((st.oor_since, st.oor_seen), (1_000, 1_500));
        // non-oracle pool: first return pending, an out-of-range mark cancels it, the run goes on
        assert!(!run_on_return(&mut st, 1_600, Evidence::NoOpenGate));
        assert_eq!(st.back_since, 1_600);
        assert!(!run_on_return(&mut st, 1_899, Evidence::NoOpenGate));
        run_on_mark(&mut st, &pol, f, 1, 1_700);
        assert_eq!((st.oor_since, st.back_since), (1_000, 0));
        // two returns RECOVERY_CONFIRM_S apart end it
        assert!(!run_on_return(&mut st, 1_800, Evidence::NoOpenGate));
        assert!(!run_on_return(&mut st, 1_800 + RECOVERY_CONFIRM_S - 1, Evidence::NoOpenGate));
        assert!(run_on_return(&mut st, 1_800 + RECOVERY_CONFIRM_S, Evidence::NoOpenGate));
        assert_eq!((st.oor_since, st.oor_side, st.back_since, st.oor_seen), (0, 0, 0, 0));
        // a confirmed oracle recovery ends it at once
        run_on_mark(&mut st, &pol, f, -1, 5_000);
        assert!(run_on_return(&mut st, 5_001, Evidence::Oracle(true)));
        assert_eq!(st.oor_since, 0);
        // the other side starts a new run
        run_on_mark(&mut st, &pol, f, 1, 6_000);
        run_on_mark(&mut st, &pol, f, -1, 6_100);
        assert_eq!((st.oor_since, st.oor_side), (6_100, -1));
        // a gap longer than a mark's life starts a new run: mark_last_use(6_100) = 6_100 + 600 + 300
        run_on_mark(&mut st, &pol, f, -1, 7_000);
        assert_eq!(st.oor_since, 6_100);
        run_on_mark(&mut st, &pol, f, -1, 7_901);
        assert_eq!(st.oor_since, 7_901);
        // no run: a return does nothing
        let mut none = AutoState::default();
        assert!(!run_on_return(&mut none, 1, Evidence::Oracle(true)));
        assert_eq!(none, AutoState::default());
        // without an exit rule signed, a return ends the run with the mark (nothing to protect)
        let mut r = AutoState { mark_time: 9, mark_side: 1, oor_since: 9, oor_side: 1, oor_seen: 9, ..Default::default() };
        on_return(&mut r, &Policy { exit_on_oor: false, ..pol }, 10, Evidence::None);
        assert_eq!(r, AutoState::default());
        let mut r = AutoState { mark_time: 9, mark_side: 1, oor_since: 9, oor_side: 1, oor_seen: 9, ..Default::default() };
        on_return(&mut r, &pol, 10, Evidence::None);
        assert_eq!((r.mark_time, r.oor_since, r.oor_seen), (0, 9, 9));
        // a record without a run side (written before M2.8) never continues a run
        let mut old = AutoState { oor_since: 1_000, oor_side: 0, oor_seen: 0, ..Default::default() };
        run_on_mark(&mut old, &pol, f, 1, 1_100);
        assert_eq!(old.oor_since, 1_100);
    }

    #[test]
    fn fee_is_floored() {
        assert_eq!(fee_of(1_999, 500), 99);
        assert_eq!(fee_of(13, 750), 0);
        assert_eq!(fee_of(u64::MAX, 750), ((u64::MAX as u128) * 750 / 10_000) as u64);
    }
}

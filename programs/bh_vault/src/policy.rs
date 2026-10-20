//! M2 "bounded automation": the owner-signed policy of one position, the automation state the
//! program keeps for it, and every pure rule that decides whether a keeper action may run.
//!
//! Nothing in here trusts a value supplied by the keeper. Prices, the active bin and the position's
//! range are read from Meteora DLMM accounts (`lb_pair`, `position`) whose owner is the DLMM program
//! and whose addresses are bound to the PositionRecord.

use crate::VaultError;
use anchor_lang::prelude::*;

pub const WSOL_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");

pub const DIR_UP: u8 = 1;
pub const DIR_DOWN: u8 = 2;
/// A DLMM position holds at most 70 bins.
pub const MAX_WIDTH: u16 = 70;

/// Owner's suggested defaults (documentation / clients). On chain a new position starts with an
/// all-zero policy, under which no keeper action can run.
pub const DEFAULT_MAX_REBALANCES_PER_DAY: u16 = 3;
pub const DEFAULT_OOR_MARGIN_BINS: u16 = 2;
pub const DEFAULT_OOR_WAIT_SECS: u32 = 600;
pub const DEFAULT_MAX_COST_BPS: u16 = 500;

const LB_PAIR_DISC: [u8; 8] = [33, 11, 49, 98, 181, 101, 177, 13];
const POSITION_V2_DISC: [u8; 8] = [117, 176, 212, 199, 245, 180, 133, 182];

/// Set only by `set_policy` (owner signs). Every field is a limit the keeper cannot change.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, PartialEq, Debug)]
pub struct Policy {
    // ---- compounding
    /// Minimum claimed swap fees, in token base units. Both zero = compounding cannot run.
    /// Rule (`min_claim_met`): claimed_x / min_claim_x + claimed_y / min_claim_y >= 1; a zero
    /// minimum means that token does not count.
    pub min_claim_x: u64,
    pub min_claim_y: u64,
    /// Max network cost of the compound as bps of the claimed fees, valued in lamports. Enforced
    /// only when one pool token is wrapped SOL; for any other pool it must be 0 (off-chain only).
    pub max_cost_bps: u16,
    /// Minimum seconds between two compounds.
    pub compound_cooldown: u32,
    pub max_compounds_per_day: u16,
    // ---- rebalancing
    /// Lowest / highest bin the position may ever occupy after a keeper rebalance.
    pub min_bin: i32,
    pub max_bin: i32,
    /// DIR_UP | DIR_DOWN: which way the range may follow the price.
    pub direction: u8,
    pub min_width: u16,
    pub max_width: u16,
    /// The new range must start (price fell) or end (price rose) at the active bin, at most this
    /// many bins beyond it.
    pub edge_slack: u16,
    /// Max bins the pool's active bin may have moved inside the pool's own volatility filter
    /// window (lb_pair.v_parameters) when a keeper action runs.
    pub max_slippage_bins: u16,
    pub rebalance_cooldown: u32,
    pub max_rebalances_per_day: u16,
    /// Out of range = active bin at least this many bins outside the range.
    pub oor_margin_bins: u16,
    /// Seconds a mark must have aged before a rebalance.
    pub oor_wait: u32,
    /// Seconds after the wait during which the mark can still be used.
    pub mark_ttl: u32,
    pub max_marks_per_day: u16,
    /// DLMM StrategyType index for every keeper deposit.
    pub strategy: u8,
    // ---- cost (lamports). 0 = the vault's own limit applies. These can only tighten it.
    pub max_action_cost: u64,
    pub max_priority_fee: u64,
    // ---- exit rules for keeper_close (needs FLAG_CLOSE too)
    /// Close when the out-of-range mark is at least `exit_wait` seconds old.
    pub exit_on_oor: bool,
    pub exit_wait: u32,
    /// Close at or after this unix time. 0 = off.
    pub exit_after: i64,
    // ---- M2.1
    /// Lamports of the vault's SOL reserve the program may spend, over the whole life of the position,
    /// on creating DLMM bin arrays that a keeper rebalance needs and that do not exist yet. That rent
    /// is never returned by DLMM. 0 = never create one (the rebalance fails instead).
    pub rent_budget: u64,
    // ---- M2.2
    /// Most bins either edge of the range may move in ONE keeper rebalance. 0 = keeper rebalancing
    /// cannot run.
    pub max_shift_bins: u16,
    /// M2.3: most bins, added up over every keeper rebalance of the last 86,400 seconds (a ROLLING
    /// window, no reset at midnight). Moves in opposite directions add up. 0 = keeper rebalancing
    /// cannot run.
    pub max_shift_day: u16,
    // ---- M2.3
    /// Most price movement of the range in ONE keeper rebalance, in bps: (1 + bin_step)^bins - 1,
    /// rounded up. 0 = keeper rebalancing cannot run.
    pub max_move_bps: u16,
    /// The same over the rolling 24 hours, computed on the bins added up. 0 = cannot run.
    pub max_move_bps_day: u32,
    /// Most the pool's price may differ from the external price band, in bps. The pool gate's own
    /// limit applies when it is stricter. 0 = no oracle-checked mark and no keeper rebalance.
    pub max_dev_bps: u16,
    /// Most value (at the external price) a keeper rebalance may lose, in bps of what came out of
    /// the old position. 0 = nothing beyond rounding dust.
    pub max_loss_bps: u16,
    // ---- M2.5
    /// Least share (bps, at the external price) of what came out of the old position, net of the
    /// performance fee, that the new position must really hold after a keeper rebalance. The pool
    /// gate's own minimum applies when it is higher: an owner can ask for more, never for less.
    /// 0 = the gate's minimum alone.
    pub min_placed_bps: u16,
}

impl Policy {
    pub const SIZE: usize = 8 + 8 + 2 + 4 + 2 + 4 + 4 + 1 + 2 + 2 + 2 + 2 + 4 + 2 + 2 + 4 + 4 + 2 + 1 + 8 + 8 + 1 + 4 + 8 + 8 + 2 + 2 + 2 + 4 + 2 + 2 + 2;

    pub fn validate(&self) -> Result<()> {
        require!(self.min_bin <= self.max_bin, VaultError::BadPolicy);
        require!(self.min_width >= 1 && self.min_width <= self.max_width && self.max_width <= MAX_WIDTH, VaultError::BadPolicy);
        require!(self.direction <= (DIR_UP | DIR_DOWN), VaultError::BadPolicy);
        require!(self.max_cost_bps <= 10_000, VaultError::BadPolicy);
        require!(self.strategy <= 8, VaultError::BadPolicy);
        require!(self.exit_after >= 0, VaultError::BadPolicy);
        require!(self.max_shift_day >= self.max_shift_bins, VaultError::BadPolicy);
        require!(self.max_move_bps_day >= self.max_move_bps as u32, VaultError::BadPolicy);
        require!(self.max_dev_bps <= crate::oracle::MAX_DEV_BPS_CAP && self.max_loss_bps <= 10_000 && self.min_placed_bps <= 10_000, VaultError::BadPolicy);
        Ok(())
    }
}

/// Kept by the program, never set by anyone directly.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, PartialEq, Debug)]
pub struct AutoState {
    /// UTC day the three counters below belong to.
    pub day: i64,
    pub compounds_today: u16,
    pub rebalances_today: u16,
    pub marks_today: u16,
    pub last_compound: i64,
    pub last_rebalance: i64,
    /// Unix time the program itself saw the active bin out of range. 0 = no mark.
    pub mark_time: i64,
    pub mark_active_id: i32,
    /// +1 the price is above the range, -1 below.
    pub mark_side: i8,
    // ---- M2.1
    /// sha256 over DLMM's own swap-fee counters of every bin of the range, taken at the mark. The
    /// counters only grow, and only when a swap trades in that bin: an unchanged fingerprint means no
    /// swap traded inside the range since the mark.
    pub mark_fp: [u8; 32],
    /// Lamports of bin-array rent the SOL reserve has paid for this position (never reset).
    pub rent_spent: u64,
    // ---- M2.3
    /// 1 = the mark was set with the pool gate and the external price check (Mode P). A keeper
    /// rebalance needs such a mark; an automated exit does not.
    pub mark_oracle: u8,
    /// The keeper rebalances of the last 24 hours: when, and how many bins the range moved.
    pub ring: [ShiftEntry; SHIFT_RING],
    // ---- M2.5
    /// Since when the program has seen this position out of range without a break: the time of the
    /// first mark of the current run of marks (same side, same fingerprint, so no swap has traded
    /// inside the range since). A later mark of any kind (a retry, a plain mark made into an
    /// oracle-checked one, a new mark after the old one expired) never moves it; the owner's
    /// out-of-range exit wait counts from here. 0 = no mark.
    /// M2.8: it now outlives the mark itself. A swap inside the range, a dust trade, a mark that is
    /// replaced or retried, an in-range observation that is not CONFIRMED as a recovery: none of them
    /// moves it. It ends only on a confirmed recovery, a change of side, an owner policy change, a
    /// keeper rebalance, or a gap in the program's observations longer than a mark's own life.
    pub oor_since: i64,
    // ---- M2.8
    /// The side (+1 above, -1 below) of the run `oor_since` belongs to. 0 = no run (or a record
    /// written before M2.8: the exit wait then counts from the mark itself, which is never earlier).
    pub oor_side: i8,
    /// Non-oracle pools only: time of the first in-range observation of a recovery that is not yet
    /// confirmed. A second in-range observation at least RECOVERY_CONFIRM_S later confirms it; any
    /// out-of-range mark in between sets it back to 0. 0 = no recovery pending.
    pub back_since: i64,
    /// Time of the last observation (in or out of range) of the current run. A run is continued by an
    /// out-of-range mark only while that observation could still have been used (`mark_last_use`).
    pub oor_seen: i64,
}

/// One keeper rebalance. `time` 0 = empty slot.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, PartialEq, Debug)]
pub struct ShiftEntry {
    pub time: i64,
    pub bins: u32,
}
pub const SHIFT_RING: usize = 8;

impl AutoState {
    pub const SIZE: usize = 8 + 2 + 2 + 2 + 8 + 8 + 8 + 4 + 1 + 32 + 8 + 1 + 12 * SHIFT_RING + 8 + 1 + 8 + 8;

    pub fn roll_day(&mut self, now: i64) {
        let day = crate::day_bucket(now);
        if day != self.day {
            self.day = day;
            self.compounds_today = 0;
            self.rebalances_today = 0;
            self.marks_today = 0;
        }
    }

    /// Drops the mark AND ends the exit run: an owner policy change, a keeper rebalance (new position).
    pub fn clear_mark(&mut self) {
        self.drop_mark();
        self.end_run();
    }

    /// M2.8: drops the rebalance mark only. The owner's exit run (`oor_since`) is left as it is.
    pub fn drop_mark(&mut self) {
        self.mark_time = 0;
        self.mark_active_id = 0;
        self.mark_side = 0;
        self.mark_fp = [0u8; 32];
        self.mark_oracle = 0;
    }

    /// M2.8: ends the owner's exit run.
    pub fn end_run(&mut self) {
        self.oor_since = 0;
        self.oor_side = 0;
        self.back_since = 0;
        self.oor_seen = 0;
    }
}

// ---------------------------------------------------------------------- DLMM account views

/// What the program reads from a DLMM `LbPair` account (bytemuck layout, idl/dlmm.json).
#[derive(Clone, Copy, Debug)]
pub struct PairView {
    pub filter_period: u16,
    pub index_reference: i32,
    pub last_update: i64,
    pub active_id: i32,
    pub bin_step: u16,
    pub mint_x: Pubkey,
    pub mint_y: Pubkey,
}

pub fn parse_pair(owner: &Pubkey, d: &[u8]) -> Result<PairView> {
    require!(*owner == crate::DLMM_ID && d.len() >= 216 && d[0..8] == LB_PAIR_DISC, VaultError::WrongPairAccount);
    Ok(PairView {
        filter_period: u16::from_le_bytes(d[10..12].try_into().unwrap()),
        index_reference: i32::from_le_bytes(d[48..52].try_into().unwrap()),
        last_update: i64::from_le_bytes(d[56..64].try_into().unwrap()),
        active_id: i32::from_le_bytes(d[76..80].try_into().unwrap()),
        bin_step: u16::from_le_bytes(d[80..82].try_into().unwrap()),
        mint_x: Pubkey::new_from_array(d[88..120].try_into().unwrap()),
        mint_y: Pubkey::new_from_array(d[120..152].try_into().unwrap()),
    })
}

/// (lower_bin_id, upper_bin_id) of a DLMM `PositionV2` that belongs to `lb_pair` and `vault`.
pub fn parse_position(owner: &Pubkey, d: &[u8], lb_pair: &Pubkey, vault: &Pubkey) -> Result<(i32, i32)> {
    require!(*owner == crate::DLMM_ID && d.len() >= 7920 && d[0..8] == POSITION_V2_DISC, VaultError::WrongPositionAccount);
    require!(d[8..40] == lb_pair.to_bytes() && d[40..72] == vault.to_bytes(), VaultError::WrongPositionAccount);
    let lower = i32::from_le_bytes(d[7912..7916].try_into().unwrap());
    let upper = i32::from_le_bytes(d[7916..7920].try_into().unwrap());
    require!(lower <= upper, VaultError::WrongPositionAccount);
    Ok((lower, upper))
}

// ---------------------------------------------------------------------- M2.1: DLMM bin arrays

const BIN_ARRAY_DISC: [u8; 8] = [92, 142, 92, 220, 5, 148, 70, 181];
pub const BINS_PER_ARRAY: i32 = 70;
/// One `Bin` (idl/dlmm.json, bytemuck, repr C): amount_x 0, amount_y 8, price 16, liquidity_supply 32,
/// fulfilled_order_amount_x 48, fulfilled_order_amount_y 56, limit_order_fee_ask_side 64,
/// limit_order_fee_bid_side 72, fee_amount_x_per_token_stored 80, fee_amount_y_per_token_stored 96,
/// open_order_amount 112, total_processing_order_amount 120, processed_order_remaining_amount 128,
/// order_age 136, limit_order_ask_side 140, padding 141..144.
pub const BIN_SIZE: usize = 144;
/// discriminator 8 | index i64 | version u8 + 7 padding | lb_pair 32 | 70 bins
pub const BIN_ARRAY_HEADER: usize = 56;
pub const BIN_ARRAY_LEN: usize = BIN_ARRAY_HEADER + BIN_SIZE * BINS_PER_ARRAY as usize;
/// Bytes of one bin that go into the fingerprint: the two swap-fee counters (offsets 80..112).
const FP_FROM: usize = 80;
const FP_TO: usize = 112;
/// PositionV2.liquidity_shares: [u128; 70] right after lb_pair and owner.
const POSITION_SHARES: usize = 72;

pub fn bin_array_index(bin: i32) -> i64 {
    bin.div_euclid(BINS_PER_ARRAY) as i64
}

/// A genuine DLMM BinArray of `lb_pair` with this index. Fails closed on any layout surprise.
pub fn check_bin_array(owner: &Pubkey, d: &[u8], lb_pair: &Pubkey, index: i64) -> Result<()> {
    require!(*owner == crate::DLMM_ID && d.len() == BIN_ARRAY_LEN && d[0..8] == BIN_ARRAY_DISC, VaultError::WrongBinArray);
    require!(i64::from_le_bytes(d[8..16].try_into().unwrap()) == index && d[24..56] == lb_pair.to_bytes(), VaultError::WrongBinArray);
    Ok(())
}

/// Appends (bin id, fee_x_per_token, fee_y_per_token) for every bin of this array inside lower..=upper.
pub fn fingerprint_feed(out: &mut Vec<u8>, d: &[u8], index: i64, lower: i32, upper: i32) {
    let first = index * BINS_PER_ARRAY as i64;
    for i in 0..BINS_PER_ARRAY as i64 {
        let bin = first + i;
        if bin < lower as i64 || bin > upper as i64 {
            continue;
        }
        let o = BIN_ARRAY_HEADER + BIN_SIZE * i as usize;
        out.extend_from_slice(&(bin as i32).to_le_bytes());
        out.extend_from_slice(&d[o + FP_FROM..o + FP_TO]);
    }
}

/// The position's own liquidity share in `bin` (a bin of its range). `d` already passed parse_position.
pub fn position_share(d: &[u8], lower: i32, bin: i32) -> u128 {
    let i = (bin - lower) as usize;
    let o = POSITION_SHARES + 16 * i;
    u128::from_le_bytes(d[o..o + 16].try_into().unwrap())
}

/// The bin of the range nearest to the price (`side` +1: scan down from `upper`, -1: up from `lower`)
/// in which the position itself holds liquidity. None = the position holds nothing anywhere.
pub fn nearest_own_bin(d: &[u8], lower: i32, upper: i32, side: i8) -> Option<i32> {
    let n = upper - lower + 1;
    (0..n).map(|i| if side > 0 { upper - i } else { lower + i }).find(|b| position_share(d, lower, *b) > 0)
}

/// `liquidity_supply` of `bin`, read from the data of its (already checked) bin array `index`.
pub fn bin_liquidity_supply(d: &[u8], index: i64, bin: i32) -> u128 {
    let o = BIN_ARRAY_HEADER + BIN_SIZE * (bin as i64 - index * BINS_PER_ARRAY as i64) as usize;
    u128::from_le_bytes(d[o + 32..o + 48].try_into().unwrap())
}

/// Price movement of `bins` bins of a pool with this bin step, in bps, rounded UP:
/// (1 + bin_step / 10_000)^bins - 1. None = too large to express.
pub fn move_bps(bin_step: u16, bins: u32) -> Option<u32> {
    let ratio = bin_price_q64(bin_step, i32::try_from(bins).ok()?)?;
    let scaled = ratio.checked_sub(ONE_Q64)?.checked_mul(10_000)?;
    let bps = (scaled >> 64) + u128::from(scaled & (ONE_Q64 - 1) != 0);
    u32::try_from(bps).ok()
}

/// M2.3: how far a keeper rebalance may move the range: per rebalance and over the ROLLING last
/// 24 hours, in bins and in price movement. Every rebalance younger than 86,400 seconds counts with
/// its full size, whatever its direction: going up and coming back down costs twice.
/// Returns (bins of this rebalance, the ring slot to record it in).
pub fn check_rolling(pol: &Policy, ring: &[ShiftEntry; SHIFT_RING], now: i64, bin_step: u16, old: (i32, i32), new: (i32, i32)) -> Result<(u32, usize)> {
    require!(pol.max_shift_bins > 0 && pol.max_shift_day > 0 && pol.max_move_bps > 0 && pol.max_move_bps_day > 0, VaultError::ShiftNotSet);
    let far = (old.0 as i64 - new.0 as i64).abs().max((old.1 as i64 - new.1 as i64).abs());
    require!(far <= pol.max_shift_bins as i64, VaultError::ShiftExceeded);
    let bins = far as u32;
    require!(move_bps(bin_step, bins).map_or(false, |b| b <= pol.max_move_bps as u32), VaultError::MoveExceeded);
    // an entry counts until it is a full 86,400 seconds old; one stamped in the future counts too
    let live = |e: &ShiftEntry| e.time != 0 && now.saturating_sub(e.time) < crate::SECONDS_PER_DAY;
    let total = ring.iter().filter(|e| live(e)).fold(bins as u64, |s, e| s + e.bins as u64);
    require!(total <= pol.max_shift_day as u64, VaultError::DailyShiftExceeded);
    require!(move_bps(bin_step, total as u32).map_or(false, |b| b <= pol.max_move_bps_day), VaultError::DailyMoveExceeded);
    // every slot still inside the window: no room to record this one, so it does not run
    let slot = ring.iter().position(|e| !live(e)).ok_or(VaultError::ShiftRingFull)?;
    Ok((bins, slot))
}

/// True when a Token-2022 mint carries the TransferFeeConfig extension (type 1), whatever the fee.
/// Mint data: 82 base bytes, padding to 165, account type at 165, then TLV (type u16, length u16).
/// Anything that cannot be parsed as a plain list of extensions counts as "has it" (fail closed).
pub fn has_transfer_fee_ext(d: &[u8]) -> bool {
    if d.len() <= 166 {
        return false;
    }
    let mut o = 166;
    while o + 4 <= d.len() {
        let t = u16::from_le_bytes([d[o], d[o + 1]]);
        let l = u16::from_le_bytes([d[o + 2], d[o + 3]]) as usize;
        if t == 0 {
            return false;
        }
        if t == 1 {
            return true;
        }
        o += 4 + l;
    }
    o != d.len()
}

// ---------------------------------------------------------------------- pure rules

/// +1 if the active bin is at least `margin` bins above the range, -1 if at least `margin` below,
/// 0 otherwise. A margin of 0 is treated as 1 (inside the range is never "out").
pub fn side_of(active: i32, lower: i32, upper: i32, margin: u16) -> i8 {
    let m = (margin.max(1)) as i64;
    let a = active as i64;
    if a - upper as i64 >= m {
        1
    } else if lower as i64 - a >= m {
        -1
    } else {
        0
    }
}

/// Bins the active bin has moved since the pool's own reference bin, while the pool's volatility
/// filter window is still open. DLMM resets `index_reference` to the active bin on the first swap
/// that comes at least `filter_period` seconds after the previous one, so once the pool has been
/// quiet that long the move counts as settled (0).
pub fn recent_move(p: &PairView, now: i64) -> u32 {
    if now.saturating_sub(p.last_update) < p.filter_period as i64 {
        (p.active_id as i64 - p.index_reference as i64).unsigned_abs().min(u32::MAX as u64) as u32
    } else {
        0
    }
}

/// claimed_x / min_x + claimed_y / min_y >= 1, in integers. A zero minimum switches that token off;
/// both zero = never.
pub fn min_claim_met(claimed_x: u64, claimed_y: u64, min_x: u64, min_y: u64) -> bool {
    match (min_x, min_y) {
        (0, 0) => false,
        (_, 0) => claimed_x >= min_x,
        (0, _) => claimed_y >= min_y,
        _ => {
            let lhs = (claimed_x as u128 * min_y as u128).checked_add(claimed_y as u128 * min_x as u128);
            match lhs {
                Some(v) => v >= min_x as u128 * min_y as u128,
                None => true,
            }
        }
    }
}

pub const ONE_Q64: u128 = 1u128 << 64;

/// (a * b) >> 64 without losing the high bits; None on overflow.
pub fn mul_q64(a: u128, b: u128) -> Option<u128> {
    let (a1, a0) = (a >> 64, a & (ONE_Q64 - 1));
    let (b1, b0) = (b >> 64, b & (ONE_Q64 - 1));
    let hi = a1 * b1;
    if hi >> 64 != 0 {
        return None;
    }
    (hi << 64).checked_add(a1 * b0)?.checked_add(a0 * b1)?.checked_add((a0 * b0) >> 64)
}

/// Price of one base unit of X in base units of Y at bin `id`, Q64.64: (1 + bin_step/10_000)^id.
pub fn bin_price_q64(bin_step: u16, id: i32) -> Option<u128> {
    let base = ONE_Q64 + ((bin_step as u128) << 64) / 10_000;
    let mut sq = if id < 0 { u128::MAX / base } else { base };
    let mut n = id.unsigned_abs();
    let mut out = ONE_Q64;
    while n > 0 {
        if n & 1 == 1 {
            out = mul_q64(out, sq)?;
        }
        n >>= 1;
        if n > 0 {
            sq = mul_q64(sq, sq)?;
        }
    }
    if out == 0 {
        None
    } else {
        Some(out)
    }
}

/// Lamport value of the claimed fees of a pool with a wrapped-SOL leg, at the pool's own active-bin
/// price. Outer None = the pool has no SOL leg (cannot be valued on chain).
pub fn claim_value_lamports(p: &PairView, claimed_x: u64, claimed_y: u64) -> Option<Result<u128>> {
    let x_is_sol = p.mint_x == WSOL_MINT;
    let y_is_sol = p.mint_y == WSOL_MINT;
    if !x_is_sol && !y_is_sol {
        return None;
    }
    let calc = || -> Option<u128> {
        let price = bin_price_q64(p.bin_step, p.active_id)?;
        if y_is_sol {
            mul_q64(claimed_x as u128, price)?.checked_add(claimed_y as u128)
        } else {
            (((claimed_y as u128) << 64) / price).checked_add(claimed_x as u128)
        }
    };
    Some(calc().ok_or_else(|| error!(VaultError::Math)))
}

/// cost / value <= max_bps / 10_000
pub fn cost_ratio_ok(cost_lamports: u64, value_lamports: u128, max_bps: u16) -> bool {
    (cost_lamports as u128).saturating_mul(10_000) <= value_lamports.saturating_mul(max_bps as u128)
}

/// The owner's rules about WHERE a keeper may put the new range: width, bounds, direction. `side` is the
/// program's own observation (+1 price above the old range, -1 below).
///
/// M2.7: the range is no longer placed against the pool's active bin here. Where the new liquidity may
/// sit relative to the price is decided by `oracle::check_placement` from the VERIFIED external price
/// (Mode P): bids at or below it, asks at or above it, never the active bin itself.
pub fn check_new_range(pol: &Policy, side: i8, old_lower: i32, old_upper: i32, new_lower: i32, width: i32) -> Result<i32> {
    require!(width >= pol.min_width as i32 && width <= pol.max_width as i32, VaultError::WidthOutOfPolicy);
    let new_upper = new_lower.checked_add(width - 1).ok_or(VaultError::Math)?;
    require!(new_lower >= pol.min_bin && new_upper <= pol.max_bin, VaultError::RangeOutOfBounds);
    if side > 0 {
        require!(pol.direction & DIR_UP != 0, VaultError::DirectionNotAllowed);
        require!(new_lower > old_lower && new_upper > old_upper, VaultError::WrongDirection);
    } else {
        require!(pol.direction & DIR_DOWN != 0, VaultError::DirectionNotAllowed);
        require!(new_lower < old_lower && new_upper < old_upper, VaultError::WrongDirection);
    }
    Ok(new_upper)
}

/// Number of DLMM bin arrays (70 bins each) a range touches.
pub fn bin_arrays_spanned(lower: i32, upper: i32) -> usize {
    (upper.div_euclid(70) - lower.div_euclid(70) + 1) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_array(lb: &Pubkey, index: i64) -> Vec<u8> {
        let mut d = vec![0u8; BIN_ARRAY_LEN];
        d[0..8].copy_from_slice(&BIN_ARRAY_DISC);
        d[8..16].copy_from_slice(&index.to_le_bytes());
        d[24..56].copy_from_slice(&lb.to_bytes());
        d
    }

    #[test]
    fn bin_array_layout_and_fingerprint() {
        assert_eq!(BIN_ARRAY_LEN, 10_136);
        assert_eq!(bin_array_index(0), 0);
        assert_eq!(bin_array_index(69), 0);
        assert_eq!(bin_array_index(70), 1);
        assert_eq!(bin_array_index(-1), -1);
        assert_eq!(bin_array_index(-70), -1);
        assert_eq!(bin_array_index(-71), -2);
        let lb = Pubkey::new_unique();
        let mut a = fake_array(&lb, -1);
        assert!(check_bin_array(&crate::DLMM_ID, &a, &lb, -1).is_ok());
        assert!(check_bin_array(&crate::DLMM_ID, &a, &lb, 0).is_err());
        assert!(check_bin_array(&crate::DLMM_ID, &a, &Pubkey::new_unique(), -1).is_err());
        assert!(check_bin_array(&Pubkey::new_unique(), &a, &lb, -1).is_err());
        assert!(check_bin_array(&crate::DLMM_ID, &a[..BIN_ARRAY_LEN - 1], &lb, -1).is_err());
        let mut longer = a.clone();
        longer.push(0);
        assert!(check_bin_array(&crate::DLMM_ID, &longer, &lb, -1).is_err());
        // bins -5..=-1 live at slots 65..=69 of array -1
        let mut f0 = Vec::new();
        fingerprint_feed(&mut f0, &a, -1, -5, 3);
        assert_eq!(f0.len(), 5 * 36);
        assert_eq!(i32::from_le_bytes(f0[0..4].try_into().unwrap()), -5);
        // a fee counter of a bin inside the range changes the bytes; one outside does not; amounts never do
        let o_in = BIN_ARRAY_HEADER + BIN_SIZE * 67;
        let o_out = BIN_ARRAY_HEADER + BIN_SIZE * 10;
        a[o_out + 80] = 9;
        a[o_in] = 7; // amount_x
        a[o_in + 32] = 7; // liquidity_supply
        a[o_in + 112] = 7; // open_order_amount
        let mut f1 = Vec::new();
        fingerprint_feed(&mut f1, &a, -1, -5, 3);
        assert_eq!(f0, f1);
        a[o_in + 96] = 1; // fee_y_per_token
        let mut f2 = Vec::new();
        fingerprint_feed(&mut f2, &a, -1, -5, 3);
        assert_ne!(f0, f2);
    }

    #[test]
    fn transfer_fee_extension_detection() {
        assert!(!has_transfer_fee_ext(&[0u8; 82]));
        assert!(!has_transfer_fee_ext(&[0u8; 166]));
        let mut d = vec![0u8; 166];
        d[165] = 1;
        // a different extension (type 3, length 32) and nothing else
        let mut other = d.clone();
        other.extend_from_slice(&[3, 0, 32, 0]);
        other.extend_from_slice(&[0u8; 32]);
        assert!(!has_transfer_fee_ext(&other));
        // ... followed by TransferFeeConfig (type 1, length 108)
        let mut with = other.clone();
        with.extend_from_slice(&[1, 0, 108, 0]);
        with.extend_from_slice(&[0u8; 108]);
        assert!(has_transfer_fee_ext(&with));
        // truncated TLV: fail closed
        let mut bad = d.clone();
        bad.extend_from_slice(&[3, 0, 32, 0, 1, 2]);
        assert!(has_transfer_fee_ext(&bad));
    }

    #[test]
    fn position_share_offsets() {
        let mut d = vec![0u8; 7920];
        d[72 + 16 * 3] = 5;
        assert_eq!(position_share(&d, 10, 13), 5);
        assert_eq!(position_share(&d, 10, 10), 0);
    }

    #[test]
    fn nearest_own_bin_and_supply() {
        let mut d = vec![0u8; 7920];
        assert_eq!(nearest_own_bin(&d, 10, 19, 1), None);
        assert_eq!(nearest_own_bin(&d, 10, 19, -1), None);
        d[72 + 16 * 3] = 5; // bin 13
        d[72 + 16 * 6 + 15] = 1; // bin 16, high byte only
        assert_eq!(nearest_own_bin(&d, 10, 19, 1), Some(16));
        assert_eq!(nearest_own_bin(&d, 10, 19, -1), Some(13));
        assert_eq!(nearest_own_bin(&d, 7, 7, 1), None); // width 1, slot 0 empty
        d[72] = 1;
        assert_eq!(nearest_own_bin(&d, 7, 7, -1), Some(7));
        let lb = Pubkey::new_unique();
        let mut a = fake_array(&lb, -1);
        let o = BIN_ARRAY_HEADER + BIN_SIZE * 67; // bin -3
        a[o + 32 + 9] = 2;
        assert_eq!(bin_liquidity_supply(&a, -1, -3), 2u128 << 72);
        assert_eq!(bin_liquidity_supply(&a, -1, -4), 0);
        assert_eq!(bin_liquidity_supply(&a, -1, -70), 0);
    }

    #[test]
    fn move_bps_rounds_up() {
        assert_eq!(move_bps(100, 1), Some(100));
        assert_eq!(move_bps(25, 1), Some(25));
        assert_eq!(move_bps(25, 5), Some(126)); // 1.0025^5 - 1 = 1.25627%
        assert_eq!(move_bps(100, 5), Some(511)); // 5.10100501%
        assert_eq!(move_bps(1, 1), Some(1));
        assert_eq!(move_bps(25, 0), Some(0));
    }

    #[test]
    fn rolling_limits() {
        let p = Policy { max_shift_bins: 5, max_shift_day: 8, max_move_bps: 200, max_move_bps_day: 250, ..pol() };
        let empty = [ShiftEntry::default(); SHIFT_RING];
        let t = 1_800_000_000i64;
        assert_eq!(check_rolling(&p, &empty, t, 25, (10, 19), (15, 24)).unwrap(), (5, 0));
        assert_eq!(check_rolling(&p, &empty, t, 25, (10, 19), (16, 25)).unwrap_err(), VaultError::ShiftExceeded.into());
        // a width change counts on the edge that moved most
        assert_eq!(check_rolling(&p, &empty, t, 25, (10, 19), (12, 25)).unwrap_err(), VaultError::ShiftExceeded.into());
        // the same 5 bins are 1.26% at bin step 25 and 5.11% at bin step 100
        assert_eq!(check_rolling(&p, &empty, t, 100, (10, 19), (15, 24)).unwrap_err(), VaultError::MoveExceeded.into());
        assert_eq!(check_rolling(&p, &empty, t, 39, (10, 19), (15, 24)).unwrap(), (5, 0)); // 1.966%
        assert_eq!(check_rolling(&p, &empty, t, 40, (10, 19), (15, 24)).unwrap_err(), VaultError::MoveExceeded.into()); // 2.016%
        // up 3, down 3, up 3: the third does not fit in 8, although the range is only 3 bins from the start
        let mut ring = empty;
        ring[0] = ShiftEntry { time: t, bins: 3 };
        assert_eq!(check_rolling(&p, &ring, t + 10, 25, (13, 22), (10, 19)).unwrap(), (3, 1));
        ring[1] = ShiftEntry { time: t + 10, bins: 3 };
        assert_eq!(check_rolling(&p, &ring, t + 20, 25, (10, 19), (13, 22)).unwrap_err(), VaultError::DailyShiftExceeded.into());
        assert_eq!(check_rolling(&p, &ring, t + 20, 25, (10, 19), (12, 21)).unwrap(), (2, 2));
        // an entry leaves the window at exactly 86,400 seconds, not one second earlier, and not at midnight
        assert_eq!(check_rolling(&p, &ring, t + 86_399, 25, (10, 19), (13, 22)).unwrap_err(), VaultError::DailyShiftExceeded.into());
        assert_eq!(check_rolling(&p, &ring, t + 86_400, 25, (10, 19), (13, 22)).unwrap(), (3, 0));
        let midnight = (t / 86_400 + 1) * 86_400;
        assert_eq!(check_rolling(&p, &ring, midnight, 25, (10, 19), (13, 22)).unwrap_err(), VaultError::DailyShiftExceeded.into());
        // the 24h price limit: 8 bins of step 25 = 2.02% fits 250 bps, of step 32 = 2.59% does not
        let q = Policy { max_shift_bins: 5, max_shift_day: 8, max_move_bps: 250, max_move_bps_day: 250, ..pol() };
        ring[1] = ShiftEntry::default();
        assert_eq!(check_rolling(&q, &ring, t + 20, 25, (10, 19), (15, 24)).unwrap(), (5, 1));
        assert_eq!(check_rolling(&q, &ring, t + 20, 32, (10, 19), (15, 24)).unwrap_err(), VaultError::DailyMoveExceeded.into());
        // ring full: eight live entries of one bin each, the budget would still allow more
        let w = Policy { max_shift_bins: 5, max_shift_day: 100, max_move_bps: 500, max_move_bps_day: 5_000, ..pol() };
        let full = [ShiftEntry { time: t, bins: 1 }; SHIFT_RING];
        assert_eq!(check_rolling(&w, &full, t + 1, 25, (10, 19), (11, 20)).unwrap_err(), VaultError::ShiftRingFull.into());
        assert_eq!(check_rolling(&w, &full, t + 86_400, 25, (10, 19), (11, 20)).unwrap(), (1, 0));
        // an entry stamped in the future still counts
        let mut fut = empty;
        fut[0] = ShiftEntry { time: t + 500, bins: 8 };
        assert_eq!(check_rolling(&p, &fut, t, 25, (10, 19), (11, 20)).unwrap_err(), VaultError::DailyShiftExceeded.into());
        for z in 0..4 {
            let mut o = p;
            match z {
                0 => o.max_shift_bins = 0,
                1 => o.max_shift_day = 0,
                2 => o.max_move_bps = 0,
                _ => o.max_move_bps_day = 0,
            }
            assert_eq!(check_rolling(&o, &empty, t, 25, (10, 19), (11, 20)).unwrap_err(), VaultError::ShiftNotSet.into());
        }
    }

    fn pol() -> Policy {
        Policy { min_bin: -100, max_bin: 200, direction: DIR_UP | DIR_DOWN, min_width: 10, max_width: 40, edge_slack: 3, ..Default::default() }
    }
    fn code(r: Result<i32>) -> Error {
        r.unwrap_err()
    }

    #[test]
    fn side_needs_the_margin() {
        assert_eq!(side_of(64, 5, 64, 2), 0);
        assert_eq!(side_of(65, 5, 64, 2), 0);
        assert_eq!(side_of(66, 5, 64, 2), 1);
        assert_eq!(side_of(4, 5, 64, 2), 0);
        assert_eq!(side_of(3, 5, 64, 2), -1);
        assert_eq!(side_of(64, 5, 64, 0), 0); // margin 0 never makes the range itself "out"
        assert_eq!(side_of(65, 5, 64, 0), 1);
        assert_eq!(side_of(i32::MAX, i32::MIN, 0, u16::MAX), 1);
    }

    #[test]
    fn recent_move_uses_the_pools_filter_window() {
        let p = PairView { filter_period: 30, index_reference: 100, last_update: 1_000, active_id: 107, bin_step: 25, mint_x: Pubkey::default(), mint_y: Pubkey::default() };
        assert_eq!(recent_move(&p, 1_000), 7);
        assert_eq!(recent_move(&p, 1_029), 7);
        assert_eq!(recent_move(&p, 1_030), 0);
        let q = PairView { active_id: 93, ..p };
        assert_eq!(recent_move(&q, 1_010), 7);
    }

    #[test]
    fn min_claim_rule_both_sides() {
        assert!(!min_claim_met(u64::MAX, u64::MAX, 0, 0));
        assert!(min_claim_met(100, 0, 100, 0));
        assert!(!min_claim_met(99, u64::MAX, 100, 0));
        assert!(min_claim_met(0, 50, 0, 50));
        assert!(!min_claim_met(u64::MAX, 49, 0, 50));
        // both set: either alone, or the two halves together
        assert!(min_claim_met(100, 0, 100, 50));
        assert!(min_claim_met(0, 50, 100, 50));
        assert!(min_claim_met(50, 25, 100, 50));
        assert!(!min_claim_met(50, 24, 100, 50));
        assert!(!min_claim_met(49, 25, 100, 50));
        assert!(!min_claim_met(0, 0, 1, 1));
        assert!(min_claim_met(u64::MAX, u64::MAX, u64::MAX, u64::MAX));
    }

    #[test]
    fn bin_price_matches_floating_point() {
        for (step, id) in [(25u16, 0i32), (25, 35), (25, -35), (10, 5000), (10, -5000), (100, 1234), (1, 100_000), (80, -3000), (25, 8388)] {
            let got = bin_price_q64(step, id).unwrap() as f64 / ONE_Q64 as f64;
            let want = (1.0 + step as f64 / 10_000.0).powi(id);
            assert!((got / want - 1.0).abs() < 1e-9, "step {step} id {id}: {got} vs {want}");
        }
        assert_eq!(bin_price_q64(25, 0), Some(ONE_Q64));
        assert_eq!(bin_price_q64(100, 443_636), None); // overflows Q64.64: refused, never wrapped
    }

    #[test]
    fn claim_value_and_ratio() {
        let other = Pubkey::new_unique();
        let mut p = PairView { filter_period: 30, index_reference: 0, last_update: 0, active_id: 0, bin_step: 25, mint_x: other, mint_y: WSOL_MINT };
        assert_eq!(claim_value_lamports(&p, 1_000, 500).unwrap().unwrap(), 1_500);
        p.active_id = 277; // 1.0025^277 = 1.99706...
        let v = claim_value_lamports(&p, 1_000_000, 0).unwrap().unwrap();
        assert!((1_996_000..1_998_000).contains(&v), "{v}");
        p.mint_x = WSOL_MINT;
        p.mint_y = other;
        let v = claim_value_lamports(&p, 7, 1_000_000).unwrap().unwrap();
        assert!((500_700..500_800).contains(&v), "{v}");
        p.mint_x = other;
        assert!(claim_value_lamports(&p, 1, 1).is_none());
        // 5%: cost 5_000 needs fees worth at least 100_000 lamports
        assert!(cost_ratio_ok(5_000, 100_000, 500));
        assert!(!cost_ratio_ok(5_000, 99_999, 500));
        assert!(!cost_ratio_ok(5_001, 100_000, 500));
        assert!(!cost_ratio_ok(1, u128::MAX, 0));
    }

    #[test]
    fn new_range_rules() {
        let p = pol();
        // price rose above the old range 5..64 (where the new range sits against the price: oracle::check_placement)
        assert_eq!(check_new_range(&p, 1, 5, 64, 41, 30).unwrap(), 70);
        assert_eq!(check_new_range(&p, 1, 5, 64, 44, 30).unwrap(), 73);
        assert_eq!(check_new_range(&p, 1, 5, 64, 40, 30).unwrap(), 69);
        assert_eq!(code(check_new_range(&p, 1, 5, 64, 62, 9)), VaultError::WidthOutOfPolicy.into());
        assert_eq!(code(check_new_range(&p, 1, 5, 64, 30, 41)), VaultError::WidthOutOfPolicy.into());
        assert_eq!(code(check_new_range(&p, 1, 5, 64, 41, 0)), VaultError::WidthOutOfPolicy.into());
        assert_eq!(code(check_new_range(&p, 1, 5, 64, 41, -5)), VaultError::WidthOutOfPolicy.into());
        // bounds
        assert_eq!(code(check_new_range(&p, 1, 5, 64, 172, 30)), VaultError::RangeOutOfBounds.into());
        assert_eq!(check_new_range(&p, 1, 5, 64, 171, 30).unwrap(), 200);
        assert_eq!(code(check_new_range(&p, -1, 5, 64, -101, 30)), VaultError::RangeOutOfBounds.into());
        // direction
        let up_only = Policy { direction: DIR_UP, ..p };
        let down_only = Policy { direction: DIR_DOWN, ..p };
        let none = Policy { direction: 0, ..p };
        assert_eq!(code(check_new_range(&down_only, 1, 5, 64, 41, 30)), VaultError::DirectionNotAllowed.into());
        assert_eq!(code(check_new_range(&up_only, -1, 5, 64, 0, 30)), VaultError::DirectionNotAllowed.into());
        assert_eq!(code(check_new_range(&none, 1, 5, 64, 41, 30)), VaultError::DirectionNotAllowed.into());
        assert_eq!(check_new_range(&down_only, -1, 5, 64, 0, 30).unwrap(), 29);
        assert_eq!(check_new_range(&p, -1, 5, 64, -3, 30).unwrap(), 26);
        // a keeper cannot move the range against the price, even where the other rules would allow it
        assert_eq!(code(check_new_range(&Policy { min_width: 1, max_width: 70, ..p }, 1, 5, 64, 2, 65)), VaultError::WrongDirection.into());
        assert_eq!(code(check_new_range(&p, -1, 5, 64, 5, 30)), VaultError::WrongDirection.into());
        assert_eq!(code(check_new_range(&p, 1, 5, 64, i32::MAX - 3, 30)), VaultError::Math.into());
    }

    #[test]
    fn bin_arrays() {
        assert_eq!(bin_arrays_spanned(5, 64), 1);
        assert_eq!(bin_arrays_spanned(5, 74), 2);
        assert_eq!(bin_arrays_spanned(-1, 0), 2);
        assert_eq!(bin_arrays_spanned(-70, -1), 1);
        assert_eq!(bin_arrays_spanned(-71, 70), 4);
    }

    #[test]
    fn policy_validation_and_sizes() {
        assert!(pol().validate().is_ok());
        assert!(Policy { min_bin: 1, max_bin: 0, ..pol() }.validate().is_err());
        assert!(Policy { min_width: 0, ..pol() }.validate().is_err());
        assert!(Policy { max_width: 71, ..pol() }.validate().is_err());
        assert!(Policy { min_width: 41, ..pol() }.validate().is_err());
        assert!(Policy { direction: 4, ..pol() }.validate().is_err());
        assert!(Policy { max_cost_bps: 10_001, ..pol() }.validate().is_err());
        assert!(Policy { strategy: 9, ..pol() }.validate().is_err());
        assert!(Policy { max_shift_bins: 6, max_shift_day: 5, ..pol() }.validate().is_err());
        assert!(Policy { max_shift_bins: 5, max_shift_day: 5, ..pol() }.validate().is_ok());
        assert!(Policy { max_move_bps: 6, max_move_bps_day: 5, ..pol() }.validate().is_err());
        assert!(Policy { max_dev_bps: 151, ..pol() }.validate().is_err());
        assert!(Policy { max_dev_bps: 150, max_loss_bps: 10_000, ..pol() }.validate().is_ok());
        assert!(Policy { max_loss_bps: 10_001, ..pol() }.validate().is_err());
        assert!(Policy::default().validate().is_err()); // an all-zero policy is "nothing set", not a valid one
        assert_eq!(Policy::default().try_to_vec().unwrap().len(), Policy::SIZE);
        assert_eq!(AutoState::default().try_to_vec().unwrap().len(), AutoState::SIZE);
    }
}

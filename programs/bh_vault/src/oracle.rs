//! M2.3 "Mode P": the admin-controlled pool gate and the external (Pyth) price checks that a keeper
//! mark and a keeper rebalance must pass.
//!
//! Nothing in here trusts the keeper. The keeper only chooses WHICH accounts it passes; every one
//! of them is checked: the gate is this program's PDA for the pool, the two price accounts are
//! owned by the Pyth receiver program, fully verified, and carry the feed ids the gate names.
//! Any doubt (missing, stale, from the future, wide confidence, far from the moving average,
//! arithmetic that does not fit) refuses the instruction.

use crate::policy::{bin_price_q64, mul_q64, ONE_Q64};
use crate::VaultError;
use anchor_lang::prelude::*;

/// The UPGRADED Pyth Solana receiver program (the same address on mainnet and devnet). It is the
/// only owner of a price account this program accepts.
pub const PYTH_RECEIVER_ID: Pubkey = pubkey!("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp");
/// The older receiver. Named only so that tests can show it is refused: a price account it owns,
/// however well formed, fails OracleWrongOwner like any other foreign account.
pub const PYTH_RECEIVER_OLD_ID: Pubkey = pubkey!("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ");
/// sha256("account:PriceUpdateV2")[..8]
const PRICE_UPDATE_DISC: [u8; 8] = [34, 241, 35, 99, 157, 126, 244, 205];
/// 8 disc | 32 write_authority | verification_level (Full = one byte 1; Partial = byte 0 + a count)
/// | feed_id 32 | price i64 | conf u64 | exponent i32 | publish_time i64 | prev_publish_time i64
/// | ema_price i64 | ema_conf u64 | posted_slot u64. The account is always allocated 134 bytes.
pub const PRICE_UPDATE_LEN: usize = 134;
const LEVEL_AT: usize = 40;
const LEVEL_FULL: u8 = 1;

// ---- hard caps on what an admin can put in a gate (experimental devnet settings, not production defaults)
pub const MAX_AGE_CAP: u16 = 30;
pub const FUTURE_TOL_CAP: u8 = 2;
pub const MAX_FEED_GAP_CAP: u16 = 30;
pub const MAX_CONF_BPS_CAP: u16 = 100;
pub const MAX_EMA_DEV_BPS_CAP: u16 = 1_000;
/// deviation limit <= bin step + this, and never above MAX_DEV_BPS_CAP
pub const DEV_OVER_STEP_BPS: u16 = 50;
pub const MAX_DEV_BPS_CAP: u16 = 150;
pub const MAX_GATE_VALIDITY: i64 = 7 * 86_400;
/// 2 = M2.5 (minimum width and minimum placed share taken from the reserved bytes; same size).
/// Layout 1 was never written outside a local validator.
pub const GATE_LAYOUT: u8 = 2;
pub const GATE_RESERVED: usize = 60;

/// The limits of one pool gate. Set by the admin only.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, PartialEq, Debug)]
pub struct GateLimits {
    /// Oldest price accepted, seconds.
    pub max_age_s: u16,
    /// A publish time this many seconds ahead of the cluster clock is still accepted.
    pub future_tol_s: u8,
    /// Most seconds between the publish times of the two feeds.
    pub max_feed_gap_s: u16,
    /// Widest confidence interval, bps of the price, per feed.
    pub max_conf_bps: u16,
    /// Most the pool's price may differ from the external price, bps, the confidence of both feeds
    /// included (the uncertainty uses up this limit, it does not widen it).
    pub max_dev_bps: u16,
    /// Most each price may differ from its own Pyth moving average, bps.
    pub max_ema_dev_bps: u16,
    // ---- M2.5
    /// Fewest bins a keeper rebalance may give the new range in this pool. The owner's own
    /// `min_width` applies when it is larger. 0 = no keeper rebalance in this pool.
    pub min_width: u16,
    /// Least share (bps, at the external price) of what came out of the old position, net of the
    /// performance fee, that the new position must really hold. The owner's `min_placed_bps`
    /// applies when it is higher. 0 = no keeper rebalance in this pool.
    pub min_placed_bps: u16,
}

impl GateLimits {
    pub const SIZE: usize = 2 + 1 + 2 + 2 + 2 + 2 + 2 + 2;

    pub fn validate(&self, bin_step: u16) -> Result<()> {
        require!(self.max_age_s >= 1 && self.max_age_s <= MAX_AGE_CAP, VaultError::BadGate);
        require!(self.future_tol_s <= FUTURE_TOL_CAP, VaultError::BadGate);
        require!(self.max_feed_gap_s <= MAX_FEED_GAP_CAP, VaultError::BadGate);
        require!(self.max_conf_bps >= 1 && self.max_conf_bps <= MAX_CONF_BPS_CAP, VaultError::BadGate);
        require!(self.max_ema_dev_bps >= 1 && self.max_ema_dev_bps <= MAX_EMA_DEV_BPS_CAP, VaultError::BadGate);
        let cap = bin_step.saturating_add(DEV_OVER_STEP_BPS).min(MAX_DEV_BPS_CAP);
        require!(self.max_dev_bps >= 1 && self.max_dev_bps <= cap, VaultError::BadGate);
        // zero is allowed in both and means "no keeper rebalance" (fail closed), never "no minimum"
        require!(self.min_width <= crate::policy::MAX_WIDTH && self.min_placed_bps <= 10_000, VaultError::BadGate);
        Ok(())
    }
}

/// One per pool, PDA ["gate", lb_pair]. Created, enabled, renewed and changed by the admin only;
/// the guardian can only disable or revoke. No keeper instruction can write it.
#[account]
pub struct PoolGate {
    pub layout: u8,
    pub bump: u8,
    pub lb_pair: Pubkey,
    pub mint_x: Pubkey,
    pub mint_y: Pubkey,
    /// Read from the mint accounts when the gate is created.
    pub decimals_x: u8,
    pub decimals_y: u8,
    pub bin_step: u16,
    /// Pyth feed id of token X in USD and of token Y in USD. Both are always read.
    pub feed_x: [u8; 32],
    pub feed_y: [u8; 32],
    pub enabled: bool,
    pub revoked: bool,
    /// The gate is good up to and including this unix time. At most 7 days ahead when set.
    pub valid_until: i64,
    pub limits: GateLimits,
    pub reserved: [u8; GATE_RESERVED],
}

impl PoolGate {
    pub const SPACE: usize = 8 + 1 + 1 + 32 * 3 + 1 + 1 + 2 + 32 * 2 + 1 + 1 + 8 + GateLimits::SIZE + GATE_RESERVED;

    /// Usable for a keeper mark or rebalance right now.
    pub fn check_open(&self, now: i64) -> Result<()> {
        require!(self.layout == GATE_LAYOUT, VaultError::GateMissing);
        require!(!self.revoked, VaultError::GateRevoked);
        require!(self.enabled, VaultError::GateDisabled);
        require!(now <= self.valid_until, VaultError::GateExpired);
        Ok(())
    }
}

/// PDA ["guardian"]: the one key that may disable or revoke gates besides the admin.
#[account]
pub struct GuardianSet {
    pub guardian: Pubkey,
    pub bump: u8,
    pub reserved: [u8; 32],
}
impl GuardianSet {
    pub const SPACE: usize = 8 + 32 + 1 + 32;
}

// ---------------------------------------------------------------------- Pyth price account

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PriceView {
    pub price: i64,
    pub conf: u64,
    pub expo: i32,
    pub publish_time: i64,
    pub ema_price: i64,
}

/// A fully verified PriceUpdateV2 of exactly this feed, owned by the Pyth receiver. Who posted it
/// (write_authority) does not matter: the receiver only stores what Pyth's signers attested.
pub fn parse_price(owner: &Pubkey, d: &[u8], feed: &[u8; 32]) -> Result<PriceView> {
    require!(*owner == PYTH_RECEIVER_ID, VaultError::OracleWrongOwner);
    require!(d.len() == PRICE_UPDATE_LEN && d[0..8] == PRICE_UPDATE_DISC, VaultError::OracleBadAccount);
    require!(d[LEVEL_AT] == LEVEL_FULL, VaultError::OracleNotFull);
    let o = LEVEL_AT + 1;
    require!(d[o..o + 32] == feed[..], VaultError::OracleWrongFeed);
    let i = |a: usize| i64::from_le_bytes(d[a..a + 8].try_into().unwrap());
    Ok(PriceView {
        price: i(o + 32),
        conf: i(o + 40) as u64,
        expo: i32::from_le_bytes(d[o + 48..o + 52].try_into().unwrap()),
        publish_time: i(o + 52),
        ema_price: i(o + 68),
    })
}

// ---------------------------------------------------------------------- 256-bit helpers

/// (high 128 bits, low 128 bits)
pub type U256 = (u128, u128);

pub fn mul_wide(a: u128, b: u128) -> U256 {
    const M: u128 = (1u128 << 64) - 1;
    let (a1, a0) = (a >> 64, a & M);
    let (b1, b0) = (b >> 64, b & M);
    let ll = a0 * b0;
    let lh = a0 * b1;
    let hl = a1 * b0;
    let hh = a1 * b1;
    let mid = (ll >> 64) + (lh & M) + (hl & M);
    let lo = (ll & M) | ((mid & M) << 64);
    let hi = hh + (lh >> 64) + (hl >> 64) + (mid >> 64);
    (hi, lo)
}

fn add_wide(a: U256, b: U256) -> Option<U256> {
    let (lo, c) = a.1.overflowing_add(b.1);
    let hi = a.0.checked_add(b.0)?.checked_add(c as u128)?;
    Some((hi, lo))
}

/// a * k, None on overflow
fn mul_wide_small(a: U256, k: u128) -> Option<U256> {
    let lo = mul_wide(a.1, k);
    let hi = mul_wide(a.0, k);
    if hi.0 != 0 {
        return None;
    }
    Some((hi.1.checked_add(lo.0)?, lo.1))
}

// ---------------------------------------------------------------------- the price band

/// The external price of one base unit of token X in base units of token Y: mid = Px / Py, already
/// scaled by the two price exponents and the two mints' decimals, and how uncertain it is.
///
/// M2.4: the uncertainty does not widen what is allowed, it USES UP the deviation limit. The
/// effective deviation of a pool price p is |p - mid| / mid + conf_x / Px + conf_y / Py and that
/// sum must be inside the limit. `conf_ppm` is the last two terms in millionths, each rounded up.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Band {
    pub mid_num: u128,
    pub mid_den: u128,
    pub conf_ppm: u32,
}

/// conf / price in millionths, rounded up. (conf < price is checked before, so this is < 1_000_000.)
fn conf_ppm(conf: u128, price: u128) -> u32 {
    ((conf * 1_000_000 + price - 1) / price) as u32
}

/// What is left of a deviation limit (bps) after the oracle's own uncertainty, in millionths.
/// None = the uncertainty alone already uses the whole limit: nothing can pass.
pub fn room_ppm(b: &Band, dev_bps: u16) -> Option<u32> {
    (dev_bps as u32 * 100).checked_sub(b.conf_ppm)
}

fn one_feed(p: &PriceView, lim: &GateLimits, now: i64) -> Result<(u128, u128)> {
    require!(p.price > 0 && p.ema_price > 0, VaultError::OraclePriceInvalid);
    require!(now.saturating_sub(p.publish_time) <= lim.max_age_s as i64, VaultError::OracleStale);
    require!(p.publish_time.saturating_sub(now) <= lim.future_tol_s as i64, VaultError::OracleFromFuture);
    let (price, conf, ema) = (p.price as u128, p.conf as u128, p.ema_price as u128);
    // conf / price <= max_conf_bps / 10_000
    require!(conf.checked_mul(10_000).ok_or(VaultError::OracleMath)? <= price * lim.max_conf_bps as u128, VaultError::OracleConfidence);
    // |price - ema| / ema <= max_ema_dev_bps / 10_000. Never skipped.
    require!(price.abs_diff(ema) * 10_000 <= ema * lim.max_ema_dev_bps as u128, VaultError::OracleEmaDeviation);
    require!(conf < price, VaultError::OracleConfidence);
    Ok((price, conf))
}

/// Every check on the two price accounts, then the band. `px` is the feed of token X in USD,
/// `py` of token Y in USD: the pair price is always built from both, no leg is assumed to be 1.
pub fn oracle_band(px: &PriceView, py: &PriceView, decimals_x: u8, decimals_y: u8, lim: &GateLimits, now: i64) -> Result<Band> {
    let (x, cx) = one_feed(px, lim, now)?;
    let (y, cy) = one_feed(py, lim, now)?;
    require!((px.publish_time as i128 - py.publish_time as i128).unsigned_abs() <= lim.max_feed_gap_s as u128, VaultError::OracleFeedGap);
    // raw Y per raw X = (x * 10^ex) / (y * 10^ey) * 10^(dy - dx)
    let e = px.expo as i64 - py.expo as i64 + decimals_y as i64 - decimals_x as i64;
    require!(e.abs() <= 30, VaultError::OracleMath);
    let pow = 10u128.pow(e.unsigned_abs() as u32);
    let (sn, sd) = if e >= 0 { (pow, 1) } else { (1, pow) };
    let m = |a: u128, b: u128| a.checked_mul(b).ok_or(error!(VaultError::OracleMath));
    Ok(Band { mid_num: m(x, sn)?, mid_den: m(y, sd)?, conf_ppm: conf_ppm(cx, x) + conf_ppm(cy, y) })
}

const PPM: u128 = 1_000_000;

/// p (Q64.64) <= (num / den) * (1_000_000 + ppm) / 1_000_000. Err = the numbers do not fit.
fn le_up(p: u128, num: u128, den: u128, ppm: u32) -> Result<bool> {
    let a = den.checked_mul(PPM).ok_or(VaultError::OracleMath)?;
    let r = num.checked_mul(PPM + ppm as u128).ok_or(VaultError::OracleMath)?;
    require!(r >> 64 == 0, VaultError::OracleMath);
    Ok(mul_wide(p, a) <= (r >> 64, r << 64))
}
/// p (Q64.64) >= (num / den) * (1_000_000 - ppm) / 1_000_000
fn ge_down(p: u128, num: u128, den: u128, ppm: u32) -> Result<bool> {
    let a = den.checked_mul(PPM).ok_or(VaultError::OracleMath)?;
    let r = num.checked_mul(PPM.saturating_sub(ppm as u128)).ok_or(VaultError::OracleMath)?;
    require!(r >> 64 == 0, VaultError::OracleMath);
    Ok(mul_wide(p, a) >= (r >> 64, r << 64))
}

/// The pool's price (Q64.64, raw Y per raw X) is acceptable under a deviation limit of `dev_bps`:
/// |p - mid| / mid plus the uncertainty of both feeds is inside the limit.
pub fn price_in_band(p: u128, b: &Band, dev_bps: u16) -> Result<bool> {
    let Some(room) = room_ppm(b, dev_bps) else { return Ok(false) };
    Ok(le_up(p, b.mid_num, b.mid_den, room)? && ge_down(p, b.mid_num, b.mid_den, room)?)
}

// ---------------------------------------------------------------------- M2.7: where new liquidity may sit

/// Allowance for the rounding of `bin_price_q64` (repeated Q64.64 products, each rounded down): one
/// millionth, far above the real error and always applied in the LP's favour.
pub const PLACEMENT_ROUNDING_PPM: u32 = 1;

/// p (Q64.64) <= (num / den) * (1_000_000 - ppm) / 1_000_000
fn le_down(p: u128, num: u128, den: u128, ppm: u32) -> Result<bool> {
    let a = den.checked_mul(PPM).ok_or(VaultError::OracleMath)?;
    let r = num.checked_mul(PPM.checked_sub(ppm as u128).ok_or(VaultError::OracleMath)?).ok_or(VaultError::OracleMath)?;
    require!(r >> 64 == 0, VaultError::OracleMath);
    Ok(mul_wide(p, a) <= (r >> 64, r << 64))
}
/// p (Q64.64) >= (num / den) * (1_000_000 + ppm) / 1_000_000
fn ge_up(p: u128, num: u128, den: u128, ppm: u32) -> Result<bool> {
    let a = den.checked_mul(PPM).ok_or(VaultError::OracleMath)?;
    let r = num.checked_mul(PPM + ppm as u128).ok_or(VaultError::OracleMath)?;
    require!(r >> 64 == 0, VaultError::OracleMath);
    Ok(mul_wide(p, a) >= (r >> 64, r << 64))
}

/// M2.8: is the WHOLE external price band (mid -/+ both feeds' uncertainty, plus the rounding
/// allowance) no longer out of the range [lower, upper] on `side`, by the owner's margin, read the way
/// `side_of` reads the active bin? A price P lies in bin k when price(k) <= P < price(k + 1).
///   side +1 (out above): out when its bin >= upper + m, so "not out" = price(upper + m) > mid * (1 + u)
///   side -1 (out below): out when its bin <= lower - m, so "not out" = price(lower - m + 1) <= mid * (1 - u)
/// The far end of the band is used, so uncertainty never makes a price look back in range.
/// Used twice: a keeper rebalance must leave a position this test calls "not out" (it would otherwise
/// meet the owner's exit rule at once), and in a gated pool only this test, on fresh Pyth prices,
/// confirms that a position out of range has really recovered.
pub fn oracle_within(side: i8, lower: i32, upper: i32, margin: u16, bin_step: u16, b: &Band) -> Result<bool> {
    let m = margin.max(1) as i64;
    let ppm = b.conf_ppm.checked_add(PLACEMENT_ROUNDING_PPM).ok_or(VaultError::OracleMath)?;
    require!((ppm as u128) < PPM, VaultError::OracleMath);
    let price = |id: i64| -> Result<u128> {
        let id = i32::try_from(id).map_err(|_| error!(VaultError::OracleMath))?;
        bin_price_q64(bin_step, id).ok_or(error!(VaultError::OracleMath))
    };
    if side > 0 {
        Ok(!le_up(price(upper as i64 + m)?, b.mid_num, b.mid_den, ppm)?)
    } else if side < 0 {
        le_down(price(lower as i64 - m + 1)?, b.mid_num, b.mid_den, ppm)
    } else {
        Ok(true)
    }
}

/// M2.9: is the WHOLE external price band (mid -/+ both feeds' uncertainty, plus the rounding
/// allowance) still out of the range [lower, upper] on `side` by the owner's margin, read the way
/// `side_of` reads the active bin (bin k holds a price P when price(k) <= P < price(k + 1))?
///   side +1 (out above): out when its bin >= upper + m, so the band's BOTTOM must be in such a bin:
///            price(upper + m) <= mid * (1 - u)
///   side -1 (out below): out when its bin <= lower - m, so the band's TOP must be in such a bin:
///            price(lower - m + 1) > mid * (1 + u)
/// The near end of the band is used: uncertainty never makes a price look out of range. A band that
/// is neither wholly out (this) nor wholly back (`oracle_within`) is "unsure": a keeper exit is refused.
pub fn oracle_out(side: i8, lower: i32, upper: i32, margin: u16, bin_step: u16, b: &Band) -> Result<bool> {
    let m = margin.max(1) as i64;
    let ppm = b.conf_ppm.checked_add(PLACEMENT_ROUNDING_PPM).ok_or(VaultError::OracleMath)?;
    require!((ppm as u128) < PPM, VaultError::OracleMath);
    let price = |id: i64| -> Result<u128> {
        let id = i32::try_from(id).map_err(|_| error!(VaultError::OracleMath))?;
        bin_price_q64(bin_step, id).ok_or(error!(VaultError::OracleMath))
    };
    if side > 0 {
        le_down(price(upper as i64 + m)?, b.mid_num, b.mid_den, ppm)
    } else if side < 0 {
        Ok(!le_up(price(lower as i64 - m + 1)?, b.mid_num, b.mid_den, ppm)?)
    } else {
        Ok(false)
    }
}

/// M2.7 (owner's proposals 1 and 2): where a KEEPER rebalance may place the new liquidity, judged
/// against the VERIFIED external price (the Pyth band of Mode P), never against Meteora's active bin.
///
/// A keeper rebalance is always one-sided: the old range is wholly on one side of the price, so the
/// vault holds the token of that side only (claimed swap fees aside, see keeper_rebalance).
///   * `side` > 0 (price rose above the old range; the vault holds token Y): the new liquidity is BIDS,
///     token Y that buys token X. Every bin must be priced at or below the lowest price the oracle
///     allows: price(upper) <= mid * (1 - conf_x/Px - conf_y/Py - rounding). The highest bin is the
///     dearest, so checking it checks them all.
///   * `side` < 0 (price fell below the old range; the vault holds token X): ASKS, token X sold for
///     token Y, at or above the highest price the oracle allows: price(lower) >= mid * (1 + conf + rounding).
///   * Neither may include the active bin (`RangeIncludesActive`): a deposit into the active bin is
///     partly swapped by DLMM inside the bin and pays the composition fee to that bin's owners.
///     Bids sit strictly below it, asks strictly above it.
///   * Not further away than the owner's `edge_slack` from the best bin these rules allow
///     (`PlacementTooFar`): bids end within `slack` bins of the highest allowed bid bin
///     (= min(active - 1, highest bin priced <= the lower oracle bound)), asks start within `slack`
///     bins of the lowest allowed ask bin.
/// Prices are raw token Y per raw token X with both mints' decimals in (`oracle_band`), so the rule
/// holds whichever token is wrapped SOL. Uncertainty narrows what is allowed, it never widens it.
pub fn check_placement(side: i8, active: i32, lower: i32, upper: i32, slack: u16, bin_step: u16, b: &Band) -> Result<()> {
    let ppm = b.conf_ppm.checked_add(PLACEMENT_ROUNDING_PPM).ok_or(VaultError::OracleMath)?;
    require!((ppm as u128) < PPM, VaultError::OracleMath);
    let price = |id: i64| -> Result<u128> {
        let id = i32::try_from(id).map_err(|_| error!(VaultError::OracleMath))?;
        bin_price_q64(bin_step, id).ok_or(error!(VaultError::OracleMath))
    };
    let (a, lo, up, slack) = (active as i64, lower as i64, upper as i64, slack as i64);
    require!(lo <= up, VaultError::WidthOutOfPolicy);
    if side > 0 {
        require!(up < a, VaultError::RangeIncludesActive);
        require!(le_down(price(up)?, b.mid_num, b.mid_den, ppm)?, VaultError::PlacementVsReference);
        // one bin higher than the slack allows must be either the active bin (or above) or above the bound
        let probe = up + slack + 1;
        if probe < a {
            require!(!le_down(price(probe)?, b.mid_num, b.mid_den, ppm)?, VaultError::PlacementTooFar);
        }
    } else {
        require!(lo > a, VaultError::RangeIncludesActive);
        require!(ge_up(price(lo)?, b.mid_num, b.mid_den, ppm)?, VaultError::PlacementVsReference);
        let probe = lo - slack - 1;
        if probe > a {
            require!(!ge_up(price(probe)?, b.mid_num, b.mid_den, ppm)?, VaultError::PlacementTooFar);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------- the outcome of a rebalance

/// What the new position holds after the deposit, one entry per bin of its range, lowest bin
/// first: (token X, token Y) in base units.
pub type Holdings = Vec<(u64, u64)>;

/// The orders the new position has actually placed, as a whole:
///   * all its token Y (bids): effective buy price  = sum(y) / sum(y / p_bin)  <= mid * (1 + room)
///   * all its token X (asks): effective sell price = sum(x * p_bin) / sum(x)  >= mid * (1 - room)
/// where room = the deviation limit less the uncertainty of both feeds (the same rule as at the mark).
/// `first_price` = Q64.64 price of the lowest bin; `base` = Q64.64 of 1 + bin_step.
pub fn outcome_prices_ok(first_price: u128, first_inv: u128, base: u128, base_inv: u128, h: &[(u64, u64)], b: &Band, dev_bps: u16) -> Result<bool> {
    let (mut p, mut inv) = (first_price, first_inv);
    let (mut sum_x, mut sum_y) = (0u128, 0u128);
    // Q32 fixed point, rounded down: x-equivalent of the bids, y-equivalent of the asks
    let (mut bid_x32, mut ask_y32) = (0u128, 0u128);
    let q32 = |amount: u64, price: u128| -> Result<u128> {
        let w = mul_wide(amount as u128, price);
        require!(w.0 >> 32 == 0, VaultError::OracleMath);
        Ok((w.0 << 96) | (w.1 >> 32))
    };
    for (i, (x, y)) in h.iter().enumerate() {
        if i > 0 {
            p = mul_q64(p, base).ok_or(VaultError::OracleMath)?;
            inv = mul_q64(inv, base_inv).ok_or(VaultError::OracleMath)?;
        }
        if *y > 0 {
            sum_y += *y as u128;
            bid_x32 = bid_x32.checked_add(q32(*y, inv)?).ok_or(VaultError::OracleMath)?;
        }
        if *x > 0 {
            sum_x += *x as u128;
            ask_y32 = ask_y32.checked_add(q32(*x, p)?).ok_or(VaultError::OracleMath)?;
        }
    }
    let m = |a: u128, k: u128| a.checked_mul(k).ok_or(error!(VaultError::OracleMath));
    if sum_x == 0 && sum_y == 0 {
        return Ok(true);
    }
    let Some(room) = room_ppm(b, dev_bps) else { return Ok(false) };
    // sum_y / (bid_x32 / 2^32) <= mid_num / mid_den * (1_000_000 + room) / 1_000_000
    if sum_y > 0 {
        let l = mul_wide(m(sum_y, 1u128 << 32)?, m(b.mid_den, PPM)?);
        let r = mul_wide(bid_x32, m(b.mid_num, PPM + room as u128)?);
        if l > r {
            return Ok(false);
        }
    }
    // (ask_y32 / 2^32) / sum_x >= mid_num / mid_den * (1_000_000 - room) / 1_000_000
    if sum_x > 0 {
        let l = mul_wide(ask_y32, m(b.mid_den, PPM)?);
        let r = mul_wide(m(sum_x, 1u128 << 32)?, m(b.mid_num, PPM.saturating_sub(room as u128))?);
        if l < r {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Value conservation at the external mid price: what the vault owns after the rebalance (the new
/// position's holdings plus whatever stayed in the vault's token accounts, the booked performance
/// fee included) is worth at least what came out of the old position, less `loss_bps`.
/// value(x, y) = x * mid + y, compared as x * mid_num + y * mid_den on both sides.
pub fn value_conserved(before: (u128, u128), after: (u128, u128), b: &Band, loss_bps: u16) -> Result<bool> {
    let v = |x: u128, y: u128| add_wide(mul_wide(x, b.mid_num), mul_wide(y, b.mid_den)).ok_or(error!(VaultError::OracleMath));
    let l = mul_wide_small(v(after.0, after.1)?, 10_000).ok_or(VaultError::OracleMath)?;
    let r = mul_wide_small(v(before.0, before.1)?, 10_000u128.saturating_sub(loss_bps as u128)).ok_or(VaultError::OracleMath)?;
    Ok(l >= r)
}

/// M2.5: the new position really holds enough. Value at the external mid price of what it holds
/// (`held`) is at least `min_bps` of the value that came out of the old position net of the
/// performance fee (`net`), and it is not nothing. `min_bps` 0 never passes.
pub fn placed_enough(net: (u128, u128), held: (u128, u128), b: &Band, min_bps: u16) -> Result<bool> {
    if min_bps == 0 || (held.0 == 0 && held.1 == 0) {
        return Ok(false);
    }
    let v = |x: u128, y: u128| add_wide(mul_wide(x, b.mid_num), mul_wide(y, b.mid_den)).ok_or(error!(VaultError::OracleMath));
    let l = mul_wide_small(v(held.0, held.1)?, 10_000).ok_or(VaultError::OracleMath)?;
    let r = mul_wide_small(v(net.0, net.1)?, min_bps as u128).ok_or(VaultError::OracleMath)?;
    Ok(l >= r)
}

/// amount * share / supply, rounded down, without overflow: share and supply are cut to 64
/// significant bits together (the cut supply is rounded up, so the result is never overstated).
pub fn pro_rata(amount: u64, share: u128, supply: u128) -> u64 {
    if share == 0 || supply == 0 || amount == 0 {
        return 0;
    }
    if share >= supply {
        return amount;
    }
    let s = (128 - supply.leading_zeros()).saturating_sub(64);
    let (sh, su) = if s == 0 { (share, supply) } else { (share >> s, (supply >> s) + 1) };
    ((amount as u128 * sh) / su) as u64
}

pub fn base_q64(bin_step: u16) -> u128 {
    ONE_Q64 + ((bin_step as u128) << 64) / 10_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::bin_price_q64;

    const NOW: i64 = 1_800_000_000;
    fn lim() -> GateLimits {
        GateLimits { max_age_s: 30, future_tol_s: 2, max_feed_gap_s: 10, max_conf_bps: 50, max_dev_bps: 75, max_ema_dev_bps: 500, min_width: 5, min_placed_bps: 9_000 }
    }
    fn pv(price: i64, conf: u64, expo: i32) -> PriceView {
        PriceView { price, conf, expo, publish_time: NOW, ema_price: price }
    }
    fn acct(feed: &[u8; 32], p: &PriceView, level: u8) -> Vec<u8> {
        let mut d = vec![0u8; PRICE_UPDATE_LEN];
        d[0..8].copy_from_slice(&PRICE_UPDATE_DISC);
        d[40] = level;
        let o = if level == 1 { 41 } else { 42 };
        d[o..o + 32].copy_from_slice(feed);
        d[o + 32..o + 40].copy_from_slice(&p.price.to_le_bytes());
        d[o + 40..o + 48].copy_from_slice(&p.conf.to_le_bytes());
        d[o + 48..o + 52].copy_from_slice(&p.expo.to_le_bytes());
        d[o + 52..o + 60].copy_from_slice(&p.publish_time.to_le_bytes());
        d[o + 68..o + 76].copy_from_slice(&p.ema_price.to_le_bytes());
        d
    }
    fn e(r: Result<impl core::fmt::Debug>) -> anchor_lang::error::Error {
        r.unwrap_err()
    }

    #[test]
    fn price_account_layout_and_identity() {
        let feed = [7u8; 32];
        let p = PriceView { price: 10_681_618_006, conf: 3_019_632, expo: -8, publish_time: NOW - 3, ema_price: 10_659_542_600 };
        let d = acct(&feed, &p, 1);
        assert_eq!(parse_price(&PYTH_RECEIVER_ID, &d, &feed).unwrap(), p);
        assert_eq!(e(parse_price(&crate::ID, &d, &feed)), VaultError::OracleWrongOwner.into());
        // the older Pyth receiver is not trusted: the very same bytes, owned by it, are refused
        assert_eq!(e(parse_price(&PYTH_RECEIVER_OLD_ID, &d, &feed)), VaultError::OracleWrongOwner.into());
        assert_ne!(PYTH_RECEIVER_ID, PYTH_RECEIVER_OLD_ID);
        assert_eq!(PYTH_RECEIVER_ID.to_string(), "rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp");
        assert_eq!(e(parse_price(&PYTH_RECEIVER_ID, &d, &[8u8; 32])), VaultError::OracleWrongFeed.into());
        assert_eq!(e(parse_price(&PYTH_RECEIVER_ID, &d[..133], &feed)), VaultError::OracleBadAccount.into());
        let mut bad = d.clone();
        bad[0] ^= 1;
        assert_eq!(e(parse_price(&PYTH_RECEIVER_ID, &bad, &feed)), VaultError::OracleBadAccount.into());
        // Partial verification (level byte 0, then the number of signatures), even with 13 signatures
        let mut part = acct(&feed, &p, 0);
        part[41] = 13;
        assert_eq!(e(parse_price(&PYTH_RECEIVER_ID, &part, &feed)), VaultError::OracleNotFull.into());
        let mut odd = d.clone();
        odd[40] = 2;
        assert_eq!(e(parse_price(&PYTH_RECEIVER_ID, &odd, &feed)), VaultError::OracleNotFull.into());
    }

    #[test]
    fn freshness_one_second_each_side() {
        let l = lim();
        let y = pv(100_000_000, 10_000, -8);
        let at = |dt: i64| oracle_band(&PriceView { publish_time: NOW + dt, ..pv(200_000_000, 10_000, -8) }, &PriceView { publish_time: NOW + dt, ..y }, 6, 6, &l, NOW);
        assert!(at(-30).is_ok());
        assert_eq!(e(at(-31)), VaultError::OracleStale.into());
        assert!(at(0).is_ok() && at(1).is_ok() && at(2).is_ok());
        assert_eq!(e(at(3)), VaultError::OracleFromFuture.into());
        let l0 = GateLimits { future_tol_s: 0, ..l };
        let x1 = PriceView { publish_time: NOW + 1, ..pv(200_000_000, 10_000, -8) };
        assert_eq!(e(oracle_band(&x1, &PriceView { publish_time: NOW + 1, ..y }, 6, 6, &l0, NOW)), VaultError::OracleFromFuture.into());
        // the two feeds must come from nearly the same moment
        let gap = |a: i64, b: i64| oracle_band(&PriceView { publish_time: NOW - a, ..pv(200_000_000, 10_000, -8) }, &PriceView { publish_time: NOW - b, ..y }, 6, 6, &l, NOW);
        assert!(gap(0, 10).is_ok() && gap(10, 0).is_ok());
        assert_eq!(e(gap(0, 11)), VaultError::OracleFeedGap.into());
        assert_eq!(e(gap(11, 0)), VaultError::OracleFeedGap.into());
        // one leg stale is enough
        assert_eq!(e(oracle_band(&pv(200_000_000, 10_000, -8), &PriceView { publish_time: NOW - 31, ..y }, 6, 6, &GateLimits { max_feed_gap_s: 30, ..l }, NOW)), VaultError::OracleStale.into());
    }

    #[test]
    fn confidence_ema_and_bad_prices() {
        let l = lim();
        let y = pv(100_000_000, 0, -8);
        let x = |price: i64, conf: u64, ema: i64| PriceView { ema_price: ema, ..pv(price, conf, -8) };
        // 0.50% of 200_000_000 = 1_000_000
        assert!(oracle_band(&x(200_000_000, 1_000_000, 200_000_000), &y, 6, 6, &l, NOW).is_ok());
        assert_eq!(e(oracle_band(&x(200_000_000, 1_000_001, 200_000_000), &y, 6, 6, &l, NOW)), VaultError::OracleConfidence.into());
        assert_eq!(e(oracle_band(&y, &x(200_000_000, 1_000_001, 200_000_000), 6, 6, &l, NOW)), VaultError::OracleConfidence.into());
        assert_eq!(e(oracle_band(&x(200_000_000, u64::MAX, 200_000_000), &y, 6, 6, &l, NOW)), VaultError::OracleConfidence.into());
        // 5% from the moving average: 210_000_000 vs 200_000_000 passes, one unit more does not; same below
        assert!(oracle_band(&x(210_000_000, 0, 200_000_000), &y, 6, 6, &l, NOW).is_ok());
        assert_eq!(e(oracle_band(&x(210_000_001, 0, 200_000_000), &y, 6, 6, &l, NOW)), VaultError::OracleEmaDeviation.into());
        assert!(oracle_band(&x(190_000_000, 0, 200_000_000), &y, 6, 6, &l, NOW).is_ok());
        assert_eq!(e(oracle_band(&x(189_999_999, 0, 200_000_000), &y, 6, 6, &l, NOW)), VaultError::OracleEmaDeviation.into());
        assert_eq!(e(oracle_band(&y, &x(210_000_001, 0, 200_000_000), 6, 6, &l, NOW)), VaultError::OracleEmaDeviation.into());
        for bad in [0i64, -1, i64::MIN] {
            assert_eq!(e(oracle_band(&x(bad, 0, 200_000_000), &y, 6, 6, &l, NOW)), VaultError::OraclePriceInvalid.into());
            assert_eq!(e(oracle_band(&y, &x(bad, 0, 200_000_000), 6, 6, &l, NOW)), VaultError::OraclePriceInvalid.into());
        }
        assert_eq!(e(oracle_band(&x(200_000_000, 0, 0), &y, 6, 6, &l, NOW)), VaultError::OraclePriceInvalid.into());
    }

    fn q(v: f64) -> u128 {
        (v * ONE_Q64 as f64) as u128
    }

    #[test]
    fn band_with_exponents_decimals_and_inverted_pair() {
        let l = lim();
        // SOL 106.81618006 USD (expo -8, 9 decimals) against USDC 0.99989841 USD (expo -8, 6 decimals):
        // one lamport = 106.816 / 0.99990 * 10^(6-9) micro-USDC = 0.10682703 raw Y per raw X
        let sol = pv(10_681_618_006, 3_019_632, -8);
        let usdc = pv(99_989_841, 123_159, -8);
        let b = oracle_band(&sol, &usdc, 9, 6, &l, NOW).unwrap();
        let mid = b.mid_num as f64 / b.mid_den as f64;
        assert!((mid - 0.1068270326).abs() < 1e-9, "{mid}");
        // uncertainty: 3_019_632 / 10_681_618_006 = 282.7 ppm -> 283, 123_159 / 99_989_841 = 1231.7 ppm -> 1232
        assert_eq!(b.conf_ppm, 283 + 1232);
        // it uses up the limit: 15 bps (1500 ppm) is less than the uncertainty alone, so even the mid price fails
        assert!(!price_in_band(q(mid), &b, 15).unwrap());
        assert_eq!(room_ppm(&b, 15), None);
        // 16 bps leaves 85 ppm of room, 50 bps leaves 3485 ppm
        assert_eq!(room_ppm(&b, 16), Some(85));
        assert!(price_in_band(q(mid), &b, 16).unwrap());
        assert!(price_in_band(q(mid * 1.00008), &b, 16).unwrap());
        assert!(!price_in_band(q(mid * 1.00009), &b, 16).unwrap());
        assert!(price_in_band(q(mid * 1.00348), &b, 50).unwrap());
        assert!(!price_in_band(q(mid * 1.00349), &b, 50).unwrap());
        assert!(price_in_band(q(mid * 0.99652), &b, 50).unwrap());
        assert!(!price_in_band(q(mid * 0.99651), &b, 50).unwrap());
        // the pool created the other way round (X = USDC, Y = SOL): the feeds swap with the mints, the price is the inverse
        let inv = oracle_band(&usdc, &sol, 6, 9, &l, NOW).unwrap();
        let imid = inv.mid_num as f64 / inv.mid_den as f64;
        assert!((imid * mid - 1.0).abs() < 1e-12);
        assert_eq!(inv.conf_ppm, b.conf_ppm);
        assert!(price_in_band(q(1.0 / mid), &inv, 16).unwrap());
        // the feeds given the wrong way round for the pool: the price is off by mid^2, far outside any band
        assert!(!price_in_band(q(mid), &inv, 150).unwrap());
        // different exponents for the same price give the same band
        let sol5 = pv(10_681_618, 3_020, -5);
        let b5 = oracle_band(&sol5, &usdc, 9, 6, &l, NOW).unwrap();
        assert!(((b5.mid_num as f64 / b5.mid_den as f64) / mid - 1.0).abs() < 1e-7);
        // a wrong exponent (-7 instead of -8) or wrong decimals (8 instead of 9) is a factor 10: refused by the band
        let wrong_expo = oracle_band(&pv(10_681_618_006, 3_019_632, -7), &usdc, 9, 6, &l, NOW).unwrap();
        assert!(!price_in_band(q(mid), &wrong_expo, 150).unwrap());
        let wrong_dec = oracle_band(&sol, &usdc, 8, 6, &l, NOW).unwrap();
        assert!(!price_in_band(q(mid), &wrong_dec, 150).unwrap());
        // exponents that cannot be scaled: refused, not guessed
        assert_eq!(e(oracle_band(&pv(10_681_618_006, 0, 30), &usdc, 0, 9, &l, NOW)), VaultError::OracleMath.into());
        assert_eq!(e(oracle_band(&pv(i64::MAX, 0, 12), &pv(1, 0, -12), 0, 6, &l, NOW)), VaultError::OracleMath.into());
    }

    #[test]
    fn deviation_one_unit_each_side() {
        let l = lim();
        // price exactly 1, no confidence: the whole limit is room
        let b = oracle_band(&pv(100_000_000, 0, -8), &pv(100_000_000, 0, -8), 6, 6, &l, NOW).unwrap();
        let up = ONE_Q64 + ONE_Q64 / 10_000 * 75; // 1.0075 rounded down
        assert!(price_in_band(up, &b, 75).unwrap());
        assert!(!price_in_band(up + (1 << 51), &b, 75).unwrap());
        assert!(!price_in_band(up, &b, 74).unwrap());
        let down = ONE_Q64 - ONE_Q64 / 10_000 * 75 + (1 << 51);
        assert!(price_in_band(down, &b, 75).unwrap());
        assert!(!price_in_band(down - (1 << 52), &b, 75).unwrap());
        // bin step 25: bins 0..=2 are inside 75 bps (1.0025^3 = 1.007519 is not)
        for (id, ok) in [(0, true), (2, true), (3, false), (-2, true), (-3, true), (-4, false)] {
            assert_eq!(price_in_band(bin_price_q64(25, id).unwrap(), &b, 75).unwrap(), ok, "bin {id}");
        }
    }

    #[test]
    fn confidence_uses_up_the_deviation_limit() {
        let l = GateLimits { max_age_s: 10, max_conf_bps: 20, max_dev_bps: 50, ..lim() };
        let at = |ppm: u128| ONE_Q64 + ONE_Q64 / 1_000_000 * ppm;
        let below = |ppm: u128| ONE_Q64 - ONE_Q64 / 1_000_000 * ppm;
        // price 1; 0.10% confidence on X and 0.15% on Y use 2500 ppm of a 50 bps limit: 2500 ppm of room
        let b = oracle_band(&pv(100_000_000, 100_000, -8), &pv(100_000_000, 150_000, -8), 6, 6, &l, NOW).unwrap();
        assert_eq!((b.conf_ppm, room_ppm(&b, 50)), (2500, Some(2500)));
        assert!(price_in_band(at(2500), &b, 50).unwrap());
        assert!(!price_in_band(at(2501), &b, 50).unwrap());
        assert!(price_in_band(below(2499), &b, 50).unwrap());
        assert!(!price_in_band(below(2501), &b, 50).unwrap());
        // the same pool price with no confidence would have 5000 ppm: the uncertainty did not widen anything
        let tight = oracle_band(&pv(100_000_000, 0, -8), &pv(100_000_000, 0, -8), 6, 6, &l, NOW).unwrap();
        assert!(price_in_band(at(5000), &tight, 50).unwrap());
        assert!(!price_in_band(at(5001), &tight, 50).unwrap());
        assert!(!price_in_band(at(5000), &b, 50).unwrap());
        // both feeds at the gate's confidence limit (0.20% each): 0.10% is left
        let wide = oracle_band(&pv(100_000_000, 200_000, -8), &pv(100_000_000, 200_000, -8), 6, 6, &l, NOW).unwrap();
        assert_eq!(room_ppm(&wide, 50), Some(1000));
        assert!(price_in_band(at(1000), &wide, 50).unwrap());
        assert!(!price_in_band(at(1001), &wide, 50).unwrap());
        // one unit over the confidence limit is refused before any band exists
        assert_eq!(e(oracle_band(&pv(100_000_000, 200_001, -8), &pv(100_000_000, 0, -8), 6, 6, &l, NOW)), VaultError::OracleConfidence.into());
        // an owner limit smaller than the uncertainty: nothing passes, not even the mid price
        assert!(!price_in_band(ONE_Q64, &wide, 39).unwrap());
        assert!(price_in_band(ONE_Q64, &wide, 40).unwrap());
        // rounded up: a confidence of one unit in 10^8 costs a whole millionth
        assert_eq!(oracle_band(&pv(100_000_000, 1, -8), &pv(100_000_000, 1, -8), 6, 6, &l, NOW).unwrap().conf_ppm, 2);
        // the outcome check uses the same room: bids at bin 1 of a step-25 pool cost 0.25% over mid
        let bids = [(0u64, 1_000_000u64)];
        assert!(outcome(25, 1, &bids, &tight, 50)); // 5000 ppm of room, bin 1 = 1.0025
        assert!(!outcome(25, 1, &bids, &wide, 50)); // 1000 ppm of room
        assert!(!outcome(25, 2, &bids, &tight, 50)); // bin 2 = 1.00500625
        assert!(!outcome(25, 2, &bids, &b, 50));
        let asks = [(1_000_000u64, 0u64)];
        assert!(outcome(25, -1, &asks, &tight, 50));
        assert!(!outcome(25, -1, &asks, &wide, 50));
        assert!(!outcome(25, 0, &asks, &wide, 39));
    }

    #[test]
    fn wide_math() {
        assert_eq!(mul_wide(u128::MAX, u128::MAX), (u128::MAX - 1, 1));
        assert_eq!(mul_wide(1 << 100, 1 << 100), (1 << 72, 0));
        assert_eq!(mul_wide(12345, 67890), (0, 838102050));
        assert_eq!(mul_wide_small((1, 5), 10), Some((10, 50)));
        assert_eq!(mul_wide_small((u128::MAX, 0), 2), None);
        assert_eq!(add_wide((0, u128::MAX), (0, 1)), Some((1, 0)));
        assert_eq!(add_wide((u128::MAX, u128::MAX), (0, 1)), None);
    }

    fn outcome(step: u16, lower: i32, h: &[(u64, u64)], b: &Band, dev: u16) -> bool {
        outcome_prices_ok(bin_price_q64(step, lower).unwrap(), bin_price_q64(step, -lower).unwrap(), base_q64(step), bin_price_q64(step, -1).unwrap(), h, b, dev).unwrap()
    }

    #[test]
    fn outcome_effective_prices() {
        let l = lim();
        let b = oracle_band(&pv(100_000_000, 0, -8), &pv(100_000_000, 0, -8), 6, 6, &l, NOW).unwrap(); // fair price 1 = bin 0
        // bids spread over bins -9..0: effective buy price below 1
        let bids: Vec<(u64, u64)> = (0..10).map(|_| (0, 1_000_000)).collect();
        assert!(outcome(25, -9, &bids, &b, 0));
        // the same bids ten bins higher (1..10): average about 1.014, outside 75 bps, inside 150
        assert!(!outcome(25, 1, &bids, &b, 75));
        assert!(outcome(25, 1, &bids, &b, 150));
        // bids in -6..3 reach bin 3 (1.0075 is over a 75 bps limit as a single bin) but the whole is bought below 1.0075
        assert!(outcome(25, -6, &bids, &b, 75));
        // asks: selling ten bins below fair is refused, at or above fair is fine
        let asks: Vec<(u64, u64)> = (0..10).map(|_| (1_000_000, 0)).collect();
        assert!(outcome(25, 0, &asks, &b, 0));
        assert!(!outcome(25, -10, &asks, &b, 75));
        // weights matter: 99% of the bids at bin 10, 1% at bin -9
        let mut skew = vec![(0u64, 10_000u64); 20];
        skew[19] = (0, 20_000_000);
        assert!(!outcome(25, -9, &skew, &b, 75));
        // dust (1 unit) does not break the arithmetic
        assert!(outcome(25, -9, &[(0, 1)], &b, 0));
        assert!(outcome(25, 0, &[(1, 0)], &b, 0));
        // empty position: nothing to judge
        assert!(outcome(25, 0, &[(0, 0); 5], &b, 0));
    }

    #[test]
    fn outcome_value() {
        let l = lim();
        // X worth 2 Y
        let b = oracle_band(&pv(200_000_000, 0, -8), &pv(100_000_000, 0, -8), 6, 6, &l, NOW).unwrap();
        assert!(value_conserved((0, 1_000_000), (0, 1_000_000), &b, 0).unwrap());
        assert!(!value_conserved((0, 1_000_000), (0, 999_999), &b, 0).unwrap());
        // 100 Y became 49 X: worth 98, a 2% loss
        assert!(!value_conserved((0, 100_000), (49_000, 0), &b, 199).unwrap());
        assert!(value_conserved((0, 100_000), (49_000, 0), &b, 200).unwrap());
        assert!(value_conserved((0, 100_000), (50_000, 0), &b, 0).unwrap());
        assert!(value_conserved((u64::MAX as u128, u64::MAX as u128), (u64::MAX as u128, u64::MAX as u128), &b, 0).unwrap());
    }

    #[test]
    fn placement_against_the_external_price() {
        let one = Band { mid_num: 1, mid_den: 1, conf_ppm: 0 }; // fair price = bin 0 of any bin step
        let pl = |side: i8, active: i32, lo: i32, up: i32, slack: u16, b: &Band| check_placement(side, active, lo, up, slack, 25, b);
        // BIDS (price rose above the old range; the vault holds token Y)
        assert!(pl(1, 0, -10, -1, 0, &one).is_ok());
        assert_eq!(e(pl(1, 0, -10, 0, 0, &one)), VaultError::RangeIncludesActive.into());
        assert_eq!(e(pl(1, 0, -10, 3, 9, &one)), VaultError::RangeIncludesActive.into());
        assert_eq!(e(pl(1, 0, -10, -2, 0, &one)), VaultError::PlacementTooFar.into());
        assert!(pl(1, 0, -10, -2, 1, &one).is_ok());
        // a bid exactly AT the fair price is refused: the rounding allowance is in the LP's favour
        assert_eq!(e(pl(1, 1, -10, 0, 9, &one)), VaultError::PlacementVsReference.into());
        // the pool held 4 bins ABOVE the fair price: bids must still stop below the fair price, not below the pool
        assert_eq!(e(pl(1, 4, -6, 3, 0, &one)), VaultError::PlacementVsReference.into());
        assert_eq!(e(pl(1, 4, -6, 0, 9, &one)), VaultError::PlacementVsReference.into());
        assert!(pl(1, 4, -6, -1, 0, &one).is_ok());
        assert_eq!(e(pl(1, 4, -6, -2, 0, &one)), VaultError::PlacementTooFar.into());
        // the pool BELOW the fair price on this side: below the active bin is below the fair price too
        assert!(pl(1, -3, -10, -4, 0, &one).is_ok());
        assert_eq!(e(pl(1, -3, -10, -3, 0, &one)), VaultError::RangeIncludesActive.into());
        // uncertainty narrows: 0.50% of confidence; bin -1 = 0.99751, bin -2 = 0.99502, bin -3 = 0.99254
        let unsure = Band { conf_ppm: 5_000, ..one };
        assert_eq!(e(pl(1, 0, -10, -1, 0, &unsure)), VaultError::PlacementVsReference.into());
        assert_eq!(e(pl(1, 0, -10, -2, 0, &unsure)), VaultError::PlacementVsReference.into());
        assert!(pl(1, 0, -10, -3, 0, &unsure).is_ok());
        assert_eq!(e(pl(1, 0, -10, -4, 0, &unsure)), VaultError::PlacementTooFar.into());
        // ASKS (price fell below the old range; the vault holds token X)
        assert!(pl(-1, 0, 1, 10, 0, &one).is_ok());
        assert_eq!(e(pl(-1, 0, 0, 10, 0, &one)), VaultError::RangeIncludesActive.into());
        assert_eq!(e(pl(-1, 0, -3, 10, 9, &one)), VaultError::RangeIncludesActive.into());
        assert_eq!(e(pl(-1, 0, 2, 10, 0, &one)), VaultError::PlacementTooFar.into());
        assert!(pl(-1, 0, 2, 10, 1, &one).is_ok());
        assert_eq!(e(pl(-1, -1, 0, 10, 9, &one)), VaultError::PlacementVsReference.into());
        // the pool held 4 bins BELOW the fair price: asks must still start above the fair price
        assert_eq!(e(pl(-1, -4, -3, 6, 0, &one)), VaultError::PlacementVsReference.into());
        assert!(pl(-1, -4, 1, 10, 0, &one).is_ok());
        assert_eq!(e(pl(-1, -4, 2, 10, 0, &one)), VaultError::PlacementTooFar.into());
        assert_eq!(e(pl(-1, 0, 1, 10, 0, &unsure)), VaultError::PlacementVsReference.into());
        // bin 2 = 1.0050063 >= 1.005 + rounding: allowed; bin 3 is then one bin too far
        assert!(pl(-1, 0, 2, 10, 0, &unsure).is_ok());
        assert_eq!(e(pl(-1, 0, 3, 10, 0, &unsure)), VaultError::PlacementTooFar.into());
    }

    /// M2.8: the far end of the external band against the owner's margin, the way side_of reads bins.
    #[test]
    fn oracle_within_reads_the_far_end() {
        let one = Band { mid_num: 1, mid_den: 1, conf_ppm: 0 }; // fair price exactly at bin 0's price
        let w = |side: i8, lo: i32, up: i32, m: u16, b: &Band| oracle_within(side, lo, up, m, 25, b).unwrap();
        // out ABOVE [-10, -1]: with margin 1 the fair price (bin 0) is out; margin 2 holds it
        assert!(!w(1, -10, -1, 1, &one));
        assert!(!w(1, -10, -1, 0, &one)); // a margin of 0 reads as 1, like side_of
        assert!(w(1, -10, -1, 2, &one));
        // 0.50% uncertainty: the band's top (1.005) is in bin 1, so margin 2 is not enough, 3 is
        let unsure = Band { conf_ppm: 5_000, ..one };
        assert!(!w(1, -10, -1, 2, &unsure));
        assert!(w(1, -10, -1, 3, &unsure));
        // out BELOW [1, 10]: the band's bottom (1 - 1 ppm rounding) is in bin -1, so margin 3 is needed
        assert!(!w(-1, 1, 10, 1, &one));
        assert!(!w(-1, 1, 10, 2, &one));
        assert!(w(-1, 1, 10, 3, &one));
        // 0.50%: the bottom 0.995 is in bin -3 (0.99254 <= 0.995 < 0.99502): margin 4 refused, 5 holds
        assert!(!w(-1, 1, 10, 4, &unsure));
        assert!(w(-1, 1, 10, 5, &unsure));
        // the same margins read through side_of on the band's far bin agree
        assert_eq!(crate::policy::side_of(0, -10, -1, 2), 0);
        assert_eq!(crate::policy::side_of(0, -10, -1, 1), 1);
        assert_eq!(crate::policy::side_of(-3, 1, 10, 4), -1);
        assert_eq!(crate::policy::side_of(-3, 1, 10, 5), 0);
        // side 0 is never "out"
        assert!(w(0, 1, 10, 1, &unsure));
    }

    /// M2.9: the near end of the external band against the owner's margin: wholly out, or not.
    #[test]
    fn oracle_out_reads_the_near_end() {
        let s = 25u16; // 0.25% bin step
        let f = |id: i32| (1.0 + s as f64 / 10_000.0).powi(id);
        // a fair price in the middle of bin k: f(k) * (1 + step / 2)
        let at = |k: i32, conf_ppm: u32| {
            let mid = f(k) * (1.0 + s as f64 / 20_000.0);
            Band { mid_num: (mid * 1e12) as u128, mid_den: 1_000_000_000_000, conf_ppm }
        };
        let o = |side: i8, lo: i32, up: i32, m: u16, b: &Band| oracle_out(side, lo, up, m, s, b).unwrap();
        let w = |side: i8, lo: i32, up: i32, m: u16, b: &Band| oracle_within(side, lo, up, m, s, b).unwrap();
        // range [-10, -1], out ABOVE. Fair price in bin 1: out by margin 1 and 2 (bin >= upper + m), not by 3
        let b1 = at(1, 0);
        assert!(o(1, -10, -1, 1, &b1) && o(1, -10, -1, 2, &b1) && !o(1, -10, -1, 3, &b1));
        assert!(!w(1, -10, -1, 2, &b1) && w(1, -10, -1, 3, &b1)); // margin 3: wholly back by that margin
        // 0.20% uncertainty (more than half a bin): the band's bottom falls into bin 0, so margin 2 is no longer certain
        let u1 = at(1, 2_000);
        assert!(o(1, -10, -1, 1, &u1) && !o(1, -10, -1, 2, &u1));
        // ...and not wholly back either: unsure, both say no
        assert!(!w(1, -10, -1, 2, &u1));
        // a fair price exactly at a bin's edge price(k): the rounding allowance puts the band's bottom below it
        let edge = Band { mid_num: 1, mid_den: 1, conf_ppm: 0 }; // price(0) = 1
        assert!(!o(1, -10, -1, 1, &edge)); // bin 0 = upper + 1 but the band reaches just under it: refused
        assert!(o(1, -10, -2, 1, &edge)); // one bin further: out
        // range [1, 10], out BELOW. Fair price in bin -1: out by margin 1 and 2 (bin <= lower - m), not by 3
        let bm = at(-1, 0);
        assert!(o(-1, 1, 10, 1, &bm) && o(-1, 1, 10, 2, &bm) && !o(-1, 1, 10, 3, &bm));
        let um = at(-1, 2_000); // the band's top reaches bin 0
        assert!(o(-1, 1, 10, 1, &um) && !o(-1, 1, 10, 2, &um));
        // the wrong side is never out; side 0 is never out
        assert!(!o(-1, -10, -1, 1, &b1));
        assert!(!o(1, 1, 10, 1, &bm));
        assert!(!o(0, -10, -1, 1, &b1));
        // never both: wholly out and wholly back exclude each other for every margin and uncertainty tried
        for k in -6..6 {
            for c in [0u32, 500, 2_000, 5_000, 20_000] {
                for m in 0..6u16 {
                    for side in [-1i8, 1] {
                        let b = at(k, c);
                        assert!(!(o(side, -2, 2, m, &b) && w(side, -2, 2, m, &b)), "k {k} c {c} m {m} side {side}");
                    }
                }
            }
        }
    }

    /// Both orientations of a SOL / USDC pair from real feed values: the allowed bins land on the right
    /// side of the external price whichever token is wrapped SOL.
    #[test]
    fn placement_both_orientations() {
        let l = lim();
        let sol = pv(150_00000000, 0, -8);
        let usdc = pv(1_00000000, 0, -8);
        for (px, py, dx, dy) in [(&sol, &usdc, 9u8, 6u8), (&usdc, &sol, 6, 9)] {
            let b = oracle_band(px, py, dx, dy, &l, NOW).unwrap();
            let mid = b.mid_num as f64 / b.mid_den as f64; // 0.15 (SOL is X) or 6.667 (SOL is Y), raw Y per raw X
            for step in [1u16, 10, 25, 100] {
                let f = |id: i32| (1.0 + step as f64 / 10_000.0).powi(id);
                let fair = (mid.ln() / (1.0 + step as f64 / 10_000.0).ln()).floor() as i32; // f(fair) <= mid < f(fair + 1)
                assert!(f(fair) <= mid && mid < f(fair + 1));
                let bid_top = if f(fair) < mid * (1.0 - 2e-6) { fair } else { fair - 1 };
                // bids: the active bin well above; ok at bid_top, refused one bin higher
                assert!(check_placement(1, bid_top + 50, bid_top - 5, bid_top, 0, step, &b).is_ok(), "step {step} mid {mid}");
                assert_eq!(e(check_placement(1, bid_top + 50, bid_top - 4, bid_top + 1, 0, step, &b)), VaultError::PlacementVsReference.into());
                // asks: the active bin well below; ok from fair + 1, refused one bin lower
                let ask_lo = if f(fair + 1) > mid * (1.0 + 2e-6) { fair + 1 } else { fair + 2 };
                assert!(check_placement(-1, ask_lo - 50, ask_lo, ask_lo + 5, 0, step, &b).is_ok(), "step {step} mid {mid}");
                assert_eq!(e(check_placement(-1, ask_lo - 50, ask_lo - 1, ask_lo + 4, 0, step, &b)), VaultError::PlacementVsReference.into());
            }
        }
    }

    #[test]
    fn placed_enough_one_unit_each_side() {
        let l = lim();
        // X worth 2 Y
        let b = oracle_band(&pv(200_000_000, 0, -8), &pv(100_000_000, 0, -8), 6, 6, &l, NOW).unwrap();
        // 1,000,000 Y came out net; the position holds 900,000 Y: exactly 90%
        assert!(placed_enough((0, 1_000_000), (0, 900_000), &b, 9_000).unwrap());
        assert!(!placed_enough((0, 1_000_000), (0, 899_999), &b, 9_000).unwrap());
        assert!(!placed_enough((0, 1_000_000), (0, 900_000), &b, 9_001).unwrap());
        // across tokens, at the external price: 450,000 X are worth 900,000 Y
        assert!(placed_enough((0, 1_000_000), (450_000, 0), &b, 9_000).unwrap());
        assert!(!placed_enough((0, 1_000_000), (449_999, 1), &b, 9_000).unwrap());
        assert!(placed_enough((500_000, 0), (0, 900_000), &b, 9_000).unwrap());
        // nothing held never passes, whatever came out; dust passes a "not zero" test but not a real minimum
        assert!(!placed_enough((0, 1_000_000), (0, 0), &b, 1).unwrap());
        assert!(!placed_enough((0, 0), (0, 0), &b, 1).unwrap());
        assert!(placed_enough((0, 1_000_000), (0, 100), &b, 1).unwrap());
        assert!(!placed_enough((0, 1_000_000), (0, 99), &b, 1).unwrap());
        assert!(!placed_enough((0, 1_000_000), (0, 100), &b, 9_000).unwrap());
        // a minimum of zero is "not set": it refuses
        assert!(!placed_enough((0, 1_000_000), (0, 1_000_000), &b, 0).unwrap());
        assert!(placed_enough((0, 1_000_000), (0, 1_000_000), &b, 10_000).unwrap());
        assert!(placed_enough((u64::MAX as u128, u64::MAX as u128), (u64::MAX as u128, u64::MAX as u128), &b, 10_000).unwrap());
    }

    #[test]
    fn pro_rata_never_overstates() {
        assert_eq!(pro_rata(1_000, 1, 3), 333);
        assert_eq!(pro_rata(1_000, 3, 3), 1_000);
        assert_eq!(pro_rata(1_000, 0, 3), 0);
        assert_eq!(pro_rata(1_000, 5, 0), 0);
        let big = 1u128 << 120;
        assert_eq!(pro_rata(u64::MAX, big, big), u64::MAX);
        let half = pro_rata(1_000_000_000, big / 2, big);
        assert!(half <= 500_000_000 && half >= 499_999_999);
        let third = pro_rata(u64::MAX, big / 3, big);
        assert!(third <= u64::MAX / 3 && third >= u64::MAX / 3 - 4);
    }

    #[test]
    fn gate_limits_caps() {
        let l = lim();
        assert!(l.validate(25).is_ok());
        assert!(GateLimits { max_dev_bps: 76, ..l }.validate(25).is_err()); // bin step + 50
        assert!(GateLimits { max_dev_bps: 150, ..l }.validate(100).is_ok());
        assert!(GateLimits { max_dev_bps: 151, ..l }.validate(400).is_err());
        assert!(GateLimits { max_dev_bps: 0, ..l }.validate(25).is_err());
        assert!(GateLimits { max_age_s: 31, ..l }.validate(25).is_err());
        assert!(GateLimits { max_age_s: 0, ..l }.validate(25).is_err());
        assert!(GateLimits { future_tol_s: 3, ..l }.validate(25).is_err());
        assert!(GateLimits { future_tol_s: 0, ..l }.validate(25).is_ok());
        assert!(GateLimits { max_conf_bps: 101, ..l }.validate(25).is_err());
        assert!(GateLimits { max_ema_dev_bps: 1_001, ..l }.validate(25).is_err());
        assert!(GateLimits { max_ema_dev_bps: 0, ..l }.validate(25).is_err());
        assert!(GateLimits { max_feed_gap_s: 31, ..l }.validate(25).is_err());
        // M2.5: zero is a legal gate value (it refuses every keeper rebalance), more than a position can be is not
        assert!(GateLimits { min_width: 0, min_placed_bps: 0, ..l }.validate(25).is_ok());
        assert!(GateLimits { min_width: 70, min_placed_bps: 10_000, ..l }.validate(25).is_ok());
        assert!(GateLimits { min_width: 71, ..l }.validate(25).is_err());
        assert!(GateLimits { min_placed_bps: 10_001, ..l }.validate(25).is_err());
        assert_eq!(l.try_to_vec().unwrap().len(), GateLimits::SIZE);
        let mut g = PoolGate { layout: GATE_LAYOUT, bump: 0, lb_pair: Pubkey::default(), mint_x: Pubkey::default(), mint_y: Pubkey::default(), decimals_x: 6, decimals_y: 6, bin_step: 25, feed_x: [0; 32], feed_y: [0; 32], enabled: false, revoked: false, valid_until: NOW, limits: l, reserved: [0; GATE_RESERVED] };
        assert_eq!(g.check_open(NOW).unwrap_err(), VaultError::GateDisabled.into());
        g.enabled = true;
        assert!(g.check_open(NOW).is_ok());
        assert_eq!(g.check_open(NOW + 1).unwrap_err(), VaultError::GateExpired.into());
        g.revoked = true;
        assert_eq!(g.check_open(NOW).unwrap_err(), VaultError::GateRevoked.into());
        assert_eq!(g.try_to_vec().unwrap().len() + 8, PoolGate::SPACE);
    }
}

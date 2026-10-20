//! M2.3: the versioned layout of a PositionRecord and the conversion of every older layout to it.
//!
//! Account data length (8-byte discriminator included) of a PositionRecord by release:
//!   M2    279 bytes   prefix 147 | Policy  89 | AutoState 43
//!   M2.1  327 bytes   prefix 147 | Policy  97 | AutoState 83
//!   M2.2  347 bytes   prefix 147 | Policy 101 | AutoState 99
//!   M2.3  503 bytes   prefix 147 | layout 1 | Policy 111 | AutoState 180 | reserved 64   (layout 3, local only)
//!   M2.5  503 bytes   prefix 147 | layout 1 | Policy 113 | AutoState 188 | reserved 54   (layout 4)
//!   M2.8  503 bytes   prefix 147 | layout 1 | Policy 113 | AutoState 205 | reserved 37   (layout 4)
//! M2.8 took 17 reserved bytes (exit run side, pending recovery time, last observation time) and kept
//! layout 4: in a layout-4 record written before M2.8 those bytes are zero, and zero means "no run
//! side known", for which the exit wait counts from the mark itself (never earlier).
//! The 147-byte prefix (discriminator, vault, lb_pair, position, flags, paused, version, bump,
//! origin) is the same in all of them. From M2.3 on the record carries `layout` and reserved
//! bytes, so a later release can add fields without changing the size: M2.5 took 10 of them (the
//! owner's minimum placed share, the out-of-range-since time) and the record is still 503 bytes.
//! Layout 3 was never written outside a local validator; no conversion from it exists and a
//! keeper action on such a record is refused (RecordLayout).
//!
//! A position is never closed to migrate it. `convert` keeps every field an older record has and
//! leaves every limit it does not have at zero, and a zero limit means "that automatic action is
//! refused" until the owner signs a new policy.

use crate::policy::{AutoState, Policy};

/// Value of PositionRecord.layout written by this release.
pub const RECORD_LAYOUT: u8 = 4;
/// Reserved bytes at the end of a record of this layout.
pub const RECORD_RESERVED: usize = 37;
pub const PREFIX: usize = 147;
pub const LEN_M2: usize = 279;
pub const LEN_M21: usize = 327;
pub const LEN_M22: usize = 347;
pub const LEN_M23: usize = PREFIX + 1 + Policy::SIZE + AutoState::SIZE + RECORD_RESERVED;
const VERSION_AT: usize = 106;
/// AutoState bytes that mean the same in every layout: everything through `rent_spent`.
const ST_COMMON: usize = 83;

const LAST_REBALANCE_AT: usize = 22;
const MARK_TIME_AT: usize = 30;
/// AutoState: 83 common bytes | mark_oracle 1 | ring 8 x 12 | oor_since 8
const RING_AT: usize = ST_COMMON + 1;
const OOR_SINCE_AT: usize = RING_AT + 12 * crate::policy::SHIFT_RING;
/// M2.8: oor_side 1 | back_since 8 | oor_seen 8, right after oor_since
const OOR_SIDE_AT: usize = OOR_SINCE_AT + 8;
const OOR_SEEN_AT: usize = OOR_SIDE_AT + 1 + 8;
const MARK_SIDE_AT: usize = 42;
/// A keeper rebalance made by an older release has no recorded size. Inside the rolling window it
/// counts as more than any budget an owner can sign.
pub const UNKNOWN_MOVE: u32 = u32::MAX;

/// The M2.3 bytes of an older record. None = not an older layout this release knows.
///   * identity (vault, pool, position, origin, bump), flags and pause: copied
///   * policy: old bytes first (the M2.3 Policy only appended fields), every field the old layout
///     does not have is zero = the automatic action that needs it is refused. Nothing gets looser:
///     the M2.2 `max_shift_per_day` (distance from the first range of the day) becomes the rolling
///     `max_shift_day` (every move added up), which is the stricter reading of the same number
///   * state: counters, cooldown times, `rent_spent` and the mark as they were; `mark_oracle` is 0,
///     so an old mark can never authorise a rebalance; `oor_since` is the old mark's own time, so
///     an out-of-range exit the owner signed is due exactly when the old release would have allowed
///     it: not a second earlier, and the conversion does not start the wait again
///   * rolling window: an older record does not say how far its last keeper rebalance moved the
///     range (M2.2 kept only the first range of the day). If that rebalance is less than 24 hours
///     old at `now`, it is entered with UNKNOWN_MOVE: no keeper rebalance until it is 24 hours old,
///     whatever the owner signs. The budget is never handed out fresh
///   * version + 1, like every state change
pub fn convert(old: &[u8], now: i64) -> Option<Vec<u8>> {
    let (pol_len, st_len) = match old.len() {
        LEN_M2 => (89, 43),
        LEN_M21 => (97, 83),
        LEN_M22 => (101, 99),
        _ => return None,
    };
    let mut out = vec![0u8; LEN_M23];
    out[..PREFIX].copy_from_slice(&old[..PREFIX]);
    let version = u64::from_le_bytes(old[VERSION_AT..VERSION_AT + 8].try_into().unwrap()).checked_add(1)?;
    out[VERSION_AT..VERSION_AT + 8].copy_from_slice(&version.to_le_bytes());
    out[PREFIX] = RECORD_LAYOUT;
    let p = PREFIX + 1;
    out[p..p + pol_len].copy_from_slice(&old[PREFIX..PREFIX + pol_len]);
    let s = p + Policy::SIZE;
    let keep = st_len.min(ST_COMMON);
    let old_st = PREFIX + pol_len;
    out[s..s + keep].copy_from_slice(&old[old_st..old_st + keep]);
    let last = i64::from_le_bytes(old[old_st + LAST_REBALANCE_AT..old_st + LAST_REBALANCE_AT + 8].try_into().unwrap());
    // also when the stamp is in the future: it cannot be shown to be older than 24 hours
    if last != 0 && now.saturating_sub(last) < crate::SECONDS_PER_DAY {
        let ring = s + RING_AT;
        out[ring..ring + 8].copy_from_slice(&last.to_le_bytes());
        out[ring + 8..ring + 12].copy_from_slice(&UNKNOWN_MOVE.to_le_bytes());
    }
    // the mark's time, in every older layout at the same place (0 = no mark)
    out[s + OOR_SINCE_AT..s + OOR_SINCE_AT + 8].copy_from_slice(&old[old_st + MARK_TIME_AT..old_st + MARK_TIME_AT + 8]);
    // M2.8: the run is the old mark's own: its side, and its time as the last observation. No mark =
    // no run (all zero). Nothing about a recovery is invented: back_since stays 0.
    let mark_time = i64::from_le_bytes(old[old_st + MARK_TIME_AT..old_st + MARK_TIME_AT + 8].try_into().unwrap());
    if mark_time != 0 {
        out[s + OOR_SIDE_AT] = old[old_st + MARK_SIDE_AT];
        out[s + OOR_SEEN_AT..s + OOR_SEEN_AT + 8].copy_from_slice(&mark_time.to_le_bytes());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PositionRecord;
    use anchor_lang::prelude::*;
    use anchor_lang::{AccountDeserialize, Discriminator};

    // The older layouts, written out field by field exactly as those releases serialised them.
    #[derive(AnchorSerialize, Clone, Copy)]
    struct PolicyM2 {
        min_claim_x: u64, min_claim_y: u64, max_cost_bps: u16, compound_cooldown: u32, max_compounds_per_day: u16, min_bin: i32, max_bin: i32, direction: u8,
        min_width: u16, max_width: u16, edge_slack: u16, max_slippage_bins: u16, rebalance_cooldown: u32, max_rebalances_per_day: u16, oor_margin_bins: u16,
        oor_wait: u32, mark_ttl: u32, max_marks_per_day: u16, strategy: u8, max_action_cost: u64, max_priority_fee: u64, exit_on_oor: bool, exit_wait: u32, exit_after: i64,
    }
    #[derive(AnchorSerialize, Clone, Copy)]
    struct StateM2 {
        day: i64, compounds_today: u16, rebalances_today: u16, marks_today: u16, last_compound: i64, last_rebalance: i64, mark_time: i64, mark_active_id: i32, mark_side: i8,
    }
    #[derive(AnchorSerialize, Clone, Copy)]
    struct Prefix {
        vault: Pubkey, lb_pair: Pubkey, position: Pubkey, flags: u8, paused: bool, version: u64, bump: u8, origin: Pubkey,
    }

    const NOW: i64 = 1_800_000_000;
    fn sample() -> (Prefix, PolicyM2, StateM2) {
        (
            Prefix { vault: Pubkey::new_from_array([1; 32]), lb_pair: Pubkey::new_from_array([2; 32]), position: Pubkey::new_from_array([3; 32]), flags: 5, paused: true, version: (7u64 << 32) + 41, bump: 253, origin: Pubkey::new_from_array([4; 32]) },
            PolicyM2 {
                min_claim_x: 11, min_claim_y: 12, max_cost_bps: 500, compound_cooldown: 13, max_compounds_per_day: 14, min_bin: -15, max_bin: 16, direction: 3, min_width: 17, max_width: 18, edge_slack: 19,
                max_slippage_bins: 20, rebalance_cooldown: 21, max_rebalances_per_day: 22, oor_margin_bins: 23, oor_wait: 24, mark_ttl: 25, max_marks_per_day: 26, strategy: 6, max_action_cost: 27,
                max_priority_fee: 28, exit_on_oor: true, exit_wait: 29, exit_after: 30,
            },
            StateM2 { day: 20_000, compounds_today: 1, rebalances_today: 2, marks_today: 3, last_compound: 4, last_rebalance: NOW - 86_400, mark_time: 6, mark_active_id: -7, mark_side: -1 },
        )
    }

    fn old_bytes(extra_policy: &[u8], extra_state: &[u8]) -> Vec<u8> {
        let (pre, pol, st) = sample();
        let mut d = PositionRecord::DISCRIMINATOR.to_vec();
        d.extend(pre.try_to_vec().unwrap());
        d.extend(pol.try_to_vec().unwrap());
        d.extend_from_slice(extra_policy);
        d.extend(st.try_to_vec().unwrap());
        d.extend_from_slice(extra_state);
        d
    }

    fn check(old: Vec<u8>, rent_budget: u64, shift: (u16, u16), fp: [u8; 32], rent_spent: u64) {
        let (pre, pol, st) = sample();
        let new = convert(&old, NOW).unwrap();
        assert_eq!(new.len(), LEN_M23);
        assert_eq!(new.len(), PositionRecord::SPACE);
        let r = PositionRecord::try_deserialize(&mut &new[..]).unwrap();
        assert_eq!((r.vault, r.lb_pair, r.position, r.flags, r.paused, r.bump, r.origin), (pre.vault, pre.lb_pair, pre.position, pre.flags, pre.paused, pre.bump, pre.origin));
        assert_eq!(r.version, pre.version + 1);
        assert_eq!(r.layout, RECORD_LAYOUT);
        assert_eq!(r.reserved, [0u8; RECORD_RESERVED]);
        let p = r.policy;
        assert_eq!((p.min_claim_x, p.min_claim_y, p.max_cost_bps, p.compound_cooldown, p.max_compounds_per_day), (pol.min_claim_x, pol.min_claim_y, pol.max_cost_bps, pol.compound_cooldown, pol.max_compounds_per_day));
        assert_eq!((p.min_bin, p.max_bin, p.direction, p.min_width, p.max_width, p.edge_slack, p.max_slippage_bins), (pol.min_bin, pol.max_bin, pol.direction, pol.min_width, pol.max_width, pol.edge_slack, pol.max_slippage_bins));
        assert_eq!((p.rebalance_cooldown, p.max_rebalances_per_day, p.oor_margin_bins, p.oor_wait, p.mark_ttl, p.max_marks_per_day, p.strategy), (pol.rebalance_cooldown, pol.max_rebalances_per_day, pol.oor_margin_bins, pol.oor_wait, pol.mark_ttl, pol.max_marks_per_day, pol.strategy));
        assert_eq!((p.max_action_cost, p.max_priority_fee, p.exit_on_oor, p.exit_wait, p.exit_after), (pol.max_action_cost, pol.max_priority_fee, pol.exit_on_oor, pol.exit_wait, pol.exit_after));
        assert_eq!((p.rent_budget, p.max_shift_bins, p.max_shift_day), (rent_budget, shift.0, shift.1));
        // limits no older record has: zero, which refuses the keeper rebalance and the oracle-checked mark
        assert_eq!((p.max_move_bps, p.max_move_bps_day, p.max_dev_bps, p.max_loss_bps, p.min_placed_bps), (0, 0, 0, 0, 0));
        let s = r.st;
        assert_eq!((s.day, s.compounds_today, s.rebalances_today, s.marks_today, s.last_compound, s.last_rebalance), (st.day, st.compounds_today, st.rebalances_today, st.marks_today, st.last_compound, st.last_rebalance));
        assert_eq!((s.mark_time, s.mark_active_id, s.mark_side, s.mark_fp, s.rent_spent), (st.mark_time, st.mark_active_id, st.mark_side, fp, rent_spent));
        assert_eq!(s.mark_oracle, 0);
        // the exit wait keeps counting from the old mark
        assert_eq!(s.oor_since, st.mark_time);
        // M2.8: the run is the old mark's side, last seen at the mark; no recovery is invented
        assert_eq!((s.oor_side, s.oor_seen, s.back_since), (st.mark_side, st.mark_time, 0));
        assert!(s.ring.iter().all(|e| e.time == 0 && e.bins == 0));
    }

    #[test]
    fn m28_no_mark_no_run() {
        // an older record without a mark converts to no run at all (fail closed: nothing invented)
        for (extra_pol, extra_st) in [(0usize, 0usize), (8, 40), (12, 56)] {
            let mut old = old_bytes(&vec![0u8; extra_pol], &vec![0u8; extra_st]);
            let st_at = PREFIX + 89 + extra_pol;
            old[st_at + MARK_TIME_AT..st_at + MARK_TIME_AT + 8].copy_from_slice(&0i64.to_le_bytes());
            let r = PositionRecord::try_deserialize(&mut &convert(&old, NOW).unwrap()[..]).unwrap();
            assert_eq!((r.st.oor_since, r.st.oor_side, r.st.back_since, r.st.oor_seen), (0, 0, 0, 0));
        }
    }

    #[test]
    fn every_older_layout_converts_field_for_field() {
        // M2: 279 bytes
        let m2 = old_bytes(&[], &[]);
        assert_eq!(m2.len(), LEN_M2);
        check(m2, 0, (0, 0), [0u8; 32], 0);
        // M2.1: 327 bytes (+ rent_budget; + mark_fp, rent_spent)
        let mut st21 = [9u8; 32].to_vec();
        st21.extend(77u64.to_le_bytes());
        let m21 = old_bytes(&55u64.to_le_bytes(), &st21);
        assert_eq!(m21.len(), LEN_M21);
        check(m21, 55, (0, 0), [9u8; 32], 77);
        // M2.2: 347 bytes (+ max_shift_bins, max_shift_per_day; + anchor_day, anchor_lower, anchor_upper)
        let mut pol22 = 55u64.to_le_bytes().to_vec();
        pol22.extend(5u16.to_le_bytes());
        pol22.extend(8u16.to_le_bytes());
        let mut st22 = st21.clone();
        st22.extend(20_000i64.to_le_bytes());
        st22.extend(10i32.to_le_bytes());
        st22.extend(19i32.to_le_bytes());
        let m22 = old_bytes(&pol22, &st22);
        assert_eq!(m22.len(), LEN_M22);
        check(m22, 55, (5, 8), [9u8; 32], 77);
    }

    #[test]
    fn nothing_else_converts() {
        for len in [0usize, 146, 147, 278, 280, 326, 328, 346, 348, LEN_M23, 1000] {
            assert!(convert(&vec![1u8; len], NOW).is_none(), "{len}");
        }
        // a version that cannot be bumped does not convert
        let mut d = vec![0u8; LEN_M2];
        d[VERSION_AT..VERSION_AT + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(convert(&d, NOW).is_none());
    }

    #[test]
    fn a_recent_keeper_rebalance_keeps_the_rolling_budget_used() {
        use crate::policy::{check_rolling, Policy as P3};
        let (_, _, st) = sample();
        for (extra_pol, extra_st) in [(0usize, 0usize), (8, 40), (12, 56)] {
            let old = old_bytes(&vec![0u8; extra_pol], &vec![0u8; extra_st]);
            // the last keeper rebalance was exactly 24 hours before NOW: outside the window, ring empty
            let r = PositionRecord::try_deserialize(&mut &convert(&old, NOW).unwrap()[..]).unwrap();
            assert!(r.st.ring.iter().all(|e| e.time == 0));
            // one second less: inside the window, entered with an unknown (maximal) size
            let r = PositionRecord::try_deserialize(&mut &convert(&old, NOW - 1).unwrap()[..]).unwrap();
            assert_eq!((r.st.ring[0].time, r.st.ring[0].bins), (st.last_rebalance, UNKNOWN_MOVE));
            assert!(r.st.ring[1..].iter().all(|e| e.time == 0));
            // whatever the owner signs afterwards, no keeper rebalance until that entry is 24 hours old
            let widest = P3 { max_shift_bins: u16::MAX, max_shift_day: u16::MAX, max_move_bps: u16::MAX, max_move_bps_day: u32::MAX, ..Default::default() };
            assert_eq!(check_rolling(&widest, &r.st.ring, NOW - 1, 1, (0, 9), (1, 10)).unwrap_err(), crate::VaultError::DailyShiftExceeded.into());
            assert!(check_rolling(&widest, &r.st.ring, NOW, 1, (0, 9), (1, 10)).is_ok());
            // a stamp in the future is not "older than 24 hours"
            let r = PositionRecord::try_deserialize(&mut &convert(&old, NOW - 200_000).unwrap()[..]).unwrap();
            assert_eq!(r.st.ring[0].bins, UNKNOWN_MOVE);
        }
        // never rebalanced by a keeper: nothing to enter
        let mut never = old_bytes(&[], &[]);
        let at = PREFIX + 89 + LAST_REBALANCE_AT;
        never[at..at + 8].copy_from_slice(&0i64.to_le_bytes());
        let r = PositionRecord::try_deserialize(&mut &convert(&never, NOW).unwrap()[..]).unwrap();
        assert!(r.st.ring.iter().all(|e| e.time == 0));
    }
}

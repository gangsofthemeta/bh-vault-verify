//! TEST ONLY. Never deployed outside the local validator, where scripts/start-validator.sh loads it
//! at the address of the Pyth receiver program. It lets a test write any bytes into an account this
//! program owns, so a "price account" of any content can exist locally (stale, wrong feed, partial
//! verification, ...). bh_vault itself knows only the real receiver address and never calls it.
//! accounts[0] = the account to write (owned by this program, same length as the data).
use anchor_lang::solana_program::{account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey};

entrypoint!(process);

fn process(id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let a = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if a.owner != id || a.data_len() != data.len() {
        return Err(ProgramError::InvalidAccountData);
    }
    a.try_borrow_mut_data()?.copy_from_slice(data);
    Ok(())
}

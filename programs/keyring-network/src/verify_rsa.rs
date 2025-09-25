use crate::common::error::KeyringError;
use crate::common::types::{EntityData, KeyEntry, ProgramState, ToHash, CURRENT_VERSION};
use crate::common::verify_auth_message::verify_auth_message;
use anchor_lang::prelude::*;
use anchor_lang::solana_program::keccak;
use anchor_lang::{system_program, Accounts};

use anchor_lang::{solana_program::log::sol_log_compute_units, solana_program::msg};
use crypto_bigint::{NonZero, U1024};

#[event]
pub struct VerifiedRsa {
    modulus: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
}

#[derive(Accounts)]
#[instruction(modulus: Vec<u8>, signature: Vec<u8>, message: Vec<u8>)]
pub struct VerifyRsa<'info> {
    #[account(
        mut,
        seeds = [b"keyring_program".as_ref(), b"global_state".as_ref()],
        bump
    )]
    pub program_state: Account<'info, ProgramState>,
    #[account(mut)]
    pub signer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

pub fn do_verify_rsa(
    ctx: Context<VerifyRsa>,
    modulus: Vec<u8>,
    signature: Vec<u8>,
    message: Vec<u8>,
) -> Result<()> {
    let modulus = NonZero::new(U1024::from_be_slice(&modulus)).unwrap();
    let signature = NonZero::new(U1024::from_be_slice(&signature)).unwrap();
    let message = U1024::from_be_slice(&message);

    let result = signature.mul_mod_vartime(&signature.mul_mod_vartime(&signature, &modulus), &modulus);

    assert_eq!(result, message);

    Ok(())
}
use crate::common::error::KeyringError;
use crate::common::types::{
    KeyEntry, KeyRegistry, Role, ToHash, CURRENT_VERSION, KEY_MANAGER_ROLE, MAX_ACTIVE_KEYS,
};
use anchor_lang::prelude::*;
use anchor_lang::Accounts;

#[event]
pub struct KeyRegistered {
    key: Vec<u8>,
    valid_from: u64,
    valid_to: u64,
}

#[derive(Accounts)]
#[instruction(key: Vec<u8>)]
pub struct RegisterKey<'info> {
    #[account(
        mut,
        seeds = [b"keyring_program".as_ref(), b"active_keys".as_ref()],
        bump,
    )]
    pub key_registry: Account<'info, KeyRegistry>,
    #[account(mut)]
    pub signer: Signer<'info>,
    #[account(
        seeds = [KEY_MANAGER_ROLE.as_ref(), signer.key().to_bytes().as_ref()],
        bump
    )]
    pub key_manager_role: Account<'info, Role>,
    #[account(
        init_if_needed,
        payer = signer,
        seeds = [b"keyring_program".as_ref(), b"_key_mapping".as_ref(), &key.to_hash().as_ref()],
        bump,
        space = 8 + KeyEntry::MAX_SIZE
    )]
    pub key_mapping: Account<'info, KeyEntry>,
    pub system_program: Program<'info, System>,
}

pub fn do_register_key(
    ctx: Context<RegisterKey>,
    key: Vec<u8>,
    valid_from: u64,
    valid_to: u64,
) -> Result<()> {
    if !ctx.accounts.key_manager_role.has_role {
        return Err(error!(KeyringError::ErrCallerDoesNotHaveRole));
    }

    let clock: Clock = Clock::get()?;
    let time_stamp = clock.unix_timestamp;

    if key.len() != 1024 / 8 {
        return Err(error!(KeyringError::ErrInvalidPubkeyLength));
    }

    if valid_to <= valid_from {
        return Err(error!(KeyringError::ErrInvalidKeyRegistrationParams));
    }

    if valid_to < time_stamp as u64 {
        return Err(error!(KeyringError::ErrInvalidKeyRegistrationParams));
    }

    if ctx.accounts.key_mapping.is_valid {
        return Err(error!(KeyringError::ErrKeyAlreadyRegistered));
    }

    *ctx.accounts.key_mapping = KeyEntry {
        version: CURRENT_VERSION,
        is_valid: true,
        valid_from,
        valid_to,
    };

    if ctx.accounts.key_registry.active_keys.len() + 1 > MAX_ACTIVE_KEYS as usize {
        return Err(error!(KeyringError::ErrBreachedMaxActiveKeyLimit));
    }
    ctx.accounts.key_registry.active_keys.push(key.clone());

    emit!(KeyRegistered {
        key,
        valid_from,
        valid_to
    });

    Ok(())
}

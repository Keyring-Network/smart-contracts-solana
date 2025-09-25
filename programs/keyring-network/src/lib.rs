mod blacklist_entity;
mod check_credentials;
mod collect_fees;
pub mod common;
mod create_credential;
mod init;
mod manage_role;
mod register_key;
mod revoke_key;
mod unblacklist_entity;

use anchor_lang::prelude::*;
use blacklist_entity::*;
use check_credentials::*;
use collect_fees::*;
use create_credential::*;
use init::*;
use manage_role::*;
use register_key::*;
use revoke_key::*;
#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;
use unblacklist_entity::*;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Keyring Network",
    project_url: "https://Keyring.Network",
    contacts: "email:info@keyring.network",
    policy: "https://github.com/Keyring-Network/smart-contracts-solana/SECURITY.md",
    preferred_languages: "en",
    source_code: "https://github.com/Keyring-Network/smart-contracts-solana",
    auditors: "None"
}

declare_id!("3MxhjuscSykCxXaozceBAUySdp6qHieB7sTXdarYAXTp");

#[program]
pub mod keyring_network {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, chain_id: Vec<u8>) -> Result<()> {
        do_initialize(ctx, chain_id)
    }

    pub fn manage_roles(
        ctx: Context<ManageRole>,
        role: [u8; 32],
        user: Pubkey,
        has_role: bool,
    ) -> Result<()> {
        do_manage_role(ctx, role, user, has_role)
    }

    pub fn register_key(
        ctx: Context<RegisterKey>,
        key: Vec<u8>,
        valid_from: u64,
        valid_to: u64,
    ) -> Result<()> {
        do_register_key(ctx, key, valid_from, valid_to)
    }

    pub fn revoke_key(ctx: Context<RevokeKey>, key: Vec<u8>) -> Result<()> {
        do_revoke_key(ctx, key)
    }

    pub fn blacklist_entity(
        ctx: Context<BlacklistEntity>,
        policy_id: u64,
        trading_address: Pubkey,
    ) -> Result<()> {
        do_blacklist_entity(ctx, policy_id, trading_address)
    }

    pub fn unblacklist_entity(
        ctx: Context<UnblacklistEntity>,
        policy_id: u64,
        trading_address: Pubkey,
    ) -> Result<()> {
        do_unblacklist_entity(ctx, policy_id, trading_address)
    }

    pub fn collect_fees(ctx: Context<CollectFees>) -> Result<()> {
        do_collect_fees(ctx)
    }

    pub fn create_credential(
        ctx: Context<CreateCredential>,
        key: Vec<u8>,
        policy_id: u64,
        trading_address: Pubkey,
        signature: Vec<u8>,
        valid_until: u64,
        cost: u64,
        backdoor: Vec<u8>,
    ) -> Result<()> {
        do_create_credential(
            ctx,
            key,
            policy_id,
            trading_address,
            signature,
            valid_until,
            cost,
            backdoor,
        )
    }

    pub fn check_credential(
        ctx: Context<CheckCredential>,
        policy_id: u64,
        trading_address: Pubkey,
    ) -> Result<()> {
        do_check_credential(ctx, policy_id, trading_address)
    }
}

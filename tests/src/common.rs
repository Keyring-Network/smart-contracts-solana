use anchor_client::anchor_lang::prelude::{Clock, Pubkey, System};
use anchor_client::anchor_lang::Id;
use anchor_client::solana_client::rpc_client::RpcClient;
use anchor_client::solana_sdk::keccak;
use anchor_client::solana_sdk::secp256k1_recover::Secp256k1Pubkey;
use anchor_client::solana_sdk::signature::{Keypair, Signer};
use anchor_client::solana_sdk::sysvar::clock;
use anchor_client::Program;
use keyring_network::common::types::{
    ProgramState, Role, CHAIN_ID_MAX_SIZE, CHAIN_ID_MIN_SIZE, DEFAULT_ADMIN_ROLE,
};
use rand::RngCore;
use std::thread::sleep;
use std::time::Duration;

pub fn init_program(
    program: &Program<&Keypair>,
    payer: &Keypair,
    chain_id: Vec<u8>,
) -> (Pubkey, ProgramState, Pubkey) {
    // We need to wait a bit for validator to start
    sleep(Duration::from_secs(3));

    let (program_state, _) = Pubkey::find_program_address(
        &[b"keyring_program".as_ref(), b"global_state".as_ref()],
        &program.id(),
    );
    let (key_registry, _) = Pubkey::find_program_address(
        &[b"keyring_program".as_ref(), b"active_keys".as_ref()],
        &program.id(),
    );
    let (default_admin_role, _) = Pubkey::find_program_address(
        &[
            DEFAULT_ADMIN_ROLE.as_ref(),
            payer.pubkey().to_bytes().as_ref(),
        ],
        &program.id(),
    );

    // Initialization with invalid chain id should not work.
    let invalid_chain_id = vec![1; CHAIN_ID_MAX_SIZE + 1];
    program
        .request()
        .accounts(keyring_network::accounts::Initialize {
            program_state: program_state.clone(),
            key_registry: key_registry.clone(),
            signer: payer.pubkey(),
            default_admin_role,
            system_program: System::id(),
        })
        .args(keyring_network::instruction::Initialize {
            chain_id: invalid_chain_id,
        })
        .send()
        .expect_err("Invalid chain id cannot be accepted");

    let invalid_chain_id = vec![1; CHAIN_ID_MIN_SIZE - 1];
    program
        .request()
        .accounts(keyring_network::accounts::Initialize {
            program_state: program_state.clone(),
            key_registry: key_registry.clone(),
            signer: payer.pubkey(),
            default_admin_role,
            system_program: System::id(),
        })
        .args(keyring_network::instruction::Initialize {
            chain_id: invalid_chain_id,
        })
        .send()
        .expect_err("Invalid chain id cannot be accepted");

    // First initialization should be successful
    program
        .request()
        .accounts(keyring_network::accounts::Initialize {
            program_state: program_state.clone(),
            key_registry: key_registry.clone(),
            signer: payer.pubkey(),
            default_admin_role,
            system_program: System::id(),
        })
        .args(keyring_network::instruction::Initialize {
            chain_id: chain_id.clone(),
        })
        .send()
        .expect("First initialization must be successful");

    // Second initialization should return an error
    program
        .request()
        .accounts(keyring_network::accounts::Initialize {
            program_state: program_state.clone(),
            key_registry: key_registry.clone(),
            signer: payer.pubkey(),
            default_admin_role,
            system_program: System::id(),
        })
        .args(keyring_network::instruction::Initialize {
            chain_id: chain_id.clone(),
        })
        .send()
        .expect_err("Second initialization should not be successful");

    // We need to check if admin is set to payer
    let default_admin_role_data: Role = program
        .account(default_admin_role.clone())
        .expect("Default admin role must be granted after initialization");
    if !default_admin_role_data.has_role {
        panic!("Payer must have admin role");
    }

    let program_state_data: ProgramState = program
        .account(program_state.clone())
        .expect("Program state must exist after initialization");

    (program_state, program_state_data, default_admin_role)
}

pub fn get_timestamp(rpc: &RpcClient) -> u64 {
    let clock = rpc.get_account(&clock::ID).unwrap();
    let clock_sysvar: Clock = bincode::deserialize(&clock.data).unwrap();
    clock_sysvar.unix_timestamp.try_into().unwrap()
}

pub fn convert_pubkey_to_address(pubkey: &Pubkey) -> Vec<u8> {
    let hashed_pubkey = keccak::hash(&pubkey.to_bytes()).to_bytes();
    hashed_pubkey[..20].to_vec()
}

pub fn generate_random_chain_id<R: RngCore>(rng: &mut R) -> Vec<u8> {
    let mut length = rng.next_u64() % CHAIN_ID_MAX_SIZE as u64;
    if length < CHAIN_ID_MIN_SIZE as u64 {
        length = CHAIN_ID_MIN_SIZE as u64;
    }
    let mut chain_id_bytes = vec![0u8; length as usize];
    rng.fill_bytes(&mut chain_id_bytes);
    chain_id_bytes
}

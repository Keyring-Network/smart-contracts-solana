use crate::common::{
    convert_pubkey_to_address, generate_random_chain_id, get_timestamp, init_program,
};
use anchor_client::anchor_lang::prelude::System;
use anchor_client::anchor_lang::Id;
use anchor_client::solana_client::rpc_client::RpcClient;
use anchor_client::solana_sdk::native_token::LAMPORTS_PER_SOL;
use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::solana_sdk::signer::Signer;
use anchor_client::{
    solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey},
    Client, Cluster,
};
use keyring_network::common::types::{
    ChainId, EntityData, ToHash, BLACKLIST_MANAGER_ROLE, CURRENT_VERSION, KEY_MANAGER_ROLE,
};
use keyring_network::common::verify_auth_message::pack_auth_message;
use keyring_network::ID as program_id;
use rsa::pkcs1v15::SigningKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPublicKey, RsaPrivateKey, sha2::Sha256, signature::{Signer as RsaSigner, SignatureEncoding}};
use rand::rngs::OsRng;

#[test]
fn test_check_credential() {
    let anchor_rpc_client = RpcClient::new(Cluster::Localnet.url());

    let payer = Keypair::new();
    anchor_rpc_client
        .request_airdrop(&payer.pubkey(), 10000 * LAMPORTS_PER_SOL)
        .unwrap();

    let client = Client::new_with_options(Cluster::Localnet, &payer, CommitmentConfig::confirmed());
    let program = client.program(program_id).unwrap();

    // Let's fund new admin
    let dummy_payer = Keypair::new();
    let rpc = program.rpc();
    rpc.request_airdrop(&dummy_payer.pubkey(), 10 * LAMPORTS_PER_SOL)
        .unwrap();

    let mut rng = OsRng::default();
    let chain_id = generate_random_chain_id(&mut rng);
    let (program_state_pubkey, _, default_admin_role_pubkey) =
        init_program(&program, &payer, chain_id.clone());

    let mut os_rng = rsa::rand_core::OsRng::default();
    let secret_key = RsaPrivateKey::new(&mut os_rng, 1024).expect("Failed to generate RSA private key");
    let signing_key = SigningKey::<Sha256>::new(secret_key.clone());
    let public_key = RsaPublicKey::from(&secret_key.clone());
    let key = public_key.n().to_bytes_be().to_vec();
    let key_hash = key.to_hash();
    let key_mapping_seeds = [
        b"keyring_program".as_ref(),
        b"_key_mapping".as_ref(),
        key_hash.as_ref(),
    ];
    let (key_mapping_pubkey, _) = Pubkey::find_program_address(&key_mapping_seeds, &program.id());
    let (key_registry, _) = Pubkey::find_program_address(
        &[b"keyring_program".as_ref(), b"active_keys".as_ref()],
        &program.id(),
    );
    let (key_manager_role_account_for_admin, _) = Pubkey::find_program_address(
        &[
            KEY_MANAGER_ROLE.as_ref(),
            payer.pubkey().to_bytes().as_ref(),
        ],
        &program.id(),
    );
    let (blacklist_manager_role_account_for_admin, _) = Pubkey::find_program_address(
        &[
            BLACKLIST_MANAGER_ROLE.as_ref(),
            payer.pubkey().to_bytes().as_ref(),
        ],
        &program.id(),
    );

    program
        .request()
        .accounts(keyring_network::accounts::ManageRole {
            default_admin_role: default_admin_role_pubkey,
            role: key_manager_role_account_for_admin,
            signer: payer.pubkey(),
            system_program: System::id(),
        })
        .args(keyring_network::instruction::ManageRoles {
            role: KEY_MANAGER_ROLE,
            user: payer.pubkey(),
            has_role: true,
        })
        .send()
        .expect("Current admin must be able to grant key manager role");

    let timestamp = get_timestamp(&rpc);
    program
        .request()
        .accounts(keyring_network::accounts::RegisterKey {
            key_registry: key_registry.clone(),
            key_mapping: key_mapping_pubkey.clone(),
            signer: payer.pubkey(),
            key_manager_role: key_manager_role_account_for_admin,
            system_program: System::id(),
        })
        .args(keyring_network::instruction::RegisterKey {
            key: key.clone(),
            valid_from: timestamp - 1,
            valid_to: timestamp + 20,
        })
        .send()
        .expect("Valid key registration must be successful");

    let timestamp = get_timestamp(&rpc);
    let policy_id: u64 = 1;
    let trading_address = Pubkey::new_unique();
    let valid_until = timestamp + 1000;
    let cost = 21 * LAMPORTS_PER_SOL;
    let backdoor = vec![2; 20];
    let entity_mapping_seeds = [
        b"keyring_program".as_ref(),
        b"_entity_mapping".as_ref(),
        &policy_id.to_le_bytes(),
        &trading_address.to_bytes(),
    ];
    let (entity_mapping_pubkey, _) =
        Pubkey::find_program_address(&entity_mapping_seeds, &program.id());

    let packed_message = pack_auth_message(
        convert_pubkey_to_address(&trading_address),
        policy_id,
        ChainId::new(chain_id.clone()).unwrap(),
        valid_until,
        cost,
        backdoor.clone(),
    )
    .unwrap();
    let signature = signing_key.sign(packed_message.as_ref()).to_vec();

    program
        .request()
        .accounts(keyring_network::accounts::CreateCredential {
            program_state: program_state_pubkey.clone(),
            key_mapping: key_mapping_pubkey.clone(),
            signer: payer.pubkey(),
            entity_mapping: entity_mapping_pubkey.clone(),
            system_program: System::id(),
        })
        .args(keyring_network::instruction::CreateCredential {
            key: key.clone(),
            policy_id,
            trading_address,
            signature: signature.clone(),
            valid_until,
            cost,
            backdoor: backdoor.clone(),
        })
        .send()
        .expect("Valid create credentials request must succeed.");

    // Check credentials should be successful here
    program
        .request()
        .accounts(keyring_network::accounts::CheckCredential {
            signer: payer.pubkey(),
            entity_mapping: entity_mapping_pubkey.clone(),
        })
        .args(keyring_network::instruction::CheckCredential {
            policy_id,
            trading_address,
        })
        .send()
        .expect("Check credentials should be successful");

    program
        .request()
        .accounts(keyring_network::accounts::ManageRole {
            default_admin_role: default_admin_role_pubkey,
            role: blacklist_manager_role_account_for_admin,
            signer: payer.pubkey(),
            system_program: System::id(),
        })
        .args(keyring_network::instruction::ManageRoles {
            role: BLACKLIST_MANAGER_ROLE,
            user: payer.pubkey(),
            has_role: true,
        })
        .send()
        .expect("Current admin must be able to grant blacklist manager role");

    program
        .request()
        .accounts(keyring_network::accounts::BlacklistEntity {
            signer: payer.pubkey(),
            blacklist_manager_role: blacklist_manager_role_account_for_admin,
            entity_mapping: entity_mapping_pubkey.clone(),
            system_program: System::id(),
        })
        .args(keyring_network::instruction::BlacklistEntity {
            policy_id,
            trading_address,
        })
        .send()
        .expect("Admin should be able to blacklist entity");

    let entity_data: EntityData = program.account(entity_mapping_pubkey).unwrap();
    assert_eq!(
        entity_data,
        EntityData {
            version: CURRENT_VERSION,
            blacklisted: true,
            exp: 0,
        }
    );

    // Check credentials should return error for blacklisted entity
    program
        .request()
        .accounts(keyring_network::accounts::CheckCredential {
            signer: payer.pubkey(),
            entity_mapping: entity_mapping_pubkey.clone(),
        })
        .args(keyring_network::instruction::CheckCredential {
            policy_id,
            trading_address,
        })
        .send()
        .expect_err("Check credentials must not be successful for blacklisted entity");
}

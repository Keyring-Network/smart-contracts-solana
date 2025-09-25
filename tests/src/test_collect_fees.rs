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
use keyring_network::common::types::{ChainId, ToHash, KEY_MANAGER_ROLE, OPERATOR_ROLE};
use keyring_network::common::verify_auth_message::pack_auth_message;
use keyring_network::ID as program_id;
use rsa::pkcs1v15::SigningKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPublicKey, RsaPrivateKey, sha2::Sha256, signature::{Signer as RsaSigner, SignatureEncoding}};
use rand::rngs::OsRng;

#[test]
fn collect_fees() {
    let anchor_rpc_client = RpcClient::new(Cluster::Localnet.url());

    let payer = Keypair::new();
    anchor_rpc_client
        .request_airdrop(&payer.pubkey(), 10000 * LAMPORTS_PER_SOL)
        .unwrap();

    let client = Client::new_with_options(Cluster::Localnet, &payer, CommitmentConfig::confirmed());
    let program = client.program(program_id).unwrap();

    // Let's fund dummy payer
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
    let (operator_role_account_for_admin, _) = Pubkey::find_program_address(
        &[OPERATOR_ROLE.as_ref(), payer.pubkey().to_bytes().as_ref()],
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

    program
        .request()
        .accounts(keyring_network::accounts::ManageRole {
            default_admin_role: default_admin_role_pubkey,
            role: operator_role_account_for_admin,
            signer: payer.pubkey(),
            system_program: System::id(),
        })
        .args(keyring_network::instruction::ManageRoles {
            role: OPERATOR_ROLE,
            user: payer.pubkey(),
            has_role: true,
        })
        .send()
        .expect("Current admin must be able to grant operator role");

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

    let program_state_before_balance = rpc.get_balance(&program_state_pubkey).unwrap();
    let timestamp = get_timestamp(&rpc);
    let policy_id: u64 = 1;
    let trading_address = Pubkey::new_unique();
    let valid_until = timestamp + 10000;
    let cost = 6 * LAMPORTS_PER_SOL;
    let backdoor = vec![3; 24];
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

    let program_state_after_balance = rpc.get_balance(&program_state_pubkey).unwrap();
    assert_eq!(
        program_state_after_balance - program_state_before_balance,
        cost
    );

    let fee_collector = Keypair::new();

    // Fee collection can only be done by admin
    program
        .request()
        .accounts(keyring_network::accounts::CollectFees {
            program_state: program_state_pubkey.clone(),
            signer: dummy_payer.pubkey(),
            operator_role: operator_role_account_for_admin,
            receiver_account: fee_collector.pubkey(),
        })
        .args(keyring_network::instruction::CollectFees {})
        .payer(&dummy_payer)
        .send()
        .expect_err("Non-operator must not be able to collect fees");

    // Valid fee collection should credit the fee collector
    program
        .request()
        .accounts(keyring_network::accounts::CollectFees {
            program_state: program_state_pubkey.clone(),
            signer: payer.pubkey(),
            operator_role: operator_role_account_for_admin,
            receiver_account: fee_collector.pubkey(),
        })
        .args(keyring_network::instruction::CollectFees {})
        .send()
        .expect("Operator must be able to collect fees");

    // We should have received the amount paid in the previous instruction
    assert_eq!(rpc.get_balance(&fee_collector.pubkey()).unwrap(), cost);

    // Valid fee collection again should not error out
    program
        .request()
        .accounts(keyring_network::accounts::CollectFees {
            program_state: program_state_pubkey.clone(),
            signer: payer.pubkey(),
            operator_role: operator_role_account_for_admin,
            receiver_account: fee_collector.pubkey(),
        })
        .args(keyring_network::instruction::CollectFees {})
        .send()
        .expect("Operator must be able to collect fees even when it is 0.");

    // The balance should not change
    assert_eq!(rpc.get_balance(&fee_collector.pubkey()).unwrap(), cost);
}

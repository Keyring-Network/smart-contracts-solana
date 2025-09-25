use crate::common::{
    generate_random_chain_id, init_program,
};
use anchor_client::anchor_lang::prelude::System;
use anchor_client::anchor_lang::Id;
use anchor_client::solana_client::rpc_client::RpcClient;
use anchor_client::solana_sdk::native_token::LAMPORTS_PER_SOL;
use anchor_client::solana_sdk::signature::Keypair;
use anchor_client::solana_sdk::signer::Signer;
use anchor_client::{
    solana_sdk::{commitment_config::CommitmentConfig},
    Client, Cluster,
};
use keyring_network::ID as program_id;
use rand::rngs::OsRng;

#[test]
fn test_rsa() {
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
    let (program_state_pubkey, _, _default_admin_role_pubkey) =
        init_program(&program, &payer, chain_id.clone());

    program.request()
        .accounts(keyring_network::accounts::VerifyRsa {
            program_state: program_state_pubkey.clone(),
            signer: payer.pubkey(),
            system_program: System::id(),
        })
        .args(keyring_network::instruction::VerifyRsa {
            modulus: MODULUS.to_vec(),
            signature: SIGNATURE.to_vec(),
            message: MESSAGE.to_vec(),
        })
        .send()
        .expect("Test RSA should be successful");
}

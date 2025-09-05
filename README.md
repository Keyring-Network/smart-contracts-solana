# Description
This solana program is adaption of [solidity smart contracts](https://github.com/Keyring-Network/smart-contracts) and is base on Anchor framework.

# Installation
Install solana (1.18.26) and anchor cli (0.29.0) from the [official website](https://www.anchor-lang.com/docs/installation).
Ensure to install solana using the official documentation. The homebrew installation is not recommended and can cause an issue relating to `cargo-build-sbf` missing.

```shell
sh -c "$(curl -sSfL https://release.anza.xyz/v1.18.26/install)"
cargo install --git https://github.com/coral-xyz/anchor --tag v0.29.0 anchor-cli
```

# Tests

## Setup
You will need a solana keypair to run tests.

```shell
solana-keygen new
```

## Run tests
```shell
./run-tests.sh
```

# Deployment
```shell
# Make sure that you have chosen correct network and your solana keypair is up-to-date.
anchor deploy

# Wait for a bit for the deployment to be recognized and run migration to initialize the account
anchor migrate
```

# Upgrade authority
Typically, the keypair that is deploying the contract is upgrade authority which can update the program. 
Each structure in program has version byte which can be used in subsequent upgrade to provide backward compatibility and/or migration.

# Deployment to Mainnet

## Prerequisites
```bash
anchor build --verifiable
```
Create a deployment keypair for example at `$DEPLOYMENT_KEYPAIR`
Fund the deployment account (needs ~4 SOL)

## Initial Deployment

Deploy the program
```bash
anchor deploy --verifiable \
  --program-name keyring_network \
  --program-keypair $PROGRAM_KEYPAIR \
  --provider.cluster $PROVIDER_CLUSTER \
  --provider.wallet $PROGRAM_WALLET \
  -- \
  --with-compute-unit-price 50000 \
  --max-sign-attempts 100 \
  --use-rpc
```

Initialize the program state (only needed for first deployment)
```bash
anchor migrate \
  --provider.cluster $PROVIDER_CLUSTER \
  --provider.wallet $PROGRAM_WALLET
```

## Upgrading Existing Program
```bash
# Build verifiable version
anchor build --verifiable

# Deploy the upgrade
anchor deploy --verifiable \
  --program-name keyring_network \
  --program-keypair $PROGRAM_KEYPAIR \
  --provider.cluster $PROVIDER_CLUSTER \
  --provider.wallet $PROGRAM_WALLET \
  -- \
  --with-compute-unit-price 50000 \
  --max-sign-attempts 100 \
  --use-rpc
```

Hand off to Squad
```
solana program set-upgrade-authority $PROGRAM_ID \
  --url $PROVIDER_CLUSTER \
  --keypair $PROGRAM_WALLET \
  --new-upgrade-authority $SQUAD_KEYPAIR \
  --skip-new-upgrade-authority-signer-check
```

## Error Handling

If deployment fails with buffer account error, recover the buffer
```bash
solana-keygen recover -o buffer-keypair.json --force
```
Enter the seed phrase from the error message.

Close failed buffer to reclaim rent:
```bash
solana program close $(solana program show --buffers --keypair $DEPLOYMENT_KEYPAIR | awk 'NR==3 {print $1}') \
  --keypair $DEPLOYMENT_KEYPAIR \
  --url $PROVIDER_CLUSTER \
  --recipient $(solana-keygen pubkey $DEPLOYMENT_KEYPAIR)
```

Deploy upgrade with longer timeout and finalized commitment
```bash
solana program deploy \
  --program-id $PROGRAM_ID \
  --keypair $DEPLOYMENT_KEYPAIR \
  target/verifiable/keyring_network.so \
  --url $PROVIDER_CLUSTER \
  --commitment finalized
```

## Gotchas
- Deployment requires ~8 SOL for rent and transaction fees
- Failed deployments create buffer accounts that need to be closed to reclaim rent
- Use `--commitment finalized` to avoid timeout errors on mainnet
- Always build with `--verifiable` flag for mainnet deployments
- Keep deployment keypair secure as it has upgrade authority
- Program state is preserved across upgrades

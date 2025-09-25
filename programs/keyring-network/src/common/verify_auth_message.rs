use crate::common::error::KeyringError;
use crate::common::types::ChainId;
use crate::common::rsa::verify_rsa_signature;
use anchor_lang::{error, Result};

// Verify auth message
pub fn verify_auth_message(
    key: Vec<u8>,
    policy_id: u64,
    trading_address: Vec<u8>,
    signature_data: Vec<u8>,
    chain_id: ChainId,
    valid_until: u64,
    cost: u64,
    backdoor: Vec<u8>,
) -> Result<bool> {
    // Pack auth message
    let packed_message = pack_auth_message(
        trading_address,
        policy_id,
        chain_id,
        valid_until,
        cost,
        backdoor,
    )?;
    
    verify_rsa_signature(key, signature_data, packed_message)
}

// Packs auth message data
// This function mimics the exact same behaviour as this from solditiy:
// return abi.encodePacked(
//    tradingAddress,
//    uint8(0),
//    uint24(policyId),
//    uint32(validFrom),
//    uint32(validUntil),
//    uint160(cost),
//    backdoor
// );
// See full code here: https://github.com/Keyring-Network/keyring-smart-contracts/blob/master/src/lib/RsaMessagePacking.sol#L18
pub fn pack_auth_message(
    trading_address: Vec<u8>,
    policy_id: u64,
    chain_id: ChainId,
    valid_until: u64,
    cost: u64,
    backdoor: Vec<u8>,
) -> Result<Vec<u8>> {
    let mut packed = vec![];

    let reserved_byte = 0u8;

    if policy_id > 2u64.pow(24) - 1 {
        return Err(error!(KeyringError::ErrAuthMessageParameterOutOfRange));
    }
    let policy_id_in_bytes = policy_id.to_be_bytes();
    let encoded_policy_id =
        policy_id_in_bytes[policy_id_in_bytes.len() - 3..policy_id_in_bytes.len()].to_vec();

    if valid_until > u32::MAX as u64 {
        return Err(error!(KeyringError::ErrAuthMessageParameterOutOfRange));
    }
    let encoded_valid_until = (valid_until as u32).to_be_bytes().to_vec();
    let encoded_cost = (cost as u128).to_be_bytes().to_vec();

    packed.extend_from_slice(&trading_address.as_slice());
    packed.push(reserved_byte);
    packed.extend_from_slice(&encoded_policy_id.as_slice());
    packed.extend_from_slice(&chain_id.chain_id[0..4]);
    packed.extend_from_slice(&encoded_valid_until.as_slice());
    packed.extend_from_slice(vec![0u8; 4].as_slice());
    packed.extend_from_slice(&encoded_cost.as_slice());
    packed.extend_from_slice(backdoor.as_slice());

    Ok(packed)
}

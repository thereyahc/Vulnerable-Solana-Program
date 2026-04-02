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

fn make_vault_with_balance(authority: &Pubkey, balance: u64, owner: &Pubkey) -> Account {
    let vault_data = Vault {
        authority: *authority,
        balance,
    };
    let serialized = vault_data.try_to_vec().unwrap();
    Account {
        lamports: 10_000_000,
        data: serialized,
        owner: *owner,
        executable: false,
        rent_epoch: 0,
    }
}

#[tokio::test]
async fn test_deposit_overflow() {
    let program_id = program_id();
    let mut program_test = ProgramTest::new(
        "vulnerable_smart_contract",
        program_id,
        processor!(vulnerable_smart_contract::process_instruction),
    );

    let user = Keypair::new();
    let vault = Keypair::new();

    let initial_balance = u64::MAX - 100;
    program_test.add_account(
        vault.pubkey(),
        make_vault_with_balance(&user.pubkey(), initial_balance, &program_id),
    );

    let user_balance: u64 = 10_000_000;
    program_test.add_account(
        user.pubkey(),
        Account {
            lamports: user_balance,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, payer, recent_blockhash) = program_test.start().await;

    // u64::MAX - 100 + 200 = 99
    let deposit_amount: u64 = 200;
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(vault.pubkey(), false),
            AccountMeta::new(user.pubkey(), true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: VaultInstruction::DepositOverflow {
            amount: deposit_amount,
        }
        .try_to_vec()
        .unwrap(),
    };

    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[&payer, &user],
        recent_blockhash,
    );

    println!("Before Vault balance: {}", initial_balance);
    println!("Deposit amount: {}", deposit_amount);
    println!("Before User lamports: {}", user_balance);

    banks_client.process_transaction(tx).await.unwrap();

    let vault_account = banks_client
        .get_account(vault.pubkey())
        .await
        .unwrap()
        .unwrap();

    let user_account = banks_client
        .get_account(vault.pubkey())
        .await
        .unwrap()
        .unwrap();

    let vault_data = Vault::try_from_slice(&vault_account.data).unwrap();

    println!("Vault balance: {}", vault_data.balance);
    println!("User balance: {}", user_account.lamports);
}

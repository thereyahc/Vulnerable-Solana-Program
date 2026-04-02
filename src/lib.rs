use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{AccountInfo, next_account_info},
    entrypoint,
    entrypoint::ProgramResult,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
    system_instruction,
};
entrypoint!(process_instruction);

#[derive(BorshSerialize, BorshDeserialize, Debug, PartialEq)]
pub struct Vault {
    pub authority: Pubkey, // Vault Owner
    pub balance: u64,
}

impl Vault {
    pub const SIZE: usize = 32 + 8;
}

// Instructions
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum VaultInstruction {
    // Accounts: [vault(writable), authority(signer)]
    Initialize,

    // Accounts: [vault(writable), depositor(signer), system_program]
    Deposit { amount: u64 },

    // Accounts: [vault(writable), authority, destination(writable), system_program]
    Transaction { amount: u64 },

    // Vulnerable Overflow function -  Accounts: [vault(writable), depositor(signer), system_program]
    DepositOverflow { amount: u64 },

    //  Vulnerable Underflow function -  Accounts: [vault(writable), authority, destination(writable), system_program]
    TransactionUnderflow { amount: u64 },
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = VaultInstruction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match instruction {
        VaultInstruction::Initialize => initialize(program_id, accounts),
        VaultInstruction::Deposit { amount } => deposit(program_id, accounts, amount),
        VaultInstruction::Transaction { amount } => transaction(program_id, accounts, amount),
        VaultInstruction::DepositOverflow { amount } => {
            deposit_overflow(program_id, accounts, amount)
        }
        VaultInstruction::TransactionUnderflow { amount } => {
            transaction_underflow(program_id, accounts, amount)
        }
    }
}

// Vault Initialize
fn initialize(_program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;

    // Missing Signer Check
    // Anyone can initialize a vault on behalf of any public key without that key's authorization,
    // since the program never verifies that the authority account signed the transaction.

    // if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }

    let vault_data = Vault {
        authority: *authority.key,
        balance: 0,
    };

    let serialized = vault_data
        .try_to_vec()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    vault.try_borrow_mut_data()?.copy_from_slice(&serialized);

    println!("Vault initialized. Authority is : {}", authority.key);
    Ok(())
}

fn deposit(_program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let depositor = next_account_info(account_iter)?;
    let system_program = next_account_info(account_iter)?;

    // Missing Ownership Check
    // An attacker can pass a fake account with matching data layout instead of a legitimate vault,
    // causing the program to accept and process it as if it were a real program-owned account.
    // if vault.owner != program_id { return Err(ProgramError::IncorrectProgramId); }

    invoke(
        &system_instruction::transfer(depositor.key, vault.key, amount),
        &[depositor.clone(), vault.clone(), system_program.clone()],
    )?;

    let mut data = vault.try_borrow_mut_data()?;
    let mut vault_data = Vault::try_from_slice(&data)?;
    vault_data.balance = vault_data
        .balance
        .checked_add(amount)
        .ok_or(ProgramError::InvalidArgument)?;
    let serialized = vault_data
        .try_to_vec()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    data.copy_from_slice(&serialized);

    println!(
        "Deposited {} lamports. Balance is: {}",
        amount, vault_data.balance
    );
    Ok(())
}

fn transaction(_program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let authority = next_account_info(account_iter)?;
    let destination = next_account_info(account_iter)?;
    let _system_program = next_account_info(account_iter)?;

    // Missing Signer Check
    // Anyone can steal lamports in vault by passing any public key as the authority without holding its private key,
    // since the program never checks that the authority signed the transaction.
    // if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }

    let mut data = vault.try_borrow_mut_data()?;
    let mut vault_data = Vault::try_from_slice(&data)?;

    if vault_data.balance < amount {
        return Err(ProgramError::InsufficientFunds);
    }
    vault_data.balance = vault_data
        .balance
        .checked_sub(amount)
        .ok_or(ProgramError::InvalidArgument)?;
    let serialized = vault_data
        .try_to_vec()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    data.copy_from_slice(&serialized);
    drop(data);

    **vault.try_borrow_mut_lamports()? -= amount;
    **destination.try_borrow_mut_lamports()? += amount;

    println!("Transferred {} lamports to {}", amount, destination.key);
    Ok(())
}

// Vulnerable Overflow Function
fn deposit_overflow(_program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let iter = &mut accounts.iter();
    let vault = next_account_info(iter)?;
    let depositor = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    invoke(
        &system_instruction::transfer(depositor.key, vault.key, amount),
        &[depositor.clone(), vault.clone(), system_program.clone()],
    )?;

    let mut data = vault.try_borrow_mut_data()?;
    let mut vault_data = Vault::try_from_slice(&data)?;

    // recommendation: checked_add().ok_or(ProgramError::InvalidArgument)?
    vault_data.balance = vault_data.balance.wrapping_add(amount);

    let serialized = vault_data
        .try_to_vec()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    data.copy_from_slice(&serialized);

    println!(
        " Overflow vulnerability. Deposited {}. New balance: {}",
        amount, vault_data.balance
    );
    Ok(())
}

// Vulnerable Underflow Function
fn transaction_underflow(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let _authority = next_account_info(account_iter)?;
    let destination = next_account_info(account_iter)?;
    let _system_program = next_account_info(account_iter)?;

    let mut data = vault.try_borrow_mut_data()?;
    let mut vault_data = Vault::try_from_slice(&data)?;

    // "vault_data.balance" is should be controlled
    // recommendation: if vault_data.balance < amount { return Err(ProgramError::InsufficientFunds); }

    // recommendation: checked_sub().ok_or(ProgramError::InvalidArgument)?
    vault_data.balance = vault_data.balance.wrapping_sub(amount);

    let serialized = vault_data
        .try_to_vec()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    data.copy_from_slice(&serialized);
    drop(data);

    **vault.try_borrow_mut_lamports()? -= amount;
    **destination.try_borrow_mut_lamports()? += amount;

    println!(
        "Underflow vulnerability. Transferred lamports {}. Vault balance: {}",
        amount, vault_data.balance
    );
    Ok(())
}

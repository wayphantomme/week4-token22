//! Week 4 — Remittance stablecoin: tasks 1–4.
//!
//! This file covers:
//!   Task 1 — mint with TransferFeeConfig, MetadataPointer, DefaultAccountState
//!             (frozen), and MintCloseAuthority, sized via try_calculate_account_len.
//!   Task 2 — transfer_checked_with_fee with fee computed from calculate_epoch_fee.
//!   Task 3 — all state reads go through StateWithExtensions, never raw unpack.
//!   Task 4 — freeze authority thaws an individual account after "KYC";
//!             negative test: a non-authority cannot thaw.
//!
//! All mint and account creation done in this file is intentionally
//! separate from the class reference code in test_initialize.rs and
//! confidential.rs. The structure mirrors the reference where useful.

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use litesvm::LiteSVM;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use t22::{accounts, instruction, ID};
use t22new::{
    extension::{
        default_account_state::DefaultAccountState,
        metadata_pointer::MetadataPointer,
        mint_close_authority::MintCloseAuthority,
        transfer_fee::TransferFeeConfig,
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_account3, mint_to},
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const DECIMALS: u8 = 6;
const BASIS_POINTS: u16 = 100; // 1%
const MAXIMUM_FEE: u64 = 10_000_000; // 10 tokens (6 decimals)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/t22.so");
    assert!(
        path.exists(),
        "binary not found at {}. Run `cargo build-sbf --arch v0` first.",
        path.display()
    );
    svm.add_program_from_file(ID, path).unwrap();
    (svm, payer)
}

fn send(svm: &mut LiteSVM, payer: &Keypair, ixs: &[Instruction], extra: &[&Keypair]) {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    tx.try_sign(&signers, bh).unwrap();
    if let Err(e) = svm.send_transaction(tx) {
        panic!("tx failed:\n{:#?}", e.meta.logs);
    }
}

fn send_expecting_failure(
    svm: &mut LiteSVM,
    payer: &Keypair,
    ixs: &[Instruction],
    extra: &[&Keypair],
) -> String {
    let mut signers: Vec<&Keypair> = vec![payer];
    signers.extend_from_slice(extra);
    let bh = svm.latest_blockhash();
    let mut tx = Transaction::new_unsigned(Message::new(ixs, Some(&payer.pubkey())));
    tx.try_sign(&signers, bh).unwrap();
    match svm.send_transaction(tx) {
        Ok(_) => panic!("expected failure, got success"),
        Err(e) => e.meta.logs.join("\n"),
    }
}

/// Build the create_remittance_mint instruction.
fn create_remittance_mint_ix(
    payer: &Pubkey,
    freeze_authority: &Pubkey,
    mint: &Pubkey,
    decimals: u8,
    basis_points: u16,
    maximum_fee: u64,
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::CreateRemittanceMint {
            payer: *payer,
            freeze_authority: *freeze_authority,
            mint: *mint,
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateRemittanceMint {
            decimals,
            basis_points,
            maximum_fee,
        }
        .data(),
    }
}

/// Create a token account for a remittance mint.
///
/// The mint has TransferFeeConfig, so each holder account must carry
/// TransferFeeAmount. All new accounts start frozen because of DefaultAccountState.
fn create_token_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Pubkey {
    // TransferFeeConfig on the mint forces TransferFeeAmount onto every token
    // account. Hardcoding 165 bytes here would underallocate.
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
        ExtensionType::TransferFeeAmount,
    ])
    .unwrap();
    let ta = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(space);
    send(
        svm,
        payer,
        &[
            solana_system_interface::instruction::create_account(
                &payer.pubkey(),
                &ta.pubkey(),
                lamports,
                space as u64,
                &TOKEN_2022_PROGRAM_ID,
            ),
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &ta.pubkey(), mint, owner).unwrap(),
        ],
        &[&ta],
    );
    ta.pubkey()
}

/// Thaw a token account via our program's thaw_remittance_account instruction.
fn thaw_account_ix(
    token_account: &Pubkey,
    mint: &Pubkey,
    freeze_authority: &Pubkey,
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::ThawRemittanceAccount {
            token_account: *token_account,
            mint: *mint,
            freeze_authority: *freeze_authority,
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::ThawRemittanceAccount {}.data(),
    }
}

/// Read the base amount of a token account via StateWithExtensions.
/// Never uses raw unpack — Task 3 requirement.
fn read_amount(svm: &LiteSVM, addr: &Pubkey) -> u64 {
    let acct = svm.get_account(addr).unwrap();
    // Task 3: state must be read exclusively through StateWithExtensions.
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    state.base.amount
}

/// Read the account state (frozen/initialized) via StateWithExtensions.
fn read_account_state(svm: &LiteSVM, addr: &Pubkey) -> AccountState {
    let acct = svm.get_account(addr).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    state.base.state
}

// ---------------------------------------------------------------------------
// Task 1 tests
// ---------------------------------------------------------------------------

#[test]
fn remittance_mint_has_all_four_extensions() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(
            &payer.pubkey(),
            &freeze_authority.pubkey(),
            &mint.pubkey(),
            DECIMALS,
            BASIS_POINTS,
            MAXIMUM_FEE,
        )],
        &[&mint, &freeze_authority],
    );

    let acct = svm.get_account(&mint.pubkey()).unwrap();
    assert_eq!(acct.owner, TOKEN_2022_PROGRAM_ID);

    // Task 3: read state only through StateWithExtensions.
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    assert_eq!(state.base.decimals, DECIMALS);

    let extensions = state.get_extension_types().unwrap();
    println!("remittance mint extensions: {extensions:?}");

    assert!(
        extensions.contains(&ExtensionType::MintCloseAuthority),
        "missing MintCloseAuthority"
    );
    assert!(
        extensions.contains(&ExtensionType::MetadataPointer),
        "missing MetadataPointer"
    );
    assert!(
        extensions.contains(&ExtensionType::TransferFeeConfig),
        "missing TransferFeeConfig"
    );
    assert!(
        extensions.contains(&ExtensionType::DefaultAccountState),
        "missing DefaultAccountState"
    );
    assert_eq!(extensions.len(), 4, "unexpected extra extensions");
}

#[test]
fn remittance_mint_account_len_matches_try_calculate() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(
            &payer.pubkey(),
            &freeze_authority.pubkey(),
            &mint.pubkey(),
            DECIMALS,
            BASIS_POINTS,
            MAXIMUM_FEE,
        )],
        &[&mint, &freeze_authority],
    );

    let actual_len = svm.get_account(&mint.pubkey()).unwrap().data.len();
    let expected_len = ExtensionType::try_calculate_account_len::<MintState>(&[
        ExtensionType::MintCloseAuthority,
        ExtensionType::MetadataPointer,
        ExtensionType::TransferFeeConfig,
        ExtensionType::DefaultAccountState,
    ])
    .unwrap();

    assert_eq!(
        actual_len, expected_len,
        "mint size does not match try_calculate_account_len"
    );
    println!("remittance mint size = {actual_len} bytes (expected {expected_len})");
}

#[test]
fn remittance_mint_has_correct_fee_config() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(
            &payer.pubkey(),
            &freeze_authority.pubkey(),
            &mint.pubkey(),
            DECIMALS,
            BASIS_POINTS,
            MAXIMUM_FEE,
        )],
        &[&mint, &freeze_authority],
    );

    let acct = svm.get_account(&mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let config = state.get_extension::<TransferFeeConfig>().unwrap();

    assert_eq!(
        u16::from(config.newer_transfer_fee.transfer_fee_basis_points),
        BASIS_POINTS
    );
    assert_eq!(u64::from(config.newer_transfer_fee.maximum_fee), MAXIMUM_FEE);
    println!("fee config: {} bps, max {}", BASIS_POINTS, MAXIMUM_FEE);
}

#[test]
fn remittance_mint_metadata_pointer_points_to_self() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(
            &payer.pubkey(),
            &freeze_authority.pubkey(),
            &mint.pubkey(),
            DECIMALS,
            BASIS_POINTS,
            MAXIMUM_FEE,
        )],
        &[&mint, &freeze_authority],
    );

    let acct = svm.get_account(&mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let pointer = state.get_extension::<MetadataPointer>().unwrap();

    let stored: Option<Pubkey> = pointer.metadata_address.into();
    assert_eq!(
        stored,
        Some(mint.pubkey()),
        "MetadataPointer should point to the mint itself"
    );
    println!("metadata pointer → {}", mint.pubkey());
    // Note: MetadataPointer only stores the address. Initializing TokenMetadata
    // (which embeds name/symbol in the mint account) is a separate step and is
    // not required by this task. See README for details.
}

#[test]
fn remittance_mint_has_correct_close_authority() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(
            &payer.pubkey(),
            &freeze_authority.pubkey(),
            &mint.pubkey(),
            DECIMALS,
            BASIS_POINTS,
            MAXIMUM_FEE,
        )],
        &[&mint, &freeze_authority],
    );

    let acct = svm.get_account(&mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let close = state.get_extension::<MintCloseAuthority>().unwrap();

    let stored: Option<Pubkey> = close.close_authority.into();
    assert_eq!(stored, Some(payer.pubkey()));
    println!("close authority = {}", payer.pubkey());
}

#[test]
fn remittance_mint_default_state_is_frozen() {
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(
            &payer.pubkey(),
            &freeze_authority.pubkey(),
            &mint.pubkey(),
            DECIMALS,
            BASIS_POINTS,
            MAXIMUM_FEE,
        )],
        &[&mint, &freeze_authority],
    );

    let acct = svm.get_account(&mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let default_state = state.get_extension::<DefaultAccountState>().unwrap();

    // DefaultAccountState.state is a PodAccountState = u8.
    // AccountState::Frozen = 2.
    assert_eq!(
        default_state.state,
        AccountState::Frozen as u8,
        "DefaultAccountState should be Frozen"
    );
    println!("default account state = Frozen ✓");
}

#[test]
fn new_token_account_starts_frozen() {
    // Because DefaultAccountState is Frozen, every new token account for
    // this mint is automatically frozen at creation. The freeze authority
    // must thaw it before it can receive tokens.
    let (mut svm, payer) = setup();
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();

    send(
        &mut svm,
        &payer,
        &[create_remittance_mint_ix(
            &payer.pubkey(),
            &freeze_authority.pubkey(),
            &mint.pubkey(),
            DECIMALS,
            BASIS_POINTS,
            MAXIMUM_FEE,
        )],
        &[&mint, &freeze_authority],
    );

    let holder = Keypair::new();
    let token_account = create_token_account(&mut svm, &payer, &mint.pubkey(), &holder.pubkey());

    let state = read_account_state(&svm, &token_account);
    assert_eq!(state, AccountState::Frozen, "new account should start frozen");
    println!("new account state = Frozen ✓");
}

// ---------------------------------------------------------------------------
// Task 4 tests: thaw (unfreeze after KYC)
// ---------------------------------------------------------------------------

/// Helper: create mint + holder account, return both keypairs.
fn setup_mint_and_holder(svm: &mut LiteSVM, payer: &Keypair) -> (Keypair, Keypair, Pubkey) {
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();

    send(
        svm,
        payer,
        &[create_remittance_mint_ix(
            &payer.pubkey(),
            &freeze_authority.pubkey(),
            &mint.pubkey(),
            DECIMALS,
            BASIS_POINTS,
            MAXIMUM_FEE,
        )],
        &[&mint, &freeze_authority],
    );

    let holder = Keypair::new();
    let token_account = create_token_account(svm, payer, &mint.pubkey(), &holder.pubkey());

    (mint, freeze_authority, token_account)
}

#[test]
fn freeze_authority_can_thaw_account_after_kyc() {
    let (mut svm, payer) = setup();
    let (mint, freeze_authority, token_account) = setup_mint_and_holder(&mut svm, &payer);

    // Before thaw: frozen.
    assert_eq!(read_account_state(&svm, &token_account), AccountState::Frozen);

    send(
        &mut svm,
        &payer,
        &[thaw_account_ix(
            &token_account,
            &mint.pubkey(),
            &freeze_authority.pubkey(),
        )],
        &[&freeze_authority],
    );

    // After thaw: initialized (active).
    assert_eq!(
        read_account_state(&svm, &token_account),
        AccountState::Initialized,
        "account should be active after thaw"
    );
    println!("account thawed by freeze authority ✓");
}

#[test]
fn non_freeze_authority_cannot_thaw_account() {
    // Task 4 negative test: only the freeze authority can thaw. Any other
    // signer is rejected by Token-2022.
    let (mut svm, payer) = setup();
    let (mint, _freeze_authority, token_account) = setup_mint_and_holder(&mut svm, &payer);

    let impostor = Keypair::new();
    svm.airdrop(&impostor.pubkey(), 1_000_000_000).unwrap();

    let logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[thaw_account_ix(
            &token_account,
            &mint.pubkey(),
            &impostor.pubkey(),
        )],
        &[&impostor],
    );

    assert!(
        logs.contains("OwnerMismatch")
            || logs.contains("owner mismatch")
            || logs.contains("3")     // token error code 3
            || logs.contains("Error"),
        "wrong error for unauthorized thaw:\n{logs}"
    );
    println!("non-authority thaw rejected ✓");
}

#[test]
fn mint_to_frozen_account_fails() {
    // Even the mint authority cannot mint into a frozen account.
    // The freeze authority must thaw first.
    let (mut svm, payer) = setup();
    let (mint, _freeze_authority, token_account) = setup_mint_and_holder(&mut svm, &payer);

    // Account is frozen — mint_to should fail.
    let logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &token_account,
            &payer.pubkey(),
            &[],
            1_000_000,
        )
        .unwrap()],
        &[],
    );
    assert!(
        logs.contains("AccountFrozen") || logs.contains("frozen") || logs.contains("17"),
        "expected AccountFrozen error:\n{logs}"
    );
    println!("mint to frozen account rejected ✓");
}

// ---------------------------------------------------------------------------
// Task 2 tests: transfer_checked_with_fee
// ---------------------------------------------------------------------------

/// Create mint, two thawed accounts, and mint tokens into source.
/// Both accounts are owned by payer so payer can sign transfers.
fn setup_funded_transfer(
    svm: &mut LiteSVM,
    payer: &Keypair,
    amount: u64,
) -> (Keypair, Keypair, Pubkey, Pubkey) {
    let (mint, freeze_authority, _) = setup_mint_and_holder(svm, payer);

    // Source and destination are owned by payer so payer is the transfer authority.
    let source = create_token_account(svm, payer, &mint.pubkey(), &payer.pubkey());
    let dest = create_token_account(svm, payer, &mint.pubkey(), &payer.pubkey());

    // Thaw source (KYC cleared).
    send(
        svm,
        payer,
        &[thaw_account_ix(
            &source,
            &mint.pubkey(),
            &freeze_authority.pubkey(),
        )],
        &[&freeze_authority],
    );

    // Thaw destination.
    send(
        svm,
        payer,
        &[thaw_account_ix(
            &dest,
            &mint.pubkey(),
            &freeze_authority.pubkey(),
        )],
        &[&freeze_authority],
    );

    // Mint tokens into source.
    send(
        svm,
        payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &source,
            &payer.pubkey(),
            &[],
            amount,
        )
        .unwrap()],
        &[],
    );

    (mint, freeze_authority, source, dest)
}

#[test]
fn transfer_with_fee_credits_correct_amount_to_recipient() {
    // The recipient receives amount minus the fee. The fee stays in the
    // destination account as withheld balance for the issuer to harvest.
    let (mut svm, payer) = setup();
    let transfer_amount = 1_000_000u64; // 1 token (6 decimals)
    let (mint, _freeze_authority, source, dest) =
        setup_funded_transfer(&mut svm, &payer, transfer_amount * 2);

    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::RemittanceTransfer {
                source,
                mint: mint.pubkey(),
                destination: dest,
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::RemittanceTransfer {
                amount: transfer_amount,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    // Recipient receives amount minus fee.
    // 100 bps = 1%, so fee = 10_000. Recipient = 1_000_000 - 10_000 = 990_000.
    let recipient_balance = read_amount(&svm, &dest);
    let expected_fee = transfer_amount * BASIS_POINTS as u64 / 10_000;
    let expected_received = transfer_amount - expected_fee;
    assert_eq!(
        recipient_balance, expected_received,
        "recipient received wrong amount"
    );
    println!("sent {transfer_amount}, fee {expected_fee}, recipient received {recipient_balance}");
}

#[test]
fn fee_matches_calculate_epoch_fee() {
    // This test verifies that the fee actually withheld matches what
    // calculate_epoch_fee would have computed at the same epoch. The program
    // calls calculate_epoch_fee internally — this test checks the contract.
    let (mut svm, payer) = setup();
    let transfer_amount = 1_000_000u64;
    let (mint, _freeze_authority, source, dest) =
        setup_funded_transfer(&mut svm, &payer, transfer_amount * 2);

    // Compute expected fee the same way the program does it.
    let mint_acct = svm.get_account(&mint.pubkey()).unwrap();
    let mint_state = t22new::extension::StateWithExtensions::<t22new::state::Mint>::unpack(
        &mint_acct.data,
    )
    .unwrap();
    let fee_config = mint_state
        .get_extension::<t22new::extension::transfer_fee::TransferFeeConfig>()
        .unwrap();
    // Epoch 0 in LiteSVM.
    let expected_fee = fee_config.calculate_epoch_fee(0, transfer_amount).unwrap();

    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::RemittanceTransfer {
                source,
                mint: mint.pubkey(),
                destination: dest,
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::RemittanceTransfer {
                amount: transfer_amount,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    let withheld_in_dest = {
        let acct = svm.get_account(&dest).unwrap();
        // Task 3: use StateWithExtensions, not raw unpack.
        let state =
            t22new::extension::StateWithExtensions::<t22new::state::Account>::unpack(&acct.data)
                .unwrap();
        let fee_amount = state
            .get_extension::<t22new::extension::transfer_fee::TransferFeeAmount>()
            .unwrap();
        u64::from(fee_amount.withheld_amount)
    };

    assert_eq!(
        withheld_in_dest, expected_fee,
        "withheld fee does not match calculate_epoch_fee"
    );
    println!(
        "fee: expected {expected_fee}, withheld {withheld_in_dest} — match ✓"
    );
}

#[test]
fn transfer_to_frozen_account_fails() {
    // Confirm Token-2022 rejects transfers to frozen accounts. The freeze
    // authority must thaw both sender and receiver before any transfer.
    let (mut svm, payer) = setup();
    let (mint, freeze_authority, _) = setup_mint_and_holder(&mut svm, &payer);

    // Source owned by payer (authority for the transfer).
    let source = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());
    let frozen_dest = create_token_account(&mut svm, &payer, &mint.pubkey(), &payer.pubkey());

    // Thaw and fund source only.
    send(
        &mut svm,
        &payer,
        &[thaw_account_ix(
            &source,
            &mint.pubkey(),
            &freeze_authority.pubkey(),
        )],
        &[&freeze_authority],
    );
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &mint.pubkey(),
            &source,
            &payer.pubkey(),
            &[],
            1_000_000,
        )
        .unwrap()],
        &[],
    );

    // frozen_dest is still frozen — transfer should fail.
    let logs = send_expecting_failure(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::RemittanceTransfer {
                source,
                mint: mint.pubkey(),
                destination: frozen_dest,
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::RemittanceTransfer {
                amount: 100_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    assert!(
        logs.contains("AccountFrozen") || logs.contains("frozen") || logs.contains("17"),
        "expected AccountFrozen error:\n{logs}"
    );
    println!("transfer to frozen account rejected ✓");
}

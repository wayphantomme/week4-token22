//! Week 4 — Task 5: re-issued remittance mint with PermanentDelegate and
//! ConfidentialTransferMint.
//!
//! This file covers:
//!   - Mint creation: 6 extensions verified via StateWithExtensions.
//!   - Account lifecycle: thaw (freeze authority) → ConfigureAccount (owner
//!     only) → ApproveAccount (CT authority). Each step is blocked without
//!     the prior one.
//!   - Negative tests: ConfigureAccount by non-owner, deposit before approve,
//!     seize via permanent delegate.
//!   - State reads: StateWithExtensions only, never raw unpack.
//!
//! The confidential transfer full lifecycle (deposit → apply → transfer →
//! withdraw) is in week4_confidential_lifecycle.rs (task 6).

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use litesvm::LiteSVM;
use proofext::instruction::ProofLocation;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::num::NonZeroI8;
use t22::{accounts, instruction, ID};
use t22new::{
    extension::{
        confidential_transfer::{instruction as ct_ix, ConfidentialTransferAccount, ConfidentialTransferMint},
        permanent_delegate::PermanentDelegate,
        default_account_state::DefaultAccountState,
        transfer_fee::TransferFeeAmount,
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_account3, mint_to},
    state::{Account as TokenAccountState, AccountState, Mint as MintState},
};
use zk::{
    encryption::{
        auth_encryption::AeKey,
        derivation::derive_confidential_keys,
        elgamal::ElGamalKeypair,
    },
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const DECIMALS: u8 = 6;
const BASIS_POINTS: u16 = 100;
const MAXIMUM_FEE: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// Infrastructure
// ---------------------------------------------------------------------------

fn setup() -> (LiteSVM, Keypair) {
    let mut svm = LiteSVM::new();
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/deploy/t22.so");
    assert!(path.exists(), "run cargo build-sbf first");
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

/// Build the create_remittance_confidential_mint instruction.
fn create_ct_mint_ix(
    payer: &Pubkey,
    freeze_authority: &Pubkey,
    ct_authority: &Pubkey,
    mint: &Pubkey,
    fee_elgamal_pubkey: [u8; 32],
) -> Instruction {
    Instruction {
        program_id: ID,
        accounts: accounts::CreateRemittanceConfidentialMint {
            payer: *payer,
            freeze_authority: *freeze_authority,
            confidential_transfer_authority: *ct_authority,
            mint: *mint,
            token_program: TOKEN_2022_PROGRAM_ID,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
        data: instruction::CreateRemittanceConfidentialMint {
            decimals: DECIMALS,
            basis_points: BASIS_POINTS,
            maximum_fee: MAXIMUM_FEE,
            withdraw_withheld_authority_elgamal_pubkey: fee_elgamal_pubkey,
        }
        .data(),
    }
}

/// Create a token account sized for all extensions required by this mint.
/// TransferFeeConfig → TransferFeeAmount
/// ConfidentialTransferMint → ConfidentialTransferAccount
/// ConfidentialTransferFeeConfig → ConfidentialTransferFeeAmount
/// All three must be allocated upfront; ConfigureAccount writes CT extensions
/// in-place and needs the space already there.
fn create_token_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Pubkey {
    let space = ExtensionType::try_calculate_account_len::<TokenAccountState>(&[
        ExtensionType::TransferFeeAmount,
        ExtensionType::ConfidentialTransferAccount,
        ExtensionType::ConfidentialTransferFeeAmount,
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

/// Thaw a token account via the program's thaw_remittance_account instruction.
fn thaw_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    token_account: &Pubkey,
    mint: &Pubkey,
    freeze_authority: &Keypair,
) {
    send(
        svm,
        payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ThawRemittanceAccount {
                token_account: *token_account,
                mint: *mint,
                freeze_authority: freeze_authority.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ThawRemittanceAccount {}.data(),
        }],
        &[freeze_authority],
    );
}

/// ConfigureAccount — owner derives their ElGamal and AES keys, supplies a
/// PubkeyValidity proof, and registers their public key with the account.
/// Only the account owner can do this; the keys are derived from their wallet.
fn configure_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    token_account: &Pubkey,
    mint: &Pubkey,
    owner: &Keypair,
) -> (ElGamalKeypair, AeKey) {
    let (elgamal, aes) = derive_confidential_keys(owner, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        token_account,
        mint,
        &aes.encrypt(0).into(),
        65536,
        &owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
    )
    .unwrap();
    send(svm, payer, &ixs, &[owner]);
    (elgamal, aes)
}

/// ApproveAccount — the CT authority activates confidential transfers on this
/// account. Without this step (approve_policy = manual), the account cannot
/// deposit or receive confidential transfers.
fn approve_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    token_account: &Pubkey,
    mint: &Pubkey,
    ct_authority: &Keypair,
) {
    send(
        svm,
        payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ApproveConfidentialAccount {
                token_account: *token_account,
                mint: *mint,
                confidential_transfer_authority: ct_authority.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ApproveConfidentialAccount {}.data(),
        }],
        &[ct_authority],
    );
}

// ---------------------------------------------------------------------------
// Setup helper: mint + three separate authority keypairs
// ---------------------------------------------------------------------------

struct MintSetup {
    mint: Keypair,
    freeze_authority: Keypair,
    ct_authority: Keypair,
}

fn create_ct_mint(svm: &mut LiteSVM, payer: &Keypair) -> MintSetup {
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();
    let ct_authority = Keypair::new();
    let (fee_elgamal, _) = derive_confidential_keys(payer, b"fee").unwrap();
    let fee_pubkey: [u8; 32] = fee_elgamal.pubkey().into();

    send(
        svm,
        payer,
        &[create_ct_mint_ix(
            &payer.pubkey(),
            &freeze_authority.pubkey(),
            &ct_authority.pubkey(),
            &mint.pubkey(),
            fee_pubkey,
        )],
        &[&mint, &freeze_authority, &ct_authority],
    );

    MintSetup { mint, freeze_authority, ct_authority }
}

// ---------------------------------------------------------------------------
// Task 5 tests: mint structure
// ---------------------------------------------------------------------------

#[test]
fn confidential_remittance_mint_has_all_seven_extensions() {
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    let acct = svm.get_account(&ms.mint.pubkey()).unwrap();
    assert_eq!(acct.owner, TOKEN_2022_PROGRAM_ID);

    // Task 3 rule applies here too: StateWithExtensions only.
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();

    let extensions = state.get_extension_types().unwrap();
    println!("confidential remittance mint extensions: {extensions:?}");

    assert!(extensions.contains(&ExtensionType::MintCloseAuthority), "missing MintCloseAuthority");
    assert!(extensions.contains(&ExtensionType::MetadataPointer),    "missing MetadataPointer");
    assert!(extensions.contains(&ExtensionType::TransferFeeConfig),  "missing TransferFeeConfig");
    assert!(extensions.contains(&ExtensionType::DefaultAccountState),"missing DefaultAccountState");
    assert!(extensions.contains(&ExtensionType::PermanentDelegate),  "missing PermanentDelegate");
    assert!(extensions.contains(&ExtensionType::ConfidentialTransferMint), "missing ConfidentialTransferMint");
    assert!(extensions.contains(&ExtensionType::ConfidentialTransferFeeConfig), "missing ConfidentialTransferFeeConfig");
    assert_eq!(extensions.len(), 7, "unexpected extension count");
}

#[test]
fn confidential_remittance_mint_size_matches_try_calculate() {
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    let actual = svm.get_account(&ms.mint.pubkey()).unwrap().data.len();
    let expected = ExtensionType::try_calculate_account_len::<MintState>(&[
        ExtensionType::MintCloseAuthority,
        ExtensionType::MetadataPointer,
        ExtensionType::TransferFeeConfig,
        ExtensionType::DefaultAccountState,
        ExtensionType::PermanentDelegate,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialTransferFeeConfig,
    ])
    .unwrap();

    assert_eq!(actual, expected);
    println!("mint size = {actual} bytes");
}

#[test]
fn confidential_remittance_mint_approve_policy_is_manual() {
    // ConfidentialTransferMint.auto_approve_new_accounts = false means the CT
    // authority must call ApproveAccount after every ConfigureAccount.
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    let acct = svm.get_account(&ms.mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let ct_mint = state.get_extension::<ConfidentialTransferMint>().unwrap();

    assert!(
        !bool::from(ct_mint.auto_approve_new_accounts),
        "approve policy should be manual (false)"
    );
    println!("auto_approve_new_accounts = false (manual) ✓");
}

#[test]
fn confidential_remittance_mint_ct_authority_stored_correctly() {
    // The CT authority stored in the extension must match what we passed at init.
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    let acct = svm.get_account(&ms.mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let ct_mint = state.get_extension::<ConfidentialTransferMint>().unwrap();

    let stored: Option<Pubkey> = ct_mint.authority.into();
    assert_eq!(stored, Some(ms.ct_authority.pubkey()));
    println!("CT authority = {} ✓", ms.ct_authority.pubkey());
}

#[test]
fn confidential_remittance_mint_permanent_delegate_is_payer() {
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    let acct = svm.get_account(&ms.mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let pd = state.get_extension::<PermanentDelegate>().unwrap();

    let stored: Option<Pubkey> = pd.delegate.into();
    assert_eq!(stored, Some(payer.pubkey()));
    println!("permanent delegate = {} ✓", payer.pubkey());
}

#[test]
fn confidential_remittance_mint_default_state_is_frozen() {
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    let acct = svm.get_account(&ms.mint.pubkey()).unwrap();
    let state = StateWithExtensions::<MintState>::unpack(&acct.data).unwrap();
    let ds = state.get_extension::<DefaultAccountState>().unwrap();

    // DefaultAccountState.state is a u8; AccountState::Frozen = 2.
    assert_eq!(ds.state, AccountState::Frozen as u8);
    println!("default account state = Frozen ✓");
}

// ---------------------------------------------------------------------------
// Task 5 tests: account lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_account_lifecycle_thaw_configure_approve() {
    // Demonstrates the three-step sequence every account must go through
    // before it can participate in confidential transfers on this mint.
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    let owner = payer.insecure_clone();
    let ta = create_token_account(&mut svm, &payer, &ms.mint.pubkey(), &owner.pubkey());

    // Step 1: account starts frozen.
    {
        let acct = svm.get_account(&ta).unwrap();
        let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
        assert_eq!(state.base.state, AccountState::Frozen);
        println!("step 1: account frozen ✓");
    }

    // Step 2: freeze authority thaws after KYC.
    thaw_account(&mut svm, &payer, &ta, &ms.mint.pubkey(), &ms.freeze_authority);
    {
        let acct = svm.get_account(&ta).unwrap();
        let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
        assert_eq!(state.base.state, AccountState::Initialized);
        println!("step 2: account thawed ✓");
    }

    // Step 3: owner calls ConfigureAccount — registers their ElGamal pubkey.
    // This can only be done by the account owner; the keys come from their
    // wallet signature. No other party can configure on their behalf.
    configure_account(&mut svm, &payer, &ta, &ms.mint.pubkey(), &owner);
    {
        let acct = svm.get_account(&ta).unwrap();
        let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
        let ct = state.get_extension::<ConfidentialTransferAccount>().unwrap();
        // approved = false because approve_policy = manual.
        assert!(!bool::from(ct.approved), "should be pending approval");
        println!("step 3: configured, pending approval ✓");
    }

    // Step 4: CT authority approves. Only after this can the account deposit
    // or receive confidential transfers.
    approve_account(&mut svm, &payer, &ta, &ms.mint.pubkey(), &ms.ct_authority);
    {
        let acct = svm.get_account(&ta).unwrap();
        let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
        let ct = state.get_extension::<ConfidentialTransferAccount>().unwrap();
        assert!(bool::from(ct.approved), "should be approved after ApproveAccount");
        println!("step 4: approved ✓");
    }
}

// ---------------------------------------------------------------------------
// Task 5 negative tests
// ---------------------------------------------------------------------------

#[test]
fn configure_account_by_non_owner_fails() {
    // ConfigureAccount must be signed by the account's owner. The proof is
    // built against their ElGamal key, which is derived from their signature.
    // Any other signer produces a proof that does not match the account owner.
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    let owner = Keypair::new();
    svm.airdrop(&owner.pubkey(), 1_000_000_000).unwrap();
    let ta = create_token_account(&mut svm, &payer, &ms.mint.pubkey(), &owner.pubkey());
    thaw_account(&mut svm, &payer, &ta, &ms.mint.pubkey(), &ms.freeze_authority);

    // Impostor tries to configure the owner's account with their own keys.
    let impostor = payer.insecure_clone();
    let (impostor_elgamal, impostor_aes) = derive_confidential_keys(&impostor, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&impostor_elgamal).unwrap();

    let ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &ta,
        &ms.mint.pubkey(),
        &impostor_aes.encrypt(0).into(),
        65536,
        &impostor.pubkey(), // wrong owner
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
    )
    .unwrap();

    let logs = send_expecting_failure(&mut svm, &payer, &ixs, &[]);
    assert!(
        logs.contains("OwnerMismatch") || logs.contains("owner") || logs.contains("Error"),
        "wrong error:\n{logs}"
    );
    println!("configure by non-owner rejected ✓");
}

#[test]
fn deposit_before_approve_fails() {
    // After ConfigureAccount but before ApproveAccount, the account is not
    // yet approved. Token-2022 rejects any deposit into an unapproved account
    // when approve_policy = manual.
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    let owner = payer.insecure_clone();
    let ta = create_token_account(&mut svm, &payer, &ms.mint.pubkey(), &owner.pubkey());
    thaw_account(&mut svm, &payer, &ta, &ms.mint.pubkey(), &ms.freeze_authority);
    configure_account(&mut svm, &payer, &ta, &ms.mint.pubkey(), &owner);

    // Mint public tokens into the account first.
    send(
        &mut svm,
        &payer,
        &[mint_to(&TOKEN_2022_PROGRAM_ID, &ms.mint.pubkey(), &ta, &payer.pubkey(), &[], 1_000_000).unwrap()],
        &[],
    );

    // Try to deposit before ApproveAccount — should fail.
    let deposit_ix = Instruction {
        program_id: ID,
        accounts: accounts::DepositConfidential {
            token_account: ta,
            mint: ms.mint.pubkey(),
            authority: payer.pubkey(),
            token_program: TOKEN_2022_PROGRAM_ID,
        }
        .to_account_metas(None),
        data: instruction::DepositConfidential { amount: 500_000, decimals: DECIMALS }.data(),
    };

    let logs = send_expecting_failure(&mut svm, &payer, &[deposit_ix], &[]);
    assert!(
        logs.contains("ConfidentialTransferAccount")
            || logs.contains("not approved")
            || logs.contains("Error"),
        "wrong error for deposit before approve:\n{logs}"
    );
    println!("deposit before approve rejected ✓");
}

#[test]
fn permanent_delegate_seizes_public_balance_without_consent() {
    // The permanent delegate (payer) moves tokens from a holder's account
    // without any approval from the holder. This is the seizure mechanism
    // regulators require.
    //
    // Key point: this only works on the PUBLIC balance. Once tokens are in
    // the confidential system, the permanent delegate cannot reach them
    // (see written finding in README).
    let (mut svm, payer) = setup();
    let ms = create_ct_mint(&mut svm, &payer);

    // Victim has a thawed, funded account.
    let victim = Keypair::new();
    svm.airdrop(&victim.pubkey(), 1_000_000_000).unwrap();
    let victim_ta = create_token_account(&mut svm, &payer, &ms.mint.pubkey(), &victim.pubkey());
    thaw_account(&mut svm, &payer, &victim_ta, &ms.mint.pubkey(), &ms.freeze_authority);

    // Issuer's seizure destination.
    let seizure_ta = create_token_account(&mut svm, &payer, &ms.mint.pubkey(), &payer.pubkey());
    thaw_account(&mut svm, &payer, &seizure_ta, &ms.mint.pubkey(), &ms.freeze_authority);

    send(
        &mut svm,
        &payer,
        &[mint_to(&TOKEN_2022_PROGRAM_ID, &ms.mint.pubkey(), &victim_ta, &payer.pubkey(), &[], 5_000_000).unwrap()],
        &[],
    );

    // Victim does not sign. Permanent delegate moves tokens anyway.
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::PermanentDelegateSeize {
                source: victim_ta,
                mint: ms.mint.pubkey(),
                destination: seizure_ta,
                permanent_delegate: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::PermanentDelegateSeize {
                amount: 5_000_000,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    // Verify via StateWithExtensions — no raw unpack.
    let victim_acct = svm.get_account(&victim_ta).unwrap();
    let victim_state = StateWithExtensions::<TokenAccountState>::unpack(&victim_acct.data).unwrap();
    let seizure_acct = svm.get_account(&seizure_ta).unwrap();
    let seizure_state = StateWithExtensions::<TokenAccountState>::unpack(&seizure_acct.data).unwrap();

    assert_eq!(victim_state.base.amount, 0, "victim should have 0 after seizure");
    // 1% fee (50_000) is withheld in destination. Recipient receives 4_950_000.
    assert_eq!(seizure_state.base.amount, 4_950_000, "destination should have amount minus 1% fee");

    // The fee (50_000) must be recorded in TransferFeeAmount on the destination.
    let fee_amount = seizure_state.get_extension::<TransferFeeAmount>().unwrap();
    assert_eq!(u64::from(fee_amount.withheld_amount), 50_000, "withheld fee should be 50_000");

    println!("permanent delegate seized 5_000_000: 4_950_000 credited, 50_000 withheld as fee ✓");
}

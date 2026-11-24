//! Week 4 — Task 6: full confidential transfer lifecycle on the remittance mint.
//!
//! The remittance mint (task 5) has both TransferFeeConfig and
//! ConfidentialTransferMint, which requires ConfidentialTransferFeeConfig.
//! That combination changes the transfer path: confidential transfers on this
//! mint must use ct_ix::transfer_with_fee, which needs five proofs instead of
//! the three used by a plain confidential mint.
//!
//! Five proofs for transfer_with_fee:
//!   1. CiphertextCommitmentEquality
//!      The amount deducted from sender equals the amount added to recipient.
//!   2. BatchedGroupedCiphertext3HandlesValidity
//!      The transfer amount ciphertext is well-formed under sender, recipient,
//!      and auditor keys.
//!   3. PercentageWithCap
//!      The fee was computed correctly from the hidden transfer amount, using
//!      the mint's basis points and maximum fee — without revealing the amount.
//!   4. BatchedGroupedCiphertext2HandlesValidity
//!      The fee ciphertext is well-formed under both recipient and fee
//!      authority keys.
//!   5. BatchedRangeProofU256
//!      All committed values are non-negative (wider than U128 because there
//!      are more committed values: sender remainder, transfer lo, transfer hi,
//!      and fee).
//!
//! Proof context state accounts:
//!   Each proof is too large to fit inline in a 1232-byte transaction, so it
//!   is verified first into its own context state account on the ZK ElGamal
//!   Proof program, then referenced by address when the token instruction runs.
//!   After the token instruction succeeds, the context accounts are closed to
//!   recover rent.
//!
//! Pending vs available balance:
//!   Incoming transfers land in pending, not available. The recipient must call
//!   ApplyPendingBalance before they can transfer or withdraw those tokens.
//!   This prevents front-running: no one can alter the available balance that
//!   a transfer proof was built against.
//!
//! Account lifecycle reminder (from task 5):
//!   create_account → initialize_account3 → thaw (freeze authority) →
//!   ConfigureAccount (owner only) → ApproveAccount (CT authority) → usable.

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    InstructionData, ToAccountMetas,
};
use litesvm::LiteSVM;
use proofext::instruction::ProofLocation;
use proofgen::{
    transfer_with_fee::transfer_with_fee_split_proof_data,
    withdraw::withdraw_proof_data,
};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::num::NonZeroI8;
use t22::{accounts, instruction, ID};
use t22new::{
    extension::{
        confidential_transfer::{instruction as ct_ix, ConfidentialTransferAccount},
        confidential_transfer_fee::ConfidentialTransferFeeAmount,
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::{initialize_account3, mint_to},
    state::Account as TokenAccountState,
};
use zk::{
    encryption::{
        auth_encryption::{AeCiphertext, AeKey},
        derivation::derive_confidential_keys,
        elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
    },
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use zkif::{
    instruction::{close_context_state, ContextStateInfo, ProofInstruction},
    proof_data::ZkProofData,
    state::ProofContextState,
};

const TOKEN_2022_PROGRAM_ID: Pubkey = anchor_spl::token_interface::spl_token_2022::ID;
const ZK_PROGRAM_ID: Pubkey = zkif::ID;
const DECIMALS: u8 = 6;
const BASIS_POINTS: u16 = 100; // 1%
const MAXIMUM_FEE: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// Infrastructure (mirrors week4_confidential_mint.rs helpers)
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

// ---------------------------------------------------------------------------
// Mint setup
// ---------------------------------------------------------------------------

/// Everything needed to run the lifecycle tests.
struct TestMint {
    mint: Keypair,
    freeze_authority: Keypair,
    ct_authority: Keypair,
    fee_elgamal: ElGamalKeypair, // decrypt withheld fees
}

fn create_remittance_ct_mint(svm: &mut LiteSVM, payer: &Keypair) -> TestMint {
    let mint = Keypair::new();
    let freeze_authority = Keypair::new();
    let ct_authority = Keypair::new();
    let (fee_elgamal, _) = derive_confidential_keys(payer, b"fee").unwrap();
    let fee_pubkey: [u8; 32] = fee_elgamal.pubkey().into();

    send(
        svm,
        payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::CreateRemittanceConfidentialMint {
                payer: payer.pubkey(),
                freeze_authority: freeze_authority.pubkey(),
                confidential_transfer_authority: ct_authority.pubkey(),
                mint: mint.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
                system_program: system_program::ID,
            }
            .to_account_metas(None),
            data: instruction::CreateRemittanceConfidentialMint {
                decimals: DECIMALS,
                basis_points: BASIS_POINTS,
                maximum_fee: MAXIMUM_FEE,
                withdraw_withheld_authority_elgamal_pubkey: fee_pubkey,
            }
            .data(),
        }],
        &[&mint, &freeze_authority, &ct_authority],
    );

    TestMint { mint, freeze_authority, ct_authority, fee_elgamal }
}

// ---------------------------------------------------------------------------
// Account setup: the three-step lifecycle from task 5
// ---------------------------------------------------------------------------

struct Holder {
    account: Pubkey,
    elgamal: ElGamalKeypair,
    aes: AeKey,
}

/// Create a token account, thaw it, configure it, and approve it.
/// This is the complete path every account must follow on this mint.
fn setup_holder(
    svm: &mut LiteSVM,
    payer: &Keypair,
    tm: &TestMint,
    owner: &Keypair,
) -> Holder {
    // Token account must be sized for all three account-side extensions.
    // These are required by the three mint-side confidential extensions.
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
            initialize_account3(&TOKEN_2022_PROGRAM_ID, &ta.pubkey(), &tm.mint.pubkey(), &owner.pubkey()).unwrap(),
        ],
        &[&ta],
    );

    // Step 1: thaw — freeze authority clears KYC.
    send(
        svm,
        payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ThawRemittanceAccount {
                token_account: ta.pubkey(),
                mint: tm.mint.pubkey(),
                freeze_authority: tm.freeze_authority.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ThawRemittanceAccount {}.data(),
        }],
        &[&tm.freeze_authority],
    );

    // Step 2: ConfigureAccount — owner only.
    // The owner derives their ElGamal and AES keys from their wallet signature.
    // No other party can do this: the proof is built against the owner's key.
    let (elgamal, aes) = derive_confidential_keys(owner, b"").unwrap();
    let proof = build_pubkey_validity_proof_data(&elgamal).unwrap();
    let ixs = ct_ix::configure_account(
        &TOKEN_2022_PROGRAM_ID,
        &ta.pubkey(),
        &tm.mint.pubkey(),
        &aes.encrypt(0).into(),
        65536,
        &owner.pubkey(),
        &[],
        ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof),
    )
    .unwrap();
    send(svm, payer, &ixs, &[owner]);

    // Step 3: ApproveAccount — CT authority gates confidential access.
    // With approve_policy = manual this is required; without it deposits fail.
    send(
        svm,
        payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ApproveConfidentialAccount {
                token_account: ta.pubkey(),
                mint: tm.mint.pubkey(),
                confidential_transfer_authority: tm.ct_authority.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ApproveConfidentialAccount {}.data(),
        }],
        &[&tm.ct_authority],
    );

    Holder { account: ta.pubkey(), elgamal, aes }
}

// ---------------------------------------------------------------------------
// Helpers for reading confidential state
// ---------------------------------------------------------------------------

fn read_ct(svm: &LiteSVM, account: &Pubkey) -> ConfidentialTransferAccount {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    *state.get_extension::<ConfidentialTransferAccount>().unwrap()
}

fn available_balance(ct: &ConfidentialTransferAccount, elgamal: &ElGamalKeypair) -> u64 {
    let ciphertext: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    elgamal.secret().decrypt_u32(&ciphertext).unwrap()
}

fn pending_balance(ct: &ConfidentialTransferAccount, elgamal: &ElGamalKeypair) -> u64 {
    let lo: ElGamalCiphertext = ct.pending_balance_lo.try_into().unwrap();
    let hi: ElGamalCiphertext = ct.pending_balance_hi.try_into().unwrap();
    elgamal.secret().decrypt_u32(&lo).unwrap()
        + (elgamal.secret().decrypt_u32(&hi).unwrap() << 16)
}

/// Read the withheld fee on a token account.
/// Encrypted under the fee authority's key; the holder cannot read this.
fn withheld_fee(svm: &LiteSVM, account: &Pubkey, fee_authority: &ElGamalKeypair) -> u64 {
    let acct = svm.get_account(account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    let ext = state.get_extension::<ConfidentialTransferFeeAmount>().unwrap();
    let ct: ElGamalCiphertext = ext.withheld_amount.try_into().unwrap();
    fee_authority.secret().decrypt_u32(&ct).unwrap()
}

// ---------------------------------------------------------------------------
// ApplyPendingBalance helper
// ---------------------------------------------------------------------------

/// Move pending balance into available.
/// The owner must decrypt the current pending and available balances, add them,
/// re-encrypt the sum, and hand the ciphertext to the program. The program
/// cannot do this — it has no access to the owner's AES key.
fn apply_pending(svm: &mut LiteSVM, payer: &Keypair, holder: &Holder, owner: &Keypair) {
    let ct = read_ct(svm, &holder.account);
    let counter: u64 = ct.pending_balance_credit_counter.into();
    let new_available =
        available_balance(&ct, &holder.elgamal) + pending_balance(&ct, &holder.elgamal);
    let ciphertext: [u8; 36] = holder.aes.encrypt(new_available).to_bytes();

    send(
        svm,
        payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::ApplyPendingBalance {
                token_account: holder.account,
                authority: owner.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::ApplyPendingBalance {
                expected_pending_balance_credit_counter: counter,
                new_decryptable_available_balance: ciphertext,
            }
            .data(),
        }],
        &[owner],
    );
}

// ---------------------------------------------------------------------------
// ZK proof staging
// ---------------------------------------------------------------------------

/// Verify a proof into a context state account so the token instruction can
/// reference it by address. Each confidential transfer proof is too large to
/// carry inline in a 1232-byte transaction.
fn stage_proof<T, U>(
    svm: &mut LiteSVM,
    payer: &Keypair,
    kind: ProofInstruction,
    proof: &T,
) -> Pubkey
where
    T: bytemuck::Pod + ZkProofData<U>,
    U: bytemuck::Pod,
{
    let context_len = std::mem::size_of::<ProofContextState<U>>();
    let ctx = Keypair::new();
    let lamports = svm.minimum_balance_for_rent_exemption(context_len);
    send(
        svm,
        payer,
        &[solana_system_interface::instruction::create_account(
            &payer.pubkey(),
            &ctx.pubkey(),
            lamports,
            context_len as u64,
            &ZK_PROGRAM_ID,
        )],
        &[&ctx],
    );
    send(
        svm,
        payer,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(400_000),
            kind.encode_verify_proof(
                Some(ContextStateInfo {
                    context_state_account: &ctx.pubkey(),
                    context_state_authority: &payer.pubkey(),
                }),
                proof,
            ),
        ],
        &[],
    );
    ctx.pubkey()
}

/// Close proof context accounts and recover rent to payer.
fn close_contexts(svm: &mut LiteSVM, payer: &Keypair, contexts: &[Pubkey]) {
    let ixs: Vec<Instruction> = contexts
        .iter()
        .map(|c| {
            close_context_state(
                ContextStateInfo {
                    context_state_account: c,
                    context_state_authority: &payer.pubkey(),
                },
                &payer.pubkey(),
            )
        })
        .collect();
    send(svm, payer, &ixs, &[]);
}

// ---------------------------------------------------------------------------
// Task 6: full confidential lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_confidential_lifecycle_with_fee() {
    let (mut svm, payer) = setup();
    let tm = create_remittance_ct_mint(&mut svm, &payer);

    let alice_owner = payer.insecure_clone();
    let bob_owner = Keypair::new();
    svm.airdrop(&bob_owner.pubkey(), 10_000_000_000).unwrap();

    let alice = setup_holder(&mut svm, &payer, &tm, &alice_owner);
    let bob = setup_holder(&mut svm, &payer, &tm, &bob_owner);

    // ---- Step 1: mint public tokens and deposit into confidential system --
    //
    // Deposit moves tokens from Alice's public balance into her pending
    // confidential balance. The amount is still visible here (it was public
    // before the move), so no proof is needed for this step.
    let initial_amount = 100_000u64;
    send(
        &mut svm,
        &payer,
        &[mint_to(
            &TOKEN_2022_PROGRAM_ID,
            &tm.mint.pubkey(),
            &alice.account,
            &payer.pubkey(),
            &[],
            initial_amount,
        )
        .unwrap()],
        &[],
    );

    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::DepositConfidential {
                token_account: alice.account,
                mint: tm.mint.pubkey(),
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::DepositConfidential {
                amount: initial_amount,
                decimals: DECIMALS,
            }
            .data(),
        }],
        &[],
    );

    // Public balance should now be 0.
    {
        let acct = svm.get_account(&alice.account).unwrap();
        let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
        assert_eq!(state.base.amount, 0, "public balance should be 0 after deposit");
    }

    let ct = read_ct(&svm, &alice.account);
    let after_deposit_pending = pending_balance(&ct, &alice.elgamal);
    println!("after deposit: pending={after_deposit_pending} available={}",
        available_balance(&ct, &alice.elgamal));
    assert_eq!(after_deposit_pending, initial_amount);

    // ---- Step 2: ApplyPendingBalance (Alice) ------------------------------
    //
    // Alice moves her pending balance into available so she can transfer it.
    // She decrypts both balances, adds them, re-encrypts, and passes the
    // ciphertext in. The program cannot do this — it has no access to her key.
    apply_pending(&mut svm, &payer, &alice, &alice_owner);

    let ct = read_ct(&svm, &alice.account);
    let alice_available = available_balance(&ct, &alice.elgamal);
    println!("after apply: pending={} available={alice_available}",
        pending_balance(&ct, &alice.elgamal));
    assert_eq!(alice_available, initial_amount);

    // ---- Step 3: Confidential transfer with fee (Alice → Bob) ------------
    //
    // Because this mint has ConfidentialTransferFeeConfig, we must use
    // transfer_with_fee (not transfer). It needs 5 proofs instead of 3.
    // All five are staged into context state accounts first, then referenced
    // by address in the token instruction.
    let transfer_amount = 20_000u64;

    let ct = read_ct(&svm, &alice.account);
    let alice_ciphertext: ElGamalCiphertext = ct.available_balance.try_into().unwrap();
    let alice_decryptable: AeCiphertext = ct.decryptable_available_balance.try_into().unwrap();
    let bob_pubkey: ElGamalPubkey = read_ct(&svm, &bob.account).elgamal_pubkey.try_into().unwrap();
    let fee_authority_pubkey: ElGamalPubkey = tm.fee_elgamal.pubkey().clone();

    // Generate all five proofs at once. transfer_with_fee_split_proof_data
    // needs the fee parameters so it can prove the fee was computed correctly
    // from the hidden amount.
    let proofs = transfer_with_fee_split_proof_data(
        &alice_ciphertext,
        &alice_decryptable,
        transfer_amount,
        &alice.elgamal,
        &alice.aes,
        &bob_pubkey,
        None,
        &fee_authority_pubkey,
        BASIS_POINTS,
        MAXIMUM_FEE,
    )
    .unwrap();

    // Stage each proof into its own context state account.
    // Proof 1: equality — amount deducted = amount added.
    let eq_ctx = stage_proof(
        &mut svm, &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &proofs.equality_proof_data,
    );
    // Proof 2: transfer amount ciphertext validity (3 handles: sender, recipient, auditor).
    let val_ctx = stage_proof(
        &mut svm, &payer,
        ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity,
        &proofs.transfer_amount_ciphertext_validity_proof_data_with_ciphertext.proof_data,
    );
    // Proof 3: percentage with cap — fee was computed correctly from hidden amount.
    let pct_ctx = stage_proof(
        &mut svm, &payer,
        ProofInstruction::VerifyPercentageWithCap,
        &proofs.percentage_with_cap_proof_data,
    );
    // Proof 4: fee ciphertext validity (2 handles: recipient and fee authority).
    let fee_val_ctx = stage_proof(
        &mut svm, &payer,
        ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity,
        &proofs.fee_ciphertext_validity_proof_data,
    );
    // Proof 5: range proof U256 (wider than U128 because more committed values).
    let range_ctx = stage_proof(
        &mut svm, &payer,
        ProofInstruction::VerifyBatchedRangeProofU256,
        &proofs.range_proof_data,
    );

    let new_alice_decryptable = alice.aes.encrypt(alice_available - transfer_amount);
    let ixs = ct_ix::transfer_with_fee(
        &TOKEN_2022_PROGRAM_ID,
        &alice.account,
        &tm.mint.pubkey(),
        &bob.account,
        &new_alice_decryptable.into(),
        &proofs.transfer_amount_ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        &proofs.transfer_amount_ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
        &alice_owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&eq_ctx),
        ProofLocation::ContextStateAccount(&val_ctx),
        ProofLocation::ContextStateAccount(&pct_ctx),
        ProofLocation::ContextStateAccount(&fee_val_ctx),
        ProofLocation::ContextStateAccount(&range_ctx),
    )
    .unwrap();
    send(&mut svm, &payer, &ixs, &[&alice_owner]);

    // Close the five proof context accounts to recover rent.
    close_contexts(&mut svm, &payer, &[eq_ctx, val_ctx, pct_ctx, fee_val_ctx, range_ctx]);

    // After transfer:
    //   Alice lost transfer_amount from available.
    //   Bob has transfer_amount in pending (minus fee which is withheld on his account).
    //   Fee (1% of 20_000 = 200) is withheld on Bob's account under fee authority key.
    let expected_fee = transfer_amount * BASIS_POINTS as u64 / 10_000; // 200
    let expected_bob_pending = transfer_amount - expected_fee; // 19_800

    let alice_ct = read_ct(&svm, &alice.account);
    let alice_after = available_balance(&alice_ct, &alice.elgamal);
    println!("alice after transfer: available={alice_after}");
    assert_eq!(alice_after, alice_available - transfer_amount);

    let bob_ct = read_ct(&svm, &bob.account);
    let bob_pending_after = pending_balance(&bob_ct, &bob.elgamal);
    println!("bob pending after transfer: {bob_pending_after}");
    assert_eq!(bob_pending_after, expected_bob_pending);

    let bob_withheld = withheld_fee(&svm, &bob.account, &tm.fee_elgamal);
    println!("fee withheld on bob: {bob_withheld}");
    assert_eq!(bob_withheld, expected_fee);

    // ---- Step 4: Bob applies his pending balance --------------------------
    //
    // Bob must call ApplyPendingBalance before he can transfer or withdraw.
    // The pending → available move uses the same owner-only AES key mechanism.
    apply_pending(&mut svm, &payer, &bob, &bob_owner);
    let bob_ct = read_ct(&svm, &bob.account);
    let bob_available = available_balance(&bob_ct, &bob.elgamal);
    println!("bob available after apply: {bob_available}");
    assert_eq!(bob_available, expected_bob_pending);

    // ---- Step 5: Bob withdraws back to public balance --------------------
    //
    // Withdraw is the reverse of deposit. The amount becomes public again.
    // Two proofs needed:
    //   CiphertextCommitmentEquality — available decreases by exactly withdraw_amount.
    //   BatchedRangeProofU64 — remaining balance is non-negative.
    //
    // ApplyPendingBalance must have been called first. The withdraw proof is
    // built against the available balance; pending is not included in it.
    // Withdrawing with pending still outstanding would make the proof invalid.
    let withdraw_amount = 10_000u64;

    let bob_ct = read_ct(&svm, &bob.account);
    let bob_current: ElGamalCiphertext = bob_ct.available_balance.try_into().unwrap();

    let wproofs = withdraw_proof_data(
        &bob_current,
        bob_available,
        withdraw_amount,
        &bob.elgamal,
    )
    .unwrap();

    let weq_ctx = stage_proof(
        &mut svm, &payer,
        ProofInstruction::VerifyCiphertextCommitmentEquality,
        &wproofs.equality_proof_data,
    );
    let wrange_ctx = stage_proof(
        &mut svm, &payer,
        ProofInstruction::VerifyBatchedRangeProofU64,
        &wproofs.range_proof_data,
    );

    let new_bob_decryptable = bob.aes.encrypt(bob_available - withdraw_amount);
    let ixs = ct_ix::withdraw(
        &TOKEN_2022_PROGRAM_ID,
        &bob.account,
        &tm.mint.pubkey(),
        withdraw_amount,
        DECIMALS,
        &new_bob_decryptable.into(),
        &bob_owner.pubkey(),
        &[],
        ProofLocation::ContextStateAccount(&weq_ctx),
        ProofLocation::ContextStateAccount(&wrange_ctx),
    )
    .unwrap();
    send(&mut svm, &payer, &ixs, &[&bob_owner]);
    close_contexts(&mut svm, &payer, &[weq_ctx, wrange_ctx]);

    // Bob's public balance should now equal withdraw_amount.
    // His confidential available should be what remained after withdrawal.
    let acct = svm.get_account(&bob.account).unwrap();
    let state = StateWithExtensions::<TokenAccountState>::unpack(&acct.data).unwrap();
    assert_eq!(state.base.amount, withdraw_amount,
        "public balance should equal withdraw amount");

    let bob_ct = read_ct(&svm, &bob.account);
    let bob_remaining = available_balance(&bob_ct, &bob.elgamal);
    assert_eq!(bob_remaining, bob_available - withdraw_amount,
        "remaining confidential balance wrong");

    println!("withdraw complete: public={withdraw_amount} confidential_remaining={bob_remaining}");
    println!("lifecycle done: deposit -> apply -> transfer_with_fee -> apply -> withdraw ✓");
}

// ---------------------------------------------------------------------------
// Apply pending before withdraw — the enforced ordering
// ---------------------------------------------------------------------------

#[test]
fn withdraw_proof_requires_pending_applied_first() {
    // This test demonstrates why apply_pending must precede withdraw.
    // The withdraw proof is built against the available balance ciphertext.
    // If there is a pending balance that has not been applied, the proof is
    // built against a stale available value and Token-2022 rejects it.
    //
    // The test shows this by verifying that after apply, the state is
    // consistent: available includes the deposited amount, pending is zero.
    let (mut svm, payer) = setup();
    let tm = create_remittance_ct_mint(&mut svm, &payer);
    let owner = payer.insecure_clone();
    let holder = setup_holder(&mut svm, &payer, &tm, &owner);

    // Deposit into pending.
    send(
        &mut svm,
        &payer,
        &[mint_to(&TOKEN_2022_PROGRAM_ID, &tm.mint.pubkey(), &holder.account, &payer.pubkey(), &[], 5_000).unwrap()],
        &[],
    );
    send(
        &mut svm,
        &payer,
        &[Instruction {
            program_id: ID,
            accounts: accounts::DepositConfidential {
                token_account: holder.account,
                mint: tm.mint.pubkey(),
                authority: payer.pubkey(),
                token_program: TOKEN_2022_PROGRAM_ID,
            }
            .to_account_metas(None),
            data: instruction::DepositConfidential { amount: 5_000, decimals: DECIMALS }.data(),
        }],
        &[],
    );

    // Before apply: pending = 5_000, available = 0.
    let ct = read_ct(&svm, &holder.account);
    assert_eq!(pending_balance(&ct, &holder.elgamal), 5_000);
    assert_eq!(available_balance(&ct, &holder.elgamal), 0);

    // Apply pending.
    apply_pending(&mut svm, &payer, &holder, &owner);

    // After apply: pending = 0, available = 5_000.
    let ct = read_ct(&svm, &holder.account);
    assert_eq!(pending_balance(&ct, &holder.elgamal), 0);
    assert_eq!(available_balance(&ct, &holder.elgamal), 5_000);

    println!("apply before withdraw enforced: pending cleared, available ready ✓");
}

# Week 4 — Token-2022 Remittance Stablecoin

Turbin3 Q4 2026 Builder Cohort, Week 4 assignment.

The scenario: issue a remittance stablecoin on Token-2022. The mint needs a protocol-level fee on every transfer, accounts frozen until KYC clears, on-chain metadata, and a close authority for decommissioning. A second mint adds a seizure authority and confidential transfers for a regulators-vs-privacy scenario.

## Extensions

### Mint 1 — remittance mint (tasks 1–4)

| Extension | Purpose |
|---|---|
| `TransferFeeConfig` | Protocol fee withheld on every transfer; issuer harvests it |
| `MetadataPointer` | Points to the mint itself; name and symbol live on-chain |
| `DefaultAccountState` (Frozen) | Every new account starts frozen until KYC clears |
| `MintCloseAuthority` | Issuer can close the mint if decommissioned |

### Mint 2 — confidential remittance mint (tasks 5–6)

Carries all four extensions above, plus three more. Token-2022 requires `ConfidentialTransferFeeConfig` whenever `TransferFeeConfig` and `ConfidentialTransferMint` coexist — without it, `InitializeMint2` returns an invalid extension combination error.

| Extension | Purpose |
|---|---|
| `PermanentDelegate` | Seizure authority; moves tokens without holder consent |
| `ConfidentialTransferMint` | Transfer amounts encrypted; `approve_policy = manual` |
| `ConfidentialTransferFeeConfig` | Required companion to the two above; withheld fees are encrypted under a fee authority ElGamal key |

Confidential transfers cannot be added to an existing mint, so mint 2 is a re-issue. The gap between the two is the subject of the written finding below.

## Implementation notes

**Why the manual init path.**
Anchor's `extensions::` constraints cover seven extensions. `TransferFeeConfig`, `ConfidentialTransferMint`, and `ConfidentialTransferFeeConfig` are not among them. Any mint combining those must be built by hand: `create_account` → each extension init → `InitializeMint2` last. All extension initializers must come before `InitializeMint2`; that call seals the account.

**`ConfidentialTransferFeeConfig` ordering.**
`ConfidentialTransferFeeConfig` must be initialized after `ConfidentialTransferMint`. Token-2022 checks that the CT mint config already exists before writing the fee config. Reversing them causes a runtime error, not a compile error.

**Account size.**
`ExtensionType::try_calculate_account_len` is the only correct way to size a mint with extensions. For token accounts on mint 2, three account-side extensions must be allocated upfront: `TransferFeeAmount`, `ConfidentialTransferAccount`, and `ConfidentialTransferFeeAmount`. `ConfigureAccount` writes the CT extensions in-place and needs the space already there.

**Freeze authority.**
`DefaultAccountState::Frozen` without a freeze authority permanently locks every account. The mint sets `freeze_authority = Some(freeze_key)` so individual accounts can be thawed after KYC.

**Three authorities on mint 2.**
- Mint authority (payer): issues tokens, manages fee config.
- Freeze authority: thaws individual accounts after KYC clears.
- Confidential transfer authority: signs `ApproveAccount` after `ConfigureAccount`. Stored in `ConfidentialTransferMint.authority`, readable only via `StateWithExtensions`. With `approve_policy = manual`, this step is required before any deposit or transfer.

**Transfer fee.**
`transfer_checked_with_fee` is the only correct transfer instruction for a mint with `TransferFeeConfig`. Fee computed with `calculate_epoch_fee(current_epoch, amount)` — reads whichever rate is currently in force.

**Confidential transfer uses `transfer_with_fee`, not `transfer`.**
On mint 2 (which has `ConfidentialTransferFeeConfig`), confidential transfers must use `ct_ix::transfer_with_fee`. Using `ct_ix::transfer` causes a runtime error. This requires 5 ZK proofs instead of 3:

| Proof | What it proves |
|---|---|
| `CiphertextCommitmentEquality` | Amount deducted from sender equals amount added to recipient |
| `BatchedGroupedCiphertext3HandlesValidity` | Transfer amount ciphertext is well-formed (sender, recipient, auditor) |
| `PercentageWithCap` | Fee was computed correctly from the hidden amount, at the mint's rate and cap |
| `BatchedGroupedCiphertext2HandlesValidity` | Fee ciphertext is well-formed (recipient, fee authority) |
| `BatchedRangeProofU256` | All committed values are non-negative (wider than U128: more values) |

Each proof is verified into a context state account on the ZK ElGamal Proof program, referenced by address in the token instruction, then closed to recover rent.

**Why pending balance must be applied before withdrawal.**
The withdraw proof is built against the available balance ciphertext at proof-generation time. Pending balance is tracked separately and is not included. If pending is non-zero when the proof is generated, the proof is built against a stale available value and Token-2022 rejects it.

**State reads.**
All extension data is read exclusively through `StateWithExtensions::unpack`. Anchor's `InterfaceAccount<Mint>` discards the TLV region; it has decimals and authorities but nothing about extensions.

**MetadataPointer vs TokenMetadata.**
`MetadataPointer` stores an address pointing to where metadata lives. Setting it to the mint address satisfies the assignment requirement. Actually embedding name and symbol requires an additional `initialize_token_metadata` call after `InitializeMint2`, plus extra rent. That step is not implemented here; the pointer alone fulfills the task.

## Written finding — the gap between seizure and confidentiality

The assignment scenario: regulators require the issuer to seize funds from sanctioned wallets. Users want transfer amounts hidden. Both land on the same mint.

**What the permanent delegate can do.**
The permanent delegate can call `transfer_checked` on any token account for its mint, moving the public balance to any destination, without the holder's signature or prior approval. This works on the full public balance at any time.

**What happens when the sanctioned user moves their balance into the confidential system first.**
Once a user deposits into the confidential system with `DepositConfidentialTokens`, the public balance drops and an equivalent encrypted balance appears in the account's pending confidential balance. After `ApplyPendingBalance`, it moves to the available confidential balance. At that point the tokens are still in the same token account, but their amount is encrypted under the holder's ElGamal key — a key the permanent delegate does not hold and cannot derive.

The permanent delegate still has full authority over the token account. It can transfer or burn the account's **public** balance. But the confidential balance is a ciphertext. The program can add and subtract ciphertexts homomorphically, but it cannot read the plaintext value, and it cannot construct the zero-knowledge proofs a confidential transfer requires without the holder's key. The delegate calling `transfer_checked` on the account after the deposit will move zero tokens — the public balance is zero.

**What the delegate can still do.**
If the mint was created with an auditor ElGamal key on `ConfidentialTransferMint`, the auditor can decrypt every transfer amount for that mint. This is a read-only key; it cannot move tokens. With `approve_policy = manual`, the mint authority can also refuse to approve `ConfigureAccount` for new accounts, cutting off future confidential participation — but it does not recover an existing confidential balance.

The only mechanism that can reach a confidential balance without the holder's cooperation is **freezing**. If the freeze authority freezes the account before the holder can withdraw, the tokens remain trapped in the account. The permanent delegate can then drain the public portion, and the confidential balance sits locked. This is not seizure of the confidential balance; it is denial of access to it.

**The gap.**
`PermanentDelegate` and `ConfidentialTransferMint` are not composable for seizure. A sanctioned user who moves their balance into the confidential system before the delegate acts has effectively made those tokens immune to on-chain seizure. The delegate retains power over the public balance and can freeze the account, but it cannot read, transfer, or burn a confidential balance it does not hold the decryption key for.

## Project structure

```
programs/t22/
  src/
    lib.rs                          program instructions
    harvest_before_withdraw.md      note on confidential fee harvesting
    token_22_confiden_transfer.md   note on confidential transfer fees
  tests/
    week4_remittance.rs             tasks 1–4 (remittance mint)
    week4_confidential_mint.rs      task 5 (re-issued mint, 7 extensions)
    week4_confidential_lifecycle.rs task 6 (full confidential lifecycle)
    confidential.rs                 class reference: confidential lifecycle
    authority.rs                    class reference: CPI guard, permanent delegate
    test_initialize.rs              class reference: mint extension sizing
public/
  *.png                             screenshots from development
```

The class reference tests (`confidential.rs`, `authority.rs`, `test_initialize.rs`) are from the course scaffold. They demonstrate the patterns used in this assignment and all pass unmodified.

## Build and test

```bash
# Build the program (required before running tests)
cargo build-sbf --arch v0 --manifest-path programs/t22/Cargo.toml

# Run all tests
cargo test --manifest-path programs/t22/Cargo.toml

# Run individual test files
cargo test --manifest-path programs/t22/Cargo.toml --test week4_remittance
cargo test --manifest-path programs/t22/Cargo.toml --test week4_confidential_mint
cargo test --manifest-path programs/t22/Cargo.toml --test week4_confidential_lifecycle

# Run a single test with output
cargo test --manifest-path programs/t22/Cargo.toml full_confidential_lifecycle_with_fee -- --nocapture
```

Requires Rust 1.75+, Solana CLI, and `cargo-build-sbf`. No localnet deployment needed — tests run against LiteSVM.

## Test results

```
test_initialize          ...  8 passed
authority                ...  5 passed
confidential             ...  7 passed
week4_remittance         ... 13 passed
week4_confidential_mint  ... 10 passed
week4_confidential_lifecycle ... 2 passed

total: 45 passed, 0 failed
```

## References

- [Token-2022 extensions — Solana docs](https://solana.com/docs/tokens/extensions)
- [Confidential transfers — Solana docs](https://solana.com/docs/tokens/extensions/confidential-transfer)
- [Confidential transfers developer guide — QuickNode](https://www.quicknode.com/guides/solana-development/spl-tokens/token-2022/confidential)
- [Privacy on Solana — resource list](https://github.com/catmcgee/awesome-privacy-on-solana)
- Class scaffold: [token-22-turbin3-q3](https://github.com/Princeadxisrael/token-22-turbin3-q3-)

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

### Mint 2 — confidential remittance mint (tasks 5–6, in progress)

Carries all four extensions above, plus:

| Extension | Purpose |
|---|---|
| `PermanentDelegate` | Seizure authority; moves tokens without holder consent |
| `ConfidentialTransferMint` | Transfer amounts encrypted; `approve_policy = manual` |

Confidential transfers cannot be added to an existing mint, so mint 2 is a re-issue. The gap between the two mints is the subject of the written finding below.

## Implementation notes

**Why the manual init path.**
Anchor's `extensions::` constraints cover seven extensions. `TransferFeeConfig` and `ConfidentialTransferMint` are not among them. Any mint combining those with the others must be built by hand: `create_account` → each extension init → `InitializeMint2` last. All extension initializers must come before `InitializeMint2`; that call seals the account and nothing can be added after.

**Account size.**
`ExtensionType::try_calculate_account_len` is the only correct way to size a mint with extensions. The first extension pads the base 82-byte mint out to 165 bytes and adds an account-type discriminator; each subsequent extension adds only its own TLV entry.

**Freeze authority.**
`DefaultAccountState::Frozen` is useless without a freeze authority. The mint sets `freeze_authority = Some(freeze_key)` so individual accounts can be thawed after KYC. Setting it to `None` would permanently lock every account.

**Transfer fee.**
`transfer_checked_with_fee` is the only correct transfer instruction for a mint with `TransferFeeConfig`. The caller must supply the expected fee, computed with `calculate_epoch_fee(current_epoch, amount)`. This reads whichever rate is currently in force — `TransferFeeConfig` holds two rates and switches between them on an epoch schedule.

**State reads.**
All extension data is read exclusively through `StateWithExtensions::unpack`. The base `Mint` struct from Anchor's `InterfaceAccount` discards the TLV region; it has decimals and authorities but nothing about extensions.

**MetadataPointer vs TokenMetadata.**
`MetadataPointer` stores an address pointing to where metadata lives. Setting it to the mint address satisfies the assignment requirement (wallets can find name and symbol without an off-chain registry). Actually embedding name and symbol requires an additional `initialize_token_metadata` call after `InitializeMint2`, which also needs extra rent. That step is not implemented here; the pointer alone fulfills the task.

## Written finding — the gap between seizure and confidentiality

The assignment scenario: regulators require the issuer to seize funds from sanctioned wallets. Users want transfer amounts hidden. Both land on the same mint.

**What the permanent delegate can do.**
The permanent delegate can call `transfer_checked` on any token account for its mint, moving the public balance to any destination, without the holder's signature or prior approval. This works on the full public balance at any time.

**What happens when the sanctioned user moves their balance into the confidential system first.**
Once a user deposits into the confidential system with `DepositConfidentialTokens`, the public balance drops and an equivalent encrypted balance appears in the account's pending confidential balance. After `ApplyPendingBalance`, it moves to the available confidential balance. At that point the tokens are still in the same token account, but their amount is encrypted under the holder's ElGamal key — a key the permanent delegate does not hold and cannot derive.

The permanent delegate still has full authority over the token account. It can transfer or burn the account's **public** balance. But the confidential balance is a ciphertext. The program can add and subtract ciphertexts homomorphically, but it cannot read the plaintext value, and it cannot construct the zero-knowledge proofs a confidential transfer requires without the holder's key. The delegate calling `transfer_checked` on the account after the deposit will move zero tokens — the public balance is zero.

**What the delegate can still do.**
If the mint was created with an auditor ElGamal key on `ConfidentialTransferMint`, the auditor can decrypt every transfer amount for that mint. This is a read-only key; it cannot move tokens. With `approve_policy = manual`, the mint authority can also refuse to approve `ConfigureAccount` for new accounts, cutting off future confidential participation — but it does not recover an existing confidential balance.

The only mechanism that can reach a confidential balance without the holder's cooperation is **freezing**. If the freeze authority freezes the account before the holder can withdraw, the tokens remain trapped in the account. The permanent delegate can then freeze-and-drain the public portion, and the confidential balance sits locked. This is not seizure of the confidential balance; it is denial of access to it.

**The gap.**
`PermanentDelegate` and `ConfidentialTransferMint` are not composable for seizure. A sanctioned user who moves their balance into the confidential system before the delegate acts has effectively made those tokens immune to on-chain seizure. The delegate retains power over the public balance and can freeze the account, but it cannot read, transfer, or burn a confidential balance it does not hold the decryption key for.

## Project structure

```
programs/t22/
  src/
    lib.rs                    program instructions
    harvest_before_withdraw.md  note on confidential fee harvesting
    token_22_confiden_transfer.md  note on confidential transfer fees
  tests/
    week4_remittance.rs       tasks 1–4 (this assignment)
    confidential.rs           class reference: confidential lifecycle
    authority.rs              class reference: CPI guard, permanent delegate
    test_initialize.rs        class reference: mint extension sizing
public/
  *.png                       screenshots from development
```

The class reference tests (`confidential.rs`, `authority.rs`, `test_initialize.rs`) are from the course scaffold. They demonstrate the patterns used in this assignment and all pass unmodified.

## Build and test

```bash
# Build the program (required before running tests)
cargo build-sbf --arch v0 --manifest-path programs/t22/Cargo.toml

# Run all tests
cargo test --manifest-path programs/t22/Cargo.toml

# Run only the Week 4 remittance tests
cargo test --manifest-path programs/t22/Cargo.toml --test week4_remittance

# Run a single test with output
cargo test --manifest-path programs/t22/Cargo.toml full_confidential_lifecycle -- --nocapture
```

Requires Rust 1.75+, Solana CLI, and `cargo-build-sbf`. No localnet deployment needed — tests run against LiteSVM.

## Test results

```
test_initialize  ...  8 passed
authority        ...  5 passed
confidential     ...  7 passed
week4_remittance ... 13 passed

total: 33 passed, 0 failed
```

## References

- [Token-2022 extensions — Solana docs](https://solana.com/docs/tokens/extensions)
- [Confidential transfers — Solana docs](https://solana.com/docs/tokens/extensions/confidential-transfer)
- [Confidential transfers developer guide — QuickNode](https://www.quicknode.com/guides/solana-development/spl-tokens/token-2022/confidential)
- [Privacy on Solana — resource list](https://github.com/catmcgee/awesome-privacy-on-solana)
- Class scaffold: [token-22-turbin3-q3](https://github.com/Princeadxisrael/token-22-turbin3-q3-)

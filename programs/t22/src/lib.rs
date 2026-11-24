
use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_spl::token_interface::{
    approve, initialize_mint2, mint_close_authority_initialize, spl_token_2022,
    transfer_checked, transfer_fee_initialize, thaw_account, Approve,
    InitializeMint2, Mint, MintCloseAuthorityInitialize, TokenInterface,
    TransferChecked, TransferFeeInitialize, ThawAccount,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::{instruction as confidential_instruction, DecryptableBalance},
        confidential_transfer_fee::instruction as confidential_fee_instruction,
        default_account_state::instruction::initialize_default_account_state,
        metadata_pointer::instruction::initialize as initialize_metadata_pointer,
        transfer_fee::{instruction::transfer_checked_with_fee, TransferFeeConfig},
        BaseStateWithExtensions, ExtensionType, StateWithExtensions,
    },
    instruction::initialize_mint2 as raw_initialize_mint2,
    state::{AccountState, Mint as MintState},
};

// The length of a ciphertext which is how a decryptable balance is represented in the account data
pub const AE_CIPHERTEXT_LEN: usize = 36;
 
declare_id!("6sC5C8VFoTpEZQVn3YK9EUSd5g3Cs6zTT3HCDBGQkyo4");


const SUPPORTED_EXTENSIONS: &[ExtensionType] = &[
    ExtensionType::MintCloseAuthority,
    ExtensionType::MetadataPointer,
    ExtensionType::TransferFeeConfig,
];

#[program]
pub mod t22 {
    use super::*;

    ///the declarative path.
    /// Everything happens in the `#[account(init, ...)]` attribute on the
    /// `mint` field. The macro expands to exactly the sequence you would write
    /// by hand:
    ///
    ///   create_account -> each extension initializer -> initialize_mint2
    ///
    ///sizes the allocation with `find_mint_account_size`, which wraps
    /// `ExtensionType::try_calculate_account_len`
    pub fn create_mint_declarative(
        ctx: Context<CreateMintDeclarative>,
        decimals: u8,
    ) -> Result<()> {
        msg!(
            "mint {} created with {} decimals",
            ctx.accounts.mint.key(),
            decimals
        );
        Ok(())
    }



    //the imperative path.
    /// Anchor's `extensions::` constraints cover a closed set of seven:
    /// group_pointer, group_member_pointer, metadata_pointer, close_authority,
    /// permanent_delegate, transfer_hook and pausable. TransferFeeConfig is
    /// not among them, so a mint that charges a transfer fee cannot be
    /// expressed as a constraint at all.
    ///
    /// The fallback is to take the mint as an unchecked account and drive the
    /// three phases yourself with CPIs. The ordering discipline does not
    /// change, only who writes it.
    pub fn create_mint_with_fee(
        ctx: Context<CreateMintWithFee>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
    ) -> Result<()> {
        let extensions = [
            ExtensionType::MintCloseAuthority,
            ExtensionType::TransferFeeConfig,
        ];
 
        // Phase 1: allocate at the full extended length. Getting this number
        // from anywhere other than `try_calculate_account_len` is how mints
        // end up too small to initialize.
        let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions)?;
        let lamports = Rent::get()?.minimum_balance(space);
 
        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;
 
        // Phase 2: initialize each extension, before the mint itself exists.
        mint_close_authority_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                MintCloseAuthorityInitialize {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            Some(&ctx.accounts.payer.key()),
        )?;
 
        transfer_fee_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferFeeInitialize {
                    token_program_id: ctx.accounts.token_program.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            Some(&ctx.accounts.payer.key()),
            Some(&ctx.accounts.payer.key()),
            basis_points,
            maximum_fee,
        )?;
 
        // Phase 3: seal the mint. Nothing can be added after this point, and
        // most mint extensions cannot be added later at all, so a mistake here
        // is permanent rather than recoverable.
        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 {
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            decimals,
            &ctx.accounts.payer.key(),
            None,
        )?;
 
        msg!(
            "mint {} created with {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // REMITTANCE STABLECOIN — Task 1
    // -----------------------------------------------------------------------
    //
    // Mint with four extensions required by the assignment:
    //   TransferFeeConfig    — protocol fee on every transfer
    //   MetadataPointer      — pointer to self so wallets find name/symbol on-chain
    //   DefaultAccountState  — every new account starts frozen until KYC clears
    //   MintCloseAuthority   — issuer can close the mint if decommissioned
    //
    // Why the manual path:
    //   Anchor can express MetadataPointer, MintCloseAuthority, and
    //   PermanentDelegate as constraints, but NOT TransferFeeConfig nor
    //   DefaultAccountState. Because this mint needs TransferFeeConfig, the
    //   whole sequence must be driven by hand: create_account → each
    //   extension init → InitializeMint last. Mixing manual and declarative
    //   would require two separate accounts and two transactions, which is
    //   wrong.
    //
    // Freeze authority is Some(freeze_authority) — not None. A mint with
    // DefaultAccountState::Frozen but no freeze authority would permanently
    // lock every account with no way to thaw. That is not a stablecoin; it
    // is an irrecoverable lock.
    pub fn create_remittance_mint(
        ctx: Context<CreateRemittanceMint>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
    ) -> Result<()> {
        let extensions = [
            ExtensionType::MintCloseAuthority,
            ExtensionType::MetadataPointer,
            ExtensionType::TransferFeeConfig,
            ExtensionType::DefaultAccountState,
        ];

        // Phase 1: allocate space sized by the full extension list.
        // Using anything other than try_calculate_account_len is how mints
        // end up undersized and fail to initialize.
        let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions)?;
        let lamports = Rent::get()?.minimum_balance(space);

        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;

        let mint_key = ctx.accounts.mint.key();
        let payer_key = ctx.accounts.payer.key();
        let freeze_key = ctx.accounts.freeze_authority.key();
        let mint_info = ctx.accounts.mint.to_account_info();
        let prog_info = ctx.accounts.token_program.to_account_info();

        // Phase 2: initialize every extension, before the mint itself.
        // Order does not need to match the slice above, but all must precede
        // InitializeMint2 — that call seals the account.

        mint_close_authority_initialize(
            CpiContext::new(
                prog_info.key(),
                MintCloseAuthorityInitialize {
                    token_program_id: prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(&payer_key),
        )?;

        // MetadataPointer pointed at the mint itself — name and symbol will
        // be stored here rather than in an off-chain registry.
        invoke(
            &initialize_metadata_pointer(
                &prog_info.key(),
                &mint_key,
                Some(payer_key),
                Some(mint_key),
            )?,
            &[mint_info.clone(), prog_info.clone()],
        )?;

        transfer_fee_initialize(
            CpiContext::new(
                prog_info.key(),
                TransferFeeInitialize {
                    token_program_id: prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(&payer_key),
            Some(&payer_key),
            basis_points,
            maximum_fee,
        )?;

        // DefaultAccountState::Frozen — every new token account starts frozen.
        // The freeze authority thaws individual accounts after KYC clears.
        invoke(
            &initialize_default_account_state(
                &prog_info.key(),
                &mint_key,
                &AccountState::Frozen,
            )?,
            &[mint_info.clone(), prog_info.clone()],
        )?;

        // Phase 3: seal the mint. All extension init must be done before this.
        // freeze_authority is Some(freeze_key) — if it were None, frozen
        // accounts could never be thawed.
        invoke(
            &raw_initialize_mint2(
                &prog_info.key(),
                &mint_key,
                &payer_key,
                Some(&freeze_key),
                decimals,
            )?,
            &[mint_info.clone(), prog_info.clone()],
        )?;

        msg!(
            "remittance mint {} created: {} bytes, {} bps fee, frozen default",
            mint_key,
            space,
            basis_points
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // REMITTANCE STABLECOIN — Task 2
    // -----------------------------------------------------------------------
    //
    // Transfer using transfer_checked_with_fee, with fee computed at call
    // time via calculate_epoch_fee(current_epoch, amount).
    //
    // Why not transfer or transfer_checked?
    //   transfer         — legacy, no decimals check, no fee
    //   transfer_checked — checks decimals and mint, but no fee
    //   transfer_checked_with_fee — required for TransferFeeConfig mints;
    //     the program must supply the expected fee so Token-2022 can verify
    //     the caller computed it correctly before crediting the recipient.
    //
    // Why calculate_epoch_fee and not a cached rate?
    //   TransferFeeConfig has two rates: newer_transfer_fee (pending) and
    //   older_transfer_fee (current). The epoch schedule switches between them
    //   automatically. calculate_epoch_fee(epoch, amount) always reads the
    //   rate that is actually in force, so callers cannot supply a stale fee.
    pub fn remittance_transfer(
        ctx: Context<RemittanceTransfer>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        // Read the mint's live fee config to compute the expected fee.
        // StateWithExtensions is the only correct way to access extension data —
        // the base Mint struct does not expose it.
        let mint_info = ctx.accounts.mint.to_account_info();
        let mint_data = mint_info.try_borrow_data()?;
        let mint_state = StateWithExtensions::<MintState>::unpack(&mint_data)?;
        let fee_config = mint_state.get_extension::<TransferFeeConfig>()?;
        let epoch = Clock::get()?.epoch;
        let expected_fee = fee_config.calculate_epoch_fee(epoch, amount)
            .ok_or(error!(RemittanceError::FeeCalculationFailed))?;
        drop(mint_data);

        invoke(
            &transfer_checked_with_fee(
                &ctx.accounts.token_program.key(),
                &ctx.accounts.source.key(),
                &ctx.accounts.mint.key(),
                &ctx.accounts.destination.key(),
                &ctx.accounts.authority.key(),
                &[],
                amount,
                decimals,
                expected_fee,
            )?,
            &[
                ctx.accounts.source.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.destination.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;

        msg!(
            "remittance transfer: {} tokens, {} fee withheld",
            amount,
            expected_fee
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // REMITTANCE STABLECOIN — Task 4
    // -----------------------------------------------------------------------
    //
    // Thaw a single token account after KYC clears.
    //
    // This is distinct from changing DefaultAccountState on the mint.
    // DefaultAccountState is a mint-level setting that affects new accounts.
    // Thaw is an account-level operation: the freeze authority unfreezes one
    // specific account without touching any other account or the mint default.
    //
    // Only the freeze authority (the KYC oracle / issuer) can call this.
    pub fn thaw_remittance_account(ctx: Context<ThawRemittanceAccount>) -> Result<()> {
        thaw_account(CpiContext::new(
            ctx.accounts.token_program.key(),
            ThawAccount {
                account: ctx.accounts.token_account.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                authority: ctx.accounts.freeze_authority.to_account_info(),
            },
        ))?;
        msg!("account {} thawed after KYC", ctx.accounts.token_account.key());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // REMITTANCE STABLECOIN — Task 5: re-issued mint
    // -----------------------------------------------------------------------
    //
    // Why re-issue?
    //   ConfidentialTransferMint cannot be added to an existing mint.
    //   Extensions are initialized before InitializeMint2 and that call seals
    //   the account. So to add confidential transfers, the original mint must
    //   be retired and a new one created carrying all prior extensions plus
    //   the new ones.
    //
    // This mint carries seven extensions:
    //   MintCloseAuthority          — close the mint if decommissioned
    //   MetadataPointer             — points to self; name/symbol live on-chain
    //   TransferFeeConfig           — protocol fee on every transfer
    //   DefaultAccountState         — new accounts start frozen until KYC
    //   PermanentDelegate           — seizure authority
    //   ConfidentialTransferMint    — amounts encrypted; approve_policy = manual
    //   ConfidentialTransferFeeConfig — required whenever TransferFeeConfig
    //                                   and ConfidentialTransferMint coexist;
    //                                   Token-2022 rejects the combination
    //                                   without it. Withheld fees on
    //                                   confidential transfers are encrypted
    //                                   under the fee authority's ElGamal key.
    //
    // approve_policy = manual means the confidential_transfer_authority must
    // call ApproveAccount after every ConfigureAccount. That authority is a
    // separate signer — not automatically the mint authority or the payer.
    //
    // Account lifecycle after this mint:
    //   1. create_account + initialize_account3  (anyone can pay)
    //   2. thaw_remittance_account               (freeze authority, after KYC)
    //   3. ConfigureAccount                      (owner only)
    //   4. approve_confidential_account          (confidential_transfer_authority)
    //   5. deposit / transfer / withdraw
    pub fn create_remittance_confidential_mint(
        ctx: Context<CreateRemittanceConfidentialMint>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
        // The fee authority's ElGamal pubkey. Withheld fees on confidential
        // transfers are encrypted under this key; only the holder of the
        // matching secret key can read them. Required by
        // ConfidentialTransferFeeConfig.
        withdraw_withheld_authority_elgamal_pubkey: [u8; 32],
    ) -> Result<()> {
        let extensions = [
            ExtensionType::MintCloseAuthority,
            ExtensionType::MetadataPointer,
            ExtensionType::TransferFeeConfig,
            ExtensionType::DefaultAccountState,
            ExtensionType::PermanentDelegate,
            ExtensionType::ConfidentialTransferMint,
            ExtensionType::ConfidentialTransferFeeConfig,
        ];

        let space = ExtensionType::try_calculate_account_len::<MintState>(&extensions)?;
        let lamports = Rent::get()?.minimum_balance(space);

        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;

        let mint_key    = ctx.accounts.mint.key();
        let payer_key   = ctx.accounts.payer.key();
        let freeze_key  = ctx.accounts.freeze_authority.key();
        let ct_auth_key = ctx.accounts.confidential_transfer_authority.key();
        let mint_info   = ctx.accounts.mint.to_account_info();
        let prog_info   = ctx.accounts.token_program.to_account_info();

        // --- extension initializers, all before InitializeMint2 ---

        mint_close_authority_initialize(
            CpiContext::new(
                prog_info.key(),
                MintCloseAuthorityInitialize {
                    token_program_id: prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(&payer_key),
        )?;

        invoke(
            &initialize_metadata_pointer(
                &prog_info.key(),
                &mint_key,
                Some(payer_key),
                Some(mint_key),
            )?,
            &[mint_info.clone(), prog_info.clone()],
        )?;

        transfer_fee_initialize(
            CpiContext::new(
                prog_info.key(),
                TransferFeeInitialize {
                    token_program_id: prog_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(&payer_key),
            Some(&payer_key),
            basis_points,
            maximum_fee,
        )?;

        invoke(
            &initialize_default_account_state(
                &prog_info.key(),
                &mint_key,
                &AccountState::Frozen,
            )?,
            &[mint_info.clone(), prog_info.clone()],
        )?;

        invoke(
            &spl_token_2022::instruction::initialize_permanent_delegate(
                &prog_info.key(),
                &mint_key,
                &payer_key,
            )?,
            &[mint_info.clone(), prog_info.clone()],
        )?;

        // ConfidentialTransferMint: auto_approve = false enforces manual
        // approval. ct_auth_key signs ApproveAccount, stored in the extension.
        invoke(
            &confidential_instruction::initialize_mint(
                &prog_info.key(),
                &mint_key,
                Some(ct_auth_key),
                false, // approve_policy = manual
                None,  // no auditor key
            )?,
            &[mint_info.clone(), prog_info.clone()],
        )?;

        // ConfidentialTransferFeeConfig must come after ConfidentialTransferMint.
        // Token-2022 checks that CT mint config already exists before writing
        // the fee config. Reverse order causes "invalid extension combination".
        invoke(
            &confidential_fee_instruction::initialize_confidential_transfer_fee_config(
                &prog_info.key(),
                &mint_key,
                Some(payer_key),
                &withdraw_withheld_authority_elgamal_pubkey.into(),
            )?,
            &[mint_info.clone(), prog_info.clone()],
        )?;

        // InitializeMint2 last — seals the account.
        invoke(
            &raw_initialize_mint2(
                &prog_info.key(),
                &mint_key,
                &payer_key,
                Some(&freeze_key),
                decimals,
            )?,
            &[mint_info.clone(), prog_info.clone()],
        )?;

        msg!(
            "confidential remittance mint {} — {} bytes, {} bps fee, manual CT approval",
            mint_key, space, basis_points
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // REMITTANCE STABLECOIN — Task 5: approve confidential account
    // -----------------------------------------------------------------------
    //
    // With approve_policy = manual, ConfigureAccount puts the account in a
    // pending state. It cannot send or receive confidential transfers until
    // the confidential_transfer_authority calls ApproveAccount.
    //
    // This authority is whoever was passed as the authority argument to
    // initialize_mint above. It lives in ConfidentialTransferMint.authority
    // on the mint — readable via StateWithExtensions. It is NOT the payer,
    // NOT the mint authority, unless you explicitly set them the same.
    //
    // The separation matters: the issuer (mint authority) manages supply;
    // the KYC/compliance operator (CT authority) gates confidential access.
    // These can be different keys held by different people.
    pub fn approve_confidential_account(
        ctx: Context<ApproveConfidentialAccount>,
    ) -> Result<()> {
        let ix = confidential_instruction::approve_account(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.token_account.key(),
            &ctx.accounts.mint.key(),
            &ctx.accounts.confidential_transfer_authority.key(),
            &[],
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.confidential_transfer_authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        msg!("confidential account {} approved", ctx.accounts.token_account.key());
        Ok(())
    }

    /// `InterfaceAccount<'info, Mint>` looks like it gives you the whole mint.
    /// It does not. Anchor's deserializer runs
    /// `StateWithExtensions::unpack(buf).map(|t| Mint(t.base))`, which parses
    /// the TLV region and then discards it, keeping only the base struct.
    ///
    /// So the typed account has decimals, supply and authorities, and knows
    /// nothing about extensions. To see them you re-borrow the raw bytes and
    /// run `StateWithExtensions` yourself. That is the same call the plain
    /// Rust client makes.
    /// 
    /// Confidential TF: creating the mint.
    ///
    /// ConfidentialTransferMint is not one of Anchor's seven `extensions::`
    /// constraints, and anchor-spl ships no CPI helper for it either. So this
    /// builds the raw instruction and invokes it directly. Same three phases.
    pub fn create_confidential_mint(
        ctx: Context<CreateConfidentialMint>,
        decimals: u8,
        auto_approve_new_accounts: bool,
    ) -> Result<()> {
        let space = ExtensionType::try_calculate_account_len::<MintState>(&[
            ExtensionType::ConfidentialTransferMint,
        ])?;
        let lamports = Rent::get()?.minimum_balance(space);
 
        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;
 
        // No auditor key here. Passing Some(pubkey) would let its holder
        // decrypt every transfer amount for this mint, which is the usual
        // compliance escape hatch.
        let ix = confidential_instruction::initialize_mint(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.mint.key(),
            Some(ctx.accounts.payer.key()),
            auto_approve_new_accounts,
            None,
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
 
        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 {
                    mint: ctx.accounts.mint.to_account_info(),
                },
            ),
            decimals,
            &ctx.accounts.payer.key(),
            None,
        )?;
 
        msg!(
            "confidential mint {} at {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }

    /// Confidential transfer fees.
    ///
    /// A fee on a confidential transfer is a contradiction that has to be
    /// resolved: the fee is a percentage of an amount nobody can see. The
    /// resolution is that the withheld fee is itself an ElGamal ciphertext,
    /// encrypted under a key belonging to the withdraw withheld authority, so
    /// only that authority can total up what it is owed.
    ///
    /// That is why this extension takes an ElGamal public key rather than just
    /// an address, and why it requires both TransferFeeConfig and
    /// ConfidentialTransferMint to already be on the mint. Three extensions,
    /// one ordering, all before InitializeMint2.
    pub fn create_confidential_fee_mint(
        ctx: Context<CreateConfidentialFeeMint>,
        decimals: u8,
        basis_points: u16,
        maximum_fee: u64,
        withdraw_withheld_authority_elgamal_pubkey: [u8; 32],
    ) -> Result<()> {
        let space = ExtensionType::try_calculate_account_len::<MintState>(&[
            ExtensionType::TransferFeeConfig,
            ExtensionType::ConfidentialTransferMint,
            ExtensionType::ConfidentialTransferFeeConfig,
        ])?;
        let lamports = Rent::get()?.minimum_balance(space);
 
        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: ctx.accounts.mint.to_account_info(),
                },
            ),
            lamports,
            space as u64,
            &ctx.accounts.token_program.key(),
        )?;
 
        let mint_info = ctx.accounts.mint.to_account_info();
        let program_info = ctx.accounts.token_program.to_account_info();
        let infos = [mint_info.clone(), program_info.clone()];
 
        transfer_fee_initialize(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferFeeInitialize {
                    token_program_id: program_info.clone(),
                    mint: mint_info.clone(),
                },
            ),
            Some(&ctx.accounts.payer.key()),
            Some(&ctx.accounts.payer.key()),
            basis_points,
            maximum_fee,
        )?;
 
        invoke(
            &confidential_instruction::initialize_mint(
                &ctx.accounts.token_program.key(),
                &ctx.accounts.mint.key(),
                Some(ctx.accounts.payer.key()),
                true,
                None,
            )?,
            &infos,
        )?;
 
        // The fee extension must come after ConfidentialTransferMint, because
        // Token-2022 checks that the confidential mint config already exists.
        invoke(
            &confidential_fee_instruction::initialize_confidential_transfer_fee_config(
                &ctx.accounts.token_program.key(),
                &ctx.accounts.mint.key(),
                Some(ctx.accounts.payer.key()),
                &withdraw_withheld_authority_elgamal_pubkey.into(),
            )?,
            &infos,
        )?;
 
        initialize_mint2(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                InitializeMint2 { mint: mint_info },
            ),
            decimals,
            &ctx.accounts.payer.key(),
            None,
        )?;
 
        msg!(
            "confidential fee mint {} at {} bytes",
            ctx.accounts.mint.key(),
            space
        );
        Ok(())
    }


     /// Confidential: deposit.
    ///
    /// The only step of the confidential lifecycle a program can drive on its
    /// own. Moving tokens from the public balance into the pending
    /// confidential balance needs no zero knowledge proof, because the amount
    /// was already public before the move.
    pub fn deposit_confidential(
        ctx: Context<DepositConfidential>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        let ix = confidential_instruction::deposit(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.token_account.key(),
            &ctx.accounts.mint.key(),
            amount,
            decimals,
            &ctx.accounts.authority.key(),
            &[],
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.mint.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }
 
    
    /// Confidential: apply pending balance.
    ///
    /// Incoming deposits and transfers land in a pending balance that cannot
    /// be spent. Moving it to available requires the owner to supply the new
    /// available balance already encrypted under their AES key.
    ///
    /// Note what that means: the program cannot compute this value. It has no
    /// access to the owner's key. The ciphertext is an instruction argument,
    /// and the program is a pass through. 
    pub fn apply_pending_balance(
        ctx: Context<ApplyPendingBalance>,
        expected_pending_balance_credit_counter: u64,
        new_decryptable_available_balance: [u8; AE_CIPHERTEXT_LEN],
    ) -> Result<()> {
        let balance = DecryptableBalance::from(new_decryptable_available_balance);
        let ix = confidential_instruction::apply_pending_balance(
            &ctx.accounts.token_program.key(),
            &ctx.accounts.token_account.key(),
            expected_pending_balance_credit_counter,
            &balance,
            &ctx.accounts.authority.key(),
            &[],
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.token_account.to_account_info(),
                ctx.accounts.authority.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }
    
     /// Creates a mint whose permanent delegate is the payer.
    pub fn create_seizable_mint(ctx: Context<CreateSeizableMint>, decimals: u8) -> Result<()> {
        msg!("seizable mint {} with {} deccimals, permanent delegate", 
        ctx.accounts.mint.key(),
        decimals,
        // ctx.accounts.payer.key()
    );
        Ok(())
    }
 
    /// CPI guard.
    ///
    /// Delegates authority over a token account to this program's PDA by
    /// cross program invoking Approve.
    ///
    /// This is the exact pattern a lending or escrow protocol uses, and it is
    /// also the exact pattern a malicious program uses to drain an account it
    /// tricked a user into signing for. Token-2022 cannot tell them apart, so
    /// it lets the account owner decide: with the CpiGuard extension enabled,
    /// Approve issued through a CPI fails outright. The owner can still
    /// approve by signing a top level instruction.
    pub fn delegate_to_program(ctx: Context<DelegateToProgram>, amount: u64) -> Result<()> {
        approve(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                Approve {
                    to: ctx.accounts.token_account.to_account_info(),
                    delegate: ctx.accounts.delegate.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(),
                },
            ),
            amount,
        )?;
        msg!("delegated {} to {}", amount, ctx.accounts.delegate.key());
        Ok(())
    }
 
    /// Permanent delegate.
    ///
    /// Moves tokens out of an account using the mint's permanent delegate
    /// authority. Note what is missing: no Approve was ever issued by the
    /// holder, and the holder is not a signer here.
    ///
    /// A permanent delegate can move or burn tokens from every account of its
    /// mint, forever, without consent and with no way for a holder to revoke
    /// it. Any protocol accepting arbitrary Token-2022 mints must treat this
    /// extension as a reason to reject the mint, not a feature to support.
    pub fn permanent_delegate_seize(
        ctx: Context<PermanentDelegateSeize>,
        amount: u64,
        decimals: u8,
    ) -> Result<()> {
        transfer_checked(
            CpiContext::new(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.source.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.permanent_delegate.to_account_info(),
                },
            ),
            amount,
            decimals,
        )?;
        msg!("seized {} without holder consent", amount);
        Ok(())
    }
 

    pub fn assert_supported_mint(ctx: Context<AssertSupportedMint>) -> Result<()> {
      
        
 
        // Not available from the typed account. Drop to the raw bytes.
        let account_info = ctx.accounts.mint.to_account_info();
        let data = account_info.try_borrow_data()?;
        let state = StateWithExtensions::<MintState>::unpack(&data)?;
          
          // Available from the typed account, no extension awareness needed.
        let decimals = state.base.decimals;
 
        for extension in state.get_extension_types()? {
            require!(
                SUPPORTED_EXTENSIONS.contains(&extension),
                MintError::UnsupportedExtension
            );
        }
 
        // A transfer fee means the amount credited is not the amount debited.
        // Any accounting that assumes otherwise is wrong against this mint, so
        // read the live fee rather than assuming zero.
        //
        // Fees are epoch scheduled: `newer_transfer_fee` may not be in force
        // yet, which is why `get_epoch_fee` takes the current epoch.
        let basis_points = match state.get_extension::<TransferFeeConfig>() {
            Ok(config) => u16::from(
                config
                    .get_epoch_fee(Clock::get()?.epoch)
                    .transfer_fee_basis_points,
            ),
            Err(_) => 0,
        };
 
        msg!(
            "mint accepted: {} decimals, {} bps fee",
            decimals,
            basis_points
        );
        Ok(())
    }
 
  
}


#[derive(Accounts)]
#[instruction(decimals: u8)]
pub struct CreateMintDeclarative<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
 
    /// each extension constraints below adds an
    /// `ExtensionType` to the size calculation and a CPI to the init sequence.
    #[account(
        init,
        payer = payer,
        mint::decimals = decimals,
        mint::authority = payer,
        mint::token_program = token_program,
        extensions::close_authority::authority = payer,
        extensions::metadata_pointer::authority = payer,
        extensions::metadata_pointer::metadata_address = payer,
    )]
    pub mint: InterfaceAccount<'info, Mint>,
 
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}


#[derive(Accounts)]
pub struct CreateMintWithFee<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
 
    /// Unchecked because the account does not exist yet and Anchor has no
    /// constraint that can describe a transfer fee mint. The instruction body
    /// creates and initializes it.
    ///
    /// CHECK: created and initialized in the handler, and required to sign
    /// because the account is made at its own address.
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,
 
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
 
#[derive(Accounts)]
pub struct AssertSupportedMint<'info> {
    /// Unchecked so the account is parsed exactly once, in the handler.
    ///
    /// The `owner` constraint is not optional. `StateWithExtensions::unpack`
    /// receives a byte slice and validates only the layout, so without this
    /// any account from any program whose bytes look like an initialized mint
    /// would be accepted.
    ///
    /// CHECK: ownership enforced below, contents allowlisted in the handler.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// Constrains `owner` above to SPL Token or Token-2022, and nothing else.
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CreateConfidentialMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
 
    /// CHECK: created and initialized in the handler, signs because the
    /// account is made at its own address.
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,
 
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateConfidentialFeeMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
 
    /// CHECK: created and initialized in the handler.
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,
 
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
 

#[derive(Accounts)]
pub struct DepositConfidential<'info> {
    /// CHECK: validated by Token-2022, which rejects any account that is not
    /// a token account for this mint configured for confidential transfers.
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,
 
    /// CHECK: validated by Token-2022 during the deposit.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,
 
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}
 
#[derive(Accounts)]
pub struct ApplyPendingBalance<'info> {
    /// CHECK: validated by Token-2022.
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,
 
    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}



#[derive(Accounts)]
#[instruction(decimals: u8)]
pub struct CreateSeizableMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
 
    /// `permanent_delegate` is one of the seven extensions Anchor can express
    /// as a constraint, so no manual CPI is needed here.
    #[account(
        init,
        payer = payer,
        mint::decimals = decimals,
        mint::authority = payer,
        mint::token_program = token_program,
        extensions::permanent_delegate::delegate = payer,
    )]
    pub mint: InterfaceAccount<'info, Mint>,
 
    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
 
#[derive(Accounts)]
pub struct DelegateToProgram<'info> {
    /// CHECK: validated by Token-2022 during Approve.
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,
 
    /// CHECK: any address may receive delegation; Token-2022 stores it as is.
    pub delegate: UncheckedAccount<'info>,
 
    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}
 
#[derive(Accounts)]
pub struct PermanentDelegateSeize<'info> {
    /// CHECK: validated by Token-2022. Note it is not a signer.
    #[account(mut, owner = token_program.key())]
    pub source: UncheckedAccount<'info>,
 
    /// CHECK: validated by Token-2022.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,
 
    /// CHECK: validated by Token-2022.
    #[account(mut, owner = token_program.key())]
    pub destination: UncheckedAccount<'info>,
 
    /// The mint's permanent delegate. Token-2022 checks this against the
    /// extension; the holder has no say.
    pub permanent_delegate: Signer<'info>,
 
    pub token_program: Interface<'info, TokenInterface>,
}
 

#[derive(Accounts)]
pub struct CreateRemittanceMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// The freeze authority — a separate keypair so it can be a dedicated
    /// KYC oracle rather than the general mint authority / payer.
    /// CHECK: stored as freeze_authority in the mint; not validated beyond
    /// being a signer here so the caller cannot set an arbitrary address they
    /// don't control.
    pub freeze_authority: Signer<'info>,

    /// CHECK: created and initialized in the handler. Must sign because
    /// create_account requires the new account's signature.
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RemittanceTransfer<'info> {
    /// CHECK: validated by Token-2022 — it checks the account belongs to mint,
    /// is not frozen, and has enough balance.
    #[account(mut, owner = token_program.key())]
    pub source: UncheckedAccount<'info>,

    /// CHECK: validated by Token-2022.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// CHECK: validated by Token-2022.
    #[account(mut, owner = token_program.key())]
    pub destination: UncheckedAccount<'info>,

    pub authority: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ThawRemittanceAccount<'info> {
    /// CHECK: validated by Token-2022 during thaw_account.
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: validated by Token-2022.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// Must be the mint's freeze authority — Token-2022 enforces this.
    pub freeze_authority: Signer<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct CreateRemittanceConfidentialMint<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Freeze authority — thaws individual accounts after KYC.
    /// CHECK: stored as freeze_authority in InitializeMint2.
    pub freeze_authority: Signer<'info>,

    /// Confidential transfer authority — signs ApproveAccount.
    /// Stored in ConfidentialTransferMint.authority. NOT the payer or mint
    /// authority unless you explicitly pass the same key.
    /// CHECK: stored in ConfidentialTransferMint extension.
    pub confidential_transfer_authority: Signer<'info>,

    /// CHECK: created and initialized in the handler.
    #[account(mut, signer)]
    pub mint: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ApproveConfidentialAccount<'info> {
    /// The token account to approve for confidential transfers.
    /// CHECK: validated by Token-2022 during ApproveAccount.
    #[account(mut, owner = token_program.key())]
    pub token_account: UncheckedAccount<'info>,

    /// CHECK: validated by Token-2022.
    #[account(owner = token_program.key())]
    pub mint: UncheckedAccount<'info>,

    /// Must match ConfidentialTransferMint.authority stored on the mint.
    /// Token-2022 reads that field and rejects any other signer.
    pub confidential_transfer_authority: Signer<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}

#[error_code]
pub enum RemittanceError {
    #[msg("fee calculation overflowed or the mint has no TransferFeeConfig")]
    FeeCalculationFailed,
}

#[error_code]
pub enum MintError {
    #[msg("mint carries an extension this program has not been written to handle")]
    UnsupportedExtension,
}

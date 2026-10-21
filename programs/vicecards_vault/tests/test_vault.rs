use {
    anchor_lang::{
        prelude::Pubkey, solana_program::instruction::Instruction, AccountDeserialize, InstructionData,
        ToAccountMetas,
    },
    litesvm::LiteSVM,
    solana_account::Account,
    solana_keypair::Keypair,
    solana_message::{Message, VersionedMessage},
    solana_program_pack::Pack,
    solana_sha256_hasher::hashv,
    solana_signer::Signer,
    solana_transaction::versioned::VersionedTransaction,
    spl_associated_token_account_interface::address::get_associated_token_address_with_program_id as ata,
    spl_token_interface::state::{Account as TokenAccount, AccountState, Mint},
    vicecards_vault::{ClaimStatus, Config},
};

/// TTWO, 6 decimals, Token-2022. Amounts below are in TTWO base units (1 TTWO = 1_000_000).
const TTWO: u64 = 1_000_000;
const SOL: u64 = 1_000_000_000;
const SYSTEM: Pubkey = anchor_lang::solana_program::system_program::ID;
const TOKEN_2022: Pubkey = spl_token_2022_interface::ID;
const ATA_PROGRAM: Pubkey = spl_associated_token_account_interface::program::ID;

// -------------------------------------------------------------------------
// Merkle tree, written independently of the program (spec: Global Constraints)
// -------------------------------------------------------------------------

fn leaf(wallet: &Pubkey, cumulative: u64) -> [u8; 32] {
    hashv(&[&[0u8], wallet.as_ref(), &cumulative.to_le_bytes()]).to_bytes()
}

fn node(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    hashv(&[&[1u8], &lo, &hi]).to_bytes()
}

/// Root and proofs of `entries`, sorted by wallet. An odd node is carried up unchanged.
fn tree(entries: &[(Pubkey, u64)]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let mut sorted: Vec<(usize, Pubkey, u64)> = entries.iter().enumerate().map(|(i, (w, c))| (i, *w, *c)).collect();
    sorted.sort_by_key(|e| e.1.to_bytes());
    let mut level: Vec<[u8; 32]> = sorted.iter().map(|(_, w, c)| leaf(w, *c)).collect();
    // position of each entry (original order) in the current level
    let mut pos: Vec<usize> = vec![0; entries.len()];
    for (p, (i, _, _)) in sorted.iter().enumerate() {
        pos[*i] = p;
    }
    let mut proofs = vec![Vec::new(); entries.len()];
    while level.len() > 1 {
        for (i, p) in pos.iter_mut().enumerate() {
            let sibling = *p ^ 1;
            if sibling < level.len() {
                proofs[i].push(level[sibling]);
            }
            *p /= 2;
        }
        level = level.chunks(2).map(|c| if c.len() == 2 { node(c[0], c[1]) } else { c[0] }).collect();
    }
    (level[0], proofs)
}

// -------------------------------------------------------------------------
// Harness
// -------------------------------------------------------------------------

fn pda(seeds: &[&[u8]]) -> Pubkey {
    Pubkey::find_program_address(seeds, &vicecards_vault::id()).0
}

fn config_pda() -> Pubkey {
    pda(&[b"config"])
}

fn vault_pda() -> Pubkey {
    pda(&[b"vault"])
}

fn claim_pda(wallet: &Pubkey) -> Pubkey {
    pda(&[b"claim", wallet.as_ref()])
}

/// The test build's INITIALIZER (feature `test-initializer`).
fn initializer() -> Keypair {
    Keypair::new_from_array([9u8; 32])
}

struct Env {
    svm: LiteSVM,
    admin: Keypair,
    operator: Keypair,
    mint: Pubkey,
    ttwo: Pubkey,
}

fn vault_ttwo(ttwo: &Pubkey) -> Pubkey {
    ata(&vault_pda(), ttwo, &TOKEN_2022)
}

fn wallet_ttwo(wallet: &Pubkey, ttwo: &Pubkey) -> Pubkey {
    ata(wallet, ttwo, &TOKEN_2022)
}

fn set_mint(svm: &mut LiteSVM, key: Pubkey) {
    let mut data = vec![0u8; Mint::LEN];
    Mint { mint_authority: None.into(), supply: 1_000_000 * TTWO, decimals: 6, is_initialized: true, freeze_authority: None.into() }
        .pack_into_slice(&mut data);
    svm.set_account(key, Account { lamports: SOL, data, owner: TOKEN_2022, executable: false, rent_epoch: 0 }).unwrap();
}

fn set_token_account(svm: &mut LiteSVM, key: Pubkey, mint: Pubkey, owner: Pubkey, amount: u64) {
    let mut data = vec![0u8; TokenAccount::LEN];
    TokenAccount {
        mint,
        owner,
        amount,
        delegate: None.into(),
        state: AccountState::Initialized,
        is_native: None.into(),
        delegated_amount: 0,
        close_authority: None.into(),
    }
    .pack_into_slice(&mut data);
    svm.set_account(key, Account { lamports: 2_039_280, data, owner: TOKEN_2022, executable: false, rent_epoch: 0 }).unwrap();
}

/// TTWO held by `key`, 0 when the account does not exist.
fn ttwo_amount(svm: &LiteSVM, key: &Pubkey) -> u64 {
    svm.get_account(key)
        .filter(|a| a.data.len() >= TokenAccount::LEN)
        .map(|a| TokenAccount::unpack(&a.data[..TokenAccount::LEN]).unwrap().amount)
        .unwrap_or(0)
}

fn send(svm: &mut LiteSVM, ix: Instruction, signers: &[&Keypair]) -> Result<(), String> {
    svm.expire_blockhash();
    let msg = Message::new_with_blockhash(&[ix], Some(&signers[0].pubkey()), &svm.latest_blockhash());
    let tx = VersionedTransaction::try_new(VersionedMessage::Legacy(msg), signers).unwrap();
    svm.send_transaction(tx).map(|_| ()).map_err(|e| format!("{:?}\n{}", e.err, e.meta.logs.join("\n")))
}

fn config(svm: &LiteSVM) -> Config {
    Config::try_deserialize(&mut svm.get_account(&config_pda()).unwrap().data.as_slice()).unwrap()
}

fn program() -> LiteSVM {
    let mut svm = LiteSVM::new();
    svm.add_program(
        vicecards_vault::id(),
        include_bytes!(concat!(env!("CARGO_TARGET_TMPDIR"), "/../deploy/vicecards_vault.so")),
    )
    .unwrap();
    svm
}

fn initialize_ix(admin: &Pubkey, operator: Pubkey, mint: Pubkey, ttwo: Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        vicecards_vault::id(),
        &vicecards_vault::instruction::Initialize { operator, mint }.data(),
        vicecards_vault::accounts::Initialize {
            admin: *admin,
            config: config_pda(),
            vault: vault_pda(),
            quote_mint: ttwo,
            vault_quote_account: vault_ttwo(&ttwo),
            quote_token_program: TOKEN_2022,
            associated_token_program: ATA_PROGRAM,
            system_program: SYSTEM,
        }
        .to_account_metas(None),
    )
}

fn set_root_ix_with(operator: &Pubkey, epoch: u64, root: [u8; 32], total_committed: u64, ttwo: Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        vicecards_vault::id(),
        &vicecards_vault::instruction::SetRoot { epoch, root, total_committed }.data(),
        vicecards_vault::accounts::SetRoot {
            operator: *operator,
            config: config_pda(),
            vault: vault_pda(),
            vault_quote_account: vault_ttwo(&ttwo),
            quote_token_program: TOKEN_2022,
        }
        .to_account_metas(None),
    )
}

fn claim_ix_with(payer: &Pubkey, wallet: &Pubkey, cumulative: u64, proof: Vec<[u8; 32]>, ttwo: Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        vicecards_vault::id(),
        &vicecards_vault::instruction::Claim { cumulative, proof }.data(),
        vicecards_vault::accounts::Claim {
            payer: *payer,
            config: config_pda(),
            vault: vault_pda(),
            vault_quote_account: vault_ttwo(&ttwo),
            quote_mint: ttwo,
            wallet: *wallet,
            wallet_quote_account: wallet_ttwo(wallet, &ttwo),
            claim_status: claim_pda(wallet),
            quote_token_program: TOKEN_2022,
            associated_token_program: ATA_PROGRAM,
            system_program: SYSTEM,
        }
        .to_account_metas(None),
    )
}

thread_local! {
    /// The TTWO mint of the current test (set by `setup`), so the helpers below keep short signatures.
    static TTWO_MINT: std::cell::Cell<Pubkey> = std::cell::Cell::new(Pubkey::default());
}

fn set_root_ix(operator: &Pubkey, epoch: u64, root: [u8; 32], total_committed: u64) -> Instruction {
    set_root_ix_with(operator, epoch, root, total_committed, TTWO_MINT.with(|m| m.get()))
}

fn claim_ix(payer: &Pubkey, wallet: &Pubkey, cumulative: u64, proof: Vec<[u8; 32]>) -> Instruction {
    claim_ix_with(payer, wallet, cumulative, proof, TTWO_MINT.with(|m| m.get()))
}

fn admin_ix(admin: &Pubkey, data: Vec<u8>) -> Instruction {
    Instruction::new_with_bytes(
        vicecards_vault::id(),
        &data,
        vicecards_vault::accounts::AdminOnly { admin: *admin, config: config_pda() }.to_account_metas(None),
    )
}

/// A program with a TTWO mint, not yet initialized.
fn bare() -> (LiteSVM, Pubkey) {
    let mut svm = program();
    let ttwo = Pubkey::new_unique();
    set_mint(&mut svm, ttwo);
    TTWO_MINT.with(|m| m.set(ttwo));
    (svm, ttwo)
}

fn setup() -> Env {
    let (mut svm, ttwo) = bare();
    let admin = initializer();
    let operator = Keypair::new();
    svm.airdrop(&admin.pubkey(), 100 * SOL).unwrap();
    svm.airdrop(&operator.pubkey(), 10 * SOL).unwrap();
    let mint = Pubkey::new_unique();
    send(&mut svm, initialize_ix(&admin.pubkey(), operator.pubkey(), mint, ttwo), &[&admin]).unwrap();
    Env { svm, admin, operator, mint, ttwo }
}

/// Simulates pump.fun's collection: creator fees arriving in the vault's TTWO account.
fn fund_vault(env: &mut Env, amount: u64) {
    let key = vault_ttwo(&env.ttwo);
    let held = ttwo_amount(&env.svm, &key);
    set_token_account(&mut env.svm, key, env.ttwo, vault_pda(), held + amount);
}

/// What the program guarantees after every instruction: the vault covers what it still owes.
fn assert_solvent(env: &Env) {
    let c = config(&env.svm);
    assert!(ttwo_amount(&env.svm, &vault_ttwo(&env.ttwo)) >= c.total_committed - c.total_claimed);
}

// -------------------------------------------------------------------------
// initialize
// -------------------------------------------------------------------------

#[test]
fn initialize_only_initializer() {
    let (mut svm, ttwo) = bare();
    let stranger = Keypair::new();
    svm.airdrop(&stranger.pubkey(), 10 * SOL).unwrap();
    let err = send(&mut svm, initialize_ix(&stranger.pubkey(), Pubkey::new_unique(), Pubkey::new_unique(), ttwo), &[&stranger])
        .unwrap_err();
    assert!(err.contains("Unauthorized"), "{err}");

    let admin = initializer();
    svm.airdrop(&admin.pubkey(), 10 * SOL).unwrap();
    let operator = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    send(&mut svm, initialize_ix(&admin.pubkey(), operator, mint, ttwo), &[&admin]).unwrap();

    let c = config(&svm);
    assert_eq!((c.admin, c.operator, c.mint, c.quote_mint), (admin.pubkey(), operator, mint, ttwo));
    assert_eq!((c.epoch, c.root, c.total_committed, c.total_claimed, c.paused), (0, [0u8; 32], 0, 0, false));
    // the vault's TTWO account exists, empty, owned by the vault PDA
    let account = TokenAccount::unpack(&svm.get_account(&vault_ttwo(&ttwo)).unwrap().data[..TokenAccount::LEN]).unwrap();
    assert_eq!((account.owner, account.mint, account.amount), (vault_pda(), ttwo, 0));

    // once only
    assert!(send(&mut svm, initialize_ix(&admin.pubkey(), operator, mint, ttwo), &[&admin]).is_err());
}

#[test]
fn initialize_keeps_fees_collected_before_it() {
    let (mut svm, ttwo) = bare();
    let admin = initializer();
    svm.airdrop(&admin.pubkey(), 10 * SOL).unwrap();
    // the coin was launched and its fees collected before initialize
    set_token_account(&mut svm, vault_ttwo(&ttwo), ttwo, vault_pda(), 3 * TTWO);
    send(&mut svm, initialize_ix(&admin.pubkey(), Pubkey::new_unique(), Pubkey::new_unique(), ttwo), &[&admin]).unwrap();
    assert_eq!(ttwo_amount(&svm, &vault_ttwo(&ttwo)), 3 * TTWO);
}

#[test]
fn initialize_rejects_operator_equal_admin() {
    let (mut svm, ttwo) = bare();
    let admin = initializer();
    svm.airdrop(&admin.pubkey(), 10 * SOL).unwrap();
    let err = send(&mut svm, initialize_ix(&admin.pubkey(), admin.pubkey(), Pubkey::new_unique(), ttwo), &[&admin]).unwrap_err();
    assert!(err.contains("OperatorIsAdmin"), "{err}");
}

// -------------------------------------------------------------------------
// set_root
// -------------------------------------------------------------------------

#[test]
fn set_root_requires_operator_and_next_epoch() {
    let mut env = setup();
    fund_vault(&mut env, 10 * TTWO);
    let root = [7u8; 32];

    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), SOL).unwrap();
    let err = send(&mut env.svm, set_root_ix(&stranger.pubkey(), 1, root, TTWO), &[&stranger]).unwrap_err();
    assert!(err.contains("Unauthorized"), "{err}");
    let admin = env.admin.insecure_clone();
    let err = send(&mut env.svm, set_root_ix(&admin.pubkey(), 1, root, TTWO), &[&admin]).unwrap_err();
    assert!(err.contains("Unauthorized"), "{err}");

    let op = env.operator.insecure_clone();
    let err = send(&mut env.svm, set_root_ix(&op.pubkey(), 2, root, TTWO), &[&op]).unwrap_err();
    assert!(err.contains("WrongEpoch"), "{err}");
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root, TTWO), &[&op]).unwrap();
    let c = config(&env.svm);
    assert_eq!((c.epoch, c.root, c.total_committed), (1, root, TTWO));
    // the same epoch twice (a retried hourly job) is refused
    let err = send(&mut env.svm, set_root_ix(&op.pubkey(), 1, [8u8; 32], 2 * TTWO), &[&op]).unwrap_err();
    assert!(err.contains("WrongEpoch"), "{err}");
    let err = send(&mut env.svm, set_root_ix(&op.pubkey(), 2, [0u8; 32], 2 * TTWO), &[&op]).unwrap_err();
    assert!(err.contains("ZeroRoot"), "{err}");
    assert_solvent(&env);
}

#[test]
fn set_root_rejects_insolvent() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    fund_vault(&mut env, TTWO);
    // the vault holds 1 TTWO: it can commit 1 TTWO, not one base unit more
    let err = send(&mut env.svm, set_root_ix(&op.pubkey(), 1, [7u8; 32], TTWO + 1), &[&op]).unwrap_err();
    assert!(err.contains("Insolvent"), "{err}");
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, [7u8; 32], TTWO), &[&op]).unwrap();
    assert_solvent(&env);
}

#[test]
fn set_root_rejects_another_token_account() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    // a rich TTWO account that is not the vault's cannot vouch for the root
    let rich = wallet_ttwo(&op.pubkey(), &env.ttwo);
    set_token_account(&mut env.svm, rich, env.ttwo, op.pubkey(), 1_000 * TTWO);
    let mut ix = set_root_ix(&op.pubkey(), 1, [7u8; 32], TTWO);
    ix.accounts[3].pubkey = rich;
    assert!(send(&mut env.svm, ix, &[&op]).is_err());
}

#[test]
fn set_root_counts_what_was_already_claimed() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    let payer = env.operator.insecure_clone();
    let wallet = Pubkey::new_unique();
    fund_vault(&mut env, TTWO);
    let (root, proofs) = tree(&[(wallet, TTWO)]);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root, TTWO), &[&op]).unwrap();
    send(&mut env.svm, claim_ix(&payer.pubkey(), &wallet, TTWO, proofs[0].clone()), &[&payer]).unwrap();
    // the vault is empty; 0.5 TTWO of new fees allow committing 1.5 TTWO in total
    fund_vault(&mut env, TTWO / 2);
    let err = send(&mut env.svm, set_root_ix(&op.pubkey(), 2, [3u8; 32], TTWO + TTWO / 2 + 1), &[&op]).unwrap_err();
    assert!(err.contains("Insolvent"), "{err}");
    send(&mut env.svm, set_root_ix(&op.pubkey(), 2, [3u8; 32], TTWO + TTWO / 2), &[&op]).unwrap();
    assert_solvent(&env);
}

#[test]
fn set_root_rejects_decreasing_total() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    fund_vault(&mut env, 10 * TTWO);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, [7u8; 32], 2 * TTWO), &[&op]).unwrap();
    let err = send(&mut env.svm, set_root_ix(&op.pubkey(), 2, [8u8; 32], 2 * TTWO - 1), &[&op]).unwrap_err();
    assert!(err.contains("CommittedDecreased"), "{err}");
    // an hour without fees keeps the total
    send(&mut env.svm, set_root_ix(&op.pubkey(), 2, [8u8; 32], 2 * TTWO), &[&op]).unwrap();
}

// -------------------------------------------------------------------------
// claim
// -------------------------------------------------------------------------

#[test]
fn claim_pays_delta_across_epochs() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    // the crank (any payer) claims for the wallets; the wallets never sign and have no TTWO account yet
    let crank = Keypair::new();
    env.svm.airdrop(&crank.pubkey(), SOL).unwrap();
    let wallets: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();
    fund_vault(&mut env, 10 * TTWO);

    let e1: Vec<(Pubkey, u64)> = wallets.iter().enumerate().map(|(i, w)| (*w, (i as u64 + 1) * TTWO / 10)).collect();
    let total1: u64 = e1.iter().map(|e| e.1).sum();
    let (root1, proofs1) = tree(&e1);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root1, total1), &[&op]).unwrap();

    for (i, (w, c)) in e1.iter().enumerate() {
        send(&mut env.svm, claim_ix(&crank.pubkey(), w, *c, proofs1[i].clone()), &[&crank]).unwrap();
        assert_eq!(ttwo_amount(&env.svm, &wallet_ttwo(w, &env.ttwo)), *c);
        assert_solvent(&env);
    }
    assert_eq!(config(&env.svm).total_claimed, total1);

    // next hour: wallet 0 earns 0.2 TTWO more; its cumulative goes 0.1 → 0.3
    let mut e2 = e1.clone();
    e2[0].1 += TTWO / 5;
    let total2 = total1 + TTWO / 5;
    let (root2, proofs2) = tree(&e2);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 2, root2, total2), &[&op]).unwrap();
    send(&mut env.svm, claim_ix(&crank.pubkey(), &wallets[0], e2[0].1, proofs2[0].clone()), &[&crank]).unwrap();
    assert_eq!(ttwo_amount(&env.svm, &wallet_ttwo(&wallets[0], &env.ttwo)), 3 * TTWO / 10);

    let status = ClaimStatus::try_deserialize(&mut env.svm.get_account(&claim_pda(&wallets[0])).unwrap().data.as_slice()).unwrap();
    assert_eq!((status.wallet, status.claimed), (wallets[0], 3 * TTWO / 10));
    assert_eq!(config(&env.svm).total_claimed, total2);
    assert_eq!(ttwo_amount(&env.svm, &vault_ttwo(&env.ttwo)), 10 * TTWO - total2);
    assert_solvent(&env);
}

#[test]
fn single_entry_tree_has_empty_proof() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    let wallet = Keypair::new();
    env.svm.airdrop(&wallet.pubkey(), SOL).unwrap();
    fund_vault(&mut env, TTWO);
    let (root, proofs) = tree(&[(wallet.pubkey(), TTWO / 2)]);
    assert!(proofs[0].is_empty());
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root, TTWO / 2), &[&op]).unwrap();
    // the wallet claims for itself and pays the rent of its claim status and TTWO account
    send(&mut env.svm, claim_ix(&wallet.pubkey(), &wallet.pubkey(), TTWO / 2, vec![]), &[&wallet]).unwrap();
    assert_eq!(ttwo_amount(&env.svm, &wallet_ttwo(&wallet.pubkey(), &env.ttwo)), TTWO / 2);
}

#[test]
fn claim_into_an_existing_ttwo_account() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    let wallet = Pubkey::new_unique();
    set_token_account(&mut env.svm, wallet_ttwo(&wallet, &env.ttwo), env.ttwo, wallet, 7 * TTWO);
    fund_vault(&mut env, TTWO);
    let (root, proofs) = tree(&[(wallet, TTWO)]);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root, TTWO), &[&op]).unwrap();
    send(&mut env.svm, claim_ix(&op.pubkey(), &wallet, TTWO, proofs[0].clone()), &[&op]).unwrap();
    assert_eq!(ttwo_amount(&env.svm, &wallet_ttwo(&wallet, &env.ttwo)), 8 * TTWO);
}

#[test]
fn second_claim_same_cumulative_pays_zero_ok() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    let crank = env.operator.insecure_clone();
    let wallet = Pubkey::new_unique();
    let other = Pubkey::new_unique();
    fund_vault(&mut env, TTWO);
    let (root, proofs) = tree(&[(wallet, 4 * TTWO / 10), (other, TTWO / 10)]);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root, TTWO / 2), &[&op]).unwrap();
    send(&mut env.svm, claim_ix(&crank.pubkey(), &wallet, 4 * TTWO / 10, proofs[0].clone()), &[&crank]).unwrap();
    let vault_before = ttwo_amount(&env.svm, &vault_ttwo(&env.ttwo));
    // the player clicks Claim after the crank already paid: success, nothing moves
    send(&mut env.svm, claim_ix(&crank.pubkey(), &wallet, 4 * TTWO / 10, proofs[0].clone()), &[&crank]).unwrap();
    assert_eq!(ttwo_amount(&env.svm, &wallet_ttwo(&wallet, &env.ttwo)), 4 * TTWO / 10);
    assert_eq!(ttwo_amount(&env.svm, &vault_ttwo(&env.ttwo)), vault_before);
    assert_eq!(config(&env.svm).total_claimed, 4 * TTWO / 10);
}

#[test]
fn claim_bad_proof_fails() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    let crank = env.operator.insecure_clone();
    let a = Pubkey::new_unique();
    let b = Pubkey::new_unique();
    let c = Pubkey::new_unique();
    fund_vault(&mut env, 2 * TTWO);
    let (root, proofs) = tree(&[(a, TTWO / 10), (b, 2 * TTWO / 10), (c, 3 * TTWO / 10)]);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root, 6 * TTWO / 10), &[&op]).unwrap();

    // inflated amount
    let err = send(&mut env.svm, claim_ix(&crank.pubkey(), &a, TTWO / 10 + 1, proofs[0].clone()), &[&crank]).unwrap_err();
    assert!(err.contains("InvalidProof"), "{err}");
    // someone else's proof
    let err = send(&mut env.svm, claim_ix(&crank.pubkey(), &a, 2 * TTWO / 10, proofs[1].clone()), &[&crank]).unwrap_err();
    assert!(err.contains("InvalidProof"), "{err}");
    // a proof of the previous epoch's root no longer works
    let (root2, _) = tree(&[(a, 15 * TTWO / 100), (b, 2 * TTWO / 10), (c, 3 * TTWO / 10)]);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 2, root2, 65 * TTWO / 100), &[&op]).unwrap();
    let err = send(&mut env.svm, claim_ix(&crank.pubkey(), &a, TTWO / 10, proofs[0].clone()), &[&crank]).unwrap_err();
    assert!(err.contains("InvalidProof"), "{err}");
    assert_eq!(ttwo_amount(&env.svm, &wallet_ttwo(&a, &env.ttwo)), 0);
}

#[test]
fn claim_before_any_root_fails() {
    let mut env = setup();
    let crank = env.operator.insecure_clone();
    fund_vault(&mut env, TTWO);
    let wallet = Pubkey::new_unique();
    let err = send(&mut env.svm, claim_ix(&crank.pubkey(), &wallet, 0, vec![]), &[&crank]).unwrap_err();
    assert!(err.contains("InvalidProof"), "{err}");
}

#[test]
fn claim_rejects_another_destination_account() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    let wallet = Pubkey::new_unique();
    fund_vault(&mut env, TTWO);
    let (root, proofs) = tree(&[(wallet, TTWO)]);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root, TTWO), &[&op]).unwrap();
    // the caller cannot redirect the wallet's reward into its own TTWO account
    let thief = op.pubkey();
    set_token_account(&mut env.svm, wallet_ttwo(&thief, &env.ttwo), env.ttwo, thief, 0);
    let mut ix = claim_ix(&op.pubkey(), &wallet, TTWO, proofs[0].clone());
    ix.accounts[6].pubkey = wallet_ttwo(&thief, &env.ttwo);
    assert!(send(&mut env.svm, ix, &[&op]).is_err());
    assert_eq!(ttwo_amount(&env.svm, &wallet_ttwo(&thief, &env.ttwo)), 0);
}

#[test]
fn claim_when_paused_fails() {
    let mut env = setup();
    let op = env.operator.insecure_clone();
    let admin = env.admin.insecure_clone();
    let wallet = Pubkey::new_unique();
    fund_vault(&mut env, TTWO);
    let (root, proofs) = tree(&[(wallet, TTWO)]);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root, TTWO), &[&op]).unwrap();

    let err = send(&mut env.svm, admin_ix(&op.pubkey(), vicecards_vault::instruction::SetPaused { paused: true }.data()), &[&op])
        .unwrap_err();
    assert!(err.contains("Unauthorized"), "{err}");
    send(&mut env.svm, admin_ix(&admin.pubkey(), vicecards_vault::instruction::SetPaused { paused: true }.data()), &[&admin]).unwrap();
    let err = send(&mut env.svm, claim_ix(&op.pubkey(), &wallet, TTWO, proofs[0].clone()), &[&op]).unwrap_err();
    assert!(err.contains("Paused"), "{err}");
    send(&mut env.svm, admin_ix(&admin.pubkey(), vicecards_vault::instruction::SetPaused { paused: false }.data()), &[&admin]).unwrap();
    send(&mut env.svm, claim_ix(&op.pubkey(), &wallet, TTWO, proofs[0].clone()), &[&op]).unwrap();
    assert_eq!(ttwo_amount(&env.svm, &wallet_ttwo(&wallet, &env.ttwo)), TTWO);
}

// -------------------------------------------------------------------------
// admin
// -------------------------------------------------------------------------

#[test]
fn operator_and_admin_rotation() {
    let mut env = setup();
    let admin = env.admin.insecure_clone();
    let op = env.operator.insecure_clone();
    let new_op = Keypair::new();
    env.svm.airdrop(&new_op.pubkey(), SOL).unwrap();

    let err = send(&mut env.svm, admin_ix(&op.pubkey(), vicecards_vault::instruction::SetOperator { operator: new_op.pubkey() }.data()), &[&op])
        .unwrap_err();
    assert!(err.contains("Unauthorized"), "{err}");
    let err = send(&mut env.svm, admin_ix(&admin.pubkey(), vicecards_vault::instruction::SetOperator { operator: admin.pubkey() }.data()), &[&admin])
        .unwrap_err();
    assert!(err.contains("OperatorIsAdmin"), "{err}");
    send(&mut env.svm, admin_ix(&admin.pubkey(), vicecards_vault::instruction::SetOperator { operator: new_op.pubkey() }.data()), &[&admin]).unwrap();
    fund_vault(&mut env, TTWO);
    assert!(send(&mut env.svm, set_root_ix(&op.pubkey(), 1, [7u8; 32], 1), &[&op]).is_err());
    send(&mut env.svm, set_root_ix(&new_op.pubkey(), 1, [7u8; 32], 1), &[&new_op]).unwrap();

    let new_admin = Keypair::new();
    env.svm.airdrop(&new_admin.pubkey(), SOL).unwrap();
    send(&mut env.svm, admin_ix(&admin.pubkey(), vicecards_vault::instruction::ProposeAdmin { new_admin: new_admin.pubkey() }.data()), &[&admin]).unwrap();
    let accept = |k: &Keypair| {
        Instruction::new_with_bytes(
            vicecards_vault::id(),
            &vicecards_vault::instruction::AcceptAdmin {}.data(),
            vicecards_vault::accounts::AcceptAdmin { new_admin: k.pubkey(), config: config_pda() }.to_account_metas(None),
        )
    };
    let stranger = Keypair::new();
    env.svm.airdrop(&stranger.pubkey(), SOL).unwrap();
    assert!(send(&mut env.svm, accept(&stranger), &[&stranger]).is_err());
    send(&mut env.svm, accept(&new_admin), &[&new_admin]).unwrap();
    let c = config(&env.svm);
    assert_eq!((c.admin, c.pending_admin), (new_admin.pubkey(), Pubkey::default()));
    assert_eq!(c.mint, env.mint);
}

// -------------------------------------------------------------------------
// TypeScript ↔ program: the vectors written by tests/core (supabase/functions/_shared/core/merkle.ts)
// -------------------------------------------------------------------------

#[test]
fn typescript_merkle_vectors_claim_on_chain() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/merkle-vectors.json"))
        .expect("run `npx vitest run tests/core` first: it writes fixtures/merkle-vectors.json");
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let hex32 = |s: &str| -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    };
    let entries: Vec<(Pubkey, u64, Vec<[u8; 32]>)> = v["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let wallet = Pubkey::new_from_array(bs58::decode(e["wallet"].as_str().unwrap()).into_vec().unwrap().try_into().unwrap());
            let cumulative: u64 = e["cumulative"].as_str().unwrap().parse().unwrap();
            let proof = e["proof"].as_array().unwrap().iter().map(|p| hex32(p.as_str().unwrap())).collect();
            (wallet, cumulative, proof)
        })
        .collect();
    let root = hex32(v["root"].as_str().unwrap());

    // the Rust tree of these tests gives the same root
    let (rust_root, _) = tree(&entries.iter().map(|(w, c, _)| (*w, *c)).collect::<Vec<_>>());
    assert_eq!(rust_root, root);

    // and the program pays every entry with the TypeScript proofs
    let mut env = setup();
    let op = env.operator.insecure_clone();
    let total: u64 = entries.iter().map(|e| e.1).sum();
    fund_vault(&mut env, total);
    send(&mut env.svm, set_root_ix(&op.pubkey(), 1, root, total), &[&op]).unwrap();
    for (wallet, cumulative, proof) in &entries {
        send(&mut env.svm, claim_ix(&op.pubkey(), wallet, *cumulative, proof.clone()), &[&op]).unwrap();
        assert_eq!(ttwo_amount(&env.svm, &wallet_ttwo(wallet, &env.ttwo)), *cumulative);
    }
    assert_eq!(ttwo_amount(&env.svm, &vault_ttwo(&env.ttwo)), 0);
}

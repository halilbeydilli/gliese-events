/**
 * One registry of well-known access-control role hashes, shared by every renderer
 * (notifier, web, publisher). Added 2026-09-25 after the Lido DAO upgrade at 12:27 UTC printed
 * `0x2405…3b57` and `0x3396…b921` in the alert, the web page and the post: three places, two
 * divergent lookup tables, and the two roles that actually mattered in neither of them.
 *
 * How it is built. Almost every role hash on chain is `keccak256(bytes(NAME))` of a Solidity
 * constant's *name* (OpenZeppelin AccessControl) or of a short permission string (Aragon ACL,
 * Aave V3 ACLManager). So the source of truth here is a curated list of those **strings**, hashed
 * at module load — never a hand-copied hash. That matters for correctness: hashing a name can only
 * ever add an entry nothing looks up, it can never mislabel a hash as the wrong role, which is
 * exactly the failure mode of a hand-maintained hash->name table.
 *
 * The few hashes that are *not* a keccak of a name (DEFAULT_ADMIN_ROLE is 32 zero bytes) are listed
 * explicitly in `LITERAL_ROLE_HASHES`.
 *
 * Adding a family: append the strings to `HASHED_ROLE_NAMES` under a new `// --- <family> ---`
 * comment naming the canonical repository they came from, and add an assertion to
 * `test/roles.test.ts` for at least one member. Every string must be unique across the whole list
 * (the test enforces it): two names for one role would make the rendered sentence non-reproducible.
 *
 * Not role-based, deliberately absent: Circle FiatToken (masterMinter / pauser / blacklister /
 * rescuer are plain address slots, reported by us as `token.*` events, not `access.*`), Tether
 * (Ownable), Safe (modules and guards are addresses, not role hashes), Morpho MetaMorpho and
 * PublicAllocator (owner / curator / guardian / allocator mappings), Silo V2 and Gearbox V3
 * (ownable + a config contract). Venus' AccessControlManager is role-based but its roles are
 * `keccak256(abi.encodePacked(targetContract, functionSignature))`, so there is no name to recover
 * and they are left to the short-hash fallback.
 */
import { keccak256, toBytes } from 'viem';

/**
 * Role-name strings, hashed at module load. Grouped by the protocol family they come from; a name
 * shared by several families is listed once, under the family we take it from.
 */
const HASHED_ROLE_NAMES: readonly string[] = [
  // --- OpenZeppelin AccessControl: the names the templates ship with -------------------------
  // (openzeppelin-contracts `access/AccessControl.sol` users; DEFAULT_ADMIN_ROLE is a literal below)
  'MINTER_ROLE',
  'BURNER_ROLE',
  'PAUSER_ROLE',
  'UPGRADER_ROLE',
  'ADMIN_ROLE',
  'OPERATOR_ROLE',
  'GUARDIAN_ROLE',
  'GOVERNOR_ROLE',
  'OWNER_ROLE',
  'MANAGER_ROLE',
  'WHITELISTER_ROLE',
  'BLACKLISTER_ROLE',
  'BLOCKLIST_ROLE',
  'WHITELIST_ROLE',
  'SNAPSHOT_ROLE',
  'RESCUER_ROLE',
  'RELAYER_ROLE',
  'SUPER_ADMIN_ROLE',
  'ROLE_ADMIN',
  'KEEPER_ROLE',
  'GOVERNANCE_ROLE',
  'EMERGENCY_ROLE',
  'MAINTAINER_ROLE',
  'ISSUER_ROLE',
  'METADATA_ROLE',
  // NB: `keccak256('DEFAULT_ADMIN_ROLE')` (0x1effbbff…) is a real hash on chain — contracts that
  // redeclare the constant instead of inheriting it — but naming it too would put one name on two
  // hashes, so it stays on the short-hash fallback.

  // --- OpenZeppelin TimelockController (`governance/TimelockController.sol`) ------------------
  'PROPOSER_ROLE',
  'EXECUTOR_ROLE',
  'CANCELLER_ROLE',
  'TIMELOCK_ADMIN_ROLE',

  // --- Lido: Aragon-era permissions on stETH (lidofinance/core `contracts/0.4.24/Lido.sol`) ---
  // These are granted through the Aragon ACL, so they arrive as `aragon.permission_set`, not
  // `access.role_granted`. BUFFER_RESERVE_MANAGER_ROLE is the one the DAO granted to the EasyTrack
  // EVMScriptExecutor on 2026-09-25.
  'PAUSE_ROLE',
  'RESUME_ROLE',
  'STAKING_PAUSE_ROLE',
  'STAKING_CONTROL_ROLE',
  'UNSAFE_CHANGE_DEPOSITED_VALIDATORS_ROLE',
  'BUFFER_RESERVE_MANAGER_ROLE',
  'BURN_ROLE',
  'DEPOSIT_ROLE',
  'MANAGE_FEE',
  'MANAGE_WITHDRAWAL_KEY',
  'MANAGE_PROTOCOL_CONTRACTS_ROLE',
  'SET_EL_REWARDS_VAULT_ROLE',
  'SET_EL_REWARDS_WITHDRAWAL_LIMIT_ROLE',

  // --- Lido StakingRouter (lidofinance/core `contracts/0.8.9/StakingRouter.sol`) --------------
  'MANAGE_WITHDRAWAL_CREDENTIALS_ROLE',
  'STAKING_MODULE_MANAGE_ROLE',
  'STAKING_MODULE_UNVETTING_ROLE',
  'STAKING_MODULE_PAUSE_ROLE',
  'STAKING_MODULE_RESUME_ROLE',
  'REPORT_EXITED_VALIDATORS_ROLE',
  'UNSAFE_SET_EXITED_VALIDATORS_ROLE',
  'REPORT_REWARDS_MINTED_ROLE',

  // --- Lido WithdrawalQueue (`contracts/0.8.9/WithdrawalQueueBase.sol` / `WithdrawalQueueERC721.sol`)
  // (PAUSE_ROLE / RESUME_ROLE are shared with Lido.sol above)
  'FINALIZE_ROLE',
  'ORACLE_ROLE',
  'MANAGE_TOKEN_URI_ROLE',

  // --- Lido oracles (`contracts/0.8.9/oracle/*.sol`, HashConsensus, OracleReportSanityChecker) -
  'MANAGE_CONSENSUS_CONTRACT_ROLE',
  'MANAGE_CONSENSUS_VERSION_ROLE',
  'SUBMIT_DATA_ROLE',
  'MANAGE_MEMBERS_AND_QUORUM_ROLE',
  'DISABLE_CONSENSUS_ROLE',
  'MANAGE_FRAME_CONFIG_ROLE',
  'MANAGE_FAST_LANE_CONFIG_ROLE',
  'MANAGE_REPORT_PROCESSOR_ROLE',
  'ALL_LIMITS_MANAGER_ROLE',
  'EXITED_VALIDATORS_PER_DAY_LIMIT_MANAGER_ROLE',
  'APPEARED_VALIDATORS_PER_DAY_LIMIT_MANAGER_ROLE',
  'ANNUAL_BALANCE_INCREASE_LIMIT_MANAGER_ROLE',
  'SHARE_RATE_DEVIATION_LIMIT_MANAGER_ROLE',
  'MAX_VALIDATOR_EXIT_REQUESTS_PER_REPORT_ROLE',
  'MAX_ITEMS_PER_EXTRA_DATA_TRANSACTION_ROLE',
  'MAX_NODE_OPERATORS_PER_EXTRA_DATA_ITEM_ROLE',
  'REQUEST_TIMESTAMP_MARGIN_MANAGER_ROLE',
  'MAX_POSITIVE_TOKEN_REBASE_MANAGER_ROLE',
  'SECOND_OPINION_MANAGER_ROLE',
  'INITIAL_SLASHING_AND_PENALTIES_MANAGER_ROLE',
  'CONFIG_MANAGER_ROLE',

  // --- Lido Burner (`contracts/0.8.9/Burner.sol`) --------------------------------------------
  'REQUEST_BURN_MY_STETH_ROLE',
  'REQUEST_BURN_SHARES_ROLE',

  // --- Lido NodeOperatorsRegistry (`contracts/0.4.24/nos/NodeOperatorsRegistry.sol`) ----------
  'MANAGE_SIGNING_KEYS',
  'SET_NODE_OPERATOR_LIMIT_ROLE',
  'MANAGE_NODE_OPERATOR_ROLE',
  'STAKING_ROUTER_ROLE',

  // --- Aragon apps as Lido deploys them (lidofinance/aragon-core, aragon-apps, aragon-id) -----
  // ACL / Kernel / EVMScriptRegistry, then Agent, Voting, Finance, TokenManager and Vault.
  'CREATE_PERMISSIONS_ROLE',
  'APP_MANAGER_ROLE',
  'REGISTRY_ADD_EXECUTOR_ROLE',
  'REGISTRY_MANAGER_ROLE',
  'EXECUTE_ROLE',
  'SAFE_EXECUTE_ROLE',
  'RUN_SCRIPT_ROLE',
  'ADD_PROTECTED_TOKEN_ROLE',
  'REMOVE_PROTECTED_TOKEN_ROLE',
  'DESIGNATE_SIGNER_ROLE',
  'ADD_PRESIGNED_HASH_ROLE',
  'TRANSFER_ROLE',
  'CREATE_VOTES_ROLE',
  'MODIFY_SUPPORT_ROLE',
  'MODIFY_QUORUM_ROLE',
  'UNSAFELY_MODIFY_VOTE_TIME_ROLE',
  'CREATE_PAYMENTS_ROLE',
  'CHANGE_PERIOD_ROLE',
  'CHANGE_BUDGETS_ROLE',
  'EXECUTE_PAYMENTS_ROLE',
  'MANAGE_PAYMENTS_ROLE',
  'MINT_ROLE',
  'ISSUE_ROLE',
  'ASSIGN_ROLE',
  'REVOKE_VESTINGS_ROLE',

  // --- Aave V3 ACLManager (aave-v3-core `protocol/configuration/ACLManager.sol`) --------------
  // The constants are named `POOL_ADMIN_ROLE` etc. but hash the string WITHOUT the suffix
  // (`keccak256('POOL_ADMIN')`), so the preimage — and therefore the name we print — is the bare
  // word. `keccak256('POOL_ADMIN')` is the hash our Aave events actually carry.
  'POOL_ADMIN',
  'EMERGENCY_ADMIN',
  'RISK_ADMIN',
  'FLASH_BORROWER',
  'BRIDGE',
  'ASSET_LISTING_ADMIN',
  // The `_ROLE`-suffixed spellings other protocols use for the same words:
  'POOL_ADMIN_ROLE',
  'EMERGENCY_ADMIN_ROLE',
  'RISK_ADMIN_ROLE',
  'BRIDGE_ROLE',

  // --- Ethena sUSDe / EthenaMinting (2026-09-29, GAP-SCAN-2026-09-29 row 6) --------------------------
  // Read from the verified deployed sources on Sourcify (full match): sUSDe 0x9D39…3497 = StakedUSDeV2,
  // `contracts/StakedUSDe.sol` (REWARDER_ROLE, BLACKLIST_MANAGER_ROLE, SOFT_RESTRICTED_STAKER_ROLE,
  // FULL_RESTRICTED_STAKER_ROLE) and EthenaMinting 0xe349…62D3 `contracts/EthenaMinting.sol` (MINTER_ROLE
  // above, REDEEMER_ROLE, COLLATERAL_MANAGER_ROLE, GATEKEEPER_ROLE); the same constants are in
  // ethena-labs/code4arena-contest protocols/USDe/contracts. USDe.sol itself has a single `minter` address
  // (Ownable2Step), no roles. FULL_RESTRICTED_STAKER_ROLE (0x0a4af4bc…c3bd) is the freeze the 02:00 UTC
  // sUSDe role grant carried unnamed.
  'REWARDER_ROLE',
  'BLACKLIST_MANAGER_ROLE',
  'SOFT_RESTRICTED_STAKER_ROLE',
  'FULL_RESTRICTED_STAKER_ROLE',
  'REDEEMER_ROLE',
  'COLLATERAL_MANAGER_ROLE',
  'GATEKEEPER_ROLE',

  // --- Bare words: contracts that hash the word without the `_ROLE` suffix --------------------
  'ADMIN',
  'OPERATOR',
  'MINTER',
  'PAUSER',
  'MANAGER',
  'OWNER',
  'GUARDIAN',

  // --- Application roles seen in our own `events` table ---------------------------------------
  // Every one of these was recovered by hashing the candidate name and finding the hash in
  // production data (2026-09-25); they come from token, vault, bridge and marketplace templates
  // rather than from one protocol.
  'PARAMETER_ROLE',
  'SWAPPER_ROLE',
  'REPORTER_ROLE',
  'UPDATER_ROLE',
  'SIGNER_ROLE',
  'TREASURER_ROLE',
  'TREASURY_ROLE',
  'COMPLIANCE_ROLE',
  'DISTRIBUTOR_ROLE',
  'REGISTRAR_ROLE',
  'DEPOSITOR_ROLE',
  'WITHDRAWER_ROLE',
  'WITHDRAW_ROLE',
  'FEE_MANAGER_ROLE',
  'CONTROLLER_ROLE',
  'CONFIG_ROLE',
  'CONFIGURATOR_ROLE',
  'VAULT_ROLE',
  'POOL_ROLE',
  'ALLOCATOR_ROLE',
  'ASSET_MANAGER_ROLE',
  'FACTORY_ROLE',
  'DEPLOYER_ROLE',
  'RECOVERY_ROLE',
  'RESCUE_ROLE',
  'CLAIMER_ROLE',
  'MODERATOR_ROLE',
  'EXTENSION_ROLE',
  'AGENT_ROLE',
  'FREEZER_ROLE',
  'SETTLEMENT_ROLE',
  'SETTLER_ROLE',
  'SOLVER_ROLE',
  'MARKET_ROLE',
  'MARKET_MAKER_ROLE',
  'ROUTER_ROLE',
  'GAME_ROLE',
  'PRICE_UPDATER_ROLE',
  'BRIDGE_ADMIN_ROLE',
  'CROSS_CHAIN_ROLE',
  'MIGRATOR_ROLE',
  'REBALANCER_ROLE',
  'UNPAUSE_ROLE',
  'VERIFIER_ROLE',
  'SUBMITTER_ROLE',
  'ATTESTER_ROLE',
  'LIMIT_MANAGER_ROLE',
  'TIMELOCK_ROLE',
  'GOVERNANCE_ADMIN_ROLE',
  'AUTOMATION_ROLE',
  'SNAPSHOTTER_ROLE',
  'MINTER_BURNER_ROLE',
  'TOKEN_MANAGER_ROLE',
  'STAKING_ROLE',
  'CORE_ROLE',
  'INVESTOR_ROLE',
  'USER_ROLE',
  'CREATOR_ROLE',
  'ARTIST_ROLE',
  'PUBLISHER_ROLE',
  'WRITER_ROLE',
  'REVIEWER_ROLE',
  'APPROVER_ROLE',
  'ARBITER_ROLE',
  'ACCOUNTANT_ROLE',
  'PAYER_ROLE',
  'SALE_ROLE',
];

/** Role hashes that are not `keccak256` of a name. */
const LITERAL_ROLE_HASHES: readonly (readonly [string, string])[] = [
  // AccessControl's root role is 32 zero bytes, not a hash of anything.
  ['0x0000000000000000000000000000000000000000000000000000000000000000', 'DEFAULT_ADMIN_ROLE'],
];

/** Lowercase 32-byte role hash -> role name. Built once, at module load. */
export const ROLE_NAME_BY_HASH: ReadonlyMap<string, string> = new Map<string, string>([
  ...LITERAL_ROLE_HASHES.map(([hash, name]): [string, string] => [hash.toLowerCase(), name]),
  ...HASHED_ROLE_NAMES.map((name): [string, string] => [keccak256(toBytes(name)).toLowerCase(), name]),
]);

const HEX_RE = /^0x[0-9a-fA-F]{1,64}$/;

/**
 * `STAKING_MODULE_UNVETTING_ROLE` for `0x2405…3b57`, `null` for anything we cannot name — callers
 * decide the fallback (a short hash, "role 0x…"). Never throws: an object, a number, a malformed
 * string all return null. Short hex is left-padded to 32 bytes first, so a decoder that dropped
 * leading zeros still resolves DEFAULT_ADMIN_ROLE.
 */
export function roleNameOf(hash: unknown): string | null {
  if (typeof hash !== 'string') return null;
  const trimmed = hash.trim();
  if (!HEX_RE.test(trimmed)) return null;
  const padded = `0x${trimmed.slice(2).toLowerCase().padStart(64, '0')}`;
  return ROLE_NAME_BY_HASH.get(padded) ?? null;
}

/**
 * OpenZeppelin 5.x AccessManager role ids (uint64, not hashes) as Aave V4 assigns them
 * (aave/aave-v4 `src/deployments/utils/libraries/Roles.sol`, read 2026-09-26) plus the two ids OZ
 * reserves (0 = ADMIN_ROLE, 2^64-1 = PUBLIC_ROLE). Other AccessManager deployments use their own
 * numbering, so a miss falls back to "role N" and the number is always shown.
 */
export const ACCESS_MANAGER_ROLE_NAMES: ReadonlyMap<string, string> = new Map<string, string>([
  ['0', 'ADMIN_ROLE'],
  ['100', 'HUB_DOMAIN_ADMIN_ROLE'],
  ['101', 'HUB_CONFIGURATOR_ROLE'],
  ['102', 'HUB_FEE_MINTER_ROLE'],
  ['103', 'HUB_DEFICIT_ELIMINATOR_ROLE'],
  ['200', 'HUB_CONFIGURATOR_DOMAIN_ADMIN_ROLE'],
  ['300', 'SPOKE_DOMAIN_ADMIN_ROLE'],
  ['301', 'SPOKE_CONFIGURATOR_ROLE'],
  ['302', 'SPOKE_USER_POSITION_UPDATER_ROLE'],
  ['400', 'SPOKE_CONFIGURATOR_DOMAIN_ADMIN_ROLE'],
  ['18446744073709551615', 'PUBLIC_ROLE'],
]);

/** `HUB_CONFIGURATOR_DOMAIN_ADMIN_ROLE (200)` for 200 / "200" / 200n / "0xc8", `role 7` for an unknown id, `role ?` for junk. */
export function accessManagerRoleName(roleId: unknown): string {
  let id: string | null = null;
  if (typeof roleId === 'bigint' || (typeof roleId === 'number' && Number.isInteger(roleId) && roleId >= 0)) id = String(roleId);
  else if (typeof roleId === 'string') {
    const t = roleId.trim();
    if (/^\d+$/.test(t)) id = String(BigInt(t));
    else if (/^0x[0-9a-fA-F]{1,16}$/.test(t)) id = String(BigInt(t));
  }
  if (id === null) return 'role ?';
  const name = ACCESS_MANAGER_ROLE_NAMES.get(id);
  return name ? `${name} (${id})` : `role ${id}`;
}

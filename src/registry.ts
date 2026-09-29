import { parseAbiItem, toEventSelector, type AbiEvent, type Hex } from 'viem';

export type Category =
  | 'upgrade'
  | 'ownership'
  | 'access'
  | 'pause'
  | 'multisig'
  | 'timelock'
  | 'governance'
  | 'token_admin'
  /** Protocol parameter changes (2026-09-07): MakerDAO `File`, Chainlink aggregator swaps. */
  | 'parameters';

export type Severity = 'critical' | 'high' | 'info';

export interface WatchedEvent {
  /** Unique stable key, e.g. 'proxy.upgraded', 'safe.removed_owner' */
  key: string;
  category: Category;
  severity: Severity;
  abi: AbiEvent;
  /** keccak256 of the canonical signature, computed with toEventSelector(abi) */
  topic0: Hex;
  /** One-line English description */
  description: string;
}

/**
 * [key, category, severity, description, ...signatures (alternate indexed layouts share the key)]
 *
 * Adding an entry: pick a stable `<family>.<snake_case>` key, keep the description one line, add
 * the human phrasing in apps/notifier (DESCRIBERS), apps/publisher (PHRASERS, digest KEY_*) and
 * apps/web/lib/describe.ts, and bump the topic0 count asserted in test/events.test.ts
 * (330 unique signatures / 279 keys since Aave Governance V3 core + PayloadsController on 2026-09-29;
 * 317 / 268 with the OZ Governor late-quorum / quorum / timelock keys and 313 / 264 with the Venus
 * GovernorBravo typed ProposalCreated + settings keys the same day; 305 / 257 since the Lido Easy
 * Track + Arbitrum Security Council manager
 * families and AaveOracle BaseCurrencySet the same day; 284 / 236 since the Venus Diamond +
 * ResilientOracle batch on 2026-09-28;
 * 265 / 221 since Aave V4 on 2026-09-26; 239 / 195 after coverage batch 2 on 2026-09-23; 194 / 153
 * after coverage batch 1 on 2026-09-22; 116 / 96 with Morpho Vault V2 earlier the same day; 88 / 78
 * on 2026-09-18; 57 / 54 before the vault governance family).
 * Setup-noise anchors live in decode.ts (detectInit). A key normally maps to one topic0; the
 * exceptions are `auth.file` (four MakerDAO overloads with different param types) and the vault
 * umbrella keys `vault.pending_revoked` (four RevokePending* events), `vault.params_set` (five
 * GovSet* events), `vault.fee_set` / `vault.fee_recipient_set` (MetaMorpho + Vault V2 fee events),
 * `vault.cap_increased` / `vault.cap_decreased` (absolute + relative), `vault.gate_set` (four
 * gates) and `vault.metadata_set` (name + symbol), which share one key on purpose. Coverage batch 1
 * (2026-09-22) added `pause.paused` / `pause.unpaused` (five pause dialects each), `pause.state_changed`,
 * the cross-protocol lending keys (`lending.price_oracle_set`, `lending.interest_rate_model_set`,
 * `lending.borrow_cap_changed`, `lending.reserve_factor_changed`), the Aave umbrellas
 * (`lending.emode_asset_changed`, `lending.liquidation_grace_period_changed`,
 * `lending.flashloan_premium_updated`), `lending.action_paused` and `protocol.fee_config_set`. Coverage
 * batch 2 (2026-09-23) added `rollup.config_updated` (SystemConfig + SuperchainConfig ConfigUpdate),
 * `rollup.sequencer_inbox_set` (Bridge + RollupAdmin) and `rollup.assertion_forced` (created + confirmed).
 * The Venus batch (2026-09-28) put the Diamond Comptroller layouts under the Compound keys they
 * restate: `lending.supply_cap_changed` (Aave SupplyCapChanged + Venus NewSupplyCap),
 * `lending.collateral_factor_set` and `lending.liquidation_incentive_set` (Compound two/three-param +
 * Venus (poolId, vToken) four-param) and a third `lending.action_paused` overload (ActionPausedMarket).
 */
type Spec = readonly [string, Category, Severity, string, ...string[]];

const SPECS: readonly Spec[] = [
  // ---- upgrade ------------------------------------------------------------
  [
    'proxy.upgraded',
    'upgrade',
    'critical',
    'Proxy implementation address was changed (ERC-1967 Upgraded).',
    'event Upgraded(address indexed implementation)',
  ],
  [
    'proxy.admin_changed',
    'upgrade',
    'critical',
    'Proxy admin address was changed (ERC-1967 AdminChanged).',
    'event AdminChanged(address previousAdmin, address newAdmin)',
  ],
  [
    'proxy.beacon_upgraded',
    'upgrade',
    'critical',
    'Beacon proxy now points at a new beacon (ERC-1967 BeaconUpgraded).',
    'event BeaconUpgraded(address indexed beacon)',
  ],
  [
    'diamond.cut',
    'upgrade',
    'critical',
    'Diamond (EIP-2535) facets were added, replaced or removed.',
    'event DiamondCut((address facetAddress, uint8 action, bytes4[] functionSelectors)[] _diamondCut, address _init, bytes _calldata)',
  ],
  // Compound-style delegators (2026-09-07): Comptroller/Unitroller, cTokens (CErc20Delegator),
  // GovernorBravoDelegator and every fork (Venus, Moonwell, Benqi, Sonne, Strike...). The
  // implementation lives in the proxy's own storage, not in an ERC-1967 slot, and changes
  // through _setImplementation / _acceptImplementation. Both params are non-indexed.
  [
    'proxy.new_implementation',
    'upgrade',
    'critical',
    'Compound-style delegator implementation was changed (NewImplementation).',
    'event NewImplementation(address oldImplementation, address newImplementation)',
  ],
  [
    'proxy.new_pending_implementation',
    'upgrade',
    'high',
    'A pending implementation was set on a Compound-style delegator (NewPendingImplementation).',
    'event NewPendingImplementation(address oldPendingImplementation, address newPendingImplementation)',
  ],
  [
    'proxy.initialized',
    'upgrade',
    'high',
    'Initializable contract ran an initializer (OpenZeppelin v4, uint8 version).',
    'event Initialized(uint8 version)',
  ],
  [
    'proxy.initialized_v5',
    'upgrade',
    'high',
    'Initializable contract ran an initializer (OpenZeppelin v5, uint64 version).',
    'event Initialized(uint64 version)',
  ],

  // ---- ownership ----------------------------------------------------------
  [
    'ownable.transferred',
    'ownership',
    'critical',
    'Contract ownership was transferred to a new owner.',
    'event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)',
  ],
  [
    'ownable.transfer_started',
    'ownership',
    'high',
    'A two-step ownership transfer was started (Ownable2Step).',
    'event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner)',
  ],
  // Chainlink ConfirmedOwner (2026-09-07): the two-step transfer used by every Chainlink
  // aggregator, proxy and CCIP contract. Acceptance emits the plain OwnershipTransferred above.
  [
    'ownable.transfer_requested',
    'ownership',
    'high',
    'A two-step ownership transfer was requested (Chainlink ConfirmedOwner).',
    'event OwnershipTransferRequested(address indexed from, address indexed to)',
  ],
  // Curve / Vyper two-step admin transfer (2026-09-07): VotingEscrow, GaugeController, older
  // StableSwap pools and forks. `commit_transfer_ownership` then `apply_transfer_ownership`;
  // the param is called `admin` and is not indexed.
  [
    'ownable.commit_ownership',
    'ownership',
    'high',
    'A Curve-style ownership transfer was committed (CommitOwnership), pending apply.',
    'event CommitOwnership(address admin)',
  ],
  [
    'ownable.apply_ownership',
    'ownership',
    'critical',
    'A Curve-style ownership transfer was applied (ApplyOwnership): admin() changed.',
    'event ApplyOwnership(address admin)',
  ],

  // ---- access -------------------------------------------------------------
  [
    'access.role_granted',
    'access',
    'high',
    'An AccessControl role was granted to an account.',
    'event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)',
  ],
  [
    'access.role_revoked',
    'access',
    'info',
    'An AccessControl role was revoked from an account.',
    'event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)',
  ],
  [
    'access.role_admin_changed',
    'access',
    'high',
    'The admin role governing an AccessControl role was changed.',
    'event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole)',
  ],
  // MakerDAO / Sky "auth" pattern (2026-09-07): `wards[usr]` on every Maker core module (Vat,
  // Jug, Spot, Dog, Vow, PSM, OSM...), Spark and countless forks. A ward can do anything the
  // module allows, including rely-ing further addresses. Chain-wide like everything else here;
  // a Rely in the deploying transaction is flagged as setup by the watcher (getCode at block-1).
  [
    'auth.rely',
    'access',
    'critical',
    'An address was authorised as a ward (MakerDAO-style Rely).',
    'event Rely(address indexed usr)',
  ],
  [
    'auth.deny',
    'access',
    'high',
    'An address lost its ward authorisation (MakerDAO-style Deny).',
    'event Deny(address indexed usr)',
  ],

  // ---- pause --------------------------------------------------------------
  // Five signatures, one key (2026-09-22): OpenZeppelin Paused(address account), Circle FiatToken /
  // CCTP / Paxos Pause(), Lido PausableUntil Paused(uint256 duration), EigenLayer Paused(address
  // indexed account, uint256 newPausedStatus) and OP SuperchainConfig Paused(string identifier).
  [
    'pause.paused',
    'pause',
    'high',
    'Contract was paused (OpenZeppelin Paused, Circle Pause, Lido Paused(duration), EigenLayer Paused(account, status) or OP SuperchainConfig Paused(identifier)).',
    'event Paused(address account)',
    'event Pause()',
    'event Paused(uint256 duration)',
    'event Paused(address indexed account, uint256 newPausedStatus)',
    'event Paused(string identifier)',
  ],
  [
    'pause.unpaused',
    'pause',
    'info',
    'Contract was unpaused (OpenZeppelin Unpaused, Circle Unpause, Lido Resumed, EigenLayer Unpaused(account, status) or OP SuperchainConfig Unpaused).',
    'event Unpaused(address account)',
    'event Unpause()',
    'event Resumed()',
    'event Unpaused(address indexed account, uint256 newPausedStatus)',
    'event Unpaused()',
  ],

  // ---- multisig (Gnosis Safe) --------------------------------------------
  [
    'safe.added_owner',
    'multisig',
    'high',
    'A new signer was added to the Safe.',
    'event AddedOwner(address owner)',
    'event AddedOwner(address indexed owner)',
  ],
  [
    'safe.removed_owner',
    'multisig',
    'critical',
    'A signer was removed from the Safe.',
    'event RemovedOwner(address owner)',
    'event RemovedOwner(address indexed owner)',
  ],
  [
    'safe.changed_threshold',
    'multisig',
    'critical',
    'The Safe signature threshold was changed.',
    'event ChangedThreshold(uint256 threshold)',
  ],
  [
    'safe.enabled_module',
    'multisig',
    'critical',
    'A module that can execute transactions without signatures was enabled (Safe EnabledModule; also emitted by Zodiac modifiers such as Delay and Roles).',
    'event EnabledModule(address module)',
    'event EnabledModule(address indexed module)',
  ],
  [
    'safe.disabled_module',
    'multisig',
    'high',
    'A module was disabled (Safe DisabledModule; also emitted by Zodiac modifiers).',
    'event DisabledModule(address module)',
    'event DisabledModule(address indexed module)',
  ],
  [
    'safe.changed_guard',
    'multisig',
    'critical',
    'The Safe transaction guard was changed.',
    'event ChangedGuard(address guard)',
    'event ChangedGuard(address indexed guard)',
  ],
  [
    'safe.changed_fallback_handler',
    'multisig',
    'high',
    'The Safe fallback handler was changed.',
    'event ChangedFallbackHandler(address handler)',
    'event ChangedFallbackHandler(address indexed handler)',
  ],
  [
    'safe.changed_master_copy',
    'multisig',
    'critical',
    'The Safe singleton (master copy) implementation was changed.',
    'event ChangedMasterCopy(address masterCopy)',
  ],
  [
    'safe.setup',
    'multisig',
    'info',
    'A Safe was initialized with its owners and threshold.',
    'event SafeSetup(address indexed initiator, address[] owners, uint256 threshold, address initializer, address fallbackHandler)',
  ],

  // ---- timelock -----------------------------------------------------------
  [
    'timelock.call_scheduled',
    'timelock',
    'high',
    'An operation was scheduled in an OpenZeppelin TimelockController.',
    'event CallScheduled(bytes32 indexed id, uint256 indexed index, address target, uint256 value, bytes data, bytes32 predecessor, uint256 delay)',
  ],
  [
    'timelock.call_executed',
    'timelock',
    'info',
    'A scheduled operation was executed by an OpenZeppelin TimelockController.',
    'event CallExecuted(bytes32 indexed id, uint256 indexed index, address target, uint256 value, bytes data)',
  ],
  [
    'timelock.cancelled',
    'timelock',
    'info',
    'A scheduled operation was cancelled in an OpenZeppelin TimelockController.',
    'event Cancelled(bytes32 indexed id)',
  ],
  [
    'timelock.min_delay_changed',
    'timelock',
    'critical',
    'The minimum delay of an OpenZeppelin TimelockController was changed.',
    'event MinDelayChange(uint256 oldDuration, uint256 newDuration)',
  ],
  [
    'timelock.queue_transaction',
    'timelock',
    'high',
    'A transaction was queued in a Compound-style Timelock.',
    'event QueueTransaction(bytes32 indexed txHash, address indexed target, uint256 value, string signature, bytes data, uint256 eta)',
  ],
  [
    'timelock.execute_transaction',
    'timelock',
    'info',
    'A queued transaction was executed by a Compound-style Timelock.',
    'event ExecuteTransaction(bytes32 indexed txHash, address indexed target, uint256 value, string signature, bytes data, uint256 eta)',
  ],
  [
    'timelock.cancel_transaction',
    'timelock',
    'info',
    'A queued transaction was cancelled in a Compound-style Timelock.',
    'event CancelTransaction(bytes32 indexed txHash, address indexed target, uint256 value, string signature, bytes data, uint256 eta)',
  ],
  // `NewAdmin(address)` is also emitted by Curve / Vyper contracts (StableSwap pools, factories)
  // after `apply_transfer_ownership`; identical ABI types mean the same topic0, so one entry
  // serves both and the phrasing stays generic ("admin changed") (2026-09-07).
  [
    'timelock.new_admin',
    'timelock',
    'critical',
    'The admin was changed (Compound-style Timelock or Curve/Vyper NewAdmin).',
    'event NewAdmin(address indexed newAdmin)',
  ],
  [
    'timelock.new_pending_admin',
    'timelock',
    'high',
    'A new pending admin was set on a Compound-style Timelock.',
    'event NewPendingAdmin(address indexed newPendingAdmin)',
  ],
  [
    'timelock.new_delay',
    'timelock',
    'critical',
    'The delay of a Compound-style Timelock was changed.',
    'event NewDelay(uint256 indexed newDelay)',
  ],

  // ---- governance ---------------------------------------------------------
  // Two ProposalCreated layouts under one key (2026-09-29, GAP-SCAN-2026-09-29 row 1): the OpenZeppelin
  // IGovernor / Compound GovernorBravo nine-arg form, and Venus GovernorBravoDelegate's with the trailing
  // `proposalType` (VenusProtocol/governance-contracts develop contracts/Governance/GovernorBravoInterfaces.sol,
  // `GovernorBravoEvents`; `uint` = uint256; enum ProposalType { NORMAL, FASTTRACK, CRITICAL } = uint8 0 / 1 / 2;
  // the source names the id `id` and the window `startBlock` / `endBlock`, kept as written). Different
  // param types, different topic0: a declared overload key in the test, like `lending.supply_cap_changed`.
  // VIP-664's creation (BNB block 124,657,988) is the real log the test decodes. Third layout (row 3): Aave
  // Governance V3 core (bgd-labs/aave-governance-v3 main src/interfaces/IGovernanceCore.sol), where the
  // payloads live elsewhere (`payloads.created`) and the event carries the creator, the access level
  // (PayloadsControllerUtils.AccessControl: 0 Level_null, 1 Level_1, 2 Level_2; uint8) and the IPFS hash.
  [
    'governor.proposal_created',
    'governance',
    'info',
    'A governance proposal was created.',
    'event ProposalCreated(uint256 proposalId, address proposer, address[] targets, uint256[] values, string[] signatures, bytes[] calldatas, uint256 voteStart, uint256 voteEnd, string description)',
    'event ProposalCreated(uint256 id, address proposer, address[] targets, uint256[] values, string[] signatures, bytes[] calldatas, uint256 startBlock, uint256 endBlock, string description, uint8 proposalType)',
    'event ProposalCreated(uint256 indexed proposalId, address indexed creator, uint8 indexed accessLevel, bytes32 ipfsHash)',
  ],
  // OZ / Bravo `(proposalId, etaSeconds)` and Aave Governance V3's `(proposalId, votesFor, votesAgainst)`
  // (2026-09-29): there the eta belongs to each payload, see `payloads.queued`. Different types, overload key.
  [
    'governor.proposal_queued',
    'governance',
    'info',
    'A governance proposal was queued for execution.',
    'event ProposalQueued(uint256 proposalId, uint256 etaSeconds)',
    'event ProposalQueued(uint256 indexed proposalId, uint128 votesFor, uint128 votesAgainst)',
  ],
  // Aave Governance V3 indexes the id: same topic0, second layout (2026-09-29).
  [
    'governor.proposal_executed',
    'governance',
    'info',
    'A governance proposal was executed.',
    'event ProposalExecuted(uint256 proposalId)',
    'event ProposalExecuted(uint256 indexed proposalId)',
  ],
  [
    'governor.proposal_canceled',
    'governance',
    'info',
    'A governance proposal was canceled.',
    'event ProposalCanceled(uint256 proposalId)',
    'event ProposalCanceled(uint256 indexed proposalId)',
  ],

  // ---- token_admin (Circle FiatToken style) ------------------------------
  [
    'token.blacklisted',
    'token_admin',
    'high',
    'An account was blacklisted by the token issuer.',
    'event Blacklisted(address indexed _account)',
  ],
  [
    'token.unblacklisted',
    'token_admin',
    'info',
    'An account was removed from the token blacklist.',
    'event UnBlacklisted(address indexed _account)',
  ],
  [
    'token.master_minter_changed',
    'token_admin',
    'critical',
    'The token master minter was changed.',
    'event MasterMinterChanged(address indexed newMasterMinter)',
  ],
  [
    'token.minter_configured',
    'token_admin',
    'high',
    'A token minter was configured with a minting allowance.',
    'event MinterConfigured(address indexed minter, uint256 minterAllowedAmount)',
  ],
  [
    'token.minter_removed',
    'token_admin',
    'info',
    'A token minter was removed.',
    'event MinterRemoved(address indexed oldMinter)',
  ],
  [
    'token.pauser_changed',
    'token_admin',
    'critical',
    'The token pauser role was reassigned.',
    'event PauserChanged(address indexed newAddress)',
  ],
  [
    'token.blacklister_changed',
    'token_admin',
    'critical',
    'The token blacklister role was reassigned.',
    'event BlacklisterChanged(address indexed newBlacklister)',
  ],
  [
    'token.rescuer_changed',
    'token_admin',
    'high',
    'The token rescuer role was reassigned.',
    'event RescuerChanged(address indexed newRescuer)',
  ],

  // ---- parameters (2026-09-07) --------------------------------------------
  // MakerDAO / Sky `file`: risk and system parameters (line, dust, duty, mat, hole, chop, vow,
  // pip, ...) set by the ward. Four overloads = four topic0s under one key; the describers decode
  // `what` / `ilk` as ASCII ("line", "ETH-A"). Global (2 params) and per-ilk (3 params) variants,
  // each with a uint256 or an address payload.
  // Severity `info` (2026-09-08): chain-wide, a single unnamed contract emitted 682 File events in
  // 12 hours and flooded the "high" feed; watchers of a named Maker module still receive it on Pro.
  [
    'auth.file',
    'parameters',
    'info',
    'A MakerDAO-style parameter was set (File).',
    'event File(bytes32 indexed what, uint256 data)',
    'event File(bytes32 indexed what, address data)',
    'event File(bytes32 indexed ilk, bytes32 indexed what, uint256 data)',
    'event File(bytes32 indexed ilk, bytes32 indexed what, address data)',
  ],
  // Chainlink EACAggregatorProxy: the proxy every lending oracle reads swaps its underlying
  // aggregator in two steps (proposeAggregator / confirmAggregator). A confirmed swap changes
  // the price source of everything downstream.
  [
    'oracle.aggregator_proposed',
    'parameters',
    'high',
    'A new price aggregator was proposed on a Chainlink feed proxy (AggregatorProposed).',
    'event AggregatorProposed(address indexed current, address indexed proposed)',
  ],
  [
    'oracle.aggregator_confirmed',
    'parameters',
    'critical',
    'A Chainlink feed proxy switched to a new price aggregator (AggregatorConfirmed).',
    'event AggregatorConfirmed(address indexed previous, address indexed latest)',
  ],

  // ---- vault governance (2026-09-18) --------------------------------------
  // Morpho MetaMorpho v1.0 and v1.1 (src/libraries/EventsLib.sol in morpho-org/metamorpho and
  // morpho-org/metamorpho-v1.1; the governance signatures are identical in both). `Id` is a
  // user-defined value type over bytes32, so the canonical signature uses bytes32. The owner sets
  // the curator / guardian / allocators / fee; the curator submits caps and market removals that
  // the timelock later lets anyone accept (SetCap / SetTimelock / SetGuardian are the acceptances).
  // Category `parameters` on purpose (no new category): vault roles and risk limits are the
  // protocol's parameters, and the category list is enumerated in the web UI and the API docs.
  [
    'vault.curator_set',
    'parameters',
    'critical',
    'The curator of a MetaMorpho-style vault (MetaMorpho, Silo Vaults, Euler Earn, Morpho Vault V2) was changed (SetCurator).',
    'event SetCurator(address indexed newCurator)',
  ],
  [
    'vault.guardian_set',
    'parameters',
    'critical',
    'The guardian of a MetaMorpho-style vault (MetaMorpho, Silo Vaults, Euler Earn) was changed (SetGuardian).',
    'event SetGuardian(address indexed caller, address indexed guardian)',
  ],
  [
    'vault.guardian_submitted',
    'parameters',
    'high',
    'A new guardian was submitted for a MetaMorpho-style vault, pending the timelock (SubmitGuardian).',
    'event SubmitGuardian(address indexed newGuardian)',
  ],
  [
    'vault.allocator_set',
    'parameters',
    'high',
    'An allocator was added to or removed from a MetaMorpho-style vault (MetaMorpho, Silo Vaults, Morpho Vault V2) (SetIsAllocator).',
    'event SetIsAllocator(address indexed allocator, bool isAllocator)',
  ],
  [
    'vault.timelock_submitted',
    'parameters',
    'high',
    'A new timelock was submitted for a MetaMorpho-style vault (SubmitTimelock).',
    'event SubmitTimelock(uint256 newTimelock)',
  ],
  [
    'vault.timelock_set',
    'parameters',
    'high',
    'The timelock of a MetaMorpho-style vault (MetaMorpho, Silo Vaults, Euler Earn) was changed (SetTimelock).',
    'event SetTimelock(address indexed caller, uint256 newTimelock)',
  ],
  [
    'vault.cap_submitted',
    'parameters',
    'high',
    'A supply cap was submitted for a market of a MetaMorpho vault, pending the timelock (SubmitCap).',
    'event SubmitCap(address indexed caller, bytes32 indexed id, uint256 cap)',
  ],
  [
    'vault.cap_set',
    'parameters',
    'high',
    'The supply cap of a market in a MetaMorpho vault was changed (SetCap).',
    'event SetCap(address indexed caller, bytes32 indexed id, uint256 cap)',
  ],
  [
    'vault.market_removal_submitted',
    'parameters',
    'high',
    'A market was submitted for forced removal from a MetaMorpho vault (SubmitMarketRemoval).',
    'event SubmitMarketRemoval(address indexed caller, bytes32 indexed id)',
  ],
  // Four events, four topic0s, one key: a pending change was withdrawn before it took effect.
  // The args tell cap / market removal (has `id`) from timelock / guardian (only `caller`) apart.
  [
    'vault.pending_revoked',
    'parameters',
    'info',
    'A pending MetaMorpho change (cap, timelock, guardian or market removal) was revoked.',
    'event RevokePendingCap(address indexed caller, bytes32 indexed id)',
    'event RevokePendingTimelock(address indexed caller)',
    'event RevokePendingGuardian(address indexed caller)',
    'event RevokePendingMarketRemoval(address indexed caller, bytes32 indexed id)',
  ],
  // Three events, one key (2026-09-22): MetaMorpho's single fee recipient and Vault V2's performance /
  // management fee recipients; the arg name says which.
  [
    'vault.fee_recipient_set',
    'parameters',
    'info',
    'The fee recipient was changed (SetFeeRecipient on MetaMorpho-style vaults and Morpho Blue; SetPerformanceFeeRecipient / SetManagementFeeRecipient on Morpho Vault V2).',
    'event SetFeeRecipient(address indexed newFeeRecipient)',
    'event SetPerformanceFeeRecipient(address indexed newPerformanceFeeRecipient)',
    'event SetManagementFeeRecipient(address indexed newManagementFeeRecipient)',
  ],
  [
    'vault.skim_recipient_set',
    'parameters',
    'info',
    'The skim recipient of a MetaMorpho vault was changed (SetSkimRecipient).',
    'event SetSkimRecipient(address indexed newSkimRecipient)',
  ],
  // Three events, one key (2026-09-22): MetaMorpho SetFee plus Vault V2's SetPerformanceFee /
  // SetManagementFee (all WAD-scaled; the V2 management fee is per second).
  [
    'vault.fee_set',
    'parameters',
    'info',
    'A fee of a MetaMorpho-style vault or Morpho Vault V2 was changed (SetFee, SetPerformanceFee or SetManagementFee; WAD-scaled).',
    'event SetFee(address indexed caller, uint256 newFee)',
    'event SetPerformanceFee(uint256 newPerformanceFee)',
    'event SetManagementFee(uint256 newManagementFee)',
  ],
  [
    'vault.supply_queue_set',
    'parameters',
    'info',
    'The supply queue of a MetaMorpho vault was reordered (SetSupplyQueue).',
    'event SetSupplyQueue(address indexed caller, bytes32[] newSupplyQueue)',
  ],
  [
    'vault.withdraw_queue_set',
    'parameters',
    'info',
    'The withdraw queue of a MetaMorpho vault was reordered (SetWithdrawQueue).',
    'event SetWithdrawQueue(address indexed caller, bytes32[] newWithdrawQueue)',
  ],
  // Morpho Vault V2 (2026-09-22; morpho-org/vault-v2 src/VaultV2.sol, verified source of
  // 0x244f46262d9ad408b746e74abdd010e9002fb7ee). A different design from MetaMorpho: the owner
  // sets the curator, sentinels, name and symbol at once; the curator `submit()`s every other
  // change and anyone executes it after the per-function `timelock(bytes4)` (Submit -> Accept +
  // the specific event); the curator or a sentinel `revoke()`s a pending change and decreases caps
  // at once; allocators move funds and set the liquidity adapter / max rate. Shared signatures
  // reuse the MetaMorpho keys: SetCurator(address) -> `vault.curator_set`, SetIsAllocator(address,
  // bool) -> `vault.allocator_set`, the fee / fee recipient events -> `vault.fee_set` /
  // `vault.fee_recipient_set`. `Accept(bytes4,bytes)` is not watched (the executed function's own
  // event fires in the same transaction); `Constructor` / deposits / allocations are not governance.
  [
    'vault.owner_set',
    'parameters',
    'critical',
    'The owner was changed (SetOwner; Morpho Vault V2 and Morpho Blue share the signature).',
    'event SetOwner(address indexed newOwner)',
  ],
  [
    'vault.sentinel_set',
    'parameters',
    'critical',
    'A sentinel of a Morpho Vault V2 was added or removed (SetIsSentinel); sentinels revoke pending changes and cut caps.',
    'event SetIsSentinel(address indexed account, bool newIsSentinel)',
  ],
  [
    'vault.adapter_registry_set',
    'parameters',
    'critical',
    'The adapter registry of a Morpho Vault V2 was changed (SetAdapterRegistry); it decides which adapters may be added.',
    'event SetAdapterRegistry(address indexed newAdapterRegistry)',
  ],
  [
    'vault.adapter_added',
    'parameters',
    'high',
    'An adapter (a place funds can be allocated to) was added to a Morpho Vault V2 (AddAdapter).',
    'event AddAdapter(address indexed account)',
  ],
  [
    'vault.adapter_removed',
    'parameters',
    'high',
    'An adapter was removed from a Morpho Vault V2 (RemoveAdapter).',
    'event RemoveAdapter(address indexed account)',
  ],
  [
    'vault.timelock_increased',
    'parameters',
    'info',
    'The timelock of one function of a Morpho Vault V2 was increased (IncreaseTimelock).',
    'event IncreaseTimelock(bytes4 indexed selector, uint256 newDuration)',
  ],
  [
    'vault.timelock_decreased',
    'parameters',
    'high',
    'The timelock of one function of a Morpho Vault V2 was decreased (DecreaseTimelock).',
    'event DecreaseTimelock(bytes4 indexed selector, uint256 newDuration)',
  ],
  [
    'vault.action_submitted',
    'parameters',
    'high',
    'The curator of a Morpho Vault V2 submitted a timelocked change (Submit); it can be executed at executableAt.',
    'event Submit(bytes4 indexed selector, bytes data, uint256 executableAt)',
  ],
  [
    'vault.action_revoked',
    'parameters',
    'high',
    'A pending Morpho Vault V2 change was revoked by the curator or a sentinel (Revoke).',
    'event Revoke(address indexed sender, bytes4 indexed selector, bytes data)',
  ],
  [
    'vault.function_abdicated',
    'parameters',
    'high',
    'A function of a Morpho Vault V2 was abdicated (Abdicate): it can never be called again.',
    'event Abdicate(bytes4 indexed selector)',
  ],
  // Two events, one key: the absolute cap (asset units) or the relative cap (WAD share of assets)
  // of an allocation id was raised after the timelock; `newAbsoluteCap` / `newRelativeCap` says which.
  [
    'vault.cap_increased',
    'parameters',
    'high',
    'An allocation cap of a Morpho Vault V2 was increased after the timelock (IncreaseAbsoluteCap or IncreaseRelativeCap).',
    'event IncreaseAbsoluteCap(bytes32 indexed id, bytes idData, uint256 newAbsoluteCap)',
    'event IncreaseRelativeCap(bytes32 indexed id, bytes idData, uint256 newRelativeCap)',
  ],
  [
    'vault.cap_decreased',
    'parameters',
    'high',
    'An allocation cap of a Morpho Vault V2 was decreased at once by the curator or a sentinel (DecreaseAbsoluteCap or DecreaseRelativeCap).',
    'event DecreaseAbsoluteCap(address indexed sender, bytes32 indexed id, bytes idData, uint256 newAbsoluteCap)',
    'event DecreaseRelativeCap(address indexed sender, bytes32 indexed id, bytes idData, uint256 newRelativeCap)',
  ],
  // Four events, one key: the gates decide who may deposit / withdraw / send / receive shares; a
  // hostile gate blocks exits, so critical like Euler's hook config. The arg name says which gate.
  [
    'vault.gate_set',
    'parameters',
    'critical',
    'A gate of a Morpho Vault V2 was changed (SetReceiveSharesGate, SetSendSharesGate, SetReceiveAssetsGate or SetSendAssetsGate).',
    'event SetReceiveSharesGate(address indexed newReceiveSharesGate)',
    'event SetSendSharesGate(address indexed newSendSharesGate)',
    'event SetReceiveAssetsGate(address indexed newReceiveAssetsGate)',
    'event SetSendAssetsGate(address indexed newSendAssetsGate)',
  ],
  [
    'vault.max_rate_set',
    'parameters',
    'info',
    'The maximum interest rate of a Morpho Vault V2 was changed by an allocator (SetMaxRate, WAD per second).',
    'event SetMaxRate(uint256 newMaxRate)',
  ],
  [
    'vault.penalty_set',
    'parameters',
    'info',
    'The force-deallocate penalty of an adapter of a Morpho Vault V2 was changed (SetForceDeallocatePenalty, WAD).',
    'event SetForceDeallocatePenalty(address indexed adapter, uint256 forceDeallocatePenalty)',
  ],
  [
    'vault.liquidity_adapter_set',
    'parameters',
    'info',
    'The liquidity adapter of a Morpho Vault V2 (where deposits go and withdrawals come from) was changed by an allocator (SetLiquidityAdapterAndData).',
    'event SetLiquidityAdapterAndData(address indexed sender, address indexed newLiquidityAdapter, bytes indexed newLiquidityData)',
  ],
  // Two events, one key: the owner renamed the share token.
  [
    'vault.metadata_set',
    'parameters',
    'info',
    'The name or symbol of a Morpho Vault V2 was changed (SetName or SetSymbol).',
    'event SetName(string newName)',
    'event SetSymbol(string newSymbol)',
  ],
  // VaultV2Factory: a new vault; on the factory row, so protocol watchers see new vaults appear.
  [
    'vault.created',
    'parameters',
    'info',
    'A Morpho Vault V2 was deployed by the factory (CreateVaultV2).',
    'event CreateVaultV2(address indexed owner, address indexed asset, bytes32 salt, address indexed newVaultV2)',
  ],
  // Euler v2 EVault governance (euler-xyz/euler-vault-kit src/EVault/modules/Governance.sol; the
  // Gov* events are declared in the module, not in shared/Events.sol). LTVs, fees and discounts
  // are in 1e4 scale, caps in the AmountCap format (mantissa << 6 | exponent, 0 = no cap).
  [
    'vault.governor_admin_set',
    'parameters',
    'critical',
    'The governor of an Euler v2 vault was changed (GovSetGovernorAdmin).',
    'event GovSetGovernorAdmin(address indexed newGovernorAdmin)',
  ],
  [
    'vault.hook_config_set',
    'parameters',
    'critical',
    'The hook target or hooked operations of an Euler v2 vault were changed (GovSetHookConfig).',
    'event GovSetHookConfig(address indexed newHookTarget, uint32 newHookedOps)',
  ],
  [
    'vault.caps_set',
    'parameters',
    'high',
    'The supply or borrow cap of an Euler v2 vault was changed (GovSetCaps).',
    'event GovSetCaps(uint16 newSupplyCap, uint16 newBorrowCap)',
  ],
  [
    'vault.ltv_set',
    'parameters',
    'high',
    'The LTV of a collateral in an Euler v2 vault was changed (GovSetLTV).',
    'event GovSetLTV(address indexed collateral, uint16 borrowLTV, uint16 liquidationLTV, uint16 initialLiquidationLTV, uint48 targetTimestamp, uint32 rampDuration)',
  ],
  [
    'vault.irm_set',
    'parameters',
    'high',
    'The interest rate model of an Euler v2 vault was changed (GovSetInterestRateModel).',
    'event GovSetInterestRateModel(address newInterestRateModel)',
  ],
  // Five events, five topic0s, one key; the describers tell them apart by the arg name.
  [
    'vault.params_set',
    'parameters',
    'info',
    'A secondary parameter of an Euler v2 vault was changed (cool-off time, max liquidation discount, interest fee, fee receiver or config flags).',
    'event GovSetLiquidationCoolOffTime(uint16 newCoolOffTime)',
    'event GovSetMaxLiquidationDiscount(uint16 newDiscount)',
    'event GovSetInterestFee(uint16 newFee)',
    'event GovSetFeeReceiver(address indexed newFeeReceiver)',
    'event GovSetConfigFlags(uint32 newConfigFlags)',
  ],
  // Euler price router (euler-xyz/euler-price-oracle src/EulerRouter.sol). The events are named
  // ConfigSet / ResolvedVaultSet / FallbackOracleSet (not GovSet*); the governor of the router
  // sets which oracle prices a (base, quote) pair, which ERC-4626 vaults are unwrapped to their
  // asset (asset = 0x0 clears the entry), and the fallback oracle for unconfigured pairs.
  [
    'oracle.router_config_set',
    'parameters',
    'critical',
    'An Euler price router changed the oracle of an asset pair (ConfigSet).',
    'event ConfigSet(address indexed asset0, address indexed asset1, address indexed oracle)',
  ],
  [
    'oracle.router_vault_set',
    'parameters',
    'high',
    'An Euler price router changed how an ERC-4626 vault is resolved to its asset (ResolvedVaultSet).',
    'event ResolvedVaultSet(address indexed vault, address indexed asset)',
  ],
  [
    'oracle.router_fallback_set',
    'parameters',
    'high',
    'An Euler price router changed its fallback oracle (FallbackOracleSet).',
    'event FallbackOracleSet(address indexed fallbackOracle)',
  ],

  // ---- pause family beyond OpenZeppelin (2026-09-22, coverage batch 1) --------------------------
  // Same keys as the OZ Paused(address) / Unpaused(address) so the web filter and the phrasing stay
  // one family; the describers branch on the arg shape. Sources: circlefin/stablecoin-evm
  // contracts/v1/Pausable.sol (`Pause()` / `Unpause()`, also CCTP MessageTransmitter / TokenMessenger
  // and Paxos), lidofinance/core PausableUntil.sol (`Paused(uint256 duration)` / `Resumed()`),
  // Layr-Labs/eigenlayer-contracts IPausable.sol (`Paused(address indexed account, uint256
  // newPausedStatus)` / `Unpaused(...)`, a bitmap), ethereum-optimism op-contracts/v1.8.0
  // SuperchainConfig.sol (`Paused(string identifier)` / `Unpaused()`). Toggles that can mean either
  // state (Balancer v3 IVaultEvents `VaultPausedStateChanged(bool)`, Compound Comet
  // `PauseAction(bool x5)`) get their own key. Across `Paused(bool)` was not verifiable from source
  // (HubPool.sol not reachable on 2026-09-22) and is left out.
  [
    'pause.state_changed',
    'pause',
    'high',
    'A pause flag was toggled (Balancer v3 VaultPausedStateChanged or Compound Comet PauseAction); the args say whether it is a pause or an unpause.',
    'event VaultPausedStateChanged(bool paused)',
    'event PauseAction(bool supplyPaused, bool transferPaused, bool withdrawPaused, bool absorbPaused, bool buyPaused)',
  ],

  // ---- lending: Aave V3 PoolAddressesProvider (2026-09-22) -----------------------------------------
  // aave-dao/aave-v3-origin src/contracts/interfaces/IPoolAddressesProvider.sol (identical in
  // aave/aave-v3-core 3.0.2). The provider is the root of trust of a market: Aave-layout proxies
  // (Pool, PoolConfigurator, a/vTokens) store it as their admin, so PoolUpdated /
  // PoolConfiguratorUpdated / AddressSetAsProxy are the upgrade events of those proxies, and
  // PriceOracleUpdated / ACLAdminUpdated swap the oracle and the role admin of everything below.
  // SparkLend, Radiant v2 and Aave V2 (LendingPoolAddressesProvider) share most signatures.
  [
    'lending.pool_updated',
    'upgrade',
    'critical',
    'The Pool implementation of an Aave V3-style market was changed by its addresses provider (PoolUpdated).',
    'event PoolUpdated(address indexed oldAddress, address indexed newAddress)',
  ],
  [
    'lending.pool_configurator_updated',
    'upgrade',
    'critical',
    'The PoolConfigurator implementation of an Aave V3-style market was changed by its addresses provider (PoolConfiguratorUpdated).',
    'event PoolConfiguratorUpdated(address indexed oldAddress, address indexed newAddress)',
  ],
  // Two events, one key: Aave PriceOracleUpdated (provider) and Compound V2 / Venus / Moonwell
  // NewPriceOracle (Comptroller) both swap the price oracle of a whole lending market.
  [
    'lending.price_oracle_set',
    'parameters',
    'critical',
    'The price oracle of a lending market was changed (Aave PriceOracleUpdated or Compound-style NewPriceOracle).',
    'event PriceOracleUpdated(address indexed oldAddress, address indexed newAddress)',
    'event NewPriceOracle(address oldPriceOracle, address newPriceOracle)',
  ],
  [
    'lending.acl_manager_updated',
    'access',
    'critical',
    'The ACLManager (role registry) of an Aave V3-style market was changed (ACLManagerUpdated).',
    'event ACLManagerUpdated(address indexed oldAddress, address indexed newAddress)',
  ],
  [
    'lending.acl_admin_updated',
    'access',
    'critical',
    'The ACL admin (who administers every role) of an Aave V3-style market was changed (ACLAdminUpdated).',
    'event ACLAdminUpdated(address indexed oldAddress, address indexed newAddress)',
  ],
  [
    'lending.price_oracle_sentinel_updated',
    'parameters',
    'high',
    'The price oracle sentinel (L2 sequencer-uptime guard) of an Aave V3-style market was changed (PriceOracleSentinelUpdated).',
    'event PriceOracleSentinelUpdated(address indexed oldAddress, address indexed newAddress)',
  ],
  [
    'lending.pool_data_provider_updated',
    'parameters',
    'high',
    'The pool data provider of an Aave V3-style market was changed (PoolDataProviderUpdated).',
    'event PoolDataProviderUpdated(address indexed oldAddress, address indexed newAddress)',
  ],
  [
    'lending.provider_proxy_created',
    'upgrade',
    'critical',
    'An Aave V3-style addresses provider deployed a new proxy for an id (ProxyCreated).',
    'event ProxyCreated(bytes32 indexed id, address indexed proxyAddress, address indexed implementationAddress)',
  ],
  [
    'lending.provider_address_set',
    'parameters',
    'critical',
    'An Aave V3-style addresses provider re-pointed an id at a new address (AddressSet).',
    'event AddressSet(bytes32 indexed id, address indexed oldAddress, address indexed newAddress)',
  ],
  [
    'lending.provider_proxy_upgraded',
    'upgrade',
    'critical',
    'An Aave V3-style addresses provider upgraded the proxy behind an id (AddressSetAsProxy).',
    'event AddressSetAsProxy(bytes32 indexed id, address indexed proxyAddress, address oldImplementationAddress, address indexed newImplementationAddress)',
  ],
  [
    'lending.market_id_set',
    'parameters',
    'info',
    'The market id of an Aave V3-style addresses provider was changed (MarketIdSet).',
    'event MarketIdSet(string indexed oldMarketId, string indexed newMarketId)',
  ],

  // ---- oracle: AaveOracle (2026-09-22) -------------------------------------------------------------
  // aave-dao/aave-v3-origin src/contracts/interfaces/IAaveOracle.sol. One level above Chainlink's
  // AggregatorConfirmed: the market's own price source per asset, and the fallback for assets
  // whose source fails.
  [
    'oracle.asset_source_updated',
    'parameters',
    'critical',
    'An Aave-style oracle changed the price source of an asset (AssetSourceUpdated).',
    'event AssetSourceUpdated(address indexed asset, address indexed source)',
  ],
  [
    'oracle.fallback_oracle_updated',
    'parameters',
    'critical',
    'An Aave-style oracle changed its fallback oracle (FallbackOracleUpdated).',
    'event FallbackOracleUpdated(address indexed fallbackOracle)',
  ],
  // 2026-09-29: the third event of IAaveOracle.sol (aave-dao/aave-v3-origin main). AaveOracle only
  // emits it from its constructor (`_setBaseCurrency`), so a live log means a new oracle was
  // deployed, not that an existing one changed; info, and it names the oracle's quote currency
  // (the zero address + 1e8 = USD on every Aave V3 market we seed).
  [
    'oracle.base_currency_set',
    'parameters',
    'info',
    'An Aave-style oracle set its base currency and unit at deployment (BaseCurrencySet).',
    'event BaseCurrencySet(address indexed baseCurrency, uint256 baseCurrencyUnit)',
  ],

  // ---- lending: Aave V3 PoolConfigurator (2026-09-22) ----------------------------------------------
  // aave/aave-v3-core 3.0.2 and aave-dao/aave-v3-origin v3.3.0 IPoolConfigurator.sol, both read
  // today. 3.3 dropped ReserveStableRateBorrowing, StableDebtTokenUpgraded, EModeAssetCategoryChanged
  // and BridgeProtocolFeeUpdated and added PendingLtvChanged, LiquidationGracePeriod*, the
  // per-asset e-mode flags and ReserveInterestRateDataChanged; both generations are still live
  // (Aave V3 markets, SparkLend, Radiant v2), so both sets are watched. ltv / liquidationThreshold /
  // liquidationBonus are in bps (8000 = 80%), caps in whole tokens, the reserve factor in bps.
  [
    'lending.reserve_paused',
    'pause',
    'critical',
    'A reserve of an Aave V3-style market was paused or unpaused (ReservePaused): no supply, borrow, repay, withdraw or liquidation while paused.',
    'event ReservePaused(address indexed asset, bool paused)',
  ],
  [
    'lending.reserve_frozen',
    'parameters',
    'critical',
    'A reserve of an Aave V3-style market was frozen or unfrozen (ReserveFrozen): no new supply or borrow while frozen.',
    'event ReserveFrozen(address indexed asset, bool frozen)',
  ],
  [
    'lending.reserve_active',
    'parameters',
    'critical',
    'A reserve of an Aave V3-style market was activated or deactivated (ReserveActive).',
    'event ReserveActive(address indexed asset, bool active)',
  ],
  [
    'lending.reserve_dropped',
    'parameters',
    'critical',
    'A reserve was removed from an Aave V3-style market (ReserveDropped).',
    'event ReserveDropped(address indexed asset)',
  ],
  [
    'lending.collateral_config_changed',
    'parameters',
    'high',
    'The LTV, liquidation threshold or liquidation bonus of a reserve in an Aave V3-style market was changed (CollateralConfigurationChanged, bps).',
    'event CollateralConfigurationChanged(address indexed asset, uint256 ltv, uint256 liquidationThreshold, uint256 liquidationBonus)',
  ],
  [
    'lending.pending_ltv_changed',
    'parameters',
    'high',
    'A pending LTV was recorded for a frozen reserve of an Aave V3.3+ market (PendingLtvChanged); it applies when the reserve is unfrozen.',
    'event PendingLtvChanged(address indexed asset, uint256 ltv)',
  ],
  // Two events, one key: Aave ReserveInterestRateStrategyChanged and Compound-style cToken
  // NewMarketInterestRateModel both swap the rate model of one market.
  [
    'lending.interest_rate_model_set',
    'parameters',
    'high',
    'The interest rate model of a lending market was changed (Aave ReserveInterestRateStrategyChanged or Compound-style NewMarketInterestRateModel).',
    'event ReserveInterestRateStrategyChanged(address indexed asset, address oldStrategy, address newStrategy)',
    'event NewMarketInterestRateModel(address oldInterestRateModel, address newInterestRateModel)',
  ],
  [
    'lending.interest_rate_data_changed',
    'parameters',
    'high',
    'The interest rate parameters of a reserve in an Aave V3.3+ market were changed (ReserveInterestRateDataChanged).',
    'event ReserveInterestRateDataChanged(address indexed asset, address indexed strategy, bytes data)',
  ],
  [
    'lending.liquidation_protocol_fee_changed',
    'parameters',
    'high',
    'The liquidation protocol fee of a reserve in an Aave V3-style market was changed (LiquidationProtocolFeeChanged, bps).',
    'event LiquidationProtocolFeeChanged(address indexed asset, uint256 oldFee, uint256 newFee)',
  ],
  [
    'lending.emode_category_added',
    'parameters',
    'high',
    'An e-mode category was added to or reconfigured in an Aave V3-style market (EModeCategoryAdded, bps).',
    'event EModeCategoryAdded(uint8 indexed categoryId, uint256 ltv, uint256 liquidationThreshold, uint256 liquidationBonus, address oracle, string label)',
  ],
  // Three events, one key: the 3.0-3.2 single-category assignment and the 3.2+ per-asset
  // collateral / borrowable flags; the args tell them apart.
  [
    'lending.emode_asset_changed',
    'parameters',
    'high',
    'The e-mode membership of an asset in an Aave V3-style market was changed (EModeAssetCategoryChanged, AssetCollateralInEModeChanged or AssetBorrowableInEModeChanged).',
    'event EModeAssetCategoryChanged(address indexed asset, uint8 oldCategoryId, uint8 newCategoryId)',
    'event AssetCollateralInEModeChanged(address indexed asset, uint8 categoryId, bool collateral)',
    'event AssetBorrowableInEModeChanged(address indexed asset, uint8 categoryId, bool borrowable)',
  ],
  [
    'lending.debt_ceiling_changed',
    'parameters',
    'high',
    'The isolation-mode debt ceiling of a reserve in an Aave V3-style market was changed (DebtCeilingChanged, 2 decimals).',
    'event DebtCeilingChanged(address indexed asset, uint256 oldDebtCeiling, uint256 newDebtCeiling)',
  ],
  [
    'lending.siloed_borrowing_changed',
    'parameters',
    'high',
    'Siloed borrowing was enabled or disabled for a reserve of an Aave V3-style market (SiloedBorrowingChanged).',
    'event SiloedBorrowingChanged(address indexed asset, bool oldState, bool newState)',
  ],
  [
    'lending.borrowable_in_isolation_changed',
    'parameters',
    'high',
    'A reserve of an Aave V3-style market became borrowable or non-borrowable in isolation mode (BorrowableInIsolationChanged).',
    'event BorrowableInIsolationChanged(address asset, bool borrowable)',
  ],
  // Two events, one key (2026-09-28): Aave SupplyCapChanged (whole tokens) and Venus NewSupplyCap
  // (base units; SetterFacet.sol, the supply-side twin of NewBorrowCap below).
  [
    'lending.supply_cap_changed',
    'parameters',
    'high',
    'The supply cap of a lending market was changed (Aave SupplyCapChanged in whole tokens or Venus NewSupplyCap in base units; 0 = no cap).',
    'event SupplyCapChanged(address indexed asset, uint256 oldSupplyCap, uint256 newSupplyCap)',
    'event NewSupplyCap(address indexed vToken, uint256 newSupplyCap)',
  ],
  // Two events, one key: Aave BorrowCapChanged (whole tokens) and Compound-style NewBorrowCap
  // (base units) both cap the borrows of one market.
  [
    'lending.borrow_cap_changed',
    'parameters',
    'high',
    'The borrow cap of a lending market was changed (Aave BorrowCapChanged or Compound-style NewBorrowCap; 0 = no cap).',
    'event BorrowCapChanged(address indexed asset, uint256 oldBorrowCap, uint256 newBorrowCap)',
    'event NewBorrowCap(address indexed cToken, uint256 newBorrowCap)',
  ],
  [
    'lending.reserve_flash_loaning',
    'parameters',
    'high',
    'Flash loans were enabled or disabled for a reserve of an Aave V3-style market (ReserveFlashLoaning).',
    'event ReserveFlashLoaning(address indexed asset, bool enabled)',
  ],
  [
    'lending.reserve_borrowing',
    'parameters',
    'high',
    'Borrowing was enabled or disabled for a reserve of an Aave V3-style market (ReserveBorrowing).',
    'event ReserveBorrowing(address indexed asset, bool enabled)',
  ],
  [
    'lending.reserve_stable_borrowing',
    'parameters',
    'high',
    'Stable-rate borrowing was enabled or disabled for a reserve of an Aave V3.0-3.2 market (ReserveStableRateBorrowing).',
    'event ReserveStableRateBorrowing(address indexed asset, bool enabled)',
  ],
  [
    'lending.unbacked_mint_cap_changed',
    'parameters',
    'high',
    'The unbacked mint cap (bridge minting) of a reserve in an Aave V3-style market was changed (UnbackedMintCapChanged).',
    'event UnbackedMintCapChanged(address indexed asset, uint256 oldUnbackedMintCap, uint256 newUnbackedMintCap)',
  ],
  // Two events, one key: the grace period is set to a timestamp or disabled at once.
  [
    'lending.liquidation_grace_period_changed',
    'parameters',
    'high',
    'The liquidation grace period of a reserve in an Aave V3.1+ market was set or disabled (LiquidationGracePeriodChanged or LiquidationGracePeriodDisabled).',
    'event LiquidationGracePeriodChanged(address indexed asset, uint40 gracePeriodUntil)',
    'event LiquidationGracePeriodDisabled(address indexed asset)',
  ],
  [
    'lending.bridge_protocol_fee_updated',
    'parameters',
    'high',
    'The bridge protocol fee of an Aave V3.0-3.2 market was changed (BridgeProtocolFeeUpdated, bps).',
    'event BridgeProtocolFeeUpdated(uint256 oldBridgeProtocolFee, uint256 newBridgeProtocolFee)',
  ],
  // Two events, one key: the total flash loan premium and the share of it that goes to the protocol.
  [
    'lending.flashloan_premium_updated',
    'parameters',
    'high',
    'A flash loan premium of an Aave V3-style market was changed (FlashloanPremiumTotalUpdated or FlashloanPremiumToProtocolUpdated, bps).',
    'event FlashloanPremiumTotalUpdated(uint128 oldFlashloanPremiumTotal, uint128 newFlashloanPremiumTotal)',
    'event FlashloanPremiumToProtocolUpdated(uint128 oldFlashloanPremiumToProtocol, uint128 newFlashloanPremiumToProtocol)',
  ],
  [
    'lending.reserve_initialized',
    'parameters',
    'high',
    'A new reserve was listed in an Aave V3-style market (ReserveInitialized).',
    'event ReserveInitialized(address indexed asset, address indexed aToken, address stableDebtToken, address variableDebtToken, address interestRateStrategyAddress)',
  ],
  // The reserve token proxies also emit the plain ERC-1967 Upgraded (covered, but on an unnamed
  // address); these carry the asset and are emitted by the configurator row.
  [
    'lending.atoken_upgraded',
    'upgrade',
    'high',
    'The aToken implementation of a reserve in an Aave V3-style market was upgraded (ATokenUpgraded).',
    'event ATokenUpgraded(address indexed asset, address indexed proxy, address indexed implementation)',
  ],
  [
    'lending.stable_debt_token_upgraded',
    'upgrade',
    'high',
    'The stable debt token implementation of a reserve in an Aave V3.0-3.2 market was upgraded (StableDebtTokenUpgraded).',
    'event StableDebtTokenUpgraded(address indexed asset, address indexed proxy, address indexed implementation)',
  ],
  [
    'lending.variable_debt_token_upgraded',
    'upgrade',
    'high',
    'The variable debt token implementation of a reserve in an Aave V3-style market was upgraded (VariableDebtTokenUpgraded).',
    'event VariableDebtTokenUpgraded(address indexed asset, address indexed proxy, address indexed implementation)',
  ],
  // Two events, one key: Aave ReserveFactorChanged (bps) and Compound-style cToken NewReserveFactor (1e18 mantissa).
  [
    'lending.reserve_factor_changed',
    'parameters',
    'info',
    'The reserve factor of a lending market was changed (Aave ReserveFactorChanged in bps or Compound-style NewReserveFactor as a 1e18 mantissa).',
    'event ReserveFactorChanged(address indexed asset, uint256 oldReserveFactor, uint256 newReserveFactor)',
    'event NewReserveFactor(uint256 oldReserveFactorMantissa, uint256 newReserveFactorMantissa)',
  ],

  // ---- Compound V2-style admin and Comptroller (2026-09-22) ---------------------------------------
  // compound-finance/compound-protocol Unitroller.sol, CTokenInterfaces.sol and Comptroller.sol
  // (Venus, Moonwell, Benqi, Sonne, Strike and every fork share them). `CToken` / `PriceOracle` /
  // `ComptrollerInterface` / `InterestRateModel` parameters are addresses in the ABI. The two-param
  // NewAdmin / NewPendingAdmin are different topic0s from the one-param Timelock events
  // (`timelock.new_admin` / `timelock.new_pending_admin`), so they get their own keys; the
  // one-param versions are also Curve's, the two-param ones are the admin() handover of every
  // Unitroller / cToken / fork proxy. NewImplementation(address,address) is already
  // `proxy.new_implementation`.
  [
    'ownable.new_admin',
    'ownership',
    'critical',
    'The admin of a Compound-style contract (Unitroller, cToken, Comptroller or fork) was changed (NewAdmin).',
    'event NewAdmin(address oldAdmin, address newAdmin)',
  ],
  [
    'ownable.new_pending_admin',
    'ownership',
    'high',
    'A pending admin was set on a Compound-style contract, waiting to be accepted (NewPendingAdmin).',
    'event NewPendingAdmin(address oldPendingAdmin, address newPendingAdmin)',
  ],
  // Two events, one key (2026-09-28): the Compound three-param form and the Venus Diamond form keyed
  // by (poolId, vToken), both indexed (SetterFacet.sol; poolId 0 is the core pool).
  [
    'lending.collateral_factor_set',
    'parameters',
    'high',
    'The collateral factor of a Compound-style or Venus market was changed (NewCollateralFactor, 1e18 mantissa).',
    'event NewCollateralFactor(address cToken, uint256 oldCollateralFactorMantissa, uint256 newCollateralFactorMantissa)',
    'event NewCollateralFactor(uint96 indexed poolId, address indexed vToken, uint256 oldCollateralFactorMantissa, uint256 newCollateralFactorMantissa)',
  ],
  [
    'lending.close_factor_set',
    'parameters',
    'high',
    'The close factor (share of a borrow one liquidation may repay) of a Compound-style Comptroller was changed (NewCloseFactor, 1e18 mantissa).',
    'event NewCloseFactor(uint256 oldCloseFactorMantissa, uint256 newCloseFactorMantissa)',
  ],
  // Two events, one key (2026-09-28): Compound's Comptroller-wide incentive and Venus's per-market one
  // keyed by (poolId, vToken).
  [
    'lending.liquidation_incentive_set',
    'parameters',
    'high',
    'The liquidation incentive of a Compound-style Comptroller or of one Venus market was changed (NewLiquidationIncentive, 1e18 mantissa).',
    'event NewLiquidationIncentive(uint256 oldLiquidationIncentiveMantissa, uint256 newLiquidationIncentiveMantissa)',
    'event NewLiquidationIncentive(uint96 indexed poolId, address indexed vToken, uint256 oldLiquidationIncentiveMantissa, uint256 newLiquidationIncentiveMantissa)',
  ],
  [
    'lending.pause_guardian_set',
    'access',
    'critical',
    'The pause guardian of a Compound-style Comptroller was changed (NewPauseGuardian).',
    'event NewPauseGuardian(address oldPauseGuardian, address newPauseGuardian)',
  ],
  [
    'lending.borrow_cap_guardian_set',
    'access',
    'high',
    'The borrow cap guardian of a Compound-style Comptroller was changed (NewBorrowCapGuardian).',
    'event NewBorrowCapGuardian(address oldBorrowCapGuardian, address newBorrowCapGuardian)',
  ],
  // Three signatures, one key: a global Compound action (mint / borrow / transfer / seize), one
  // market's, or (2026-09-28) Venus's ActionPausedMarket with a numeric Action (0 MINT, 1 REDEEM,
  // 2 BORROW, 3 REPAY, 4 SEIZE, 5 LIQUIDATE, 6 TRANSFER, 7 ENTER_MARKET, 8 EXIT_MARKET).
  [
    'lending.action_paused',
    'pause',
    'high',
    'An action of a Compound-style or Venus Comptroller was paused or unpaused, globally or for one market (ActionPaused or ActionPausedMarket).',
    'event ActionPaused(string action, bool pauseState)',
    'event ActionPaused(address cToken, string action, bool pauseState)',
    'event ActionPausedMarket(address indexed vToken, uint8 indexed action, bool pauseState)',
  ],
  // Two layouts, one topic0: Compound emits the market in the data, Venus (MarketFacet.sol) indexes it.
  [
    'lending.market_listed',
    'parameters',
    'info',
    'A market was listed on a Compound-style or Venus Comptroller (MarketListed).',
    'event MarketListed(address cToken)',
    'event MarketListed(address indexed vToken)',
  ],
  [
    'lending.comptroller_set',
    'parameters',
    'critical',
    'The Comptroller (risk engine) of a Compound-style market was changed (NewComptroller).',
    'event NewComptroller(address oldComptroller, address newComptroller)',
  ],

  // ---- Venus core-pool Comptroller (Diamond) and ResilientOracle (2026-09-28) ---------------------
  // VenusProtocol/venus-protocol develop: contracts/Comptroller/Diamond/facets/SetterFacet.sol,
  // MarketFacet.sol, FacetBase.sol and ComptrollerInterface.sol (enum Action); VenusProtocol/oracle
  // develop: contracts/ResilientOracle.sol (enum OracleRole: 0 MAIN, 1 PIVOT, 2 FALLBACK). Read after
  // VIP-663 executed on BNB (tx 0x0592453d…a426, block 124462424): its receipt carried nine control
  // logs the Compound-shaped block above did not decode. Venus forks the Compound V2 setters with its
  // own layouts (see the shared keys above: NewSupplyCap, the (poolId, vToken) NewCollateralFactor /
  // NewLiquidationIncentive, ActionPausedMarket, the indexed MarketListed); NewCloseFactor,
  // NewPauseGuardian, NewPriceOracle and NewBorrowCap hash the same as Compound's and are not repeated.
  // `VToken` / `ResilientOracleInterface` / `IDeviationBoundedOracle` parameters are addresses, the
  // `Action` enum is uint8. Not watched: XVS / VAI / Prime reward wiring (NewXVSToken, NewXVSVToken,
  // NewPrimeToken, NewVAIController, NewVAIMintRate, NewVenusVAIVaultRate, NewVAIVaultInfo), the
  // treasury share (NewTreasuryAddress, NewTreasuryPercent), the flash-loan whitelist and the e-mode
  // pool bookkeeping (PoolCreated, PoolLabelUpdated, PoolActiveStatusUpdated, PoolFallbackStatusUpdated,
  // PoolMarketInitialized, PoolMarketRemoved, PoolSelected): accounting and grouping, not control.
  [
    'lending.protocol_paused',
    'pause',
    'critical',
    'A whole Venus Comptroller was paused or unpaused (ActionProtocolPaused): every market action is blocked while paused.',
    'event ActionProtocolPaused(bool state)',
  ],
  [
    'lending.flash_loan_paused',
    'pause',
    'high',
    'Flash loans on a Venus Comptroller were paused or unpaused (FlashLoanPauseChanged).',
    'event FlashLoanPauseChanged(bool oldPaused, bool newPaused)',
  ],
  [
    'lending.liquidation_threshold_set',
    'parameters',
    'high',
    'The liquidation threshold of a Venus market was changed (NewLiquidationThreshold, 1e18 mantissa, per e-mode pool; poolId 0 is the core pool).',
    'event NewLiquidationThreshold(uint96 indexed poolId, address indexed vToken, uint256 oldLiquidationThresholdMantissa, uint256 newLiquidationThresholdMantissa)',
  ],
  [
    'lending.borrow_allowed_changed',
    'parameters',
    'high',
    'Borrowing of a Venus market was enabled or disabled inside an e-mode pool (BorrowAllowedUpdated).',
    'event BorrowAllowedUpdated(uint96 indexed poolId, address indexed market, bool oldStatus, bool newStatus)',
  ],
  [
    'lending.forced_liquidation_set',
    'parameters',
    'high',
    'Forced liquidation (positions liquidatable regardless of health) was enabled or disabled for a Venus market (IsForcedLiquidationEnabledUpdated).',
    'event IsForcedLiquidationEnabledUpdated(address indexed vToken, bool enable)',
  ],
  [
    'lending.market_unlisted',
    'parameters',
    'high',
    'A market was unlisted from a Venus Comptroller (MarketUnlisted).',
    'event MarketUnlisted(address indexed vToken)',
  ],
  [
    'lending.access_control_set',
    'access',
    'critical',
    'The AccessControlManager of a Venus Comptroller (who may call every guarded setter) was changed (NewAccessControl).',
    'event NewAccessControl(address oldAccessControlAddress, address newAccessControlAddress)',
  ],
  [
    'lending.comptroller_lens_set',
    'upgrade',
    'critical',
    'The ComptrollerLens (the contract that computes account liquidity and seize amounts for a Venus Comptroller) was changed (NewComptrollerLens).',
    'event NewComptrollerLens(address oldComptrollerLens, address newComptrollerLens)',
  ],
  [
    'lending.treasury_guardian_set',
    'access',
    'high',
    'The treasury guardian of a Venus Comptroller was changed (NewTreasuryGuardian).',
    'event NewTreasuryGuardian(address oldTreasuryGuardian, address newTreasuryGuardian)',
  ],
  [
    'lending.liquidator_set',
    'access',
    'high',
    'The Liquidator contract of a Venus Comptroller (the only caller allowed to liquidate while set) was changed (NewLiquidatorContract).',
    'event NewLiquidatorContract(address oldLiquidatorContract, address newLiquidatorContract)',
  ],
  [
    'lending.deviation_oracle_set',
    'parameters',
    'critical',
    'The deviation-bounded oracle of a Venus Comptroller was changed (NewDeviationBoundedOracle).',
    'event NewDeviationBoundedOracle(address oldDeviationBoundedOracle, address newDeviationBoundedOracle)',
  ],
  [
    'oracle.token_config_set',
    'parameters',
    'critical',
    'A Venus ResilientOracle set the main / pivot / fallback oracles of an asset (TokenConfigAdded; the zero address means no oracle in that role).',
    'event TokenConfigAdded(address indexed asset, address indexed mainOracle, address indexed pivotOracle, address fallbackOracle)',
  ],
  [
    'oracle.role_oracle_set',
    'parameters',
    'critical',
    'A Venus ResilientOracle changed the oracle in one role of an asset (OracleSet; role 0 main, 1 pivot, 2 fallback).',
    'event OracleSet(address indexed asset, address indexed oracle, uint256 indexed role)',
  ],
  [
    'oracle.role_oracle_enabled',
    'parameters',
    'high',
    'A Venus ResilientOracle enabled or disabled the oracle in one role of an asset (OracleEnabled; role 0 main, 1 pivot, 2 fallback).',
    'event OracleEnabled(address indexed asset, uint256 indexed role, bool indexed enable)',
  ],
  [
    'oracle.caching_set',
    'parameters',
    'info',
    'A Venus ResilientOracle enabled or disabled price caching for an asset (CachedEnabled).',
    'event CachedEnabled(address indexed asset, bool indexed enabled)',
  ],

  // ---- Euler v2 GenericFactory and ProtocolConfig (2026-09-22) ----------------------------------
  // euler-xyz/euler-vault-kit src/GenericFactory/GenericFactory.sol and
  // src/ProtocolConfig/ProtocolConfig.sol. The factory is the beacon of every upgradeable EVault:
  // one SetImplementation re-points all of them and no proxy emits Upgraded. `SetAdmin(address)`
  // is also Morpho PublicAllocator's signature (same topic0), so the phrasing stays generic.
  [
    'beacon.implementation_set',
    'upgrade',
    'critical',
    'A beacon-style factory changed the implementation of every upgradeable proxy it created (SetImplementation; Euler GenericFactory).',
    'event SetImplementation(address indexed newImplementation)',
  ],
  [
    'beacon.upgrade_admin_set',
    'upgrade',
    'critical',
    'The upgrade admin of a beacon-style factory was changed (SetUpgradeAdmin; Euler GenericFactory).',
    'event SetUpgradeAdmin(address indexed newUpgradeAdmin)',
  ],
  [
    'ownable.admin_set',
    'ownership',
    'critical',
    'The admin was changed (SetAdmin; Euler ProtocolConfig, Morpho PublicAllocator).',
    'event SetAdmin(address indexed newAdmin)',
  ],
  [
    'protocol.fee_receiver_set',
    'parameters',
    'info',
    'The protocol fee receiver of Euler v2 was changed (SetFeeReceiver).',
    'event SetFeeReceiver(address indexed newFeeReceiver)',
  ],
  // Four events, one key: the protocol-wide fee share and interest fee range, and their per-vault overrides.
  [
    'protocol.fee_config_set',
    'parameters',
    'info',
    'A protocol fee setting of Euler v2 was changed (SetProtocolFeeShare, SetFeeConfigSetting, SetInterestFeeRange or SetVaultInterestFeeRange; 1e4 scale).',
    'event SetProtocolFeeShare(uint16 protocolFeeShare, uint16 newProtocolFeeShare)',
    'event SetFeeConfigSetting(address indexed vault, bool exists, address indexed feeReceiver, uint16 protocolFeeShare)',
    'event SetInterestFeeRange(uint16 newMinInterestFee, uint16 newMaxInterestFee)',
    'event SetVaultInterestFeeRange(address indexed vault, bool exists, uint16 minInterestFee, uint16 maxInterestFee)',
  ],

  // ---- coverage batch 2 (2026-09-23): Lido / Aragon, rollup roots of trust ------------------
  // Sources read on the day: aragon/aragonOS master `kernel/IKernel.sol` + `acl/ACL.sol`, lidofinance/core
  // master `0.4.24/utils/Pausable.sol`, `0.4.24/Lido.sol`, `0.8.25/sr/ISRBase.sol` + `SRTypes.sol` (LidoLocator
  // is immutable and emits nothing), ethereum-optimism op-contracts/v1.8.0 `SystemConfig.sol`,
  // `SuperchainConfig.sol`, `DisputeGameFactory.sol`, `OptimismPortal2.sol`, `dispute/lib/LibUDT.sol`
  // (GameType = uint32, Timestamp = uint64), OffchainLabs nitro-contracts v3.1.0 `IRollupAdmin.sol`,
  // `IBridge.sol`, `ISequencerInbox.sol` (+ v2.1.0 `IRollupAdmin.sol` for the pre-BoLD OwnerFunctionCalled),
  // OffchainLabs upgrade-executor `UpgradeExecutor.sol`.
  //
  // Aragon Kernel / ACL: every Lido app (stETH, Voting, Agent, NodeOperatorsRegistry...) is an
  // AppProxyUpgradeable whose implementation lives in the Kernel's app mapping, so SetApp is the stETH
  // upgrade event and the ERC-1967 slot diff never sees it. `namespace` is keccak256("base") for
  // implementations, `appId` the ENS namehash of the app.
  [
    'aragon.app_set',
    'upgrade',
    'critical',
    'An Aragon Kernel app mapping was changed (SetApp): the implementation behind every AppProxyUpgradeable of that appId (e.g. Lido stETH) now points elsewhere.',
    'event SetApp(bytes32 indexed namespace, bytes32 indexed appId, address app)',
  ],
  [
    'aragon.permission_set',
    'access',
    'high',
    'An Aragon ACL permission was granted or revoked (SetPermission): an entity can or can no longer call a role-protected function of an app.',
    'event SetPermission(address indexed entity, address indexed app, bytes32 indexed role, bool allowed)',
  ],
  [
    'aragon.permission_params_set',
    'access',
    'high',
    'The parameters of an Aragon ACL permission were changed (SetPermissionParams).',
    'event SetPermissionParams(address indexed entity, address indexed app, bytes32 indexed role, bytes32 paramsHash)',
  ],
  [
    'aragon.permission_manager_changed',
    'access',
    'critical',
    'The manager of an Aragon ACL role was changed (ChangePermissionManager): the new manager can grant that role to anyone.',
    'event ChangePermissionManager(address indexed app, bytes32 indexed role, address indexed manager)',
  ],
  // Lido core (Lido.sol 0.4.24 + Pausable.sol): Stopped() is the whole-protocol stop; Resumed() is
  // already registered under pause.unpaused (same signature as the PausableUntil dialect).
  [
    'staking.stopped',
    'pause',
    'critical',
    'Lido was stopped (Stopped): submits, transfers and every state-changing call of stETH halt until Resumed.',
    'event Stopped()',
  ],
  [
    'staking.staking_paused',
    'pause',
    'high',
    'Lido staking was paused (StakingPaused): new ETH deposits are rejected; the token keeps working.',
    'event StakingPaused()',
  ],
  [
    'staking.staking_resumed',
    'pause',
    'info',
    'Lido staking was resumed (StakingResumed).',
    'event StakingResumed()',
  ],
  [
    'staking.staking_limit_set',
    'parameters',
    'info',
    'The Lido staking rate limit was changed (StakingLimitSet; max limit and per-block increase in wei).',
    'event StakingLimitSet(uint256 maxStakeLimit, uint256 stakeLimitIncreasePerBlock)',
  ],
  [
    'staking.staking_limit_removed',
    'parameters',
    'info',
    'The Lido staking rate limit was removed (StakingLimitRemoved).',
    'event StakingLimitRemoved()',
  ],
  [
    'staking.locator_set',
    'parameters',
    'critical',
    'The LidoLocator of stETH was changed (LidoLocatorSet): the locator resolves every Lido module (oracle, router, withdrawal queue, treasury...).',
    'event LidoLocatorSet(address lidoLocator)',
  ],
  [
    'staking.max_external_ratio_set',
    'parameters',
    'info',
    'The maximum share of externally minted stETH was changed (MaxExternalRatioBPSet; basis points).',
    'event MaxExternalRatioBPSet(uint256 maxExternalRatioBP)',
  ],
  // StakingRouter (ISRBase.sol): status 0 = Active, 1 = DepositsPaused, 2 = Stopped.
  [
    'staking.module_status_set',
    'pause',
    'high',
    'The status of a Lido staking module was changed (StakingModuleStatusSet: 0 active, 1 deposits paused, 2 stopped).',
    'event StakingModuleStatusSet(uint256 indexed stakingModuleId, uint8 status, address setBy)',
  ],
  [
    'staking.module_added',
    'parameters',
    'info',
    'A staking module was added to the Lido StakingRouter (StakingModuleAdded).',
    'event StakingModuleAdded(uint256 indexed stakingModuleId, address stakingModule, string name, address createdBy)',
  ],
  // OP Stack L1 (op-contracts/v1.8.0). SystemConfig.UpdateType: 0 BATCHER, 1 FEE_SCALARS, 2 GAS_LIMIT,
  // 3 UNSAFE_BLOCK_SIGNER, 4 EIP_1559_PARAMS; SuperchainConfig.UpdateType: 0 GUARDIAN. Two signatures,
  // one key (the describers branch on the presence of `version`).
  [
    'rollup.config_updated',
    'parameters',
    'critical',
    'An OP Stack L1 configuration value was changed (SystemConfig ConfigUpdate: batcher, fee scalars, gas limit, unsafe block signer, EIP-1559 params; SuperchainConfig ConfigUpdate: guardian).',
    'event ConfigUpdate(uint256 indexed version, uint8 indexed updateType, bytes data)',
    'event ConfigUpdate(uint8 indexed updateType, bytes data)',
  ],
  [
    'rollup.game_implementation_set',
    'upgrade',
    'critical',
    'The implementation of an OP Stack dispute game type was changed (DisputeGameFactory ImplementationSet): the fault-proof program that guards withdrawals.',
    'event ImplementationSet(address indexed impl, uint32 indexed gameType)',
  ],
  [
    'rollup.init_bond_updated',
    'parameters',
    'high',
    'The bond required to open an OP Stack dispute game was changed (DisputeGameFactory InitBondUpdated; wei).',
    'event InitBondUpdated(uint32 indexed gameType, uint256 indexed newBond)',
  ],
  [
    'rollup.respected_game_type_set',
    'parameters',
    'critical',
    'The dispute game type the OptimismPortal accepts for withdrawals was changed (RespectedGameTypeSet); games created before updatedAt no longer count.',
    'event RespectedGameTypeSet(uint32 indexed newGameType, uint64 indexed updatedAt)',
  ],
  [
    'rollup.dispute_game_blacklisted',
    'parameters',
    'high',
    'The guardian blacklisted a dispute game on the OptimismPortal (DisputeGameBlacklisted): withdrawals proven against it are void.',
    'event DisputeGameBlacklisted(address indexed disputeGame)',
  ],
  // Arbitrum Nitro L1 (nitro-contracts v3.1.0 unless noted). OwnerFunctionCalled(id) is emitted by the
  // pre-BoLD RollupAdminLogic (v2.1.0) and still by the SequencerInbox; the id is the admin function index.
  [
    'rollup.owner_function_called',
    'parameters',
    'high',
    'An Arbitrum owner-only admin function was called (OwnerFunctionCalled on the SequencerInbox or a pre-BoLD Rollup; the id indexes the admin function).',
    'event OwnerFunctionCalled(uint256 indexed id)',
  ],
  // Bridge (IBridge.sol): inbox / outbox toggles decide which contracts can enqueue messages and execute withdrawals.
  [
    'rollup.inbox_toggled',
    'parameters',
    'critical',
    'A delayed inbox was enabled or disabled on the Arbitrum Bridge (InboxToggle).',
    'event InboxToggle(address indexed inbox, bool enabled)',
  ],
  [
    'rollup.outbox_toggled',
    'parameters',
    'critical',
    'An outbox was enabled or disabled on the Arbitrum Bridge (OutboxToggle): an enabled outbox can execute L2-to-L1 withdrawals.',
    'event OutboxToggle(address indexed outbox, bool enabled)',
  ],
  // Bridge SequencerInboxUpdated and RollupAdmin SequencerInboxSet: two signatures, one key.
  [
    'rollup.sequencer_inbox_set',
    'parameters',
    'critical',
    'The sequencer inbox of an Arbitrum chain was changed (Bridge SequencerInboxUpdated or RollupAdmin SequencerInboxSet).',
    'event SequencerInboxUpdated(address newSequencerInbox)',
    'event SequencerInboxSet(address newSequencerInbox)',
  ],
  [
    'rollup.rollup_updated',
    'upgrade',
    'critical',
    'The rollup contract behind an Arbitrum Bridge was changed (RollupUpdated).',
    'event RollupUpdated(address rollup)',
  ],
  // SequencerInbox (ISequencerInbox.sol): keysets are the AnyTrust data-availability committee.
  [
    'rollup.keyset_set',
    'parameters',
    'critical',
    'A data-availability keyset was authorised on an Arbitrum SequencerInbox (SetValidKeyset).',
    'event SetValidKeyset(bytes32 indexed keysetHash, bytes keysetBytes)',
  ],
  [
    'rollup.keyset_invalidated',
    'parameters',
    'critical',
    'A data-availability keyset was invalidated on an Arbitrum SequencerInbox (InvalidateKeyset).',
    'event InvalidateKeyset(bytes32 indexed keysetHash)',
  ],
  [
    'rollup.batch_poster_set',
    'access',
    'high',
    'A batch poster was added or removed on an Arbitrum SequencerInbox (BatchPosterSet).',
    'event BatchPosterSet(address batchPoster, bool isBatchPoster)',
  ],
  [
    'rollup.sequencer_set',
    'access',
    'high',
    'A sequencer was added or removed on an Arbitrum SequencerInbox (SequencerSet).',
    'event SequencerSet(address addr, bool isSequencer)',
  ],
  [
    'rollup.batch_poster_manager_set',
    'access',
    'high',
    'The batch poster manager of an Arbitrum SequencerInbox was changed (BatchPosterManagerSet).',
    'event BatchPosterManagerSet(address newBatchPosterManager)',
  ],
  // UpgradeExecutor (OffchainLabs/upgrade-executor): the last hop of every Arbitrum DAO / Security Council action.
  [
    'rollup.upgrade_executed',
    'upgrade',
    'critical',
    'An Arbitrum UpgradeExecutor delegatecalled an upgrade action contract (UpgradeExecuted).',
    'event UpgradeExecuted(address indexed upgrade, uint256 value, bytes data)',
  ],
  [
    'rollup.target_call_executed',
    'upgrade',
    'high',
    'An Arbitrum UpgradeExecutor called a target contract directly (TargetCallExecuted).',
    'event TargetCallExecuted(address indexed target, uint256 value, bytes data)',
  ],
  // RollupAdminLogic (BoLD, IRollupAdmin.sol v3.1.0): the validator set, fraud-proof program and forced confirmations.
  [
    'rollup.wasm_module_root_set',
    'upgrade',
    'critical',
    'The WASM module root of an Arbitrum rollup was changed (WasmModuleRootSet): a new fraud-proof program (node software) is now the reference.',
    'event WasmModuleRootSet(bytes32 newWasmModuleRoot)',
  ],
  [
    'rollup.validators_set',
    'access',
    'critical',
    'Validators were added or removed on an Arbitrum rollup (ValidatorsSet).',
    'event ValidatorsSet(address[] validators, bool[] enabled)',
  ],
  [
    'rollup.validator_whitelist_disabled_set',
    'access',
    'critical',
    'The validator whitelist of an Arbitrum rollup was enabled or disabled (ValidatorWhitelistDisabledSet).',
    'event ValidatorWhitelistDisabledSet(bool _validatorWhitelistDisabled)',
  ],
  [
    'rollup.fast_confirmer_set',
    'access',
    'critical',
    'The AnyTrust fast confirmer of an Arbitrum rollup was changed (AnyTrustFastConfirmerSet): that address can confirm assertions without the challenge period.',
    'event AnyTrustFastConfirmerSet(address anyTrustFastConfirmer)',
  ],
  [
    'rollup.confirm_period_set',
    'parameters',
    'critical',
    'The confirmation period of an Arbitrum rollup was changed (ConfirmPeriodBlocksSet; L1 blocks before an assertion is final).',
    'event ConfirmPeriodBlocksSet(uint64 newConfirmPeriod)',
  ],
  [
    'rollup.base_stake_set',
    'parameters',
    'high',
    'The base stake of an Arbitrum rollup validator was changed (BaseStakeSet; wei).',
    'event BaseStakeSet(uint256 newBaseStake)',
  ],
  [
    'rollup.outbox_set',
    'parameters',
    'critical',
    'The outbox of an Arbitrum rollup was changed (OutboxSet).',
    'event OutboxSet(address outbox)',
  ],
  [
    'rollup.inbox_set',
    'parameters',
    'critical',
    'The inbox of an Arbitrum rollup was changed (InboxSet).',
    'event InboxSet(address inbox)',
  ],
  [
    'rollup.delayed_inbox_set',
    'parameters',
    'critical',
    'A delayed inbox of an Arbitrum rollup was enabled or disabled (DelayedInboxSet).',
    'event DelayedInboxSet(address inbox, bool enabled)',
  ],
  [
    'rollup.challenge_manager_set',
    'upgrade',
    'critical',
    'The challenge manager of an Arbitrum rollup was changed (ChallengeManagerSet).',
    'event ChallengeManagerSet(address challengeManager)',
  ],
  // Two signatures, one key: an assertion forced by the owner, whether created or confirmed.
  [
    'rollup.assertion_forced',
    'parameters',
    'critical',
    'The owner forced an assertion on an Arbitrum rollup (AssertionForceCreated / AssertionForceConfirmed): the normal validation path was bypassed.',
    'event AssertionForceCreated(bytes32 indexed assertionHash)',
    'event AssertionForceConfirmed(bytes32 indexed assertionHash)',
  ],
  [
    'rollup.stakers_force_refunded',
    'parameters',
    'high',
    'The owner force-refunded stakers of an Arbitrum rollup (StakersForceRefunded).',
    'event StakersForceRefunded(address[] staker)',
  ],

  // ---- lending: Aave V4 Hub (2026-09-26) -----------------------------------------------------------
  // aave/aave-v4 main @ 40232a0 src/hub/interfaces/IHub.sol (+ IHubBase.sol for the structs). V4 keeps
  // none of the V3 configurator signatures: the Hub is the liquidity layer, a Spoke draws from it
  // through a per-asset credit line. `UpdateSpokeConfig` carries that credit line (drawCap), the
  // debit line (addCap), the risk-premium threshold and the active / halted flags in one struct;
  // `UpdateAssetConfig` the fee receiver, liquidity fee (bps), interest rate strategy and reinvestment
  // controller of a Hub asset. Structs are declared inline so topic0 is the tuple keccak; all four
  // topic0s (and the Spoke / oracle / AccessManager ones below) were matched against live logs of the
  // Ethereum Core Hub / Main Spoke and the Base Equities Hub / MAG7 Spoke on 2026-09-26.
  [
    'lending.hub_asset_added',
    'parameters',
    'high',
    'An asset was listed on an Aave V4 Hub (AddAsset).',
    'event AddAsset(uint256 indexed assetId, address indexed underlying, uint8 decimals)',
  ],
  [
    'lending.hub_asset_config_updated',
    'parameters',
    'high',
    'The fee receiver, liquidity fee, interest rate strategy or reinvestment controller of an Aave V4 Hub asset was changed (UpdateAssetConfig).',
    'event UpdateAssetConfig(uint256 indexed assetId, (address feeReceiver, uint16 liquidityFee, address irStrategy, address reinvestmentController) config)',
  ],
  [
    'lending.hub_spoke_added',
    'parameters',
    'high',
    'A Spoke was connected to an asset of an Aave V4 Hub (AddSpoke): it can now be given a credit line.',
    'event AddSpoke(uint256 indexed assetId, address indexed spoke)',
  ],
  [
    'lending.hub_spoke_config_updated',
    'parameters',
    'high',
    'The credit line (draw cap), debit line (add cap), risk-premium threshold or active / halted flag of a Spoke on an Aave V4 Hub asset was changed (UpdateSpokeConfig).',
    'event UpdateSpokeConfig(uint256 indexed assetId, address indexed spoke, (uint40 addCap, uint40 drawCap, uint24 riskPremiumThreshold, bool active, bool halted) config)',
  ],
  // src/hub/interfaces/IAssetInterestRateStrategy.sol: emitted by the strategy contract, per Hub asset (bps).
  [
    'lending.hub_rate_data_changed',
    'parameters',
    'high',
    'The interest rate curve of an Aave V4 Hub asset was changed on its rate strategy (UpdateInterestRateData, bps).',
    'event UpdateInterestRateData(address indexed hub, uint256 indexed assetId, uint256 optimalUsageRatio, uint256 baseDrawnRate, uint256 rateGrowthBeforeOptimal, uint256 rateGrowthAfterOptimal)',
  ],

  // ---- lending: Aave V4 Spoke (2026-09-26) ---------------------------------------------------------
  // src/spoke/interfaces/ISpoke.sol. A reserve of a Spoke is (assetId, hub); `UpdateReserveConfig` is
  // the pause / freeze / borrowable switch of V4 (one struct, no ReservePaused / ReserveFrozen), the
  // dynamic config is the collateral factor / max liquidation bonus / liquidation fee (bps), keyed so a
  // position can stay on an older key until refreshed. Not added: SetSpokeImmutables (initialize only),
  // the user flows (Supply / Withdraw / Borrow / Repay / LiquidationCall / SetUsingAsCollateral ...).
  [
    'lending.spoke_liquidation_config_updated',
    'parameters',
    'high',
    'The liquidation config (target health factor, health factor for max bonus, bonus factor) of an Aave V4 Spoke was changed (UpdateLiquidationConfig).',
    'event UpdateLiquidationConfig((uint128 targetHealthFactor, uint64 healthFactorForMaxBonus, uint16 liquidationBonusFactor) config)',
  ],
  [
    'lending.spoke_reserve_added',
    'parameters',
    'high',
    'A reserve was added to an Aave V4 Spoke for an asset of a Hub (AddReserve).',
    'event AddReserve(uint256 indexed reserveId, uint256 indexed assetId, address indexed hub)',
  ],
  [
    'lending.spoke_reserve_config_updated',
    'parameters',
    'critical',
    'A reserve of an Aave V4 Spoke was paused, frozen, made (non-)borrowable or had its collateral risk changed (UpdateReserveConfig): the V4 pause and freeze switch.',
    'event UpdateReserveConfig(uint256 indexed reserveId, (uint24 collateralRisk, bool paused, bool frozen, bool borrowable, bool receiveSharesEnabled) config)',
  ],
  [
    'lending.spoke_reserve_price_source_updated',
    'parameters',
    'critical',
    'The price source of a reserve of an Aave V4 Spoke was changed (UpdateReservePriceSource).',
    'event UpdateReservePriceSource(uint256 indexed reserveId, address indexed priceSource)',
  ],
  [
    'lending.spoke_dynamic_config_added',
    'parameters',
    'high',
    'A new collateral factor / max liquidation bonus / liquidation fee set was added for a reserve of an Aave V4 Spoke (AddDynamicReserveConfig, bps).',
    'event AddDynamicReserveConfig(uint256 indexed reserveId, uint32 indexed dynamicConfigKey, (uint16 collateralFactor, uint32 maxLiquidationBonus, uint16 liquidationFee) config)',
  ],
  [
    'lending.spoke_dynamic_config_updated',
    'parameters',
    'high',
    'The collateral factor / max liquidation bonus / liquidation fee set of a reserve of an Aave V4 Spoke was changed in place (UpdateDynamicReserveConfig, bps).',
    'event UpdateDynamicReserveConfig(uint256 indexed reserveId, uint32 indexed dynamicConfigKey, (uint16 collateralFactor, uint32 maxLiquidationBonus, uint16 liquidationFee) config)',
  ],
  [
    'lending.spoke_position_manager_updated',
    'access',
    'high',
    'A position manager was activated or deactivated on an Aave V4 Spoke (UpdatePositionManager): active managers may act on positions of users who approved them.',
    'event UpdatePositionManager(address indexed positionManager, bool active)',
  ],

  // ---- oracle: Aave V4 AaveOracle (2026-09-26) -----------------------------------------------------
  // src/spoke/interfaces/IAaveOracle.sol: one oracle per Spoke, one price source per reserve id. Not
  // added: SetSpoke (set once at deployment, SpokeAlreadySet afterwards).
  [
    'oracle.reserve_source_updated',
    'parameters',
    'critical',
    'An Aave V4 Spoke oracle changed the price source of a reserve (UpdateReserveSource).',
    'event UpdateReserveSource(uint256 indexed reserveId, address indexed source)',
  ],

  // ---- access: OpenZeppelin 5.x AccessManaged / AccessManager (2026-09-26) -----------------------
  // aave/aave-v4 src/dependencies/openzeppelin/IAccessManaged.sol + IAccessManager.sol (OZ 5.5.0).
  // Every Aave V4 Hub, Spoke and configurator is AccessManaged: `authority()` is the AccessManager
  // that decides who may call which function; swapping it rewires the whole role system. On the
  // manager, RoleGranted / RoleRevoked (uint64 role ids, a grant delay and an execution delay per
  // member) are the role events, TargetFunctionRoleUpdated maps a target's selectors to a role,
  // TargetClosed is the manager-level pause of a target, TargetAdminDelayUpdated / RoleGrantDelayChanged
  // change the delays, Operation* is the built-in schedule / execute / cancel of delayed calls.
  // Role ids are protocol-specific; Aave V4 (Roles.sol): 0 ADMIN, 100 HUB_DOMAIN_ADMIN, 101
  // HUB_CONFIGURATOR, 102 HUB_FEE_MINTER, 103 HUB_DEFICIT_ELIMINATOR, 200 HUB_CONFIGURATOR_DOMAIN_ADMIN,
  // 300 SPOKE_DOMAIN_ADMIN, 301 SPOKE_CONFIGURATOR, 302 SPOKE_USER_POSITION_UPDATER, 400
  // SPOKE_CONFIGURATOR_DOMAIN_ADMIN; 2^64-1 is PUBLIC_ROLE. On the live V4 managers only
  // TargetFunctionRoleUpdated, RoleGranted, RoleRevoked and RoleLabel have fired so far (no delays set).
  [
    'access.authority_updated',
    'access',
    'critical',
    'An AccessManaged contract switched to a new AccessManager authority (AuthorityUpdated): every permission now comes from the new manager.',
    'event AuthorityUpdated(address authority)',
  ],
  [
    'access.manager_role_granted',
    'access',
    'high',
    'An OpenZeppelin AccessManager granted a role to an account (RoleGranted, uint64 role id, with the execution delay of that member).',
    'event RoleGranted(uint64 indexed roleId, address indexed account, uint32 delay, uint48 since, bool newMember)',
  ],
  [
    'access.manager_role_revoked',
    'access',
    'info',
    'An OpenZeppelin AccessManager revoked a role from an account (RoleRevoked, uint64 role id).',
    'event RoleRevoked(uint64 indexed roleId, address indexed account)',
  ],
  [
    'access.manager_role_admin_changed',
    'access',
    'high',
    'The admin role of a role on an OpenZeppelin AccessManager was changed (RoleAdminChanged).',
    'event RoleAdminChanged(uint64 indexed roleId, uint64 indexed admin)',
  ],
  [
    'access.manager_role_guardian_changed',
    'access',
    'high',
    'The guardian role (who can cancel scheduled operations) of a role on an OpenZeppelin AccessManager was changed (RoleGuardianChanged).',
    'event RoleGuardianChanged(uint64 indexed roleId, uint64 indexed guardian)',
  ],
  [
    'access.manager_role_grant_delay_changed',
    'access',
    'high',
    'The grant delay of a role on an OpenZeppelin AccessManager was changed (RoleGrantDelayChanged).',
    'event RoleGrantDelayChanged(uint64 indexed roleId, uint32 delay, uint48 since)',
  ],
  [
    'pause.target_closed',
    'pause',
    'critical',
    'An OpenZeppelin AccessManager closed or reopened a target (TargetClosed): while closed, no restricted function of that contract can be called.',
    'event TargetClosed(address indexed target, bool closed)',
  ],
  [
    'access.manager_target_function_role_updated',
    'access',
    'critical',
    'An OpenZeppelin AccessManager changed which role may call a function of a target (TargetFunctionRoleUpdated).',
    'event TargetFunctionRoleUpdated(address indexed target, bytes4 selector, uint64 indexed roleId)',
  ],
  [
    'access.manager_target_admin_delay_updated',
    'access',
    'high',
    'The admin delay of a target on an OpenZeppelin AccessManager was changed (TargetAdminDelayUpdated).',
    'event TargetAdminDelayUpdated(address indexed target, uint32 delay, uint48 since)',
  ],
  [
    'access.manager_operation_scheduled',
    'timelock',
    'high',
    'A delayed call was scheduled on an OpenZeppelin AccessManager (OperationScheduled).',
    'event OperationScheduled(bytes32 indexed operationId, uint32 indexed nonce, uint48 schedule, address caller, address target, bytes data)',
  ],
  [
    'access.manager_operation_executed',
    'timelock',
    'info',
    'A scheduled call was executed through an OpenZeppelin AccessManager (OperationExecuted).',
    'event OperationExecuted(bytes32 indexed operationId, uint32 indexed nonce)',
  ],
  [
    'access.manager_operation_canceled',
    'timelock',
    'info',
    'A scheduled call on an OpenZeppelin AccessManager was cancelled (OperationCanceled).',
    'event OperationCanceled(bytes32 indexed operationId, uint32 indexed nonce)',
  ],
  [
    'access.manager_role_label',
    'access',
    'info',
    'A role on an OpenZeppelin AccessManager was given a label (RoleLabel).',
    'event RoleLabel(uint64 indexed roleId, string label)',
  ],

  // ---- easytrack: Lido Easy Track (2026-09-29, GAP-SCAN-2026-09-27 row 5) --------------------------
  // Sources read on the day: lidofinance/easy-track master `contracts/EasyTrack.sol` (motions +
  // EVMScriptExecutorChanged), `contracts/EVMScriptFactoriesRegistry.sol` (factory add / remove),
  // `contracts/MotionSettings.sol` (duration, count limit, objections threshold) and
  // `contracts/EVMScriptExecutor.sol` (EasyTrackChanged; ScriptExecuted is not registered, every
  // enactment already lands as motion_enacted). Param names keep the source's leading underscore.
  // Easy Track is the DAO's delegated-power path: a factory is a permission (which contract, which
  // selectors, from `_permissions`) that a trusted caller can exercise through a 72-hour optimistic
  // motion; adding one (DG proposal #14 on 2026-09-25 added SetDepositsReserveTarget) widens what can
  // change without a vote, so factory_added is critical. The EasyTrack contract holds the
  // BUFFER_RESERVE_MANAGER_ROLE-style Aragon permissions through its EVMScriptExecutor, so swapping
  // either contract re-routes every delegated power at once.
  [
    'easytrack.factory_added',
    'access',
    'critical',
    'An EVM script factory was added to Lido Easy Track (EVMScriptFactoryAdded): a new delegated power that motions can exercise without a DAO vote.',
    'event EVMScriptFactoryAdded(address indexed _evmScriptFactory, bytes _permissions)',
  ],
  [
    'easytrack.factory_removed',
    'access',
    'high',
    'An EVM script factory was removed from Lido Easy Track (EVMScriptFactoryRemoved).',
    'event EVMScriptFactoryRemoved(address indexed _evmScriptFactory)',
  ],
  [
    'easytrack.executor_changed',
    'governance',
    'critical',
    'The EVMScriptExecutor of Lido Easy Track was changed (EVMScriptExecutorChanged): every enacted motion now runs through the new executor.',
    'event EVMScriptExecutorChanged(address indexed _evmScriptExecutor)',
  ],
  [
    'easytrack.easy_track_changed',
    'governance',
    'critical',
    'The Easy Track allowed to drive a Lido EVMScriptExecutor was changed (EasyTrackChanged).',
    'event EasyTrackChanged(address indexed _previousEasyTrack, address indexed _newEasyTrack)',
  ],
  [
    'easytrack.motion_created',
    'governance',
    'info',
    'A Lido Easy Track motion was created (MotionCreated); it enacts after the motion duration unless LDO holders object.',
    'event MotionCreated(uint256 indexed _motionId, address _creator, address indexed _evmScriptFactory, bytes _evmScriptCallData, bytes _evmScript)',
  ],
  [
    'easytrack.motion_objected',
    'governance',
    'info',
    'An LDO holder objected to a Lido Easy Track motion (MotionObjected; weight and running objection total).',
    'event MotionObjected(uint256 indexed _motionId, address indexed _objector, uint256 _weight, uint256 _newObjectionsAmount, uint256 _newObjectionsAmountPct)',
  ],
  [
    'easytrack.motion_rejected',
    'governance',
    'info',
    'A Lido Easy Track motion was rejected by objections (MotionRejected).',
    'event MotionRejected(uint256 indexed _motionId)',
  ],
  [
    'easytrack.motion_canceled',
    'governance',
    'info',
    'A Lido Easy Track motion was cancelled by its creator or the CANCEL_ROLE (MotionCanceled).',
    'event MotionCanceled(uint256 indexed _motionId)',
  ],
  [
    'easytrack.motion_enacted',
    'governance',
    'high',
    'A Lido Easy Track motion was enacted (MotionEnacted): its EVM script ran through the EVMScriptExecutor.',
    'event MotionEnacted(uint256 indexed _motionId)',
  ],
  [
    'easytrack.motion_duration_changed',
    'parameters',
    'high',
    'The Lido Easy Track motion duration was changed (MotionDurationChanged; seconds the DAO has to object).',
    'event MotionDurationChanged(uint256 _motionDuration)',
  ],
  [
    'easytrack.motions_count_limit_changed',
    'parameters',
    'info',
    'The limit of simultaneously active Lido Easy Track motions was changed (MotionsCountLimitChanged).',
    'event MotionsCountLimitChanged(uint256 _newMotionsCountLimit)',
  ],
  [
    'easytrack.objections_threshold_changed',
    'parameters',
    'high',
    'The Lido Easy Track objections threshold was changed (ObjectionsThresholdChanged; basis points of LDO total supply).',
    'event ObjectionsThresholdChanged(uint256 _newThreshold)',
  ],

  // ---- council: Arbitrum SecurityCouncilManager (2026-09-29, GAP-SCAN-2026-09-27 row 7) ------------
  // Source read on the day: ArbitrumFoundation/governance main
  // `src/security-council-mgmt/SecurityCouncilManager.sol` (events) + `Common.sol` (enum Cohort
  // { FIRST, SECOND } = uint8 0 / 1). The manager on Arbitrum One (proxy 0xD509…eDFC) is the source
  // of truth for the 12 Security Council signers; every change here is pushed to the three Safes
  // (L1 emergency, Arb One emergency + non-emergency, Nova) through the L2 timelock, so a member event
  // on the manager precedes the `safe.added_owner` / `safe.removed_owner` pair on each Safe by days.
  // rotateMember (same member, new key) is what Reacher Report #002 (Arbitrum forum 31491) is about.
  [
    'council.cohort_replaced',
    'multisig',
    'critical',
    'A whole Security Council cohort was replaced on the manager (CohortReplaced; the election outcome or an emergency swap).',
    'event CohortReplaced(address[] newCohort, uint8 indexed cohort)',
  ],
  [
    'council.member_added',
    'multisig',
    'high',
    'A member was added to a Security Council cohort on the manager (MemberAdded).',
    'event MemberAdded(address indexed newMember, uint8 indexed cohort)',
  ],
  [
    'council.member_removed',
    'multisig',
    'critical',
    'A member was removed from a Security Council cohort on the manager (MemberRemoved).',
    'event MemberRemoved(address indexed member, uint8 indexed cohort)',
  ],
  [
    'council.member_replaced',
    'multisig',
    'critical',
    'A Security Council member was replaced by another on the manager (MemberReplaced).',
    'event MemberReplaced(address indexed replacedMember, address indexed newMember, uint8 cohort)',
  ],
  [
    'council.member_rotated',
    'multisig',
    'high',
    'A Security Council member rotated to a new signing key on the manager (MemberRotated; same seat, new address).',
    'event MemberRotated(address indexed replacedAddress, address indexed newAddress, uint8 cohort)',
  ],
  [
    'council.security_council_added',
    'access',
    'critical',
    'A Safe was added to the set the Security Council manager keeps in sync (SecurityCouncilAdded).',
    'event SecurityCouncilAdded(address indexed securityCouncil, address indexed updateAction, uint256 securityCouncilsLength)',
  ],
  [
    'council.security_council_removed',
    'access',
    'critical',
    'A Safe was removed from the set the Security Council manager keeps in sync (SecurityCouncilRemoved).',
    'event SecurityCouncilRemoved(address indexed securityCouncil, address indexed updateAction, uint256 securityCouncilsLength)',
  ],
  [
    'council.route_builder_set',
    'parameters',
    'critical',
    'The UpgradeExecRouteBuilder of the Security Council manager was changed (UpgradeExecRouteBuilderSet): it builds the timelock route every member update travels.',
    'event UpgradeExecRouteBuilderSet(address indexed UpgradeExecRouteBuilder)',
  ],

  // ---- governor: GovernorBravo settings and Venus guardian / configs (2026-09-29, GAP-SCAN-2026-09-29 row 1)
  // Source read on the day: VenusProtocol/governance-contracts develop
  // contracts/Governance/GovernorBravoInterfaces.sol (`GovernorBravoEvents`, `uint` = uint256), emitted by
  // GovernorBravoDelegate.sol. VotingDelaySet / VotingPeriodSet / ProposalThresholdSet are byte-identical in
  // compound-finance GovernorBravoDelegate and OpenZeppelin GovernorSettings (governance/extensions/
  // GovernorSettings.sol), so one entry each serves all three governors. Venus' NewAdmin / NewPendingAdmin /
  // NewImplementation are already `ownable.new_admin` / `ownable.new_pending_admin` / `proxy.new_implementation`;
  // ProposalQueued / ProposalExecuted / ProposalCanceled share the OZ topic0s under `governor.*` above.
  [
    'governor.voting_delay_set',
    'governance',
    'high',
    'The voting delay of a governor was changed (VotingDelaySet; OpenZeppelin GovernorSettings, Compound and Venus GovernorBravo).',
    'event VotingDelaySet(uint256 oldVotingDelay, uint256 newVotingDelay)',
  ],
  [
    'governor.voting_period_set',
    'governance',
    'high',
    'The voting period of a governor was changed (VotingPeriodSet; OpenZeppelin GovernorSettings, Compound and Venus GovernorBravo).',
    'event VotingPeriodSet(uint256 oldVotingPeriod, uint256 newVotingPeriod)',
  ],
  [
    'governor.proposal_threshold_set',
    'governance',
    'high',
    'The proposal threshold (votes needed to propose) of a governor was changed (ProposalThresholdSet; OpenZeppelin GovernorSettings, Compound and Venus GovernorBravo).',
    'event ProposalThresholdSet(uint256 oldProposalThreshold, uint256 newProposalThreshold)',
  ],
  [
    'governor.guardian_set',
    'access',
    'critical',
    'The guardian of a Venus GovernorBravo, the address that may cancel any proposal, was changed (NewGuardian).',
    'event NewGuardian(address oldGuardian, address newGuardian)',
  ],
  [
    'governor.proposal_max_operations_updated',
    'governance',
    'info',
    'The maximum number of actions per proposal of a Venus GovernorBravo was changed (ProposalMaxOperationsUpdated).',
    'event ProposalMaxOperationsUpdated(uint256 oldMaxOperations, uint256 newMaxOperations)',
  ],
  [
    'governor.validation_params_set',
    'governance',
    'high',
    'The allowed voting-period and voting-delay ranges of a Venus GovernorBravo were changed (SetValidationParams).',
    'event SetValidationParams(uint256 oldMinVotingPeriod, uint256 newMinVotingPeriod, uint256 oldmaxVotingPeriod, uint256 newmaxVotingPeriod, uint256 oldminVotingDelay, uint256 newminVotingDelay, uint256 oldmaxVotingDelay, uint256 newmaxVotingDelay)',
  ],
  [
    'governor.proposal_configs_set',
    'governance',
    'high',
    'The proposal config of one Venus proposal type (voting period, voting delay, threshold) was set (SetProposalConfigs; emitted once per type, NORMAL, FASTTRACK, CRITICAL in that order).',
    'event SetProposalConfigs(uint256 votingPeriod, uint256 votingDelay, uint256 proposalThreshold)',
  ],

  // ---- governor: OpenZeppelin Governor extensions (2026-09-29, GAP-SCAN-2026-09-29 row 2) -----------
  // Source read on the day: OpenZeppelin/openzeppelin-contracts master governance/extensions/
  // GovernorPreventLateQuorum.sol (ProposalExtended, LateQuorumVoteExtensionSet),
  // GovernorVotesQuorumFraction.sol (QuorumNumeratorUpdated), GovernorTimelockControl.sol (TimelockChange);
  // GovernorSettings' three setters are the shared entries above. Compound Governor 0x309a…c8c0 extended
  // proposal 610 at block 26,076,170 (the real log the test decodes): `extendedDeadline` is in the governor's
  // clock units (block number for Compound, timestamp for timestamp-clock governors), so the "vote ends" a
  // reader keeps must come from proposalDeadline() after this event, not from the stored voteEnd.
  [
    'governor.proposal_extended',
    'governance',
    'info',
    'The voting deadline of a proposal was pushed out because quorum was reached late (OpenZeppelin GovernorPreventLateQuorum ProposalExtended; the new deadline is in the governor clock, blocks or seconds).',
    'event ProposalExtended(uint256 indexed proposalId, uint64 extendedDeadline)',
  ],
  [
    'governor.late_quorum_extension_set',
    'governance',
    'high',
    'The late-quorum vote extension of an OpenZeppelin governor was changed (LateQuorumVoteExtensionSet; governor clock units).',
    'event LateQuorumVoteExtensionSet(uint64 oldVoteExtension, uint64 newVoteExtension)',
  ],
  [
    'governor.quorum_numerator_updated',
    'governance',
    'high',
    'The quorum fraction of an OpenZeppelin governor was changed (GovernorVotesQuorumFraction QuorumNumeratorUpdated; numerator over quorumDenominator(), 100 by default).',
    'event QuorumNumeratorUpdated(uint256 oldQuorumNumerator, uint256 newQuorumNumerator)',
  ],
  [
    'governor.timelock_changed',
    'governance',
    'critical',
    'The timelock an OpenZeppelin governor executes through was changed (GovernorTimelockControl TimelockChange).',
    'event TimelockChange(address oldTimelock, address newTimelock)',
  ],

  // ---- Aave Governance V3 core + PayloadsController (2026-09-29, GAP-SCAN-2026-09-29 row 3) ----------
  // Sources read on the day: bgd-labs/aave-governance-v3 main src/interfaces/IGovernanceCore.sol (emitted by
  // src/contracts/GovernanceCore.sol), src/contracts/payloads/interfaces/IPayloadsControllerCore.sol (emitted
  // by PayloadsControllerCore.sol), src/contracts/payloads/PayloadsControllerUtils.sol (enum AccessControl
  // { Level_null, Level_1, Level_2 } = uint8 0 / 1 / 2) and bgd-labs/aave-delivery-infrastructure main
  // src/contracts/old-oz/interfaces/IWithGuardian.sol (GuardianUpdated, inherited by both through
  // OwnableWithGuardian). ProposalCreated / Queued / Executed / Canceled join the `governor.*` keys above.
  // Flow: payloads.created (per chain, before the proposal) -> governor.proposal_created -> governor.voting_activated
  // -> vote on the voting machine -> governor.proposal_queued (results bridged) -> governor.proposal_executed
  // (PayloadSent per payload) -> payloads.queued on each PayloadsController -> executor delay -> payloads.executed.
  // Not registered: PayloadSent, VoteForwarded, RepresentativeUpdated, CancellationFee*, GasLimitUpdated,
  // PayloadExecutionMessageReceived (per-voter or bridge-plumbing noise). A `MessageOriginatorSet` event does not
  // exist in the source (MESSAGE_ORIGINATOR is an immutable of IPayloadsController).
  [
    'governor.voting_activated',
    'governance',
    'info',
    'Voting on an Aave Governance V3 proposal was activated: the snapshot block hash is fixed and the vote runs for votingDuration seconds on the voting machine (VotingActivated).',
    'event VotingActivated(uint256 indexed proposalId, bytes32 indexed snapshotBlockHash, uint24 votingDuration)',
  ],
  [
    'governor.proposal_failed',
    'governance',
    'info',
    'An Aave Governance V3 proposal failed its vote once the results were bridged back (ProposalFailed; votes in 1e18 voting power).',
    'event ProposalFailed(uint256 indexed proposalId, uint128 votesFor, uint128 votesAgainst)',
  ],
  [
    'governor.voting_config_updated',
    'governance',
    'critical',
    'The voting config of one Aave Governance V3 access level was changed (VotingConfigUpdated: voting duration, cooldown before voting, yes threshold, yes/no differential, minimum proposition power).',
    'event VotingConfigUpdated(uint8 indexed accessLevel, uint24 votingDuration, uint24 coolDownBeforeVotingStart, uint256 yesThreshold, uint256 yesNoDifferential, uint256 minPropositionPower)',
  ],
  [
    'governor.power_strategy_updated',
    'governance',
    'critical',
    'The power strategy (how voting and proposition power are counted) of Aave Governance V3 was changed (PowerStrategyUpdated).',
    'event PowerStrategyUpdated(address indexed newPowerStrategy)',
  ],
  [
    'governor.voting_portal_updated',
    'governance',
    'critical',
    'A voting portal (the bridge to one voting machine) was approved or removed on Aave Governance V3 (VotingPortalUpdated).',
    'event VotingPortalUpdated(address indexed votingPortal, bool indexed approved)',
  ],
  [
    'ownable.guardian_updated',
    'ownership',
    'critical',
    'The guardian of a BGD OwnableWithGuardian contract (Aave Governance V3 core, PayloadsController, CrossChainController) was changed (GuardianUpdated).',
    'event GuardianUpdated(address oldGuardian, address newGuardian)',
  ],
  [
    'payloads.created',
    'governance',
    'info',
    'A payload (the list of executor actions a proposal will run on this chain) was registered on an Aave Governance V3 PayloadsController (PayloadCreated).',
    'event PayloadCreated(uint40 indexed payloadId, address indexed creator, (address target, bool withDelegateCall, uint8 accessLevel, uint256 value, string signature, bytes callData)[] actions, uint8 indexed maximumAccessLevelRequired)',
  ],
  [
    'payloads.queued',
    'timelock',
    'high',
    'A payload was queued on an Aave Governance V3 PayloadsController after its proposal passed; it becomes executable after the executor delay (PayloadQueued).',
    'event PayloadQueued(uint40 payloadId)',
  ],
  [
    'payloads.executed',
    'timelock',
    'info',
    'A queued payload was executed by an Aave Governance V3 PayloadsController (PayloadExecuted).',
    'event PayloadExecuted(uint40 payloadId)',
  ],
  [
    'payloads.cancelled',
    'timelock',
    'info',
    'A payload was cancelled on an Aave Governance V3 PayloadsController by the guardian (PayloadCancelled).',
    'event PayloadCancelled(uint40 payloadId)',
  ],
  [
    'payloads.executor_set',
    'access',
    'critical',
    'The executor and delay of one access level of an Aave Governance V3 PayloadsController were set (ExecutorSet).',
    'event ExecutorSet(uint8 indexed accessLevel, address indexed executor, uint40 delay)',
  ],
];

function buildEvents(specs: readonly Spec[]): WatchedEvent[] {
  const out: WatchedEvent[] = [];
  for (const [key, category, severity, description, ...signatures] of specs) {
    if (signatures.length === 0) {
      throw new Error(`Event spec "${key}" has no signature`);
    }
    for (const signature of signatures) {
      const abi = parseAbiItem(signature) as AbiEvent;
      if (abi.type !== 'event') {
        throw new Error(`Signature for "${key}" is not an event: ${signature}`);
      }
      out.push({
        key,
        category,
        severity,
        abi,
        topic0: toEventSelector(abi),
        description,
      });
    }
  }
  return out;
}

export const EVENTS: readonly WatchedEvent[] = Object.freeze(buildEvents(SPECS));

function buildByTopic0(events: readonly WatchedEvent[]): ReadonlyMap<Hex, readonly WatchedEvent[]> {
  const map = new Map<Hex, WatchedEvent[]>();
  for (const ev of events) {
    const list = map.get(ev.topic0);
    if (list) list.push(ev);
    else map.set(ev.topic0, [ev]);
  }
  return map;
}

/** Several entries may share a topic0 (same signature, different indexed layout). */
export const EVENTS_BY_TOPIC0: ReadonlyMap<Hex, readonly WatchedEvent[]> = buildByTopic0(EVENTS);

/** Unique topic0 list, for eth_getLogs topics[0]. */
export const TOPIC0S: readonly Hex[] = Object.freeze([...EVENTS_BY_TOPIC0.keys()]);

export function severityRank(s: Severity): number {
  switch (s) {
    case 'critical':
      return 3;
    case 'high':
      return 2;
    case 'info':
      return 1;
  }
}

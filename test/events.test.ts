import { describe, expect, it } from 'vitest';
import { encodeAbiParameters, encodeEventTopics, keccak256, toBytes, type AbiEvent, type Hex } from 'viem';
import {
  EVENTS,
  EVENTS_BY_TOPIC0,
  TOPIC0S,
  decodeWatchedLog,
  severityRank,
  type WatchedEvent,
} from '../src/index.js';

const ZERO = '0x0000000000000000000000000000000000000000' as const;
const ALICE = '0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B' as const; // mixed-case on purpose
const BOB = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045' as const;

function byKey(key: string): WatchedEvent[] {
  return EVENTS.filter((e) => e.key === key);
}

function firstByKey(key: string): WatchedEvent {
  const ev = byKey(key)[0];
  if (!ev) throw new Error(`missing ${key}`);
  return ev;
}

/** Encode a log for a given ABI event: indexed params to topics, the rest to data. */
function encodeLog(abi: AbiEvent, args: Record<string, unknown>): { topics: Hex[]; data: Hex } {
  const topics = encodeEventTopics({ abi: [abi], eventName: abi.name, args } as never) as Hex[];
  const nonIndexed = abi.inputs.filter((i) => !i.indexed);
  const data =
    nonIndexed.length === 0
      ? ('0x' as Hex)
      : encodeAbiParameters(
          nonIndexed,
          nonIndexed.map((i) => args[i.name as string]),
        );
  return { topics, data };
}

describe('@gliese/events registry', () => {
  it('has the expected well-known selectors', () => {
    expect(firstByKey('proxy.upgraded').topic0).toBe(
      '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b',
    );
    expect(firstByKey('ownable.transferred').topic0).toBe(
      '0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0',
    );
    expect(firstByKey('access.role_granted').topic0).toBe(
      '0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d',
    );
    expect(firstByKey('safe.changed_threshold').topic0).toBe(
      '0x610f7ff2b304ae8903c3de74c60c6ab1f7d6226b3f52c5161905bb5ad4039c93',
    );
  });

  /** Keys that deliberately span several topic0s (overloads with different param types), 2026-09-07. */
  const MULTI_SIGNATURE_KEYS = new Set([
    'auth.file',
    'vault.pending_revoked',
    'vault.params_set',
    // Morpho Vault V2 umbrellas (2026-09-22)
    'vault.fee_set',
    'vault.fee_recipient_set',
    'vault.cap_increased',
    'vault.cap_decreased',
    'vault.gate_set',
    'vault.metadata_set',
    // Coverage batch 1 (2026-09-22): pause dialects, cross-protocol lending keys, Aave umbrellas, Euler fee settings
    'pause.paused',
    'pause.unpaused',
    'pause.state_changed',
    'lending.price_oracle_set',
    'lending.interest_rate_model_set',
    'lending.emode_asset_changed',
    'lending.borrow_cap_changed',
    'lending.liquidation_grace_period_changed',
    'lending.flashloan_premium_updated',
    'lending.reserve_factor_changed',
    'lending.action_paused',
    'protocol.fee_config_set',
    // Coverage batch 2 (2026-09-23): SystemConfig + SuperchainConfig ConfigUpdate, Bridge + RollupAdmin
    // sequencer inbox, forced assertion created / confirmed
    'rollup.config_updated',
    'rollup.sequencer_inbox_set',
    'rollup.assertion_forced',
  ]);

  it('entries sharing a key share a topic0 (except declared overload keys), and each (key, layout) is unique', () => {
    const topicByKey = new Map<string, Hex>();
    const seenLayouts = new Set<string>();
    for (const ev of EVENTS) {
      const prev = topicByKey.get(ev.key);
      if (prev && !MULTI_SIGNATURE_KEYS.has(ev.key)) expect(prev).toBe(ev.topic0);
      else if (!prev) topicByKey.set(ev.key, ev.topic0);

      // Overloads differ by type, not only by indexing, so include the types in the layout id; the
      // umbrella keys (2026-09-18) group differently named events that may share a type layout
      // (RevokePendingTimelock / RevokePendingGuardian, the three uint16 GovSet* params), so the
      // event name is part of the id too. Safe dual layouts still differ by indexing.
      const layout = `${ev.key}|${ev.abi.name}|${ev.abi.inputs.map((i) => `${i.type}${i.indexed ? 'i' : 'n'}`).join(',')}`;
      expect(seenLayouts.has(layout)).toBe(false);
      seenLayouts.add(layout);

      expect(ev.description.length).toBeGreaterThan(0);
      expect(ev.topic0).toMatch(/^0x[0-9a-f]{64}$/);
    }
    // A topic0 must never map to two keys.
    const keyByTopic = new Map<Hex, string>();
    for (const ev of EVENTS) {
      const prev = keyByTopic.get(ev.topic0);
      if (prev) expect(prev).toBe(ev.key);
      else keyByTopic.set(ev.topic0, ev.key);
    }
  });

  it('TOPIC0S has no duplicates and EVENTS_BY_TOPIC0 sizes add up', () => {
    expect(new Set(TOPIC0S).size).toBe(TOPIC0S.length);
    expect(TOPIC0S.length).toBe(EVENTS_BY_TOPIC0.size);
    let total = 0;
    for (const list of EVENTS_BY_TOPIC0.values()) total += list.length;
    expect(total).toBe(EVENTS.length);
    // Safe dual layouts are registered
    for (const key of [
      'safe.added_owner',
      'safe.removed_owner',
      'safe.enabled_module',
      'safe.disabled_module',
      'safe.changed_guard',
      'safe.changed_fallback_handler',
    ]) {
      expect(byKey(key).length).toBe(2);
    }
  });

  it('watches 265 unique topic0 signatures under 221 keys (239 / 195 after batch 2, 194 / 153 after batch 1, 116 / 96 with Vault V2, 88 / 78 on 2026-09-18, 57 / 54 before the vault governance family)', () => {
    expect(TOPIC0S.length).toBe(265);
    expect(new Set(EVENTS.map((e) => e.key)).size).toBe(221);
    expect(new Set(EVENTS.map((e) => e.category)).size).toBe(9);
    // auth.file accounts for 3 extra topic0s, vault.pending_revoked for 3 and vault.params_set for 4.
    expect(byKey('auth.file').length).toBe(4);
    expect(new Set(byKey('auth.file').map((e) => e.topic0)).size).toBe(4);
    expect(new Set(byKey('vault.pending_revoked').map((e) => e.topic0)).size).toBe(4);
    expect(new Set(byKey('vault.params_set').map((e) => e.topic0)).size).toBe(5);
  });

  // ---- 2026-09-18: vault governance (Morpho MetaMorpho, Euler v2 EVault, Euler price router) ----

  it('registers the vault governance keys under parameters with the agreed severity and byte-exact topic0s', () => {
    // key: [severity, ...canonical signatures]; topic0 must equal keccak256 of each signature.
    const want: Record<string, [string, ...string[]]> = {
      'vault.curator_set': ['critical', 'SetCurator(address)'],
      'vault.guardian_set': ['critical', 'SetGuardian(address,address)'],
      'vault.guardian_submitted': ['high', 'SubmitGuardian(address)'],
      'vault.allocator_set': ['high', 'SetIsAllocator(address,bool)'],
      'vault.timelock_submitted': ['high', 'SubmitTimelock(uint256)'],
      'vault.timelock_set': ['high', 'SetTimelock(address,uint256)'],
      'vault.cap_submitted': ['high', 'SubmitCap(address,bytes32,uint256)'],
      'vault.cap_set': ['high', 'SetCap(address,bytes32,uint256)'],
      'vault.market_removal_submitted': ['high', 'SubmitMarketRemoval(address,bytes32)'],
      'vault.pending_revoked': [
        'info',
        'RevokePendingCap(address,bytes32)',
        'RevokePendingTimelock(address)',
        'RevokePendingGuardian(address)',
        'RevokePendingMarketRemoval(address,bytes32)',
      ],
      // + the two Vault V2 recipient / fee events since 2026-09-22 (same key, see the V2 test below)
      'vault.fee_recipient_set': ['info', 'SetFeeRecipient(address)', 'SetPerformanceFeeRecipient(address)', 'SetManagementFeeRecipient(address)'],
      'vault.skim_recipient_set': ['info', 'SetSkimRecipient(address)'],
      'vault.fee_set': ['info', 'SetFee(address,uint256)', 'SetPerformanceFee(uint256)', 'SetManagementFee(uint256)'],
      'vault.supply_queue_set': ['info', 'SetSupplyQueue(address,bytes32[])'],
      'vault.withdraw_queue_set': ['info', 'SetWithdrawQueue(address,bytes32[])'],
      'vault.governor_admin_set': ['critical', 'GovSetGovernorAdmin(address)'],
      'vault.hook_config_set': ['critical', 'GovSetHookConfig(address,uint32)'],
      'vault.caps_set': ['high', 'GovSetCaps(uint16,uint16)'],
      'vault.ltv_set': ['high', 'GovSetLTV(address,uint16,uint16,uint16,uint48,uint32)'],
      'vault.irm_set': ['high', 'GovSetInterestRateModel(address)'],
      'vault.params_set': [
        'info',
        'GovSetLiquidationCoolOffTime(uint16)',
        'GovSetMaxLiquidationDiscount(uint16)',
        'GovSetInterestFee(uint16)',
        'GovSetFeeReceiver(address)',
        'GovSetConfigFlags(uint32)',
      ],
      'oracle.router_config_set': ['critical', 'ConfigSet(address,address,address)'],
      'oracle.router_vault_set': ['high', 'ResolvedVaultSet(address,address)'],
      'oracle.router_fallback_set': ['high', 'FallbackOracleSet(address)'],
    };
    const seen = new Set<Hex>();
    for (const [key, [severity, ...signatures]] of Object.entries(want)) {
      const entries = byKey(key);
      expect(entries.length, key).toBe(signatures.length);
      for (const ev of entries) {
        expect(ev.category, key).toBe('parameters');
        expect(ev.severity, key).toBe(severity);
      }
      const topics = entries.map((e) => e.topic0).sort();
      expect(topics, key).toEqual(signatures.map((s) => keccak256(toBytes(s))).sort());
      for (const t of topics) {
        expect(seen.has(t), `${key} ${t}`).toBe(false);
        seen.add(t);
      }
    }
    expect(seen.size).toBe(35);
    // Spot checks against the on-chain selectors of live MetaMorpho / EVault deployments.
    expect(firstByKey('vault.curator_set').topic0).toBe('0xbd0a63c12948fbc9194a5839019f99c9d71db924e5c70018265bc778b8f1a506');
    expect(firstByKey('vault.cap_set').topic0).toBe('0xe86b6d3313d3098f4c5f689c935de8fde876a597c185def2cedab85efedac686');
    expect(firstByKey('vault.governor_admin_set').topic0).toBe('0x1c145a4cd16d4148579b0f2296884ac4aa47536e4ef10a32e1cdc0dc3dd20ea4');
    expect(firstByKey('vault.ltv_set').topic0).toBe('0xc69392046c26324e9eee913208811542aabcbde6a41ce9ee3b45473b18eb3c76');
    expect(firstByKey('oracle.router_config_set').topic0).toBe('0x4ac83f39568b63f952374c82351889b07aff4f7e261232a20ba5a2a6d82b9ce0');
  });

  // ---- 2026-09-22: Morpho Vault V2 (morpho-org/vault-v2 VaultV2 + VaultV2Factory) ----

  it('registers the Morpho Vault V2 keys under parameters with the agreed severity and byte-exact topic0s', () => {
    // Verified ABI of 0x244f46262d9ad408b746e74abdd010e9002fb7ee (UltraYield USDC Core) and of the
    // factory 0xa1d94f746defa1928926b84fb2596c06926c0405. key: [severity, ...canonical signatures].
    const want: Record<string, [string, ...string[]]> = {
      'vault.owner_set': ['critical', 'SetOwner(address)'],
      'vault.sentinel_set': ['critical', 'SetIsSentinel(address,bool)'],
      'vault.adapter_registry_set': ['critical', 'SetAdapterRegistry(address)'],
      'vault.adapter_added': ['high', 'AddAdapter(address)'],
      'vault.adapter_removed': ['high', 'RemoveAdapter(address)'],
      'vault.timelock_increased': ['info', 'IncreaseTimelock(bytes4,uint256)'],
      'vault.timelock_decreased': ['high', 'DecreaseTimelock(bytes4,uint256)'],
      'vault.action_submitted': ['high', 'Submit(bytes4,bytes,uint256)'],
      'vault.action_revoked': ['high', 'Revoke(address,bytes4,bytes)'],
      'vault.function_abdicated': ['high', 'Abdicate(bytes4)'],
      'vault.cap_increased': ['high', 'IncreaseAbsoluteCap(bytes32,bytes,uint256)', 'IncreaseRelativeCap(bytes32,bytes,uint256)'],
      'vault.cap_decreased': ['high', 'DecreaseAbsoluteCap(address,bytes32,bytes,uint256)', 'DecreaseRelativeCap(address,bytes32,bytes,uint256)'],
      'vault.gate_set': ['critical', 'SetReceiveSharesGate(address)', 'SetSendSharesGate(address)', 'SetReceiveAssetsGate(address)', 'SetSendAssetsGate(address)'],
      'vault.max_rate_set': ['info', 'SetMaxRate(uint256)'],
      'vault.penalty_set': ['info', 'SetForceDeallocatePenalty(address,uint256)'],
      'vault.liquidity_adapter_set': ['info', 'SetLiquidityAdapterAndData(address,address,bytes)'],
      'vault.metadata_set': ['info', 'SetName(string)', 'SetSymbol(string)'],
      'vault.created': ['info', 'CreateVaultV2(address,address,bytes32,address)'],
    };
    const seen = new Set<Hex>();
    for (const [key, [severity, ...signatures]] of Object.entries(want)) {
      const entries = byKey(key);
      expect(entries.length, key).toBe(signatures.length);
      for (const ev of entries) {
        expect(ev.category, key).toBe('parameters');
        expect(ev.severity, key).toBe(severity);
      }
      const topics = entries.map((e) => e.topic0).sort();
      expect(topics, key).toEqual(signatures.map((s) => keccak256(toBytes(s))).sort());
      for (const t of topics) {
        expect(seen.has(t), `${key} ${t}`).toBe(false);
        seen.add(t);
      }
    }
    expect(seen.size).toBe(24);
    // Shared signatures reuse the MetaMorpho keys instead of new ones: SetCurator(address) and
    // SetIsAllocator(address,bool) are byte-identical in both designs; the V2 fee events join the umbrellas.
    expect(EVENTS_BY_TOPIC0.get(keccak256(toBytes('SetCurator(address)')))?.map((e) => e.key)).toEqual(['vault.curator_set']);
    expect(EVENTS_BY_TOPIC0.get(keccak256(toBytes('SetIsAllocator(address,bool)')))?.map((e) => e.key)).toEqual(['vault.allocator_set']);
    expect(EVENTS_BY_TOPIC0.get(keccak256(toBytes('SetPerformanceFee(uint256)')))?.map((e) => e.key)).toEqual(['vault.fee_set']);
    expect(EVENTS_BY_TOPIC0.get(keccak256(toBytes('SetManagementFeeRecipient(address)')))?.map((e) => e.key)).toEqual(['vault.fee_recipient_set']);
    // Spot checks against topic0s seen in live logs of the two UltraYield Core vaults (blocks 24.93M+) and the factory.
    expect(firstByKey('vault.action_submitted').topic0).toBe('0x8b18afeb361b83b025999ed5b42f1d90c68aaa5a0fd49c015f04c3b8b81e80eb');
    expect(firstByKey('vault.adapter_added').topic0).toBe('0x8f125a24838c4c23e893904b255b5c672d43d4cb8af7e3d15841eaeabc1e68aa');
    expect(firstByKey('vault.sentinel_set').topic0).toBe('0x8da69db4003c01b5c7be66a7bb5953423222e5118b6af0aadf54e75feef5bc50');
    expect(firstByKey('vault.function_abdicated').topic0).toBe('0xa8480b135a28741e8c059528bf8f82de70278485fb86bfc816a183801f0a8570');
    expect(firstByKey('vault.created').topic0).toBe('0x341ce009267aa0d78cc12b34155e223904a51ed49d144beb6eb8be87813edb4e');
    expect(byKey('vault.cap_increased').map((e) => e.topic0).sort()).toEqual(
      ['0x7368d59ed82f6a538f6deef9baa54623fe3699ce07b19031f762f740c8c34b03', '0x2a343b9a1ceba40853d01c6adeea53f5c0e4b95b4eb870ed4af309a0ead7e399'].sort(),
    );
    // Decoding an umbrella member keeps the member's own arg names (the describers branch on them).
    const gate = EVENTS.find((e) => e.key === 'vault.gate_set' && e.abi.name === 'SetSendAssetsGate');
    expect(gate?.abi.inputs.map((i) => i.name)).toEqual(['newSendAssetsGate']);
  });

  // ---- 2026-09-22: coverage batch 1 (Aave V3 configuration, pause dialects, Compound V2 admin, Euler factory) ----

  it('registers coverage batch 1 with the agreed category / severity and byte-exact topic0s', () => {
    // key: [category, severity, ...canonical signatures]. Sources: aave-dao/aave-v3-origin (main + v3.3.0) and
    // aave/aave-v3-core 3.0.2 interfaces, circlefin/stablecoin-evm Pausable, lidofinance/core PausableUntil,
    // Layr-Labs IPausable, balancer-v3 IVaultEvents, compound comet CometMainInterface, compound-protocol
    // Unitroller / CTokenInterfaces / Comptroller, euler-vault-kit GenericFactory / ProtocolConfig,
    // ethereum-optimism op-contracts/v1.8.0 SuperchainConfig.
    const want: Record<string, [string, string, ...string[]]> = {
      'pause.paused': ['pause', 'high', 'Paused(address)', 'Pause()', 'Paused(uint256)', 'Paused(address,uint256)', 'Paused(string)'],
      'pause.unpaused': ['pause', 'info', 'Unpaused(address)', 'Unpause()', 'Resumed()', 'Unpaused(address,uint256)', 'Unpaused()'],
      'pause.state_changed': ['pause', 'high', 'VaultPausedStateChanged(bool)', 'PauseAction(bool,bool,bool,bool,bool)'],
      'lending.pool_updated': ['upgrade', 'critical', 'PoolUpdated(address,address)'],
      'lending.pool_configurator_updated': ['upgrade', 'critical', 'PoolConfiguratorUpdated(address,address)'],
      'lending.price_oracle_set': ['parameters', 'critical', 'PriceOracleUpdated(address,address)', 'NewPriceOracle(address,address)'],
      'lending.acl_manager_updated': ['access', 'critical', 'ACLManagerUpdated(address,address)'],
      'lending.acl_admin_updated': ['access', 'critical', 'ACLAdminUpdated(address,address)'],
      'lending.price_oracle_sentinel_updated': ['parameters', 'high', 'PriceOracleSentinelUpdated(address,address)'],
      'lending.pool_data_provider_updated': ['parameters', 'high', 'PoolDataProviderUpdated(address,address)'],
      'lending.provider_proxy_created': ['upgrade', 'critical', 'ProxyCreated(bytes32,address,address)'],
      'lending.provider_address_set': ['parameters', 'critical', 'AddressSet(bytes32,address,address)'],
      'lending.provider_proxy_upgraded': ['upgrade', 'critical', 'AddressSetAsProxy(bytes32,address,address,address)'],
      'lending.market_id_set': ['parameters', 'info', 'MarketIdSet(string,string)'],
      'oracle.asset_source_updated': ['parameters', 'critical', 'AssetSourceUpdated(address,address)'],
      'oracle.fallback_oracle_updated': ['parameters', 'critical', 'FallbackOracleUpdated(address)'],
      'lending.reserve_paused': ['pause', 'critical', 'ReservePaused(address,bool)'],
      'lending.reserve_frozen': ['parameters', 'critical', 'ReserveFrozen(address,bool)'],
      'lending.reserve_active': ['parameters', 'critical', 'ReserveActive(address,bool)'],
      'lending.reserve_dropped': ['parameters', 'critical', 'ReserveDropped(address)'],
      'lending.collateral_config_changed': ['parameters', 'high', 'CollateralConfigurationChanged(address,uint256,uint256,uint256)'],
      'lending.pending_ltv_changed': ['parameters', 'high', 'PendingLtvChanged(address,uint256)'],
      'lending.interest_rate_model_set': ['parameters', 'high', 'ReserveInterestRateStrategyChanged(address,address,address)', 'NewMarketInterestRateModel(address,address)'],
      'lending.interest_rate_data_changed': ['parameters', 'high', 'ReserveInterestRateDataChanged(address,address,bytes)'],
      'lending.liquidation_protocol_fee_changed': ['parameters', 'high', 'LiquidationProtocolFeeChanged(address,uint256,uint256)'],
      'lending.emode_category_added': ['parameters', 'high', 'EModeCategoryAdded(uint8,uint256,uint256,uint256,address,string)'],
      'lending.emode_asset_changed': ['parameters', 'high', 'EModeAssetCategoryChanged(address,uint8,uint8)', 'AssetCollateralInEModeChanged(address,uint8,bool)', 'AssetBorrowableInEModeChanged(address,uint8,bool)'],
      'lending.debt_ceiling_changed': ['parameters', 'high', 'DebtCeilingChanged(address,uint256,uint256)'],
      'lending.siloed_borrowing_changed': ['parameters', 'high', 'SiloedBorrowingChanged(address,bool,bool)'],
      'lending.borrowable_in_isolation_changed': ['parameters', 'high', 'BorrowableInIsolationChanged(address,bool)'],
      'lending.supply_cap_changed': ['parameters', 'high', 'SupplyCapChanged(address,uint256,uint256)'],
      'lending.borrow_cap_changed': ['parameters', 'high', 'BorrowCapChanged(address,uint256,uint256)', 'NewBorrowCap(address,uint256)'],
      'lending.reserve_flash_loaning': ['parameters', 'high', 'ReserveFlashLoaning(address,bool)'],
      'lending.reserve_borrowing': ['parameters', 'high', 'ReserveBorrowing(address,bool)'],
      'lending.reserve_stable_borrowing': ['parameters', 'high', 'ReserveStableRateBorrowing(address,bool)'],
      'lending.unbacked_mint_cap_changed': ['parameters', 'high', 'UnbackedMintCapChanged(address,uint256,uint256)'],
      'lending.liquidation_grace_period_changed': ['parameters', 'high', 'LiquidationGracePeriodChanged(address,uint40)', 'LiquidationGracePeriodDisabled(address)'],
      'lending.bridge_protocol_fee_updated': ['parameters', 'high', 'BridgeProtocolFeeUpdated(uint256,uint256)'],
      'lending.flashloan_premium_updated': ['parameters', 'high', 'FlashloanPremiumTotalUpdated(uint128,uint128)', 'FlashloanPremiumToProtocolUpdated(uint128,uint128)'],
      'lending.reserve_initialized': ['parameters', 'high', 'ReserveInitialized(address,address,address,address,address)'],
      'lending.atoken_upgraded': ['upgrade', 'high', 'ATokenUpgraded(address,address,address)'],
      'lending.stable_debt_token_upgraded': ['upgrade', 'high', 'StableDebtTokenUpgraded(address,address,address)'],
      'lending.variable_debt_token_upgraded': ['upgrade', 'high', 'VariableDebtTokenUpgraded(address,address,address)'],
      'lending.reserve_factor_changed': ['parameters', 'info', 'ReserveFactorChanged(address,uint256,uint256)', 'NewReserveFactor(uint256,uint256)'],
      'ownable.new_admin': ['ownership', 'critical', 'NewAdmin(address,address)'],
      'ownable.new_pending_admin': ['ownership', 'high', 'NewPendingAdmin(address,address)'],
      'lending.collateral_factor_set': ['parameters', 'high', 'NewCollateralFactor(address,uint256,uint256)'],
      'lending.close_factor_set': ['parameters', 'high', 'NewCloseFactor(uint256,uint256)'],
      'lending.liquidation_incentive_set': ['parameters', 'high', 'NewLiquidationIncentive(uint256,uint256)'],
      'lending.pause_guardian_set': ['access', 'critical', 'NewPauseGuardian(address,address)'],
      'lending.borrow_cap_guardian_set': ['access', 'high', 'NewBorrowCapGuardian(address,address)'],
      'lending.action_paused': ['pause', 'high', 'ActionPaused(string,bool)', 'ActionPaused(address,string,bool)'],
      'lending.market_listed': ['parameters', 'info', 'MarketListed(address)'],
      'lending.comptroller_set': ['parameters', 'critical', 'NewComptroller(address,address)'],
      'beacon.implementation_set': ['upgrade', 'critical', 'SetImplementation(address)'],
      'beacon.upgrade_admin_set': ['upgrade', 'critical', 'SetUpgradeAdmin(address)'],
      'ownable.admin_set': ['ownership', 'critical', 'SetAdmin(address)'],
      'protocol.fee_receiver_set': ['parameters', 'info', 'SetFeeReceiver(address)'],
      'protocol.fee_config_set': [
        'parameters',
        'info',
        'SetProtocolFeeShare(uint16,uint16)',
        'SetFeeConfigSetting(address,bool,address,uint16)',
        'SetInterestFeeRange(uint16,uint16)',
        'SetVaultInterestFeeRange(address,bool,uint16,uint16)',
      ],
    };
    const seen = new Set<Hex>();
    for (const [key, [category, severity, ...signatures]] of Object.entries(want)) {
      const entries = byKey(key);
      expect(entries.length, key).toBe(signatures.length);
      for (const ev of entries) {
        expect(ev.category, key).toBe(category);
        expect(ev.severity, key).toBe(severity);
      }
      const topics = entries.map((e) => e.topic0).sort();
      expect(topics, key).toEqual(signatures.map((s) => keccak256(toBytes(s))).sort());
      for (const t of topics) {
        expect(seen.has(t), `${key} ${t}`).toBe(false);
        seen.add(t);
      }
    }
    // 78 new topic0s + the 2 pre-existing OZ pause signatures.
    expect(seen.size).toBe(80);
    // The two-param Compound NewAdmin / NewPendingAdmin are distinct from the one-param Timelock events.
    expect(firstByKey('ownable.new_admin').topic0).not.toBe(firstByKey('timelock.new_admin').topic0);
    expect(firstByKey('ownable.new_pending_admin').topic0).not.toBe(firstByKey('timelock.new_pending_admin').topic0);
    // NewImplementation(address,address) stays on the delegator key, not duplicated.
    expect(EVENTS_BY_TOPIC0.get(keccak256(toBytes('NewImplementation(address,address)')))?.map((e) => e.key)).toEqual(['proxy.new_implementation']);
    // Spot checks against well-known selectors (Etherscan-visible on Aave V3 Ethereum core).
    expect(firstByKey('lending.reserve_frozen').topic0).toBe(keccak256(toBytes('ReserveFrozen(address,bool)')));
    expect(byKey('pause.paused').find((e) => e.abi.name === 'Pause')?.topic0).toBe('0x6985a02210a168e66602d3235cb6db0e70f92b3ba4d376a33c0f3d9434bff625');
    expect(firstByKey('ownable.new_admin').topic0).toBe('0xf9ffabca9c8276e99321725bcb43fb076a6c66a54b7f21c4e8146d8519b417dc');
    // Umbrella members keep their own arg names (the describers branch on them).
    expect(byKey('pause.paused').map((e) => e.abi.inputs.map((i) => i.name).join(',')).sort()).toEqual(['', 'account', 'account,newPausedStatus', 'duration', 'identifier'].sort());
    expect(byKey('lending.price_oracle_set').map((e) => e.abi.inputs[1]?.name).sort()).toEqual(['newAddress', 'newPriceOracle']);
  });

  it('decodes the non-OZ pause dialects under the shared keys and the Compound ActionPaused overloads', () => {
    const pause = byKey('pause.paused').find((e) => e.abi.name === 'Pause')!;
    const p = decodeWatchedLog({ topics: [pause.topic0], data: '0x' })!;
    expect(p.event.key).toBe('pause.paused');
    expect(p.args).toEqual({});
    expect(p.initAnchor).toBe(false);

    const lido = byKey('pause.paused').find((e) => e.abi.inputs[0]?.name === 'duration')!;
    const l = decodeWatchedLog(encodeLog(lido.abi, { duration: 2n ** 256n - 1n }))!;
    expect(l.event.key).toBe('pause.paused');
    expect(l.args).toEqual({ duration: (2n ** 256n - 1n).toString() });

    const eigen = byKey('pause.paused').find((e) => e.abi.inputs.length === 2)!;
    const e = decodeWatchedLog(encodeLog(eigen.abi, { account: ALICE, newPausedStatus: 3n }))!;
    expect(e.args).toEqual({ account: ALICE.toLowerCase(), newPausedStatus: '3' });

    const op = byKey('pause.paused').find((e) => e.abi.inputs[0]?.name === 'identifier')!;
    const o = decodeWatchedLog(encodeLog(op.abi, { identifier: 'Guardian' }))!;
    expect(o.args).toEqual({ identifier: 'Guardian' });

    const resumed = byKey('pause.unpaused').find((e) => e.abi.name === 'Resumed')!;
    expect(decodeWatchedLog({ topics: [resumed.topic0], data: '0x' })!.event.key).toBe('pause.unpaused');

    const perMarket = byKey('lending.action_paused').find((e) => e.abi.inputs.length === 3)!;
    const a = decodeWatchedLog(encodeLog(perMarket.abi, { cToken: BOB, action: 'Borrow', pauseState: true }))!;
    expect(a.event.key).toBe('lending.action_paused');
    expect(a.args).toEqual({ cToken: BOB.toLowerCase(), action: 'Borrow', pauseState: true });

    const frozen = firstByKey('lending.reserve_frozen');
    const f = decodeWatchedLog(encodeLog(frozen.abi, { asset: ALICE, frozen: true }))!;
    expect(f.event.severity).toBe('critical');
    expect(f.args).toEqual({ asset: ALICE.toLowerCase(), frozen: true });
    expect(f.initAnchor).toBe(false);

    const newAdmin = firstByKey('ownable.new_admin');
    const n = decodeWatchedLog(encodeLog(newAdmin.abi, { oldAdmin: ZERO, newAdmin: BOB }))!;
    expect(n.event.key).toBe('ownable.new_admin');
    expect(n.args).toEqual({ oldAdmin: ZERO, newAdmin: BOB.toLowerCase() });
    // A first admin assignment is not flagged here: the watcher's fresh-deployment layer covers it.
    expect(n.initAnchor).toBe(false);
  });

  // ---- 2026-09-23: coverage batch 2 (Lido / Aragon, OP Stack and Arbitrum roots of trust on L1) ----

  it('registers coverage batch 2 with the agreed category / severity and byte-exact topic0s', () => {
    // key: [category, severity, ...canonical signatures]. Sources: aragon/aragonOS IKernel + ACL, lidofinance/core
    // Pausable (0.4.24) + Lido.sol + sr/ISRBase.sol, optimism op-contracts/v1.8.0 SystemConfig / SuperchainConfig /
    // DisputeGameFactory / OptimismPortal2 (GameType uint32, Timestamp uint64 per LibUDT), nitro-contracts v3.1.0
    // IRollupAdmin / IBridge / ISequencerInbox (+ v2.1.0 IRollupAdmin OwnerFunctionCalled), upgrade-executor.
    const want: Record<string, [string, string, ...string[]]> = {
      'aragon.app_set': ['upgrade', 'critical', 'SetApp(bytes32,bytes32,address)'],
      'aragon.permission_set': ['access', 'high', 'SetPermission(address,address,bytes32,bool)'],
      'aragon.permission_params_set': ['access', 'high', 'SetPermissionParams(address,address,bytes32,bytes32)'],
      'aragon.permission_manager_changed': ['access', 'critical', 'ChangePermissionManager(address,bytes32,address)'],
      'staking.stopped': ['pause', 'critical', 'Stopped()'],
      'staking.staking_paused': ['pause', 'high', 'StakingPaused()'],
      'staking.staking_resumed': ['pause', 'info', 'StakingResumed()'],
      'staking.staking_limit_set': ['parameters', 'info', 'StakingLimitSet(uint256,uint256)'],
      'staking.staking_limit_removed': ['parameters', 'info', 'StakingLimitRemoved()'],
      'staking.locator_set': ['parameters', 'critical', 'LidoLocatorSet(address)'],
      'staking.max_external_ratio_set': ['parameters', 'info', 'MaxExternalRatioBPSet(uint256)'],
      'staking.module_status_set': ['pause', 'high', 'StakingModuleStatusSet(uint256,uint8,address)'],
      'staking.module_added': ['parameters', 'info', 'StakingModuleAdded(uint256,address,string,address)'],
      'rollup.config_updated': ['parameters', 'critical', 'ConfigUpdate(uint256,uint8,bytes)', 'ConfigUpdate(uint8,bytes)'],
      'rollup.game_implementation_set': ['upgrade', 'critical', 'ImplementationSet(address,uint32)'],
      'rollup.init_bond_updated': ['parameters', 'high', 'InitBondUpdated(uint32,uint256)'],
      'rollup.respected_game_type_set': ['parameters', 'critical', 'RespectedGameTypeSet(uint32,uint64)'],
      'rollup.dispute_game_blacklisted': ['parameters', 'high', 'DisputeGameBlacklisted(address)'],
      'rollup.owner_function_called': ['parameters', 'high', 'OwnerFunctionCalled(uint256)'],
      'rollup.inbox_toggled': ['parameters', 'critical', 'InboxToggle(address,bool)'],
      'rollup.outbox_toggled': ['parameters', 'critical', 'OutboxToggle(address,bool)'],
      'rollup.sequencer_inbox_set': ['parameters', 'critical', 'SequencerInboxUpdated(address)', 'SequencerInboxSet(address)'],
      'rollup.rollup_updated': ['upgrade', 'critical', 'RollupUpdated(address)'],
      'rollup.keyset_set': ['parameters', 'critical', 'SetValidKeyset(bytes32,bytes)'],
      'rollup.keyset_invalidated': ['parameters', 'critical', 'InvalidateKeyset(bytes32)'],
      'rollup.batch_poster_set': ['access', 'high', 'BatchPosterSet(address,bool)'],
      'rollup.sequencer_set': ['access', 'high', 'SequencerSet(address,bool)'],
      'rollup.batch_poster_manager_set': ['access', 'high', 'BatchPosterManagerSet(address)'],
      'rollup.upgrade_executed': ['upgrade', 'critical', 'UpgradeExecuted(address,uint256,bytes)'],
      'rollup.target_call_executed': ['upgrade', 'high', 'TargetCallExecuted(address,uint256,bytes)'],
      'rollup.wasm_module_root_set': ['upgrade', 'critical', 'WasmModuleRootSet(bytes32)'],
      'rollup.validators_set': ['access', 'critical', 'ValidatorsSet(address[],bool[])'],
      'rollup.validator_whitelist_disabled_set': ['access', 'critical', 'ValidatorWhitelistDisabledSet(bool)'],
      'rollup.fast_confirmer_set': ['access', 'critical', 'AnyTrustFastConfirmerSet(address)'],
      'rollup.confirm_period_set': ['parameters', 'critical', 'ConfirmPeriodBlocksSet(uint64)'],
      'rollup.base_stake_set': ['parameters', 'high', 'BaseStakeSet(uint256)'],
      'rollup.outbox_set': ['parameters', 'critical', 'OutboxSet(address)'],
      'rollup.inbox_set': ['parameters', 'critical', 'InboxSet(address)'],
      'rollup.delayed_inbox_set': ['parameters', 'critical', 'DelayedInboxSet(address,bool)'],
      'rollup.challenge_manager_set': ['upgrade', 'critical', 'ChallengeManagerSet(address)'],
      'rollup.assertion_forced': ['parameters', 'critical', 'AssertionForceCreated(bytes32)', 'AssertionForceConfirmed(bytes32)'],
      'rollup.stakers_force_refunded': ['parameters', 'high', 'StakersForceRefunded(address[])'],
    };
    const seen = new Set<Hex>();
    for (const [key, [category, severity, ...signatures]] of Object.entries(want)) {
      const entries = byKey(key);
      expect(entries.length, key).toBe(signatures.length);
      for (const ev of entries) {
        expect(ev.category, key).toBe(category);
        expect(ev.severity, key).toBe(severity);
      }
      const topics = entries.map((e) => e.topic0).sort();
      expect(topics, key).toEqual(signatures.map((s) => keccak256(toBytes(s))).sort());
      for (const t of topics) {
        expect(seen.has(t), `${key} ${t}`).toBe(false);
        seen.add(t);
      }
    }
    // 45 new topic0s under 42 keys.
    expect(seen.size).toBe(45);
    expect(Object.keys(want).length).toBe(42);
    // Resumed() stays the batch-1 pause.unpaused dialect (Lido Pausable and PausableUntil share the signature).
    expect(EVENTS_BY_TOPIC0.get(keccak256(toBytes('Resumed()')))?.map((e) => e.key)).toEqual(['pause.unpaused']);
    // Spot checks against well-known selectors: Aragon SetApp and OP SystemConfig ConfigUpdate as seen on Etherscan.
    expect(firstByKey('aragon.app_set').topic0).toBe(keccak256(toBytes('SetApp(bytes32,bytes32,address)')));
    expect(byKey('rollup.config_updated').find((e) => e.abi.inputs.length === 3)?.topic0).toBe('0x1d2b0bda21d56b8bd12d4f94ebacffdfb35f5e226f84b461103bb8beab6353be');
    // Umbrella members keep their own arg shapes (the describers branch on `version`).
    expect(byKey('rollup.config_updated').map((e) => e.abi.inputs.map((i) => i.name).join(',')).sort()).toEqual(['updateType,data', 'version,updateType,data']);
  });

  it('decodes SetApp, SetPermission, ConfigUpdate and ValidatorsSet with lowercased addresses and JSON-safe values', () => {
    const setApp = firstByKey('aragon.app_set');
    const ns = keccak256(toBytes('base'));
    const appId = '0x3ca7c3e38968823ccb4c78ea688df41356f182ae1d159e4ee608d30d68cef320' as Hex; // lido.aragonpm.eth
    const a = decodeWatchedLog(encodeLog(setApp.abi, { namespace: ns, appId, app: ALICE }))!;
    expect(a.event.key).toBe('aragon.app_set');
    expect(a.args).toEqual({ namespace: ns, appId, app: ALICE.toLowerCase() });
    expect(a.initAnchor).toBe(false);

    const perm = firstByKey('aragon.permission_set');
    const role = keccak256(toBytes('PAUSE_ROLE'));
    const p = decodeWatchedLog(encodeLog(perm.abi, { entity: BOB, app: ALICE, role, allowed: true }))!;
    expect(p.args).toEqual({ entity: BOB.toLowerCase(), app: ALICE.toLowerCase(), role, allowed: true });

    const sysCfg = byKey('rollup.config_updated').find((e) => e.abi.inputs.length === 3)!;
    const signerWord = `0x${'0'.repeat(24)}${ALICE.slice(2).toLowerCase()}` as Hex;
    const c = decodeWatchedLog(encodeLog(sysCfg.abi, { version: 0n, updateType: 3, data: signerWord }))!;
    expect(c.event.key).toBe('rollup.config_updated');
    expect(c.args).toEqual({ version: '0', updateType: 3, data: signerWord });
    const superCfg = byKey('rollup.config_updated').find((e) => e.abi.inputs.length === 2)!;
    const g = decodeWatchedLog(encodeLog(superCfg.abi, { updateType: 0, data: '0x' }))!;
    expect(g.args).toEqual({ updateType: 0, data: '0x' });

    const validators = firstByKey('rollup.validators_set');
    const v = decodeWatchedLog(encodeLog(validators.abi, { validators: [ALICE, BOB], enabled: [true, false] }))!;
    expect(v.args).toEqual({ validators: [ALICE.toLowerCase(), BOB.toLowerCase()], enabled: [true, false] });

    const stopped = firstByKey('staking.stopped');
    expect(decodeWatchedLog({ topics: [stopped.topic0], data: '0x' })!.event.severity).toBe('critical');
  });

  // ---- 2026-09-26: Aave V4 (Hub / Spoke / AaveOracle / rate strategy) and OpenZeppelin 5.x AccessManager ----

  it('registers Aave V4 and the OZ AccessManager with the agreed category / severity and byte-exact topic0s', () => {
    // key: [category, severity, canonical signature]. Sources: aave/aave-v4 main @ 40232a0 IHub.sol / IHubBase.sol
    // (structs) / ISpoke.sol / IAaveOracle.sol / IAssetInterestRateStrategy.sol, OZ 5.5.0 IAccessManaged.sol /
    // IAccessManager.sol. Tuples are the inline struct layouts; every topic0 below was matched against live logs of
    // the Ethereum Core Hub / Main Spoke and the Base Equities Hub / MAG7 Spoke on 2026-09-26 (UpdateDynamicReserveConfig
    // shares its layout with AddDynamicReserveConfig, which fired).
    const want: Record<string, [string, string, string]> = {
      'lending.hub_asset_added': ['parameters', 'high', 'AddAsset(uint256,address,uint8)'],
      'lending.hub_asset_config_updated': ['parameters', 'high', 'UpdateAssetConfig(uint256,(address,uint16,address,address))'],
      'lending.hub_spoke_added': ['parameters', 'high', 'AddSpoke(uint256,address)'],
      'lending.hub_spoke_config_updated': ['parameters', 'high', 'UpdateSpokeConfig(uint256,address,(uint40,uint40,uint24,bool,bool))'],
      'lending.hub_rate_data_changed': ['parameters', 'high', 'UpdateInterestRateData(address,uint256,uint256,uint256,uint256,uint256)'],
      'lending.spoke_liquidation_config_updated': ['parameters', 'high', 'UpdateLiquidationConfig((uint128,uint64,uint16))'],
      'lending.spoke_reserve_added': ['parameters', 'high', 'AddReserve(uint256,uint256,address)'],
      'lending.spoke_reserve_config_updated': ['parameters', 'critical', 'UpdateReserveConfig(uint256,(uint24,bool,bool,bool,bool))'],
      'lending.spoke_reserve_price_source_updated': ['parameters', 'critical', 'UpdateReservePriceSource(uint256,address)'],
      'lending.spoke_dynamic_config_added': ['parameters', 'high', 'AddDynamicReserveConfig(uint256,uint32,(uint16,uint32,uint16))'],
      'lending.spoke_dynamic_config_updated': ['parameters', 'high', 'UpdateDynamicReserveConfig(uint256,uint32,(uint16,uint32,uint16))'],
      'lending.spoke_position_manager_updated': ['access', 'high', 'UpdatePositionManager(address,bool)'],
      'oracle.reserve_source_updated': ['parameters', 'critical', 'UpdateReserveSource(uint256,address)'],
      'access.authority_updated': ['access', 'critical', 'AuthorityUpdated(address)'],
      'access.manager_role_granted': ['access', 'high', 'RoleGranted(uint64,address,uint32,uint48,bool)'],
      'access.manager_role_revoked': ['access', 'info', 'RoleRevoked(uint64,address)'],
      'access.manager_role_admin_changed': ['access', 'high', 'RoleAdminChanged(uint64,uint64)'],
      'access.manager_role_guardian_changed': ['access', 'high', 'RoleGuardianChanged(uint64,uint64)'],
      'access.manager_role_grant_delay_changed': ['access', 'high', 'RoleGrantDelayChanged(uint64,uint32,uint48)'],
      'pause.target_closed': ['pause', 'critical', 'TargetClosed(address,bool)'],
      'access.manager_target_function_role_updated': ['access', 'critical', 'TargetFunctionRoleUpdated(address,bytes4,uint64)'],
      'access.manager_target_admin_delay_updated': ['access', 'high', 'TargetAdminDelayUpdated(address,uint32,uint48)'],
      'access.manager_operation_scheduled': ['timelock', 'high', 'OperationScheduled(bytes32,uint32,uint48,address,address,bytes)'],
      'access.manager_operation_executed': ['timelock', 'info', 'OperationExecuted(bytes32,uint32)'],
      'access.manager_operation_canceled': ['timelock', 'info', 'OperationCanceled(bytes32,uint32)'],
      'access.manager_role_label': ['access', 'info', 'RoleLabel(uint64,string)'],
    };
    expect(Object.keys(want)).toHaveLength(26);
    for (const [key, [category, severity, signature]] of Object.entries(want)) {
      const entries = byKey(key);
      expect(entries.length, key).toBe(1);
      const ev = entries[0]!;
      expect(ev.category, key).toBe(category);
      expect(ev.severity, key).toBe(severity);
      expect(ev.topic0, key).toBe(keccak256(toBytes(signature)));
    }
    // Byte-exact spot checks against the topic0s counted in the live logs on 2026-09-26.
    expect(firstByKey('lending.hub_spoke_config_updated').topic0).toBe('0x90984699e37aaae5f79c2f33e480f273509662005a8ff82a17b325eb7072454e');
    expect(firstByKey('lending.hub_spoke_added').topic0).toBe('0x47acdb603dbca71028fbd9b37192e17a62e64fa160e2e607eef3853b792ea5ab');
    expect(firstByKey('lending.spoke_reserve_config_updated').topic0).toBe('0xe9495512a0eb05fe0cbdd52286bdeb54cb8e5a8d50e7e17d75f75903a98e2af8');
    expect(firstByKey('lending.spoke_reserve_price_source_updated').topic0).toBe('0x18a45d070f507b6387b78837652d7468e733927acc7f9a13d9cc308675735c08');
    expect(firstByKey('oracle.reserve_source_updated').topic0).toBe('0xb828dda2b9aa56f34e592f8a1c065bf11753e12bed944560d220d26367bb8140');
    expect(firstByKey('access.authority_updated').topic0).toBe('0x2f658b440c35314f52658ea8a740e05b284cdc84dc9ae01e891f21b8933e7cad');
    expect(firstByKey('access.manager_role_granted').topic0).toBe('0xf98448b987f1428e0e230e1f3c6e2ce15b5693eaf31827fbd0b1ec4b424ae7cf');
    expect(firstByKey('access.manager_target_function_role_updated').topic0).toBe('0x9ea6790c7dadfd01c9f8b9762b3682607af2c7e79e05a9f9fdf5580dde949151');
    expect(firstByKey('pause.target_closed').topic0).toBe('0x90d4e7bb7e5d933792b3562e1741306f8be94837e1348dacef9b6f1df56eb138');
    // The uint64 AccessManager RoleGranted / RoleAdminChanged must not collide with the bytes32 AccessControl ones.
    expect(firstByKey('access.manager_role_granted').topic0).not.toBe(firstByKey('access.role_granted').topic0);
    expect(firstByKey('access.manager_role_admin_changed').topic0).not.toBe(firstByKey('access.role_admin_changed').topic0);

    // Struct args decode to a named object (normalizeValue: uint256 / uint64 -> decimal string, uint <= 48 bits
    // -> number, addresses lowercased), so the phrasers can read `config.paused` / `config.drawCap`.
    const reserveCfg = firstByKey('lending.spoke_reserve_config_updated');
    const d = decodeWatchedLog(encodeLog(reserveCfg.abi, { reserveId: 3n, config: { collateralRisk: 500, paused: true, frozen: false, borrowable: true, receiveSharesEnabled: false } }))!;
    expect(d.event.severity).toBe('critical');
    expect(d.args).toEqual({ reserveId: '3', config: { collateralRisk: 500, paused: true, frozen: false, borrowable: true, receiveSharesEnabled: false } });
    const spokeCfg = firstByKey('lending.hub_spoke_config_updated');
    const s = decodeWatchedLog(encodeLog(spokeCfg.abi, { assetId: 1n, spoke: ALICE, config: { addCap: 1000, drawCap: 500, riskPremiumThreshold: 0, active: true, halted: false } }))!;
    expect(s.args).toEqual({ assetId: '1', spoke: ALICE.toLowerCase(), config: { addCap: 1000, drawCap: 500, riskPremiumThreshold: 0, active: true, halted: false } });
    const granted = firstByKey('access.manager_role_granted');
    const g = decodeWatchedLog(encodeLog(granted.abi, { roleId: 200n, account: BOB, delay: 0, since: 1_790_000_000, newMember: true }))!;
    expect(g.args).toEqual({ roleId: '200', account: BOB.toLowerCase(), delay: 0, since: 1_790_000_000, newMember: true });
  });

  it('registers the Maker auth, Chainlink aggregator and Curve ownership keys with the agreed category/severity', () => {
    // key: [category, severity, topic0 = keccak256 of the canonical signature]
    const want: Record<string, [string, string, Hex]> = {
      'auth.rely': ['access', 'critical', '0xdd0e34038ac38b2a1ce960229778ac48a8719bc900b6c4f8d0475c6e8b385a60'],
      'auth.deny': ['access', 'high', '0x184450df2e323acec0ed3b5c7531b81f9b4cdef7914dfd4c0a4317416bb5251b'],
      'ownable.transfer_requested': ['ownership', 'high', '0xed8889f560326eb138920d842192f0eb3dd22b4f139c87a2c57538e05bae1278'],
      'ownable.commit_ownership': ['ownership', 'high', '0x2f56810a6bf40af059b96d3aea4db54081f378029a518390491093a7b67032e9'],
      'ownable.apply_ownership': ['ownership', 'critical', '0xebee2d5739011062cb4f14113f3b36bf0ffe3da5c0568f64189d1012a1189105'],
      'oracle.aggregator_proposed': ['parameters', 'high', '0xc0f151710f03d713b71d9970cee0d5b11ddc9a7552abaa3f6ee818010f21600d'],
      'oracle.aggregator_confirmed': ['parameters', 'critical', '0x33745f67a407dcb785417f9c123dd3641479a102674b6e35c1f10975625b90e9'],
    };
    for (const [key, [category, severity, topic0]] of Object.entries(want)) {
      const ev = firstByKey(key);
      expect(ev.category, key).toBe(category);
      expect(ev.severity, key).toBe(severity);
      expect(ev.topic0, key).toBe(topic0);
      expect(byKey(key).length, key).toBe(1);
    }
    const file = byKey('auth.file');
    expect(file.every((e) => e.category === 'parameters' && e.severity === 'info')).toBe(true);
    expect(file.map((e) => e.topic0).sort()).toEqual(
      [
        '0xe986e40cc8c151830d4f61050f4fb2e4add8567caad2d5f5496f9158e91fe4c7', // File(bytes32,uint256)
        '0x8fef588b5fc1afbf5b2f06c1a435d513f208da2e6704c3d8f0e0ec91167066ba', // File(bytes32,address)
        '0x851aa1caf4888170ad8875449d18f0f512fd6deb2a6571ea1a41fb9f95acbcd1', // File(bytes32,bytes32,uint256)
        '0x4ff2caaa972a7c6629ea01fae9c93d73cc307d13ea4c369f9bbbb7f9b7e9461d', // File(bytes32,bytes32,address)
      ].sort(),
    );
    // Curve's NewAdmin(address indexed admin) has the same topic0 as the Compound Timelock entry:
    // one registry entry, generic phrasing.
    expect(firstByKey('timelock.new_admin').topic0).toBe('0x71614071b88dee5e0b2ae578a9dd7b2ebbe9ae832ba419dc0242cd065a290b6c');
    expect(byKey('timelock.new_admin').length).toBe(1);
  });

  it('registers the Compound delegator events with non-indexed params and the right severity', () => {
    const impl = firstByKey('proxy.new_implementation');
    expect(impl.topic0).toBe('0xd604de94d45953f9138079ec1b82d533cb2160c906d1076d1f7ed54befbca97a');
    expect(impl.category).toBe('upgrade');
    expect(impl.severity).toBe('critical');
    expect(impl.abi.inputs.map((i) => i.indexed ?? false)).toEqual([false, false]);
    expect(byKey('proxy.new_implementation').length).toBe(1);

    const pending = firstByKey('proxy.new_pending_implementation');
    expect(pending.topic0).toBe('0xe945ccee5d701fc83f9b8aa8ca94ea4219ec1fcbd4f4cab4f0ea57c5c3e1d815');
    expect(pending.category).toBe('upgrade');
    expect(pending.severity).toBe('high');
    expect(pending.abi.inputs.map((i) => i.indexed ?? false)).toEqual([false, false]);
  });

  it('severityRank orders critical > high > info', () => {
    expect(severityRank('critical')).toBe(3);
    expect(severityRank('high')).toBe(2);
    expect(severityRank('info')).toBe(1);
  });
});

describe('decodeWatchedLog', () => {
  it('decodes Upgraded with a lowercased implementation address', () => {
    const ev = firstByKey('proxy.upgraded');
    const decoded = decodeWatchedLog(encodeLog(ev.abi, { implementation: ALICE }));
    expect(decoded).not.toBeNull();
    expect(decoded!.event.key).toBe('proxy.upgraded');
    expect(decoded!.event.severity).toBe('critical');
    expect(decoded!.args).toEqual({ implementation: ALICE.toLowerCase() });
    expect(decoded!.initAnchor).toBe(false);
  });

  it('flags OwnershipTransferred from the zero address as init, others not', () => {
    const ev = firstByKey('ownable.transferred');
    const init = decodeWatchedLog(encodeLog(ev.abi, { previousOwner: ZERO, newOwner: ALICE }));
    expect(init!.event.key).toBe('ownable.transferred');
    expect(init!.args).toEqual({ previousOwner: ZERO, newOwner: ALICE.toLowerCase() });
    expect(init!.initAnchor).toBe(true);

    const real = decodeWatchedLog(encodeLog(ev.abi, { previousOwner: ALICE, newOwner: BOB }));
    expect(real!.initAnchor).toBe(false);
    expect(real!.args).toEqual({ previousOwner: ALICE.toLowerCase(), newOwner: BOB.toLowerCase() });
  });

  it('decodes ChangedThreshold with bigint -> decimal string', () => {
    const ev = firstByKey('safe.changed_threshold');
    const decoded = decodeWatchedLog(encodeLog(ev.abi, { threshold: 3n }));
    expect(decoded!.event.key).toBe('safe.changed_threshold');
    expect(decoded!.args).toEqual({ threshold: '3' });
    expect(typeof decoded!.args['threshold']).toBe('string');
    expect(decoded!.initAnchor).toBe(false);
  });

  it('decodes both AddedOwner layouts (non-indexed v1.3 and indexed v1.4.1)', () => {
    const layouts = byKey('safe.added_owner');
    expect(layouts.length).toBe(2);
    const nonIndexed = layouts.find((l) => !l.abi.inputs[0]?.indexed)!;
    const indexed = layouts.find((l) => l.abi.inputs[0]?.indexed)!;

    const logA = encodeLog(nonIndexed.abi, { owner: ALICE });
    expect(logA.topics.length).toBe(1);
    expect(logA.data).not.toBe('0x');
    const a = decodeWatchedLog(logA);
    expect(a!.event.key).toBe('safe.added_owner');
    expect(a!.event.abi.inputs[0]?.indexed).toBeFalsy();
    expect(a!.args).toEqual({ owner: ALICE.toLowerCase() });

    const logB = encodeLog(indexed.abi, { owner: ALICE });
    expect(logB.topics.length).toBe(2);
    expect(logB.data).toBe('0x');
    const b = decodeWatchedLog(logB);
    expect(b!.event.key).toBe('safe.added_owner');
    expect(b!.event.abi.inputs[0]?.indexed).toBe(true);
    expect(b!.args).toEqual({ owner: ALICE.toLowerCase() });
  });

  it('flags Initialized(version == 1) as init and SafeSetup always', () => {
    const v4 = firstByKey('proxy.initialized');
    expect(decodeWatchedLog(encodeLog(v4.abi, { version: 1 }))!.initAnchor).toBe(true);
    expect(decodeWatchedLog(encodeLog(v4.abi, { version: 2 }))!.initAnchor).toBe(false);

    const v5 = firstByKey('proxy.initialized_v5');
    const d5 = decodeWatchedLog(encodeLog(v5.abi, { version: 1n }))!;
    expect(d5.event.key).toBe('proxy.initialized_v5');
    expect(d5.args).toEqual({ version: '1' });
    expect(d5.initAnchor).toBe(true);

    const setup = firstByKey('safe.setup');
    const s = decodeWatchedLog(
      encodeLog(setup.abi, {
        initiator: ALICE,
        owners: [ALICE, BOB],
        threshold: 2n,
        initializer: ZERO,
        fallbackHandler: BOB,
      }),
    )!;
    expect(s.event.key).toBe('safe.setup');
    expect(s.initAnchor).toBe(true);
    expect(s.args).toEqual({
      initiator: ALICE.toLowerCase(),
      owners: [ALICE.toLowerCase(), BOB.toLowerCase()],
      threshold: '2',
      initializer: ZERO,
      fallbackHandler: BOB.toLowerCase(),
    });
  });

  it('decodes NewImplementation from data and flags the first assignment (old = 0x0) as init', () => {
    const ev = firstByKey('proxy.new_implementation');
    const first = encodeLog(ev.abi, { oldImplementation: ZERO, newImplementation: ALICE });
    expect(first.topics.length).toBe(1); // nothing indexed: both addresses live in data
    expect(first.data.length).toBe(2 + 64 * 2);
    const init = decodeWatchedLog(first)!;
    expect(init.event.key).toBe('proxy.new_implementation');
    expect(init.event.severity).toBe('critical');
    expect(init.args).toEqual({ oldImplementation: ZERO, newImplementation: ALICE.toLowerCase() });
    expect(init.initAnchor).toBe(true);

    const real = decodeWatchedLog(encodeLog(ev.abi, { oldImplementation: ALICE, newImplementation: BOB }))!;
    expect(real.args).toEqual({ oldImplementation: ALICE.toLowerCase(), newImplementation: BOB.toLowerCase() });
    expect(real.initAnchor).toBe(false);
  });

  it('decodes NewPendingImplementation as high and never as init', () => {
    const ev = firstByKey('proxy.new_pending_implementation');
    const d = decodeWatchedLog(encodeLog(ev.abi, { oldPendingImplementation: ZERO, newPendingImplementation: BOB }))!;
    expect(d.event.key).toBe('proxy.new_pending_implementation');
    expect(d.event.severity).toBe('high');
    expect(d.args).toEqual({ oldPendingImplementation: ZERO, newPendingImplementation: BOB.toLowerCase() });
    expect(d.initAnchor).toBe(false);
  });

  // ---- 2026-09-07: Maker auth, Chainlink aggregator proxy, Curve ownership -------------------

  it('decodes Rely / Deny with the ward in topics and never flags them as init by itself', () => {
    const rely = firstByKey('auth.rely');
    const logR = encodeLog(rely.abi, { usr: ALICE });
    expect(logR.topics.length).toBe(2);
    expect(logR.data).toBe('0x');
    const r = decodeWatchedLog(logR)!;
    expect(r.event.key).toBe('auth.rely');
    expect(r.event.severity).toBe('critical');
    expect(r.args).toEqual({ usr: ALICE.toLowerCase() });
    // The deploying tx's Rely(msg.sender) is flagged by the watcher layers, not by the decoder.
    expect(r.initAnchor).toBe(false);

    const deny = firstByKey('auth.deny');
    const d = decodeWatchedLog(encodeLog(deny.abi, { usr: BOB }))!;
    expect(d.event.key).toBe('auth.deny');
    expect(d.event.severity).toBe('high');
    expect(d.args).toEqual({ usr: BOB.toLowerCase() });
    expect(d.initAnchor).toBe(false);
  });

  it('decodes all four File overloads under the single auth.file key, keeping bytes32 names raw', () => {
    const layouts = byKey('auth.file');
    const LINE = '0x6c696e6500000000000000000000000000000000000000000000000000000000' as const; // "line"
    const ETH_A = '0x4554482d41000000000000000000000000000000000000000000000000000000' as const; // "ETH-A"
    const VOW = '0x766f770000000000000000000000000000000000000000000000000000000000' as const; // "vow"
    const pick = (n: number, last: string) => layouts.find((l) => l.abi.inputs.length === n && l.abi.inputs[n - 1]?.type === last)!;

    const g = decodeWatchedLog(encodeLog(pick(2, 'uint256').abi, { what: LINE, data: 1_000_000n * 10n ** 45n }))!;
    expect(g.event.key).toBe('auth.file');
    expect(g.event.category).toBe('parameters');
    expect(g.args).toEqual({ what: LINE, data: (1_000_000n * 10n ** 45n).toString() });
    expect(g.initAnchor).toBe(false);

    const ga = decodeWatchedLog(encodeLog(pick(2, 'address').abi, { what: VOW, data: ALICE }))!;
    expect(ga.event.key).toBe('auth.file');
    expect(ga.args).toEqual({ what: VOW, data: ALICE.toLowerCase() });

    const i = decodeWatchedLog(encodeLog(pick(3, 'uint256').abi, { ilk: ETH_A, what: LINE, data: 5n }))!;
    expect(i.event.key).toBe('auth.file');
    expect(i.args).toEqual({ ilk: ETH_A, what: LINE, data: '5' });

    const ia = decodeWatchedLog(encodeLog(pick(3, 'address').abi, { ilk: ETH_A, what: VOW, data: BOB }))!;
    expect(ia.event.key).toBe('auth.file');
    expect(ia.args).toEqual({ ilk: ETH_A, what: VOW, data: BOB.toLowerCase() });
    // The two-param and three-param overloads have different topic counts, so they cannot be confused.
    expect(encodeLog(pick(2, 'uint256').abi, { what: LINE, data: 1n }).topics.length).toBe(2);
    expect(encodeLog(pick(3, 'uint256').abi, { ilk: ETH_A, what: LINE, data: 1n }).topics.length).toBe(3);
  });

  it('decodes the Chainlink aggregator proxy pair and OwnershipTransferRequested', () => {
    const proposed = firstByKey('oracle.aggregator_proposed');
    const p = decodeWatchedLog(encodeLog(proposed.abi, { current: ALICE, proposed: BOB }))!;
    expect(p.event.key).toBe('oracle.aggregator_proposed');
    expect(p.event.severity).toBe('high');
    expect(p.args).toEqual({ current: ALICE.toLowerCase(), proposed: BOB.toLowerCase() });
    expect(p.initAnchor).toBe(false);

    const confirmed = firstByKey('oracle.aggregator_confirmed');
    const c = decodeWatchedLog(encodeLog(confirmed.abi, { previous: ALICE, latest: BOB }))!;
    expect(c.event.key).toBe('oracle.aggregator_confirmed');
    expect(c.event.severity).toBe('critical');
    expect(c.args).toEqual({ previous: ALICE.toLowerCase(), latest: BOB.toLowerCase() });
    expect(c.initAnchor).toBe(false);

    const requested = firstByKey('ownable.transfer_requested');
    const r = decodeWatchedLog(encodeLog(requested.abi, { from: ALICE, to: BOB }))!;
    expect(r.event.key).toBe('ownable.transfer_requested');
    expect(r.event.category).toBe('ownership');
    expect(r.args).toEqual({ from: ALICE.toLowerCase(), to: BOB.toLowerCase() });
  });

  it('decodes Curve CommitOwnership / ApplyOwnership from data (non-indexed admin)', () => {
    const commit = firstByKey('ownable.commit_ownership');
    const logC = encodeLog(commit.abi, { admin: ALICE });
    expect(logC.topics.length).toBe(1);
    expect(logC.data.length).toBe(2 + 64);
    const c = decodeWatchedLog(logC)!;
    expect(c.event.key).toBe('ownable.commit_ownership');
    expect(c.event.severity).toBe('high');
    expect(c.args).toEqual({ admin: ALICE.toLowerCase() });

    const apply = firstByKey('ownable.apply_ownership');
    const a = decodeWatchedLog(encodeLog(apply.abi, { admin: BOB }))!;
    expect(a.event.key).toBe('ownable.apply_ownership');
    expect(a.event.severity).toBe('critical');
    expect(a.args).toEqual({ admin: BOB.toLowerCase() });
    expect(a.initAnchor).toBe(false);

    // Curve NewAdmin(address indexed admin) decodes through the shared Compound entry.
    const newAdmin = firstByKey('timelock.new_admin');
    const n = decodeWatchedLog(encodeLog(newAdmin.abi, { newAdmin: BOB }))!;
    expect(n.event.key).toBe('timelock.new_admin');
    expect(n.args).toEqual({ newAdmin: BOB.toLowerCase() });
  });

  // ---- 2026-09-18: vault governance ----------------------------------------------------------

  it('decodes MetaMorpho SetCap (bytes32 market id in topics) and the RevokePending* umbrella key', () => {
    const MARKET = '0xb323495f7e4148be5643a4ea4a8221eef163e4bccfdedc2a6f4696baacbc86cc' as const;
    const cap = firstByKey('vault.cap_set');
    const log = encodeLog(cap.abi, { caller: ALICE, id: MARKET, cap: 1_000_000n * 10n ** 6n });
    expect(log.topics.length).toBe(3);
    const d = decodeWatchedLog(log)!;
    expect(d.event.key).toBe('vault.cap_set');
    expect(d.event.severity).toBe('high');
    expect(d.args).toEqual({ caller: ALICE.toLowerCase(), id: MARKET, cap: (1_000_000n * 10n ** 6n).toString() });
    expect(d.initAnchor).toBe(false);

    const revokes = byKey('vault.pending_revoked');
    const withId = revokes.find((e) => e.abi.name === 'RevokePendingCap')!;
    const noId = revokes.find((e) => e.abi.name === 'RevokePendingTimelock')!;
    const r1 = decodeWatchedLog(encodeLog(withId.abi, { caller: BOB, id: MARKET }))!;
    expect(r1.event.key).toBe('vault.pending_revoked');
    expect(r1.event.abi.name).toBe('RevokePendingCap');
    expect(r1.args).toEqual({ caller: BOB.toLowerCase(), id: MARKET });
    const r2 = decodeWatchedLog(encodeLog(noId.abi, { caller: BOB }))!;
    expect(r2.event.key).toBe('vault.pending_revoked');
    expect(r2.event.abi.name).toBe('RevokePendingTimelock');
    expect(r2.args).toEqual({ caller: BOB.toLowerCase() });
  });

  it('decodes Euler GovSetLTV (1e4 ratios in data) and GovSetGovernorAdmin, never as init', () => {
    const ltv = firstByKey('vault.ltv_set');
    const d = decodeWatchedLog(
      encodeLog(ltv.abi, { collateral: ALICE, borrowLTV: 8300, liquidationLTV: 8600, initialLiquidationLTV: 8600, targetTimestamp: 1_800_000_000n, rampDuration: 0 }),
    )!;
    expect(d.event.key).toBe('vault.ltv_set');
    expect(d.event.category).toBe('parameters');
    expect(d.args).toEqual({
      collateral: ALICE.toLowerCase(),
      borrowLTV: 8300,
      liquidationLTV: 8600,
      initialLiquidationLTV: 8600,
      targetTimestamp: 1_800_000_000, // uint48 decodes to a JS number (viem), only wider ints become strings
      rampDuration: 0,
    });
    expect(d.initAnchor).toBe(false);

    const gov = firstByKey('vault.governor_admin_set');
    const g = decodeWatchedLog(encodeLog(gov.abi, { newGovernorAdmin: ZERO }))!;
    expect(g.event.key).toBe('vault.governor_admin_set');
    expect(g.event.severity).toBe('critical');
    expect(g.args).toEqual({ newGovernorAdmin: ZERO });
    // Renouncing the governor (0x0) is the opposite of setup noise: it must stay a real event.
    expect(g.initAnchor).toBe(false);
  });

  it('returns null for unknown topic0 and for undecodable data', () => {
    expect(
      decodeWatchedLog({
        topics: ['0x' + 'ab'.repeat(32)] as Hex[],
        data: '0x',
      }),
    ).toBeNull();
    expect(decodeWatchedLog({ topics: [], data: '0x' })).toBeNull();
    // Right topic0 but data too short for any layout
    const ev = firstByKey('safe.changed_threshold');
    expect(decodeWatchedLog({ topics: [ev.topic0], data: '0x' })).toBeNull();
  });
});

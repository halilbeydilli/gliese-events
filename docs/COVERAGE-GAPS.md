# What the registry does not cover

Kept honest on purpose. This list is derived from the coverage audit run against the
registry on 2026-09-22 and re-checked against the registry as published on 2026-09-26.
Items the audit raised that have since been added (Aave V3 configuration, the non-OpenZeppelin
pause dialects, Compound V2 admin, Euler factory, Lido / Aragon, OP Stack and Arbitrum roots of
trust, OpenZeppelin AccessManager, Aave V4) are not repeated here.

"Not covered" means: no signature in `src/registry.ts` has that topic0. A consumer that
watches only `TOPIC0S` will not see these changes.

## Families with no signatures in the registry

| Family | What is missing | Notes |
|---|---|---|
| Zodiac Delay / Roles modules | Delay `TransactionAdded`, `DelaySetup`; Roles `AssignRoles`, `SetDefaultRole`, `ScopeTarget`, `AllowTarget`, `RevokeTarget` | Safe `EnabledModule` / `DisabledModule` are covered, so the module being attached is seen; what it then does is not |
| Silo Vaults | cap, market-removal and queue events specific to Silo V2 vaults | the Silo events that reuse MetaMorpho signatures decode under the `vault.*` keys |
| Morpho Blue core | `EnableIrm`, `EnableLltv`, `CreateMarket`; PublicAllocator `SetAdmin`, `SetFlowCaps` | Blue `SetOwner` / `SetFeeRecipient` decode under `vault.owner_set` / `vault.fee_recipient_set` |
| Stablecoin issuers other than Circle | Tether `AddedBlackList` / `RemovedBlackList` / `DestroyedBlackFunds` / `Deprecate` / `Params`; Paxos roles and freezes; GHO facilitator events; CCTP attester set; Ethena minter / custodian events | Circle FiatToken (`token.*`) and CCTP pause are covered |
| Maker / Sky | DSAuth `LogSetOwner` / `LogSetAuthority`; End `Cage`; ESM `Fire`, `DenyProxy` | `Rely` / `Deny` / `File` are covered; DSPause `plot` / `exec` emit only anonymous `LogNote`, so spell scheduling has no topic0 to watch |
| Curve | `CommitNewAdmin`, `RampA`, `StopRampA`, `ApplyNewFee`; crvUSD `SetMonetaryPolicy`, `SetDebtCeiling`, `SetImplementations`, `AddMarket` | `CommitOwnership` / `ApplyOwnership` are covered |
| Uniswap | V3 factory `OwnerChanged`, `FeeAmountEnabled`; pool `SetFeeProtocol`; V4 `ProtocolFeeControllerUpdated` | |
| Balancer | V2 / V3 `AuthorizerChanged`, V3 `VaultPausedStateChanged`, `PoolPausedStateChanged`, `ProtocolFeeControllerChanged`, `PoolRecoveryModeStateChanged` | |
| Polygon PoS | `ProxyUpdated`, `ProxyOwnerUpdate` and the Polygon proxy storage slots | |
| LayerZero v2 | default send / receive library and ULN default-config events; per-OApp routing | |
| Lagoon, Gearbox, Yearn v3 | Lagoon `StateUpdated` / `ValuationManagerUpdated`; Gearbox credit-suite configuration; Yearn role and management events | |
| Midas | `ManageableVault` limits, fees, receivers and payment tokens | roles and Pausable on the same contracts are covered |
| Oracles other than Chainlink feeds and the Euler router | Pyth, RedStone, Chronicle admin events; Chainlink OCR `ConfigSet` | `AnswerUpdated` is excluded on purpose (price updates, not control changes) |
| Spark ALM | `RateLimitDataSet` | |
| Arbitrum SequencerInbox struct settings | `MaxTimeVariationSet`, `BufferConfigSet`, `FeeTokenPricerSet`; RollupAdmin `LoserStakeEscrowSet`, `MinimumAssertionPeriodSet`, `ValidatorAfkBlocksSet`, `OldOutboxRemoved` | left out as tuple plumbing and low-value noise |
| Lido module economics | `StakingModuleShareLimitSet`, `StakingModuleFeesSet`, `StakingModuleMaxDepositsPerBlockSet`, `StakingModuleMinDepositBlockDistanceSet` | |

## Structural limits of a topic0 registry

These cannot be closed by adding signatures; they need a storage or call-level view.
The `slot.*` keys in `src/synthetic.ts` describe what a storage-diff poller emits for some of
them, but the poller itself is not part of this package.

- Anything changed without an event: Safe singleton, guard, fallback handler and module list
  (`slot.safe_*`), a proxy whose implementation slot is written directly, Diamond facets swapped
  without `DiamondCut`, Aragon Kernel app mappings, OP Stack `AddressManager` entries.
- Ownable2Step `pendingOwner()` and Compound `pendingAdmin()` / `pendingImplementation()` states.
- Beacon owner chains, Arbitrum `UpgradeExecutor` three-hop paths, EIP-1167 clones.
- Code-hash changes of controller EOAs, including EIP-7702 delegations.
- Role hashes that are not a keccak of a name: Venus `AccessControlManager`
  (`keccak256(target, functionSignature)`) and Euler `GovernorAccessControl`
  (`bytes32(bytes4 selector)`) will never resolve through `roleNameOf`.

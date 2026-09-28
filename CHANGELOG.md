# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semver.

## [0.2.0] - 2026-09-28

Venus core pool (Diamond Comptroller) and ResilientOracle control events, read from
`VenusProtocol/venus-protocol` (`contracts/Comptroller/Diamond/facets/*`, `ComptrollerStorage.sol`)
and `VenusProtocol/oracle` (`contracts/ResilientOracle.sol`) and verified byte-for-byte against the
receipt of Venus VIP-663 (BNB tx `0x0592453d…a426`, 2026-09-28): the nine control logs that
release 0.1.0 left undecoded now decode.

### Added

- 15 keys: `lending.protocol_paused`, `lending.flash_loan_paused`, `lending.liquidation_threshold_set`,
  `lending.borrow_allowed_changed`, `lending.forced_liquidation_set`, `lending.market_unlisted`,
  `lending.access_control_set`, `lending.comptroller_lens_set`, `lending.treasury_guardian_set`,
  `lending.liquidator_set`, `lending.deviation_oracle_set`, `oracle.token_config_set`,
  `oracle.role_oracle_set`, `oracle.role_oracle_enabled`, `oracle.caching_set`.
- Venus layouts under existing keys: `lending.action_paused` (`ActionPausedMarket`),
  `lending.supply_cap_changed` (`NewSupplyCap`), `lending.collateral_factor_set` and
  `lending.liquidation_incentive_set` (pool-scoped four-argument forms), `lending.market_listed`
  (indexed-market layout of the shared topic0).
- Registry is now 284 signatures under 236 keys.

### Unchanged

- Venus events whose topic0 equals a Compound event (`NewCloseFactor`, `NewPauseGuardian`,
  `NewPriceOracle`, `NewBorrowCap`) stay single entries, as the shared-topic0 rule requires.

## [0.1.0] - 2026-09-26

First public release, mirrored from the `packages/events` workspace of Gliese Watch.

### Added

- `EVENTS`, `EVENTS_BY_TOPIC0`, `TOPIC0S`: 265 event signatures under 221 keys across
  9 categories (proxy upgrades, ownership, access control, pauses, Safe, timelocks,
  governance, token admin, protocol parameters), covering ERC-1967 and Compound-style
  proxies, Ownable / Ownable2Step / Chainlink ConfirmedOwner, OpenZeppelin AccessControl,
  AccessManager and TimelockController, Safe 1.3 and 1.4.1, Compound Timelock and Governor
  Bravo, Circle FiatToken, MakerDAO auth, Chainlink feed proxies, Curve ownership, Morpho
  MetaMorpho and Vault V2, Euler v2, Aave V3 and V4, Compound V2 admin, Lido / Aragon,
  OP Stack and Arbitrum roots of trust.
- `decodeWatchedLog`: strict decode of a raw log against every registered layout of its
  topic0, with JSON-safe, lowercase-address arguments and an `initAnchor` hint.
- `SYNTHETIC_EVENTS`: the `slot.*` keys a storage-diff poller emits for silent changes.
- `ROLE_NAME_BY_HASH` / `roleNameOf`: 190 role names hashed at load, plus
  `DEFAULT_ADMIN_ROLE`; `accessManagerRoleName` for OpenZeppelin AccessManager role ids.
- `VAULT_V2_SELECTOR_NAMES` / `vaultV2SelectorName` / `vaultV2Gate`: Morpho Vault V2 helpers.
- `severityRank`.

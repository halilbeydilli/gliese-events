# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow semver.

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

import type { Category, Severity } from './registry.js';

/**
 * Synthetic event keys produced by the slot poller.
 *
 * These are not on-chain logs: the poller compares EIP-1967 storage slots,
 * `owner()`, Safe owners/threshold, timelock delay and (2026-09-22) MetaMorpho
 * vault timelock / curator between two hourly snapshots and emits one of these
 * when a tracked field changed silently
 * (i.e. without a matching event log, or as a belt-and-braces duplicate of
 * one). They live in the same `events` table as decoded logs; the tx hash is
 * derived deterministically from (chain, address, field, block).
 */
export interface SyntheticEvent {
  /** Unique stable key, always prefixed with `slot.` */
  key: string;
  category: Category;
  severity: Severity;
  /** One-line English description */
  description: string;
}

type Spec = readonly [string, Category, Severity, string];

const SPECS: readonly Spec[] = [
  ['slot.implementation_changed', 'upgrade', 'critical', 'EIP-1967 implementation slot points at a new address (silent proxy upgrade).'],
  ['slot.admin_changed', 'upgrade', 'critical', 'EIP-1967 admin slot points at a new address (silent proxy admin change).'],
  ['slot.beacon_changed', 'upgrade', 'critical', 'EIP-1967 beacon slot points at a new address (silent beacon change).'],
  ['slot.owner_changed', 'ownership', 'critical', 'owner() returns a different address than the last snapshot.'],
  ['slot.safe_owners_changed', 'multisig', 'critical', 'Safe getOwners() set differs from the last snapshot.'],
  ['slot.safe_threshold_changed', 'multisig', 'critical', 'Safe getThreshold() differs from the last snapshot.'],
  ['slot.timelock_delay_changed', 'timelock', 'critical', 'Timelock minimum delay differs from the last snapshot.'],
  // MetaMorpho vault governance (2026-09-22): category `parameters`, like the vault.* log events.
  ['slot.vault_timelock_changed', 'parameters', 'critical', 'MetaMorpho vault timelock() differs from the last snapshot (silent timelock change).'],
  ['slot.curator_changed', 'parameters', 'critical', 'MetaMorpho vault curator() returns a different address than the last snapshot (silent curator change).'],
  // Safe silent surface (2026-09-23, coverage batch 2): the four things a delegatecall attack changes
  // without an event (Bybit 2025 swapped the master copy silently). Slot 0, the guard slot
  // keccak256("guard_manager.guard.address"), the fallback slot keccak256("fallback_manager.handler.address")
  // and getModulesPaginated(0x1, 50). Args of the modules event carry {added, removed} as well.
  ['slot.safe_singleton_changed', 'multisig', 'critical', 'Safe singleton (storage slot 0) points at a different master copy than the last snapshot (silent singleton swap).'],
  ['slot.safe_guard_changed', 'multisig', 'critical', 'Safe guard slot differs from the last snapshot (silent guard change or removal).'],
  ['slot.safe_fallback_changed', 'multisig', 'high', 'Safe fallback handler slot differs from the last snapshot (silent fallback handler change).'],
  ['slot.safe_modules_changed', 'multisig', 'critical', 'Safe module list (getModulesPaginated) differs from the last snapshot (silent module enable / disable).'],
  // AccessControl admin (2026-09-23): the set of DEFAULT_ADMIN_ROLE holders, rebuilt from RoleGranted /
  // RoleRevoked logs for proxies that expose no owner() / admin() (e.g. UltraVault UUPS proxies).
  ['slot.admin_role_holders_changed', 'access', 'critical', 'The set of DEFAULT_ADMIN_ROLE holders differs from the last snapshot (silent admin role change).'],
];

export const SYNTHETIC_EVENTS: Readonly<Record<string, SyntheticEvent>> = Object.freeze(
  Object.fromEntries(
    SPECS.map(([key, category, severity, description]) => [
      key,
      Object.freeze({ key, category, severity, description }) as SyntheticEvent,
    ]),
  ),
);

export const SYNTHETIC_EVENT_KEYS: readonly string[] = Object.freeze(SPECS.map((s) => s[0]));

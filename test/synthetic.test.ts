import { describe, expect, it } from 'vitest';
import { EVENTS, SYNTHETIC_EVENTS, SYNTHETIC_EVENT_KEYS } from '../src/index.js';

const EXPECTED: Record<string, { category: string; severity: string }> = {
  'slot.implementation_changed': { category: 'upgrade', severity: 'critical' },
  'slot.admin_changed': { category: 'upgrade', severity: 'critical' },
  'slot.beacon_changed': { category: 'upgrade', severity: 'critical' },
  'slot.owner_changed': { category: 'ownership', severity: 'critical' },
  'slot.safe_owners_changed': { category: 'multisig', severity: 'critical' },
  'slot.safe_threshold_changed': { category: 'multisig', severity: 'critical' },
  'slot.timelock_delay_changed': { category: 'timelock', severity: 'critical' },
  'slot.vault_timelock_changed': { category: 'parameters', severity: 'critical' },
  'slot.curator_changed': { category: 'parameters', severity: 'critical' },
  // Safe silent surface + AccessControl admin (2026-09-23)
  'slot.safe_singleton_changed': { category: 'multisig', severity: 'critical' },
  'slot.safe_guard_changed': { category: 'multisig', severity: 'critical' },
  'slot.safe_fallback_changed': { category: 'multisig', severity: 'high' },
  'slot.safe_modules_changed': { category: 'multisig', severity: 'critical' },
  'slot.admin_role_holders_changed': { category: 'access', severity: 'critical' },
};

describe('SYNTHETIC_EVENTS', () => {
  it('contains exactly the expected keys', () => {
    expect(Object.keys(SYNTHETIC_EVENTS).sort()).toEqual(Object.keys(EXPECTED).sort());
    expect([...SYNTHETIC_EVENT_KEYS].sort()).toEqual(Object.keys(EXPECTED).sort());
  });

  it('has the expected category and severity per key', () => {
    for (const [key, want] of Object.entries(EXPECTED)) {
      const ev = SYNTHETIC_EVENTS[key];
      expect(ev, key).toBeDefined();
      expect(ev?.key).toBe(key);
      expect(ev?.category).toBe(want.category);
      expect(ev?.severity).toBe(want.severity);
      expect(ev?.description.length).toBeGreaterThan(10);
    }
  });

  it('all keys use the slot. prefix and never collide with log-event keys', () => {
    const logKeys = new Set(EVENTS.map((e) => e.key));
    for (const key of Object.keys(SYNTHETIC_EVENTS)) {
      expect(key.startsWith('slot.')).toBe(true);
      expect(logKeys.has(key)).toBe(false);
    }
  });

  it('is frozen', () => {
    expect(Object.isFrozen(SYNTHETIC_EVENTS)).toBe(true);
    expect(Object.isFrozen(SYNTHETIC_EVENTS['slot.owner_changed'])).toBe(true);
  });
});

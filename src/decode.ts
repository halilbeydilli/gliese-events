import { decodeEventLog, type Hex } from 'viem';
import { EVENTS_BY_TOPIC0, type WatchedEvent } from './registry.js';

export interface DecodedEvent {
  event: WatchedEvent;
  /** JSON-safe: bigint -> decimal string, nested arrays/objects converted recursively, addresses lowercased */
  args: Record<string, unknown>;
  /**
   * The log *looks* like a construction / first-initialization marker (`Initialized(1)`,
   * `SafeSetup`, `OwnershipTransferred(0x0, …)`).
   *
   * A hint for diagnostics only — **never** a reason to set `events.is_init`. OP Stack proxies
   * re-emit `Initialized(1)` on every upgrade, so the shape of a log says nothing about whether
   * the contract is being born or being changed. That question is answered by the contract's age
   * (`decideInit` in @gliese/evm); see docs/RUNBOOK.md "The init layer".
   */
  initAnchor: boolean;
}

const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

/** Recursively convert a decoded value into a JSON-safe shape. */
export function normalizeValue(value: unknown): unknown {
  if (typeof value === 'bigint') return value.toString(10);
  if (typeof value === 'string') return ADDRESS_RE.test(value) ? value.toLowerCase() : value;
  if (typeof value === 'number' || typeof value === 'boolean' || value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) return value.map(normalizeValue);
  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = normalizeValue(v);
    return out;
  }
  // Anything exotic (Uint8Array, class instances...) — stringify defensively.
  return String(value);
}

/** Normalize viem's `args` (object for named params, array for unnamed) to a flat record. */
export function normalizeArgs(args: unknown): Record<string, unknown> {
  if (args === undefined || args === null) return {};
  if (Array.isArray(args)) {
    const out: Record<string, unknown> = {};
    args.forEach((v, i) => {
      out[`arg${i}`] = normalizeValue(v);
    });
    return out;
  }
  if (isPlainObject(args)) {
    return normalizeValue(args) as Record<string, unknown>;
  }
  return { arg0: normalizeValue(args) };
}

function detectInitAnchor(event: WatchedEvent, args: Record<string, unknown>): boolean {
  switch (event.key) {
    case 'ownable.transferred': {
      const prev = args['previousOwner'] ?? args['arg0'];
      return typeof prev === 'string' && prev.toLowerCase() === ZERO_ADDRESS;
    }
    case 'proxy.new_implementation': {
      // First assignment of a Compound-style delegator (old implementation is the zero address).
      const prev = args['oldImplementation'] ?? args['arg0'];
      return typeof prev === 'string' && prev.toLowerCase() === ZERO_ADDRESS;
    }
    case 'proxy.initialized':
    case 'proxy.initialized_v5': {
      const version = args['version'] ?? args['arg0'];
      return version === '1' || version === 1;
    }
    case 'safe.setup':
      return true;
    // 'auth.rely' (2026-09-07): the constructor of every MakerDAO-style module emits Rely(msg.sender),
    // but a log does not carry the tx sender, so there is no anchor here. It needs none: since
    // 2026-09-25 the watcher flags a Rely as setup when the emitting contract's code first appeared
    // in that transaction, which is exactly the constructor case.
    default:
      return false;
  }
}

/**
 * Decode a raw log against the registry. Returns null when topic0 is unknown
 * or no registered layout for that topic0 decodes strictly.
 */
export function decodeWatchedLog(log: { topics: readonly Hex[]; data: Hex }): DecodedEvent | null {
  const topic0 = log.topics[0];
  if (!topic0) return null;
  const candidates = EVENTS_BY_TOPIC0.get(topic0.toLowerCase() as Hex);
  if (!candidates || candidates.length === 0) return null;

  for (const candidate of candidates) {
    try {
      const decoded = decodeEventLog({
        abi: [candidate.abi],
        topics: log.topics as [Hex, ...Hex[]],
        data: log.data,
        strict: true,
      });
      const args = normalizeArgs(decoded.args);
      return { event: candidate, args, initAnchor: detectInitAnchor(candidate, args) };
    } catch {
      // Try the next layout (e.g. indexed vs non-indexed variants).
    }
  }
  return null;
}

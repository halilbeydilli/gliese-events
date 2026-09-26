export type { Category, Severity, WatchedEvent } from './registry.js';
export { EVENTS, TOPIC0S, EVENTS_BY_TOPIC0, severityRank } from './registry.js';
export type { DecodedEvent } from './decode.js';
export { decodeWatchedLog } from './decode.js';
export type { SyntheticEvent } from './synthetic.js';
export { SYNTHETIC_EVENTS, SYNTHETIC_EVENT_KEYS } from './synthetic.js';
export { VAULT_V2_SELECTOR_NAMES, VAULT_V2_GATE_ARGS, vaultV2SelectorName, vaultV2Gate } from './vault-v2.js';
export { ROLE_NAME_BY_HASH, roleNameOf, ACCESS_MANAGER_ROLE_NAMES, accessManagerRoleName } from './roles.js';

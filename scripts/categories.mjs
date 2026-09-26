// Prints the README category table from the registry itself. Run `npm run categories`
// (builds first, then imports dist/). Paste the output into README.md; never edit it by hand.
import { EVENTS, TOPIC0S, SYNTHETIC_EVENTS, ROLE_NAME_BY_HASH } from '../dist/index.js';

const ORDER = ['upgrade', 'ownership', 'access', 'pause', 'multisig', 'timelock', 'governance', 'token_admin', 'parameters'];
const rows = new Map();
for (const ev of EVENTS) {
  const row = rows.get(ev.category) ?? { keys: new Set(), topics: new Set(), critical: new Set(), high: new Set(), info: new Set() };
  row.keys.add(ev.key);
  row.topics.add(ev.topic0);
  row[ev.severity].add(ev.key);
  rows.set(ev.category, row);
}
const missing = [...rows.keys()].filter((c) => !ORDER.includes(c));
if (missing.length) throw new Error(`categories not in ORDER: ${missing.join(', ')}`);

const lines = ['| Category | Keys | Signatures (topic0) | critical / high / info keys |', '|---|---:|---:|---|'];
for (const cat of ORDER) {
  const r = rows.get(cat);
  if (!r) continue;
  lines.push(`| \`${cat}\` | ${r.keys.size} | ${r.topics.size} | ${r.critical.size} / ${r.high.size} / ${r.info.size} |`);
}
const keys = new Set(EVENTS.map((e) => e.key)).size;
lines.push(`| **Total** | **${keys}** | **${TOPIC0S.length}** | |`);
console.log(lines.join('\n'));
console.log();
console.log(`Synthetic \`slot.*\` keys: ${Object.keys(SYNTHETIC_EVENTS).length}. Named roles: ${ROLE_NAME_BY_HASH.size} (${ROLE_NAME_BY_HASH.size - 1} hashed names plus DEFAULT_ADMIN_ROLE).`);

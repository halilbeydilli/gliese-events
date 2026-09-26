/**
 * Morpho Vault V2 helpers shared by the describers (2026-09-22).
 *
 * V2 governance events carry the 4-byte selector of the function being submitted / revoked /
 * abdicated / re-timelocked (`Submit`, `Revoke`, `Abdicate`, `IncreaseTimelock`, `DecreaseTimelock`).
 * These are the timelocked functions of morpho-org/vault-v2 `VaultV2.sol` (selectors =
 * `toFunctionSelector` of the canonical signature; asserted in test/vault-v2.test.ts).
 */
export const VAULT_V2_SELECTOR_NAMES: Readonly<Record<`0x${string}`, string>> = Object.freeze({
  '0xb192a84a': 'setIsAllocator',
  '0x2cb19f98': 'setReceiveSharesGate',
  '0xc21ad028': 'setSendSharesGate',
  '0x04dbf0ce': 'setReceiveAssetsGate',
  '0x871c979c': 'setSendAssetsGate',
  '0x5b34b823': 'setAdapterRegistry',
  '0x60d54d41': 'addAdapter',
  '0x585cd34b': 'removeAdapter',
  '0x47966291': 'increaseTimelock',
  '0x5c1a1a4f': 'decreaseTimelock',
  '0xb2e32848': 'abdicate',
  '0x70897b23': 'setPerformanceFee',
  '0xfe56e232': 'setManagementFee',
  '0x6a5f1aa2': 'setPerformanceFeeRecipient',
  '0x9faae464': 'setManagementFeeRecipient',
  '0xf6f98fd5': 'increaseAbsoluteCap',
  '0x2438525b': 'increaseRelativeCap',
  '0x3e9d2ac7': 'setForceDeallocatePenalty',
});

/**
 * Human name of a Vault V2 function selector: `addAdapter` for `0x60d54d41`, else the short hex
 * (`selector 0x12345678`). Accepts the bare bytes4 or a right-padded 32-byte word (some decoders
 * keep indexed bytes4 topics padded); never throws.
 */
export function vaultV2SelectorName(selector: unknown): string {
  if (typeof selector !== 'string' || !/^0x[0-9a-fA-F]{8,}$/.test(selector)) return 'a function';
  const four = selector.slice(0, 10).toLowerCase() as `0x${string}`;
  return VAULT_V2_SELECTOR_NAMES[four] ?? `selector ${four}`;
}

/** Which of the four Vault V2 gates an event of `vault.gate_set` changed, from the arg name. */
export const VAULT_V2_GATE_ARGS: Readonly<Record<string, string>> = Object.freeze({
  newReceiveSharesGate: 'receive-shares gate (who may receive shares)',
  newSendSharesGate: 'send-shares gate (who may send shares)',
  newReceiveAssetsGate: 'receive-assets gate (who may withdraw)',
  newSendAssetsGate: 'send-assets gate (who may deposit)',
});

/** `[argName, gateLabel, value]` of the gate arg present in `args`, or null. */
export function vaultV2Gate(args: Record<string, unknown> | null | undefined): { arg: string; label: string; value: unknown } | null {
  if (!args) return null;
  for (const [arg, label] of Object.entries(VAULT_V2_GATE_ARGS)) {
    if (args[arg] !== undefined && args[arg] !== null) return { arg, label, value: args[arg] };
  }
  return null;
}

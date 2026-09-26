import { describe, expect, it } from 'vitest';
import { toFunctionSelector } from 'viem';
import { VAULT_V2_SELECTOR_NAMES, vaultV2Gate, vaultV2SelectorName } from '../src/index.js';

/** Morpho Vault V2 selector table (2026-09-22): every entry is the keccak selector of the VaultV2.sol function. */
const SIGNATURES: Record<string, string> = {
  setIsAllocator: 'setIsAllocator(address,bool)',
  setReceiveSharesGate: 'setReceiveSharesGate(address)',
  setSendSharesGate: 'setSendSharesGate(address)',
  setReceiveAssetsGate: 'setReceiveAssetsGate(address)',
  setSendAssetsGate: 'setSendAssetsGate(address)',
  setAdapterRegistry: 'setAdapterRegistry(address)',
  addAdapter: 'addAdapter(address)',
  removeAdapter: 'removeAdapter(address)',
  increaseTimelock: 'increaseTimelock(bytes4,uint256)',
  decreaseTimelock: 'decreaseTimelock(bytes4,uint256)',
  abdicate: 'abdicate(bytes4)',
  setPerformanceFee: 'setPerformanceFee(uint256)',
  setManagementFee: 'setManagementFee(uint256)',
  setPerformanceFeeRecipient: 'setPerformanceFeeRecipient(address)',
  setManagementFeeRecipient: 'setManagementFeeRecipient(address)',
  increaseAbsoluteCap: 'increaseAbsoluteCap(bytes,uint256)',
  increaseRelativeCap: 'increaseRelativeCap(bytes,uint256)',
  setForceDeallocatePenalty: 'setForceDeallocatePenalty(address,uint256)',
};

describe('Vault V2 selector names (2026-09-22)', () => {
  it('maps every timelocked VaultV2 function selector to its name', () => {
    expect(Object.keys(VAULT_V2_SELECTOR_NAMES).length).toBe(Object.keys(SIGNATURES).length);
    for (const [name, sig] of Object.entries(SIGNATURES)) {
      expect(VAULT_V2_SELECTOR_NAMES[toFunctionSelector(sig)], name).toBe(name);
    }
  });

  it('names a selector from the bare bytes4 or a padded word, and never throws on junk', () => {
    expect(vaultV2SelectorName('0x60d54d41')).toBe('addAdapter');
    expect(vaultV2SelectorName('0x60D54D41')).toBe('addAdapter');
    expect(vaultV2SelectorName(`0x60d54d41${'0'.repeat(56)}`)).toBe('addAdapter');
    expect(vaultV2SelectorName('0x12345678')).toBe('selector 0x12345678');
    expect(vaultV2SelectorName(undefined)).toBe('a function');
    expect(vaultV2SelectorName(42)).toBe('a function');
    expect(vaultV2SelectorName('0x1')).toBe('a function');
  });

  it('picks the gate arg out of a vault.gate_set payload', () => {
    expect(vaultV2Gate({ newSendAssetsGate: '0x' + '1'.repeat(40) })).toEqual({ arg: 'newSendAssetsGate', label: 'send-assets gate (who may deposit)', value: '0x' + '1'.repeat(40) });
    expect(vaultV2Gate({})).toBeNull();
    expect(vaultV2Gate(null)).toBeNull();
  });
});

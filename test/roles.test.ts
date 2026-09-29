import { describe, expect, it } from 'vitest';
import { keccak256, toBytes } from 'viem';
import { ROLE_NAME_BY_HASH, roleNameOf } from '../src/roles.js';

const ZERO = `0x${'0'.repeat(64)}`;

describe('roleNameOf', () => {
  it('names the two roles the Lido DAO moved on 2026-09-25', () => {
    // StakingRouter.STAKING_MODULE_UNVETTING_ROLE, moved from an EOA to the DepositSecurityModule.
    expect(roleNameOf('0x240525496a9dc32284b17ce03b43e539e4bd81414634ee54395030d793463b57')).toBe('STAKING_MODULE_UNVETTING_ROLE');
    // The Aragon ACL permission granted on stETH to the EasyTrack EVMScriptExecutor.
    expect(roleNameOf('0x33969636f1fbf3d7d062d4de4a08e7bd3c46606ec28b3a4398d2665be559b921')).toBe('BUFFER_RESERVE_MANAGER_ROLE');
  });

  it('names the Ethena sUSDe restriction and minting roles (2026-09-29)', () => {
    // The 02:00 UTC 2026-09-29 sUSDe access.role_granted (tx 0x14540e44…63f3) carried this hash unnamed:
    // StakedUSDe.FULL_RESTRICTED_STAKER_ROLE, a full freeze of one holder.
    expect(roleNameOf('0x0a4af4bcc1942295207d9f047442ebdae6170a6e324850f758b14cf99b65c3bd')).toBe('FULL_RESTRICTED_STAKER_ROLE');
    for (const name of ['SOFT_RESTRICTED_STAKER_ROLE', 'REWARDER_ROLE', 'BLACKLIST_MANAGER_ROLE', 'REDEEMER_ROLE', 'COLLATERAL_MANAGER_ROLE', 'GATEKEEPER_ROLE', 'MINTER_ROLE']) {
      expect(roleNameOf(keccak256(toBytes(name))), name).toBe(name);
    }
  });

  it('maps DEFAULT_ADMIN_ROLE, which is 32 zero bytes rather than a hash', () => {
    expect(roleNameOf(ZERO)).toBe('DEFAULT_ADMIN_ROLE');
    // A decoder that dropped the leading zeros still resolves.
    expect(roleNameOf('0x0')).toBe('DEFAULT_ADMIN_ROLE');
  });

  it('names one member of every family in the registry', () => {
    const expected: Record<string, string> = {
      // OpenZeppelin AccessControl
      '0x9f2df0fed2c77648de5860a4cc508cd0818c85b8b8a1ab4ceeef8d981c8956a6': 'MINTER_ROLE',
      '0x65d7a28e3265b37a6474929f336521b332c1681b933f6cb9f3376673440d862a': 'PAUSER_ROLE',
      // OpenZeppelin TimelockController
      '0xb09aa5aeb3702cfd50b6b62bc4532604938f21248a27a1d5ca736082b6819cc1': 'PROPOSER_ROLE',
      '0xd8aa0f3194971a2a116679f7c2090f6939c8d4e01a2a8d7e41d55e5351469e63': 'EXECUTOR_ROLE',
      '0xfd643c72710c63c0180259aba6b2d05451e3591a24e58b62239378085726f783': 'CANCELLER_ROLE',
      '0x5f58e3a2316349923ce3780f8d587db2d72378aed66a8261c916544fa6846ca5': 'TIMELOCK_ADMIN_ROLE',
    };
    for (const [hash, name] of Object.entries(expected)) expect(roleNameOf(hash)).toBe(name);
  });

  it('returns null for an unknown hash and for anything that is not a hash', () => {
    expect(roleNameOf(`0x${'11'.repeat(32)}`)).toBeNull();
    // Venus' AccessControlManager roles are keccak(target, functionSignature): nothing to name.
    expect(roleNameOf('0x5bf72cee7b07e607cb3b6bbf2972d39b442c275128354c6d184351558eabb393')).toBeNull();
    expect(roleNameOf(undefined)).toBeNull();
    expect(roleNameOf(null)).toBeNull();
    expect(roleNameOf(42)).toBeNull();
    expect(roleNameOf({})).toBeNull();
    expect(roleNameOf('MINTER_ROLE')).toBeNull();
    expect(roleNameOf('0xnothex')).toBeNull();
  });

  it('is case-insensitive', () => {
    expect(roleNameOf('0x240525496A9DC32284B17CE03B43E539E4BD81414634EE54395030D793463B57')).toBe('STAKING_MODULE_UNVETTING_ROLE');
  });
});

describe('ROLE_NAME_BY_HASH', () => {
  it('never gives two hashes the same name', () => {
    const seen = new Map<string, string>();
    const clashes: string[] = [];
    for (const [hash, name] of ROLE_NAME_BY_HASH) {
      const first = seen.get(name);
      if (first) clashes.push(`${name}: ${first} and ${hash}`);
      else seen.set(name, hash);
    }
    expect(clashes).toEqual([]);
  });

  it('holds lowercase 32-byte keys only', () => {
    for (const hash of ROLE_NAME_BY_HASH.keys()) expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('keys every entry but DEFAULT_ADMIN_ROLE by the keccak of its own name', () => {
    for (const [hash, name] of ROLE_NAME_BY_HASH) {
      if (hash === ZERO) continue;
      expect(keccak256(toBytes(name)).toLowerCase()).toBe(hash);
    }
  });

  it('covers the families the registry claims to cover', () => {
    const names = new Set(ROLE_NAME_BY_HASH.values());
    for (const name of [
      'DEFAULT_ADMIN_ROLE',
      // Lido StakingRouter / stETH / WithdrawalQueue / oracles / Burner / NodeOperatorsRegistry
      'STAKING_MODULE_UNVETTING_ROLE',
      'STAKING_CONTROL_ROLE',
      'FINALIZE_ROLE',
      'MANAGE_CONSENSUS_VERSION_ROLE',
      'REQUEST_BURN_SHARES_ROLE',
      'MANAGE_SIGNING_KEYS',
      // Aragon
      'RUN_SCRIPT_ROLE',
      'EXECUTE_ROLE',
      'CREATE_VOTES_ROLE',
      'APP_MANAGER_ROLE',
      'TRANSFER_ROLE',
      'CREATE_PAYMENTS_ROLE',
      // Aave V3 ACLManager (the preimage has no _ROLE suffix)
      'POOL_ADMIN',
      'EMERGENCY_ADMIN',
      'RISK_ADMIN',
      'FLASH_BORROWER',
      'BRIDGE',
      'ASSET_LISTING_ADMIN',
      // Ethena sUSDe / EthenaMinting (2026-09-29)
      'FULL_RESTRICTED_STAKER_ROLE',
      'SOFT_RESTRICTED_STAKER_ROLE',
      'BLACKLIST_MANAGER_ROLE',
      'COLLATERAL_MANAGER_ROLE',
      'GATEKEEPER_ROLE',
    ]) {
      expect(names).toContain(name);
    }
  });

  it("does not name Aave's POOL_ADMIN with the hash of POOL_ADMIN_ROLE", () => {
    // ACLManager hashes 'POOL_ADMIN'; a table built from the constant's name would be wrong here.
    expect(roleNameOf(keccak256(toBytes('POOL_ADMIN')))).toBe('POOL_ADMIN');
    expect(roleNameOf(keccak256(toBytes('POOL_ADMIN_ROLE')))).toBe('POOL_ADMIN_ROLE');
  });
});

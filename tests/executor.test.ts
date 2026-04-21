import { describe, it, expect } from 'vitest';
import { getNetworkConfig, isAnvilRunning } from '../src/executor.js';

describe('executor', () => {
  describe('getNetworkConfig', () => {
    it('returns anvil config by default', () => {
      const config = getNetworkConfig('anvil');
      expect(config.name).toBe('anvil');
      expect(config.chainId).toBe(31337);
      expect(config.rpcUrl).toContain('127.0.0.1');
    });

    it('returns local alias for anvil', () => {
      const config = getNetworkConfig('local');
      expect(config.name).toBe('anvil');
      expect(config.chainId).toBe(31337);
    });

    it('throws for unknown network', () => {
      expect(() => getNetworkConfig('ethereum-mainnet')).toThrow('Unknown network');
    });

    it('throws for base-sepolia without DEPLOYER_PRIVATE_KEY', () => {
      const original = process.env.DEPLOYER_PRIVATE_KEY;
      delete process.env.DEPLOYER_PRIVATE_KEY;
      expect(() => getNetworkConfig('base-sepolia')).toThrow('DEPLOYER_PRIVATE_KEY');
      if (original) process.env.DEPLOYER_PRIVATE_KEY = original;
    });

    it('returns base-sepolia config when DEPLOYER_PRIVATE_KEY is set', () => {
      const original = process.env.DEPLOYER_PRIVATE_KEY;
      process.env.DEPLOYER_PRIVATE_KEY = '0x' + 'a'.repeat(64);
      const config = getNetworkConfig('base-sepolia');
      expect(config.name).toBe('base-sepolia');
      expect(config.chainId).toBe(84532);
      if (original) process.env.DEPLOYER_PRIVATE_KEY = original;
      else delete process.env.DEPLOYER_PRIVATE_KEY;
    });

    it('returns sepolia config when DEPLOYER_PRIVATE_KEY is set', () => {
      const original = process.env.DEPLOYER_PRIVATE_KEY;
      process.env.DEPLOYER_PRIVATE_KEY = '0x' + 'b'.repeat(64);
      const config = getNetworkConfig('sepolia');
      expect(config.name).toBe('sepolia');
      expect(config.chainId).toBe(11155111);
      if (original) process.env.DEPLOYER_PRIVATE_KEY = original;
      else delete process.env.DEPLOYER_PRIVATE_KEY;
    });

    it('respects ANVIL_RPC env var override', () => {
      const original = process.env.ANVIL_RPC;
      process.env.ANVIL_RPC = 'http://custom:9999';
      const config = getNetworkConfig('anvil');
      expect(config.rpcUrl).toBe('http://custom:9999');
      if (original) process.env.ANVIL_RPC = original;
      else delete process.env.ANVIL_RPC;
    });
  });

  describe('isAnvilRunning', () => {
    it('returns boolean without throwing', async () => {
      const result = await isAnvilRunning();
      expect(typeof result).toBe('boolean');
    });
  });
});
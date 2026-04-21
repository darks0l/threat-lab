import { describe, it, expect, afterEach } from 'vitest';
import { tmpdir } from 'os';
import { join } from 'path';
import { writeFile, mkdir, rm } from 'fs/promises';

describe('scanner file discovery', () => {
  const tmp = join(tmpdir(), `threat-lab-test-${Date.now()}`);

  async function cleanupTmp() {
    try { await rm(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
  }

  afterEach(async () => {
    await cleanupTmp();
  });

  it('finds .sol files in a directory', async () => {
    const { findSolFiles } = await import('../src/scanner.js');

    await mkdir(join(tmp, 'contracts'), { recursive: true });
    await writeFile(join(tmp, 'contracts', 'Token.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'contracts', 'Vault.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'README.md'), '# test'); // should be ignored

    const files = await findSolFiles(tmp);
    const solFiles = files.filter(f => f.endsWith('.sol'));

    expect(solFiles.length).toBe(2);
    expect(solFiles.some(f => f.includes('Token.sol'))).toBe(true);
    expect(solFiles.some(f => f.includes('Vault.sol'))).toBe(true);
  });

  it('handles single file target', async () => {
    const { findSolFiles } = await import('../src/scanner.js');

    await mkdir(join(tmp, 'contracts'), { recursive: true });
    const singleFile = join(tmp, 'contracts', 'Single.sol');
    await writeFile(singleFile, 'pragma solidity ^0.8.0;');

    const files = await findSolFiles(singleFile);
    expect(files.length).toBe(1);
    expect(files[0]).toBe(singleFile);
  });

  it('ignores node_modules, dist, and cache directories', async () => {
    const { findSolFiles } = await import('../src/scanner.js');

    await mkdir(join(tmp, 'node_modules', 'pkg'), { recursive: true });
    await mkdir(join(tmp, 'dist', 'contracts'), { recursive: true });
    await mkdir(join(tmp, 'cache'), { recursive: true });
    await mkdir(join(tmp, 'src'), { recursive: true });
    await writeFile(join(tmp, 'node_modules', 'pkg', 'Evil.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'dist', 'contracts', 'Built.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'cache', 'Cached.sol'), 'pragma solidity ^0.8.0;');
    await writeFile(join(tmp, 'src', 'Valid.sol'), 'pragma solidity ^0.8.0;');

    const files = await findSolFiles(tmp);
    const solFiles = files.filter(f => f.endsWith('.sol'));

    expect(solFiles.length).toBe(1);
    expect(solFiles[0]).toContain('Valid.sol');
  });

  it('returns empty array for non-existent path', async () => {
    const { findSolFiles } = await import('../src/scanner.js');
    const files = await findSolFiles('/non/existent/path');
    expect(files).toEqual([]);
  });
});

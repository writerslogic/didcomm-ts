import { jest } from '@jest/globals';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { loadOrCreateIdentity } from '../src/chat/keys.js';

const PASSPHRASE_ENV_VAR = 'DIDCOMM_TS_PASSPHRASE';

describe('loadOrCreateIdentity encryption at rest', () => {
  let tmpDir: string;
  let warnSpy: ReturnType<typeof jest.spyOn>;
  const originalPassphrase = process.env[PASSPHRASE_ENV_VAR];

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'didcomm-ts-keys-test-'));
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
    rmSync(tmpDir, { recursive: true, force: true });
    if (originalPassphrase === undefined) {
      delete process.env[PASSPHRASE_ENV_VAR];
    } else {
      process.env[PASSPHRASE_ENV_VAR] = originalPassphrase;
    }
  });

  it('round-trips an identity when a passphrase is set', () => {
    process.env[PASSPHRASE_ENV_VAR] = 'correct horse battery staple';

    const created = loadOrCreateIdentity(tmpDir);
    expect(created.did).toMatch(/^did:key:z/);

    const loaded = loadOrCreateIdentity(tmpDir);
    expect(loaded).toEqual(created);
  });

  it('round-trips an identity when no passphrase is set (plaintext, unchanged behavior)', () => {
    delete process.env[PASSPHRASE_ENV_VAR];

    const created = loadOrCreateIdentity(tmpDir);
    expect(created.did).toMatch(/^did:key:z/);

    const loaded = loadOrCreateIdentity(tmpDir);
    expect(loaded).toEqual(created);
    expect(warnSpy).toHaveBeenCalled();
  });

  it('throws a clear error naming the file path when the passphrase is wrong', () => {
    process.env[PASSPHRASE_ENV_VAR] = 'correct horse battery staple';
    loadOrCreateIdentity(tmpDir);

    process.env[PASSPHRASE_ENV_VAR] = 'wrong passphrase';
    expect(() => loadOrCreateIdentity(tmpDir)).toThrow(
      /failed to decrypt identity at .*identity\.json/,
    );
  });
});

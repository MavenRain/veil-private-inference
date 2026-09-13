import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, exactKeys, readBytes, readJson, requireThat, sha256, writePrivate } from '../core.mjs';
import { commitment, publicSignals, tuple, validField } from './binding.mjs';

export const defaultArtifacts = fileURLToPath(new URL('../artifacts/zk', import.meta.url));
const cli = fileURLToPath(new URL('../node_modules/snarkjs/build/cli.cjs', import.meta.url));
function command(args) {
  // Worker lifetime, memory and logs are bounded in a separate process.
  const result = spawnSync(process.execPath, ['--max-old-space-size=2048', cli, ...args], {
    encoding: 'utf8', maxBuffer: 1048576, timeout: 180000 });
  requireThat(result.status === 0, 'zk-command');
}
export async function prove(statement, blind, artifacts = defaultArtifacts) {
  requireThat(validField(blind) && await commitment(statement, blind) === statement.zk_commitment, 'zk-opening');
  const dir = mkdtempSync(resolve(tmpdir(), 'veil-proof-'));
  try {
    writePrivate(resolve(dir, 'input.json'), canonical({ tuple: tuple(statement),
      commitment: statement.zk_commitment, blind }));
    command(['plonk', 'fullprove', resolve(dir, 'input.json'), resolve(artifacts, 'receipt_js/receipt.wasm'),
      resolve(artifacts, 'receipt.zkey'), resolve(dir, 'proof.json'), resolve(dir, 'public.json')]);
    const public_signals = readJson(resolve(dir, 'public.json'));
    requireThat(canonical(public_signals) === canonical(publicSignals(statement)), 'zk-public-inputs');
    return { version: 'veil.receipt-proof.v2', scheme: 'plonk-bn254',
      proof: readJson(resolve(dir, 'proof.json')), public_signals };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
export async function verifyProof(statement, bundle, expectedKeyHash, artifacts = defaultArtifacts) {
  const dir = mkdtempSync(resolve(tmpdir(), 'veil-verify-'));
  try {
    requireThat(exactKeys(bundle, ['version', 'scheme', 'proof', 'public_signals'])
      && bundle.version === 'veil.receipt-proof.v2' && bundle.scheme === 'plonk-bn254'
      && canonical(bundle.public_signals) === canonical(publicSignals(statement)), 'zk-public-inputs');
    const key = readBytes(resolve(artifacts, 'verification_key.json'));
    requireThat(sha256(key) === expectedKeyHash, 'zk-key-pin');
    // Use the exact bytes checked above, avoiding a verification-key path race.
    writePrivate(resolve(dir, 'key.json'), key);
    writePrivate(resolve(dir, 'proof.json'), canonical(bundle.proof));
    writePrivate(resolve(dir, 'public.json'), canonical(bundle.public_signals));
    command(['plonk', 'verify', resolve(dir, 'key.json'), resolve(dir, 'public.json'), resolve(dir, 'proof.json')]);
    return true;
  } catch { return false; }
  finally { rmSync(dir, { recursive: true, force: true }); }
}

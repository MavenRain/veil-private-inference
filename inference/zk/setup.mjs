import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, requireThat, sha256 } from '../core.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const srs = resolve(process.argv[2] ?? resolve(root, '../_build/ppot_0080_14.ptau'));
const out = resolve(process.argv[3] ?? resolve(root, 'artifacts/zk'));
const expected = 'a91842802f01b33fd42f5f69c3e49879ae03f0ae1f448b0c151244c9957024bd30bf5e3cc999ff2aeb02ebb959124a3a6a3cc20691cb4843a1234a02232072f3';
requireThat(createHash('blake2b512').update(readFileSync(srs)).digest('hex') === expected, 'srs-checksum');
mkdirSync(out, { recursive: true, mode: 0o700 });
const run = (bin, args) => {
  const result = spawnSync(bin, args, { cwd: root, stdio: 'inherit', timeout: 600000 });
  requireThat(result.status === 0, 'zk-setup-command');
};
const snark = args => run(process.execPath, [resolve(root, 'node_modules/snarkjs/build/cli.cjs'), ...args]);
run('circom', [resolve(root, 'zk/receipt.circom'), '--r1cs', '--wasm', '--sym', '-o', out]);
snark(['plonk', 'setup', resolve(out, 'receipt.r1cs'), srs, resolve(out, 'receipt.zkey')]);
snark(['zkey', 'export', 'verificationkey', resolve(out, 'receipt.zkey'), resolve(out, 'verification_key.json')]);
const artifacts = Object.fromEntries(['receipt.r1cs', 'receipt.zkey', 'receipt_js/receipt.wasm',
  'verification_key.json'].map(path => [path, sha256(readFileSync(resolve(out, path)))]));
writeFileSync(resolve(out, 'manifest.json'), canonical({ version: 'veil.zk-artifacts.v2',
  scheme: 'plonk-bn254', circom: '2.2.3', snarkjs: '0.7.6', circomlib: '2.0.5',
  srs_blake2b512: expected, circuit_sha256: sha256(readFileSync(resolve(root, 'zk/receipt.circom'))), artifacts }) + '\n');
console.log(canonical({ ready: true, verification_key_sha256: artifacts['verification_key.json'] }));

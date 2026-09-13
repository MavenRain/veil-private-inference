import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { requireThat } from './core.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const compiler = process.argv[2] ?? resolve(root, '_build/default/bin/kanon.exe');
const build = (files, output, names) => {
  const result = spawnSync(compiler, ['build', ...files.map(p => resolve(root, p)), '-o', output,
    ...names.flatMap(name => ['--export', name])], { encoding: 'utf8', timeout: 30000 });
  if (result.status !== 0) process.stderr.write(result.stderr ?? 'compiler failed');
  requireThat(result.status === 0, 'compile');
};
mkdirSync(resolve(root, 'inference/artifacts'), { recursive: true });
build(['runtime/reactor.kan', 'examples/private-inference/relation.kan', 'examples/private-inference/proof.kan',
  'examples/private-inference/twin.kan'], resolve(root, 'inference/artifacts/receipt.wasm'), [
  'emptyBytes', 'consBytes', 'makeModelHash', 'makePromptCommitment', 'makeOutputCommitment',
  'makeGpuMeasurement', 'makeWorkloadMeasurement', 'makeReceiptDigest', 'makeReceipt', 'makeReceiptPolicy',
  'makeReceiptContext', 'makeReceiptInstance', 'makeGpuClaims', 'makeWorkloadClaims', 'makeTokenLifetime',
  'makeReceiptEvidence', 'receiptCode', 'provePlainReceipt', 'verifyPlainReceipt']);
build(['examples/private-inference/relation.kan', 'inference/privacy.kan'],
  resolve(root, 'inference/veil_privacy/assets/privacy.wasm'), ['federatedRoundCode', 'receiptBitDistance', 'encryptedDistanceTwin']);
const check = spawnSync(compiler, ['check', resolve(root, 'inference/fhc.kan')], { encoding: 'utf8', timeout: 30000 });
if (check.status !== 0) process.stderr.write(check.stderr);
requireThat(check.status === 0, 'fhc-typecheck');
const module = await WebAssembly.compile(readFileSync(resolve(root, 'inference/veil_privacy/assets/privacy.wasm')));
const api = (await WebAssembly.instantiate(module)).exports;
for (const a of [0, 1]) for (const b of [0, 1]) requireThat(api.receiptBitDistance(a, b) === (a - b) ** 2, 'fhc-twin');
requireThat(api.federatedRoundCode(0, 0, 1, 2, 0, 1000, 3000, 1, 1, 1) === 0, 'round-twin');
requireThat(api.federatedRoundCode(1, 0, 1, 2, 0, 1000, 3000, 1, 1, 1) === 1, 'round-replay');
requireThat(api.federatedRoundCode(0, 0, 1, 2, 3000, 1000, 3000, 1, 1, 1) === 3, 'round-budget');
console.log('receipt and privacy Wasm built; FHC shape and twins checked');

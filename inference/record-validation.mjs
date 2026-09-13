import { execFileSync } from 'node:child_process';
import { lstatSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, sha256 } from './core.mjs';
import { parentGateReport } from './validation.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
if (process.argv.length !== 4) throw new Error('usage: record-validation.mjs PARENT_EXIT_CODE FEDERATION_REPORT');
const parent = parentGateReport(readFileSync(join(root, 'inference/artifacts/parent-gates.log'), 'utf8'), Number(process.argv[2]));
const federation = JSON.parse(readFileSync(process.argv[3], 'utf8'));
if (federation.accepted !== true || federation.assurance !== 'simulation' || federation.clients !== 2
    || federation.rounds !== 3 || federation.receipts !== 6 || federation.encrypted_checkpoints !== 3
    || federation.epsilon_per_client !== 3 || federation.server_has_secret_key !== false) throw new Error('federation-validation');
const files = new Set(execFileSync('git', ['ls-files', '--recurse-submodules', '-z'], { cwd: root }).toString().split('\0').filter(Boolean));
const excluded = new Set(['node_modules', '.venv', 'artifacts', 'dist', '__pycache__']);
function walk(path) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.name.startsWith('.') || excluded.has(entry.name)) continue;
    const full = join(path, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (entry.isFile()) files.add(relative(root, full));
  }
}
walk(join(root, 'inference'));
files.add('dev/private-inference-release.sh');
const hashes = {};
for (const path of [...files].sort()) {
  if (!/\.(ml|mli|mjs|py|c|kan|tot|sh|zsh|json|toml|lock|lean)$/.test(path)
      && !/(^|\/)(Dockerfile(?:\.[^/]+)?|dune(?:-project)?|lean-toolchain|PIN)$/.test(path)) continue;
  if (!lstatSync(join(root, path)).isFile()) throw new Error('validation-source-type');
  hashes[path] = sha256(readFileSync(join(root, path)));
}
for (const path of ['inference/artifacts/receipt.wasm', 'inference/veil_privacy/assets/privacy.wasm',
  'inference/artifacts/zk/manifest.json', 'inference/artifacts/parent-gates.log']) hashes[path] = sha256(readFileSync(join(root, path)));
const report = { version: 'veil.software-validation.v2', release: '0.2.0',
  base_commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root }).toString().trim(),
  completed_at: new Date().toISOString(), node: process.version,
  status: parent.status === 'passed' ? 'software-validated' : parent.status,
  parent, federation,
  passed: ['veil-build', ...(parent.status === 'passed' ? ['parent-28-gates'] : []), 'receipt-and-deployment-tests', 'plonk', 'rego',
    'native-gpu-guard', 'bfv', 'nvflare-policy', 'nvflare-three-round-simulation'],
  hardware_validated: false, container_images_built: false, source_sha256: hashes };
const output = join(root, 'inference/artifacts/software-validation.json');
writeFileSync(output + '.tmp', canonical(report) + '\n', { mode: 0o600 });
renameSync(output + '.tmp', output);
console.log(`software validation recorded: ${report.status}, with source and artifact hashes`);

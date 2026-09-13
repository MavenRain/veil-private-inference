import { closeSync, fstatSync, mkdirSync, openSync, readSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { loadTwin, verifyMockReceipt } from './host.mjs';
import { createMockFixture } from './mock.mjs';

const usage = `Usage:
  node examples/private-inference/receipt.mjs demo
  node examples/private-inference/receipt.mjs fixture DIRECTORY
  node examples/private-inference/receipt.mjs verify --mock RECEIPT.json POLICY.json CONTEXT.json

All results use a mock token and veil's plaintext twin. No GPU or inference runs.
CONTEXT.json contains a trusted expected nonce and verification time (Unix seconds).
Exit codes: 0 accepted, 1 rejected, 2 IO/build/runtime failure, 64 usage.
`;

function readJson(path) {
  const fd = openSync(path, 'r');
  try {
    if (!fstatSync(fd).isFile()) throw new Error('input must be a regular file');
    const bytes = Buffer.alloc(65537);
    let used = 0;
    while (used < bytes.length) {
      const count = readSync(fd, bytes, used, bytes.length - used, null);
      if (count === 0) break;
      used += count;
    }
    if (used > 65536) throw new Error('input file exceeds 65536 bytes');
    return JSON.parse(bytes.subarray(0, used).toString('utf8'));
  } finally { closeSync(fd); }
}

async function main(args) {
  if (args.length === 1 && args[0] === '--help') { process.stdout.write(usage); return 0; }
  if (args.length === 2 && args[0] === 'fixture') {
    const { envelope, policy, nonce, now } = createMockFixture();
    mkdirSync(args[1], { recursive: true });
    for (const [name, value] of Object.entries({ receipt: envelope, policy, context: { nonce, now } })) {
      writeFileSync(join(args[1], `${name}.json`), `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx' });
    }
    console.log(JSON.stringify({ mode: 'mock', directory: args[1], files: ['receipt.json', 'policy.json', 'context.json'] }));
    return 0;
  }
  if (args.length === 1 && args[0] === 'demo') {
    const api = await loadTwin();
    const fixture = createMockFixture();
    const accepted = verifyMockReceipt(api, fixture);
    const tampered = structuredClone({ envelope: fixture.envelope, policy: fixture.policy,
      nonce: fixture.nonce, now: fixture.now });
    tampered.envelope.receipt.output_commit = '00'.repeat(32);
    const rejected = verifyMockReceipt(api, tampered);
    console.log(JSON.stringify({ mode: 'mock', assurance: 'plaintext-twin', valid: accepted, tampered_output: rejected }, null, 2));
    return accepted.accepted && !rejected.accepted && rejected.code === 'output-binding' ? 0 : 1;
  }
  if (args.length === 5 && args[0] === 'verify' && args[1] === '--mock') {
    const envelope = readJson(args[2]);
    const policy = readJson(args[3]);
    const context = readJson(args[4]);
    if (context === null || typeof context !== 'object' || Array.isArray(context)
        || Object.keys(context).sort().join(',') !== 'nonce,now') {
      console.log(JSON.stringify({ accepted: false, mode: 'mock', assurance: 'plaintext-twin', code: 'context-schema' }));
      return 1;
    }
    const result = verifyMockReceipt(await loadTwin(), { envelope, policy, ...context });
    console.log(JSON.stringify(result, null, 2));
    return result.accepted ? 0 : 1;
  }
  process.stderr.write(usage);
  return 64;
}

try { process.exitCode = await main(process.argv.slice(2)); }
catch (error) {
  // Do not print untrusted input, keys, or token contents in diagnostics.
  console.error(`veil receipt: ${error.code ?? error.name ?? 'Error'}; check input files and the compiler build`);
  process.exitCode = 2;
}

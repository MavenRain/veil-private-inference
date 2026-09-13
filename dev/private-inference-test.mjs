import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { canonical, commitOutput, commitPrompt, loadTwin, prepareMockReceipt, verifyMockReceipt } from '../examples/private-inference/host.mjs';
import { createMockFixture, signMockClaims } from '../examples/private-inference/mock.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const compiler = join(root, '_build/default/bin/kanon.exe');
const api = await loadTwin(compiler);
const seed = createMockFixture(1800000000);
const fixture = () => ({ ...seed, envelope: structuredClone(seed.envelope),
  policy: structuredClone(seed.policy), claims: structuredClone(seed.claims) });
const flip = hex => `${hex[0] === 'f' ? 'e' : 'f'}${hex.slice(1)}`;
const resign = f => { f.envelope.token = signMockClaims(f.claims, f.privateKey); return f; };

test('the compiled veil twin accepts a matching NIM receipt', () => {
  const result = verifyMockReceipt(api, fixture());
  assert.equal(result.accepted, true);
  assert.equal(result.assurance, 'plaintext-twin');
  assert.equal(result.mode, 'mock');
  assert.match(result.statement_digest, /^[0-9a-f]{64}$/);
});

test('TensorRT-LLM is a separately pinned supported runtime', () => {
  const f = fixture();
  f.policy.runtime = f.claims.workload.runtime = 'tensorrt-llm';
  assert.equal(verifyMockReceipt(api, resign(f)).accepted, true);
});

const claimRejections = [
  ['VM not attested', 'vm-attestation', f => { f.claims.workload.vm_attested = false; }],
  ['VM not confidential', 'vm-not-confidential', f => { f.claims.workload.vm_confidential = false; }],
  ['VM debug enabled', 'vm-debug-enabled', f => { f.claims.workload.vm_debug_enabled = true; }],
  ['negative GPU attestation', 'gpu-attestation', f => { f.claims.gpu.attested = false; }],
  ['CC disabled', 'cc-disabled', f => { f.claims.gpu.cc_enabled = false; }],
  ['debug enabled', 'debug-enabled', f => { f.claims.gpu.debug_enabled = true; }],
  ['no completed inference', 'workload-incomplete', f => { f.claims.workload.completed = false; }],
  ['GPU measurement mismatch', 'gpu-policy', f => { f.claims.gpu.measurement = flip(f.claims.gpu.measurement); }],
  ['workload bound to a different GPU', 'workload-gpu-binding', f => { f.claims.workload.gpu_measurement = flip(f.claims.workload.gpu_measurement); }],
  ['workload measurement mismatch', 'workload-policy', f => { f.claims.workload.measurement = flip(f.claims.workload.measurement); }],
  ['runtime substitution', 'runtime-policy', f => { f.claims.workload.runtime = 'tensorrt-llm'; }],
  ['token model substitution', 'model-binding', f => { f.claims.workload.model = flip(f.claims.workload.model); }],
  ['token prompt substitution', 'prompt-binding', f => { f.claims.workload.prompt_commit = flip(f.claims.workload.prompt_commit); }],
  ['token output substitution', 'output-binding', f => { f.claims.workload.output_commit = flip(f.claims.workload.output_commit); }],
  ['GPU challenge substitution', 'gpu-challenge', f => { f.claims.gpu.nonce = flip(f.nonce); }],
  ['workload challenge substitution', 'workload-challenge', f => { f.claims.workload.nonce = flip(f.nonce); }],
  ['inverted issuance interval', 'token-lifetime', f => { f.claims.not_before--; }],
  ['empty validity interval', 'token-lifetime', f => { f.claims.expires_at = f.claims.not_before; }],
  ['issuance in the future', 'issued-in-future', f => { f.claims.issued_at++; f.claims.not_before++; }],
  ['not before in the future', 'not-yet-valid', f => { f.claims.not_before++; }],
  ['expiry is exclusive', 'expired', f => { f.now = f.claims.expires_at; }],
  ['age limit exceeded', 'too-old', f => { f.now += 20; f.policy.max_age_seconds = 19; }],
  ['wrong relying party', 'token-audience', f => { f.claims.audience = 'another-client'; }],
];
for (const [name, code, mutate] of claimRejections) {
  test(`rejects authentic mock claims: ${name}`, () => {
    const f = fixture(); mutate(f); resign(f);
    assert.equal(verifyMockReceipt(api, f).code, code);
  });
}

const boundaryRejections = [
  ['receipt model', 'model-policy', f => { f.envelope.receipt.model = flip(f.envelope.receipt.model); }],
  ['receipt prompt', 'prompt-binding', f => { f.envelope.receipt.prompt_commit = flip(f.envelope.receipt.prompt_commit); }],
  ['receipt output', 'output-binding', f => { f.envelope.receipt.output_commit = flip(f.envelope.receipt.output_commit); }],
  ['another expected challenge', 'gpu-challenge', f => { f.nonce = flip(f.nonce); }],
  ['a forged signature', 'token-signature', f => { f.envelope.token.signature = Buffer.alloc(64).toString('base64url'); }],
  ['an unpinned signing key', 'token-signature', f => {
    f.envelope.token = signMockClaims(f.claims, generateKeyPairSync('ed25519').privateKey);
  }],
  ['a missing signature', 'unsupported-token-format', f => { delete f.envelope.token.signature; }],
  ['an extra signature-verification flag', 'unsupported-token-format', f => { f.envelope.token.verified = true; }],
  ['an actual JWT format', 'unsupported-token-format', f => { f.envelope.token.format = 'JWT'; }],
  ['production mode', 'receipt-schema', f => { f.envelope.mode = 'production'; }],
  ['uppercase digest', 'receipt-schema', f => { f.envelope.receipt.model = f.envelope.receipt.model.toUpperCase(); }],
  ['short digest', 'receipt-schema', f => { f.envelope.receipt.prompt_commit = 'ab'; }],
  ['extra receipt input', 'receipt-schema', f => { f.envelope.receipt.prompt = 'private'; }],
  ['missing receipt field', 'receipt-schema', f => { delete f.envelope.receipt.output_commit; }],
  ['unsafe JS clock', 'context-schema', f => { f.now = Number.MAX_SAFE_INTEGER + 1; }],
  ['negative clock', 'context-schema', f => { f.now = -1; }],
  ['fractional clock', 'context-schema', f => { f.now += 0.5; }],
  ['short nonce', 'context-schema', f => { f.nonce = 'ab'; }],
  ['empty audience policy', 'policy-schema', f => { f.policy.audience = ''; }],
  ['missing workload pin', 'policy-schema', f => { delete f.policy.workload_measurement; }],
  ['invalid public key', 'policy-key', f => { f.policy.attester_public_key = 'invalid'; }],
  ['base64 padding', 'token-encoding', f => { f.envelope.token.payload += '='; }],
  ['oversized payload', 'token-encoding', f => { f.envelope.token.payload = 'a'.repeat(22000); }],
];
for (const [name, code, mutate] of boundaryRejections) {
  test(`rejects untrusted boundary input: ${name}`, () => {
    const f = fixture(); mutate(f);
    assert.equal(verifyMockReceipt(api, f).code, code);
  });
}

test('editing a well-formed payload without resigning fails authentication', () => {
  const f = fixture();
  f.claims.workload.output_commit = flip(f.claims.workload.output_commit);
  f.envelope.token.payload = Buffer.from(canonical(f.claims)).toString('base64url');
  assert.equal(verifyMockReceipt(api, f).code, 'token-signature');
});

test('GPU-only evidence cannot stand in for a workload receipt', () => {
  const f = fixture(); delete f.claims.workload;
  assert.equal(verifyMockReceipt(api, resign(f)).code, 'token-schema');
});

test('duplicate JSON token keys fail even with a valid signature', () => {
  const f = fixture();
  const payload = Buffer.from(`{"issuer":"attacker",${canonical(f.claims).slice(1)}`);
  f.envelope.token.payload = payload.toString('base64url');
  f.envelope.token.signature = sign(null, payload, f.privateKey).toString('base64url');
  assert.equal(verifyMockReceipt(api, f).code, 'token-schema');
});

test('claim flags have exact boolean types', () => {
  const f = fixture(); f.claims.gpu.attested = 'true';
  assert.equal(verifyMockReceipt(api, resign(f)).code, 'token-schema');
});

test('freshness boundaries and large exact clocks are preserved', () => {
  const f = fixture(); f.now += 299; f.policy.max_age_seconds = 299;
  assert.equal(verifyMockReceipt(api, f).accepted, true);
  const huge = createMockFixture(Number.MAX_SAFE_INTEGER - 300);
  assert.equal(verifyMockReceipt(api, huge).accepted, true);
});

test('all 256 digest bits survive the Wasm boundary', () => {
  for (const digest of ['00'.repeat(32), 'ff'.repeat(32), `80${'00'.repeat(31)}`, `${'00'.repeat(31)}01`]) {
    const f = fixture();
    f.envelope.receipt.prompt_commit = f.claims.workload.prompt_commit = digest;
    assert.equal(verifyMockReceipt(api, resign(f)).accepted, true);
    f.envelope.receipt.prompt_commit = flip(digest);
    assert.equal(verifyMockReceipt(api, f).code, 'prompt-binding');
  }
});

test('commitments bind domain, salt, message and exact bytes', () => {
  const salt = Buffer.alloc(32, 7);
  const bytes = Buffer.from([0, 255, 97]);
  const p = commitPrompt(bytes, salt);
  assert.equal(p, commitPrompt(bytes, salt));
  assert.notEqual(p, commitOutput(bytes, salt));
  assert.notEqual(p, commitPrompt(bytes, Buffer.alloc(32, 8)));
  assert.notEqual(p, commitPrompt(Buffer.concat([bytes, Buffer.of(0)]), salt));
  assert.throws(() => commitPrompt(bytes, Buffer.alloc(31)), TypeError);
});

test('plaintext proof slots reject a different instance and different evidence', () => {
  const f = fixture();
  const a = prepareMockReceipt(api, f);
  const proof = api.provePlainReceipt(a.instanceHandle, a.evidenceHandle);
  assert.equal(api.verifyPlainReceipt(proof, a.instanceHandle, a.evidenceHandle, a.instance, a.evidence), 1);
  const shifted = prepareMockReceipt(api, { ...f, now: f.now + 1 });
  assert.equal(api.receiptCode(shifted.instance, shifted.evidence), 0);
  assert.equal(api.verifyPlainReceipt(proof, shifted.instanceHandle, shifted.evidenceHandle, shifted.instance, shifted.evidence), 0);
  f.claims.expires_at++;
  const b = prepareMockReceipt(api, resign(f));
  assert.equal(api.receiptCode(b.instance, b.evidence), 0);
  assert.equal(api.verifyPlainReceipt(proof, b.instanceHandle, b.evidenceHandle, b.instance, b.evidence), 0);
});

test('a failed host authentication bit fails the compiled relation', () => {
  const f = fixture(); f.envelope.token.signature = Buffer.alloc(64).toString('base64url');
  const p = prepareMockReceipt(api, f);
  assert.equal(api.receiptCode(p.instance, p.evidence), 1);
  const proof = api.provePlainReceipt(p.instanceHandle, p.evidenceHandle);
  assert.equal(api.verifyPlainReceipt(proof, p.instanceHandle, p.evidenceHandle, p.instance, p.evidence), 0);
});

test('the compiler rejects swapped commitment types', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'veil-receipt-types-'));
  try {
    const source = join(scratch, 'swapped.kan');
    writeFileSync(source, 'def swapped (m : ModelHash) (p : PromptCommitment) (o : OutputCommitment) : ReceiptFields := makeReceipt m o p\n');
    const result = spawnSync(compiler, ['build', 'runtime/reactor.kan',
      'examples/private-inference/relation.kan', 'examples/private-inference/twin.kan', source,
      '-o', join(scratch, 'bad.wasm'), '--export', 'swapped'], { cwd: root, encoding: 'utf8', timeout: 30000 });
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, /mismatch|expected/i);
  } finally { rmSync(scratch, { recursive: true, force: true }); }
});

test('the relation belongs to the circuit fragment and has no axioms', () => {
  const source = join(root, 'examples/private-inference/relation.kan');
  const circuit = spawnSync(compiler, ['circuit', source], { encoding: 'utf8', timeout: 30000 });
  assert.equal(circuit.status, 0, circuit.stderr || circuit.stdout);
  assert.match(circuit.stdout, /^receiptRelation: depth [0-9]+$/m);
  const axioms = spawnSync(compiler, ['axioms', source], { encoding: 'utf8', timeout: 30000 });
  assert.equal(axioms.status, 0, axioms.stderr);
  assert.equal(axioms.stdout, '');
});

test('CLI fixtures, acceptance, rejection and explicit mock selection', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'veil-receipt-cli-'));
  const cli = join(root, 'examples/private-inference/receipt.mjs');
  const run = args => spawnSync(process.execPath, [cli, ...args], { cwd: root, encoding: 'utf8', timeout: 30000 });
  try {
    assert.equal(run(['fixture', scratch]).status, 0);
    const args = ['verify', '--mock', ...['receipt', 'policy', 'context'].map(name => join(scratch, `${name}.json`))];
    const good = run(args);
    assert.equal(good.status, 0, good.stderr);
    assert.equal(JSON.parse(good.stdout).accepted, true);
    assert.equal(run(args.filter(arg => arg !== '--mock')).status, 64);
    const path = join(scratch, 'receipt.json');
    const bad = JSON.parse(readFileSync(path, 'utf8'));
    bad.receipt.output_commit = flip(bad.receipt.output_commit);
    writeFileSync(path, JSON.stringify(bad));
    const rejected = run(args);
    assert.equal(rejected.status, 1, rejected.stderr);
    assert.equal(JSON.parse(rejected.stdout).code, 'output-binding');
    assert.equal(run(['verify', '--mock', '/missing-receipt', args[3], args[4]]).status, 2);
    writeFileSync(path, ' '.repeat(65537));
    assert.equal(run(args).status, 2);
    writeFileSync(path, '{invalid json');
    assert.equal(run(args).status, 2);
    assert.equal(run(['--help']).status, 0);
  } finally { rmSync(scratch, { recursive: true, force: true }); }
});

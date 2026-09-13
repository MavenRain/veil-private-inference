import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical, parseJson, sha256 } from '../core.mjs';
import { verifyAttestation } from '../attestation.mjs';
import { beginClient, finishClient, InferenceRunner, sealRequest, verifyReceipt } from '../protocol.mjs';
import { decrypt, encrypt, sessionKeys } from '../crypto.mjs';
import { ChallengeStore } from '../state.mjs';
import { createManifest, modelHash, verifyManifest } from '../model.mjs';
import { loadReceiptTwin } from '../cli.mjs';
import { fixture, NOW } from './fixtures.mjs';

const scratch = mkdtempSync(join(tmpdir(), 'veil-v2-test-'));
after(() => rmSync(scratch, { recursive: true, force: true }));
const api = await loadReceiptTwin();
let serial = 0;
const store = () => new ChallengeStore(join(scratch, `state-${++serial}`));
const bytes = Buffer.from('{"model":"test","stream":false,"messages":[{"role":"user","content":"private test"}]}');
async function setup(mutate) {
  const f = fixture();
  const client = beginClient(f.policy, store(), Buffer.from(bytes), NOW);
  let calls = 0;
  const runner = new InferenceRunner({ audience: f.policy.audience, model: f.policy.model,
    runtime: f.policy.runtime, gpu_measurement: f.policy.gpu_measurement, session_ttl: 300, max_sessions: 8 },
  { attest: s => f.attest(s, mutate), infer: async () => { calls++; return Buffer.from('private output'); }, clock: () => NOW });
  const attestation = await runner.begin(client.expected);
  return { ...f, client, runner, attestation, calls: () => calls };
}

test('encrypted inference accepts, checks the veil relation, and consumes a challenge across restart', async () => {
  const f = await setup();
  const message = sealRequest(f.client, f.attestation, NOW);
  assert.ok(!canonical(message).includes('private test'));
  const response = await f.runner.complete(message);
  assert.ok(!canonical(response).includes('private output'));
  const accepted = await finishClient(api, f.client, response, { now: NOW });
  assert.equal(accepted.output.toString(), 'private output');
  assert.equal(accepted.accepted, true);
  f.client.store = new ChallengeStore(f.client.store.path);
  await assert.rejects(finishClient(api, f.client, response, { now: NOW }), /challenge-replayed/);
  await assert.rejects(f.runner.complete(message), /session-missing/);
  assert.equal(f.calls(), 1);
});

const badGpu = [
  ['wrong child nonce', c => { c.eat_nonce = sha256('other'); }],
  ['nonce verification failed', c => { c['x-nvidia-gpu-attestation-report-nonce-match'] = false; }],
  ['failed firmware', c => { c['x-nvidia-gpu-driver-rim-signature-verified'] = false; }],
  ['missing firmware claim', c => { delete c['x-nvidia-gpu-vbios-rim-version-match']; }],
  ['revoked certificate', c => { c['x-nvidia-gpu-attestation-report-cert-chain']['x-nvidia-cert-ocsp-status'] = 'revoked'; }],
  ['debug GPU', c => { c.dbgstat = 'enabled'; }],
  ['non-boolean flag', c => { c.secboot = 'true'; }],
  ['failed measurements', c => { c.measres = 'failure'; }],
  ['wrong firmware version', c => { c['x-nvidia-gpu-driver-version'] = 'other'; }],
  ['wrong GPU identity', c => { c.ueid = 'other'; }],
  ['expired token', c => { c.exp = NOW; }],
  ['future token', c => { c.iat = NOW + 1; c.nbf = NOW + 1; }],
];
test('valid not-before may precede issuance', async () => {
  const f = await setup({ gpu: c => { c.nbf = NOW - 120; } });
  const response = await f.runner.complete(sealRequest(f.client, f.attestation, NOW));
  assert.equal((await finishClient(api, f.client, response, { now: NOW })).accepted, true);
});
test('a receipt expiring during proof verification is not accepted', async t => {
  let clock = NOW;
  t.mock.method(Date, 'now', () => clock * 1000);
  const f = await setup();
  const response = await f.runner.complete(sealRequest(f.client, f.attestation, NOW));
  await assert.rejects(finishClient(api, f.client, response, { proof: {},
    verifyProof: async () => { clock += 400; return true; } }), /session-time|jwt-time/);
});
for (const [name, gpu] of badGpu) test(`rejects ${name} before sending plaintext`, async () => {
  const f = await setup({ gpu });
  assert.throws(() => sealRequest(f.client, f.attestation, NOW));
  assert.equal(f.calls(), 0);
});
for (const [name, overall] of [
  ['wrong GPU nonce', c => { c.eat_nonce = sha256('other'); }],
  ['child substitution', c => { c.submods['GPU-0'][1][1] = sha256('other'); }],
  ['failed overall', c => { c['x-nvidia-overall-att-result'] = false; }],
  ['unsupported digest', c => { c.submods['GPU-0'][1][0] = 'SHA1'; }],
]) test(`rejects ${name}`, async () => {
  const f = await setup({ overall });
  assert.throws(() => sealRequest(f.client, f.attestation, NOW));
});
const annotation = c => c.submods.cpu0['ear.veraison.annotated-evidence'];
for (const [name, cpu] of [
  ['debug VM', c => { annotation(c).tdx.td_attributes.debug = true; }],
  ['wrong runtime binding', c => { annotation(c).report_data = '0'.repeat(128); }],
  ['wrong init data', c => { annotation(c).init_data = sha256('other'); }],
  ['wrong key in runtime data', c => { annotation(c).runtime_data_claims.session.signing_key = sessionKeys().signing_public; }],
  ['unapproved appraisal', c => { c.submods.cpu0['ear.status'] = 'contraindicated'; }],
  ['unapproved policy', c => { c.submods.cpu0['ear.appraisal-policy-id'] = 'default'; }],
  ['failed executable appraisal', c => { c.submods.cpu0['ear.trustworthiness-vector'].executables = 33; }],
  ['missing CPU module', c => { c.submods = {}; }],
]) test(`rejects ${name}`, async () => {
  const f = await setup({ cpu });
  assert.throws(() => sealRequest(f.client, f.attestation, NOW));
});
test('rejects untrusted signing keys, forged signatures and changed client keys', async () => {
  const f = await setup();
  const policy = structuredClone(f.policy);
  policy.cpu.keys = fixture().policy.cpu.keys;
  assert.throws(() => verifyAttestation(f.attestation, f.client.expected, policy, NOW), /jwt-signature/);
  const forged = structuredClone(f.attestation);
  forged.gpu[1]['GPU-0'] += 'x';
  assert.throws(() => verifyAttestation(forged, f.client.expected, f.policy, NOW));
  const expected = { ...f.client.expected, client_key: sessionKeys().encryption_public };
  assert.throws(() => verifyAttestation(f.attestation, expected, f.policy, NOW), /session-binding/);
});
test('changed statement and ciphertext fail verification', async () => {
  const f = await setup();
  const response = await f.runner.complete(sealRequest(f.client, f.attestation, NOW));
  const receipt = structuredClone(response.receipt);
  receipt.statement.output_commit = sha256('other');
  assert.throws(() => verifyReceipt(api, receipt, f.client.expected, f.policy, NOW), /workload-signature/);
  response.encrypted.ciphertext = Buffer.from('tamper').toString('base64url');
  await assert.rejects(finishClient(api, f.client, response, { now: NOW }), /decryption/);
});
test('concurrent completion executes backend once', async () => {
  const f = await setup();
  const request = sealRequest(f.client, f.attestation, NOW);
  const results = await Promise.allSettled([f.runner.complete(request), f.runner.complete(request)]);
  assert.equal(results.filter(x => x.status === 'fulfilled').length, 1);
  assert.equal(f.calls(), 1);
});
test('required proof cannot be omitted', async () => {
  const f = await setup();
  const response = await f.runner.complete(sealRequest(f.client, f.attestation, NOW));
  f.client.policy.zk = { required: true, verification_key_sha256: sha256('vkey') };
  await assert.rejects(finishClient(api, f.client, response, { now: NOW }), /zk-proof-required/);
});
test('transport binds direction and session', () => {
  const a = sessionKeys(); const b = sessionKeys();
  const session = { nonce: 'test' };
  const message = encrypt(a.encryption, b.encryption_public, session, 'request', bytes);
  assert.deepEqual(decrypt(b.encryption, a.encryption_public, session, 'request', message), bytes);
  assert.throws(() => decrypt(b.encryption, a.encryption_public, session, 'response', message));
  assert.throws(() => decrypt(b.encryption, a.encryption_public, { nonce: 'other' }, 'request', message));
});
test('strict JSON rejects duplicate keys, invalid UTF8, excessive nesting and trailing data', () => {
  for (const text of ['{"a":1,"a":2}', '{"a":{"b":0,"b":1}}', '{}x', '[1,]', '1e9999', '['.repeat(34) + '0' + ']'.repeat(34)]) {
    assert.throws(() => parseJson(Buffer.from(text)));
  }
  assert.throws(() => parseJson(Buffer.from([0x22, 0xff, 0x22])));
  assert.equal(canonical(parseJson(Buffer.from('{"b":[true,null,0],"a":"x"}'))), '{"a":"x","b":[true,null,0]}');
});
test('model manifest detects mutations, extra files and symlinks', () => {
  const root = join(scratch, 'model'); mkdirSync(root);
  writeFileSync(join(root, 'weights.bin'), 'weights');
  const manifest = createManifest(root, 'nim', 'test');
  verifyManifest(root, manifest, modelHash(manifest));
  writeFileSync(join(root, 'weights.bin'), 'changed');
  assert.throws(() => verifyManifest(root, manifest, modelHash(manifest)), /model-integrity/);
  writeFileSync(join(root, 'weights.bin'), 'weights');
  writeFileSync(join(root, 'extra'), 'x');
  assert.throws(() => verifyManifest(root, manifest, modelHash(manifest)), /model-file-set/);
  symlinkSync(join(root, 'weights.bin'), join(root, 'link'));
  assert.throws(() => createManifest(root, 'nim', 'test'), /model-file-kind/);
});

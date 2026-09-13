import { createHash, createPublicKey, verify } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
const digestPattern = /^[0-9a-f]{64}$/;
const isDigest = value => typeof value === 'string' && digestPattern.test(value);
const isTime = value => Number.isSafeInteger(value) && value >= 0;
const isBool = value => typeof value === 'boolean';
const isRuntime = value => value === 'nim' || value === 'tensorrt-llm';
const runtimeCode = value => value === 'nim' ? 1 : 2;
const keys = (value, expected) => value !== null && typeof value === 'object'
  && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
const receiptKeys = ['model', 'prompt_commit', 'output_commit'];
const isReceipt = value => keys(value, receiptKeys) && receiptKeys.every(key => isDigest(value[key]));

// Canonical JSON is part of this mock format, not an NVAT JWT serialization.
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const taggedHash = (domain, bytes) => createHash('sha256')
  .update(`veil/${domain}\0`, 'utf8').update(bytes).digest('hex');

function commitment(domain, bytes, salt) {
  if (!Buffer.isBuffer(bytes) || !Buffer.isBuffer(salt) || salt.length !== 32) {
    throw new TypeError('commitments require a Buffer and a 32-byte private salt');
  }
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return taggedHash(domain, Buffer.concat([salt, length, bytes]));
}

export const commitPrompt = (bytes, salt) => commitment('prompt/v1', bytes, salt);
export const commitOutput = (bytes, salt) => commitment('output/v1', bytes, salt);

export const rejectionCodes = Object.freeze([
  'accepted', 'token-signature', 'gpu-attestation', 'cc-disabled', 'debug-enabled',
  'workload-incomplete', 'gpu-policy', 'workload-gpu-binding', 'workload-policy',
  'runtime-policy', 'model-policy', 'model-binding', 'prompt-binding', 'output-binding',
  'gpu-challenge', 'workload-challenge', 'token-lifetime', 'issued-in-future',
  'not-yet-valid', 'expired', 'too-old', 'vm-attestation', 'vm-not-confidential', 'vm-debug-enabled',
]);

export const twinExports = [
  'emptyBytes', 'consBytes', 'makeModelHash', 'makePromptCommitment',
  'makeOutputCommitment', 'makeGpuMeasurement', 'makeWorkloadMeasurement',
  'makeReceiptDigest', 'makeReceipt', 'makeReceiptPolicy', 'makeReceiptContext',
  'makeReceiptInstance', 'makeGpuClaims', 'makeWorkloadClaims', 'makeTokenLifetime',
  'makeReceiptEvidence', 'receiptCode', 'provePlainReceipt', 'verifyPlainReceipt',
];

export async function loadTwin(compiler = join(root, '_build/default/bin/kanon.exe')) {
  const scratch = mkdtempSync(join(tmpdir(), 'veil-inference-'));
  try {
    const output = join(scratch, 'receipt.wasm');
    const built = spawnSync(compiler, ['build', join(root, 'runtime/reactor.kan'),
      join(root, 'examples/private-inference/relation.kan'),
      join(root, 'examples/private-inference/proof.kan'),
      join(root, 'examples/private-inference/twin.kan'), '-o', output,
      ...twinExports.flatMap(name => ['--export', name])],
    { encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024 });
    if (built.status !== 0) {
      throw new Error(`receipt compilation failed: ${built.error?.message ?? built.stderr.trim()}`);
    }
    const module = await WebAssembly.compile(readFileSync(output));
    if (WebAssembly.Module.imports(module).length !== 0) throw new Error('receipt module must have no imports');
    return (await WebAssembly.instantiate(module)).exports;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function validPolicy(p) {
  return keys(p, ['version', 'mode', 'audience', 'attester_public_key', 'model',
    'gpu_measurement', 'workload_measurement', 'runtime', 'max_age_seconds'])
    && p.version === 'veil.inference-policy.v1' && p.mode === 'mock'
    && typeof p.audience === 'string' && p.audience.length > 0 && p.audience.length <= 256
    && typeof p.attester_public_key === 'string' && p.attester_public_key.length <= 1024
    && [p.model, p.gpu_measurement, p.workload_measurement].every(isDigest)
    && isRuntime(p.runtime) && isTime(p.max_age_seconds) && p.max_age_seconds > 0;
}

function validClaims(c) {
  if (!keys(c, ['version', 'issuer', 'audience', 'gpu', 'workload', 'issued_at', 'not_before', 'expires_at'])) return false;
  if (!keys(c.gpu, ['measurement', 'nonce', 'attested', 'cc_enabled', 'debug_enabled'])) return false;
  if (!keys(c.workload, [...receiptKeys, 'gpu_measurement', 'measurement', 'nonce', 'runtime',
    'completed', 'vm_attested', 'vm_confidential', 'vm_debug_enabled'])) return false;
  const g = c.gpu;
  const w = c.workload;
  return c.version === 'veil.mock-nvat.v1' && c.issuer === 'veil.mock-attester'
    && typeof c.audience === 'string' && c.audience.length > 0 && c.audience.length <= 256
    && [g.measurement, g.nonce, w.model, w.prompt_commit, w.output_commit,
      w.gpu_measurement, w.measurement, w.nonce].every(isDigest)
    && [g.attested, g.cc_enabled, g.debug_enabled, w.completed,
      w.vm_attested, w.vm_confidential, w.vm_debug_enabled].every(isBool)
    && isRuntime(w.runtime) && [c.issued_at, c.not_before, c.expires_at].every(isTime);
}

function base64url(value, maxBytes) {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maxBytes * 4 / 3)
      || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.length <= maxBytes && bytes.toString('base64url') === value ? bytes : null;
}

const reject = code => ({ accepted: false, mode: 'mock', assurance: 'plaintext-twin', code });

// The policy, challenge and clock are relying-party inputs, never token fields.
// This function is stateless. The relying party must consume accepted challenges.
export function prepareMockReceipt(api, { envelope, policy, nonce, now }) {
  if (!validPolicy(policy)) return { error: 'policy-schema' };
  if (!isDigest(nonce) || !isTime(now)) return { error: 'context-schema' };
  if (!keys(envelope, ['version', 'mode', 'receipt', 'token'])
      || envelope.version !== 'veil.inference-receipt.v1' || envelope.mode !== 'mock'
      || !isReceipt(envelope.receipt)) return { error: 'receipt-schema' };
  const token = envelope.token;
  if (!keys(token, ['format', 'payload', 'signature'])
      || token.format !== 'veil.mock-nvat.ed25519.v1') return { error: 'unsupported-token-format' };
  const payload = base64url(token.payload, 16384);
  const signature = base64url(token.signature, 64);
  if (!payload || !signature || signature.length !== 64) return { error: 'token-encoding' };
  let claims;
  try { claims = JSON.parse(payload.toString('utf8')); } catch { return { error: 'token-json' }; }
  if (!validClaims(claims) || !Buffer.from(canonical(claims)).equals(payload)) return { error: 'token-schema' };
  if (claims.audience !== policy.audience) return { error: 'token-audience' };
  let authenticated;
  try {
    const key = createPublicKey(policy.attester_public_key);
    if (key.asymmetricKeyType !== 'ed25519') return { error: 'policy-key' };
    authenticated = verify(null, payload, key, signature);
  } catch { return { error: 'policy-key' }; }

  return prepareRelation(api, { receipt: envelope.receipt, policy, nonce, now,
    claims, authenticated, token });
}

// Callers must authenticate and normalize evidence before entering this bridge.
// This function proves no cryptographic fact about a caller-supplied auth flag.
export function prepareRelation(api, { receipt: publicReceipt, policy, nonce, now,
  claims, authenticated, token }) {
  const bytes = buffer => {
    let list = api.emptyBytes();
    for (let i = buffer.length - 1; i >= 0; i--) list = api.consBytes(buffer[i], list);
    return list;
  };
  // Canonical hex is big-endian. Reverse before the exact little-endian Nat fold.
  const digestBytes = hex => bytes(Buffer.from(hex, 'hex').reverse());
  const timeBytes = number => {
    const buffer = Buffer.alloc(8);
    buffer.writeBigUInt64LE(BigInt(number));
    return bytes(buffer);
  };
  const model = hex => api.makeModelHash(digestBytes(hex));
  const gpu = hex => api.makeGpuMeasurement(digestBytes(hex));
  const workload = hex => api.makeWorkloadMeasurement(digestBytes(hex));
  const receipt = r => api.makeReceipt(model(r.model),
    api.makePromptCommitment(digestBytes(r.prompt_commit)), api.makeOutputCommitment(digestBytes(r.output_commit)));
  const g = claims.gpu;
  const w = claims.workload;
  const instance = api.makeReceiptInstance(receipt(publicReceipt),
    api.makeReceiptPolicy(model(policy.model), gpu(policy.gpu_measurement),
      workload(policy.workload_measurement), runtimeCode(policy.runtime), timeBytes(policy.max_age_seconds)),
    api.makeReceiptContext(digestBytes(nonce), timeBytes(now)));
  const evidence = api.makeReceiptEvidence(Number(authenticated),
    api.makeGpuClaims(gpu(g.measurement), digestBytes(g.nonce),
      Number(g.attested), Number(g.cc_enabled), Number(g.debug_enabled)),
    api.makeWorkloadClaims(receipt(w), gpu(w.gpu_measurement), workload(w.measurement),
      digestBytes(w.nonce), runtimeCode(w.runtime), Number(w.completed),
      Number(w.vm_attested), Number(w.vm_confidential), Number(w.vm_debug_enabled)),
    api.makeTokenLifetime(timeBytes(claims.issued_at), timeBytes(claims.not_before), timeBytes(claims.expires_at)));
  const statementDigest = taggedHash('receipt-instance/v1', canonical({ receipt: publicReceipt, policy, nonce, now }));
  const evidenceDigest = taggedHash('receipt-evidence/v1', canonical(token));
  return { instance, evidence, statementDigest,
    instanceHandle: api.makeReceiptDigest(digestBytes(statementDigest)),
    evidenceHandle: api.makeReceiptDigest(digestBytes(evidenceDigest)) };
}

export function verifyMockReceipt(api, input) {
  const prepared = prepareMockReceipt(api, input);
  if (prepared.error) return reject(prepared.error);
  const { instance, evidence, instanceHandle, evidenceHandle, statementDigest } = prepared;
  const code = api.receiptCode(instance, evidence);
  if (code !== 0) return reject(rejectionCodes[code] ?? 'unknown-relation-result');
  const proof = api.provePlainReceipt(instanceHandle, evidenceHandle);
  if (api.verifyPlainReceipt(proof, instanceHandle, evidenceHandle, instance, evidence) !== 1) {
    return reject('plaintext-proof-binding');
  }
  return { accepted: true, mode: 'mock', assurance: 'plaintext-twin', code: 'accepted',
    receipt: input.envelope.receipt, gpu_measurement: input.policy.gpu_measurement,
    statement_digest: statementDigest };
}

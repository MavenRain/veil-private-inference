import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { canonical, commitOutput, commitPrompt, sha256 } from './host.mjs';

// Only the mock fixture producer imports this module. The verifier has no
// signing key and never accepts a key supplied by an incoming receipt.
export function signMockClaims(claims, privateKey) {
  const payload = Buffer.from(canonical(claims));
  return { format: 'veil.mock-nvat.ed25519.v1', payload: payload.toString('base64url'),
    signature: sign(null, payload, privateKey).toString('base64url') };
}

export function createMockFixture(now = Math.floor(Date.now() / 1000)) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const nonce = randomBytes(32).toString('hex');
  const model = sha256(Buffer.from('synthetic model bytes for the veil receipt demo'));
  const gpu = sha256(Buffer.from('mock GPU reference measurements v1'));
  const workload = sha256(Buffer.from('mock measured NIM workload v1'));
  const receipt = {
    model,
    prompt_commit: commitPrompt(Buffer.from('Synthetic private prompt'), randomBytes(32)),
    output_commit: commitOutput(Buffer.from('Synthetic private answer'), randomBytes(32)),
  };
  const claims = {
    version: 'veil.mock-nvat.v1', issuer: 'veil.mock-attester', audience: 'veil-receipt-demo',
    issued_at: now, not_before: now, expires_at: now + 300,
    gpu: { measurement: gpu, nonce, attested: true, cc_enabled: true, debug_enabled: false },
    workload: { ...receipt, gpu_measurement: gpu, measurement: workload, nonce,
      runtime: 'nim', completed: true, vm_attested: true, vm_confidential: true, vm_debug_enabled: false },
  };
  const policy = {
    version: 'veil.inference-policy.v1', mode: 'mock', audience: 'veil-receipt-demo',
    attester_public_key: publicKey.export({ type: 'spki', format: 'pem' }),
    model, gpu_measurement: gpu, workload_measurement: workload, runtime: 'nim', max_age_seconds: 300,
  };
  const envelope = { version: 'veil.inference-receipt.v1', mode: 'mock', receipt,
    token: signMockClaims(claims, privateKey) };
  return { envelope, policy, nonce, now, claims, privateKey };
}

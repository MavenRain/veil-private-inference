import { randomBytes } from 'node:crypto';
import { canonical, commitOutput, commitPrompt, decode64, exactKeys, isHex, isTime,
  parseJson, requireThat, taggedHash, unixTime } from './core.mjs';
import { checkReceiptSignature, decrypt, encrypt, importPublic, sessionKeys, signReceipt } from './crypto.mjs';
import { validatePolicy, verifyAttestation, workloadMeasurement } from './attestation.mjs';
import { prepareRelation, rejectionCodes } from '../examples/private-inference/host.mjs';
import { commitment as zkCommitment, randomBlind, validField } from './zk/binding.mjs';

export const sessionDigest = s => taggedHash('session/v2', canonical(s));
const statementKeys = ['version', 'session_digest', 'nonce', 'model', 'prompt_commit',
  'output_commit', 'gpu_measurement', 'runtime', 'completed_at', 'zk_commitment'];

export class InferenceRunner {
  constructor(config, { attest, infer, clock = unixTime }) {
    requireThat(exactKeys(config, ['audience', 'model', 'runtime', 'gpu_measurement', 'session_ttl', 'max_sessions'])
      && typeof config.audience === 'string' && config.audience.length > 0
      && isHex(config.model) && isHex(config.gpu_measurement) && ['nim', 'tensorrt-llm'].includes(config.runtime)
      && isTime(config.session_ttl) && config.session_ttl > 0 && config.session_ttl <= 3600
      && isTime(config.max_sessions) && config.max_sessions > 0 && config.max_sessions <= 1024, 'runner-config');
    this.config = Object.freeze({ ...config });
    this.attest = attest; this.infer = infer; this.clock = clock; this.sessions = new Map();
  }
  async begin(request) {
    requireThat(exactKeys(request, ['nonce', 'model', 'prompt_commit', 'client_key', 'audience'])
      && [request.nonce, request.model, request.prompt_commit].every(x => isHex(x))
      && request.model === this.config.model && request.audience === this.config.audience, 'begin-request');
    importPublic(request.client_key, 'X25519');
    const now = this.clock();
    for (const [id, slot] of this.sessions) if (slot.expires_at <= now) this.sessions.delete(id);
    requireThat(this.sessions.size < this.config.max_sessions, 'session-capacity');
    const keys = sessionKeys();
    const session = { version: 'veil.inference-session.v2', ...request,
      runtime: this.config.runtime, signing_key: keys.signing_public,
      encryption_key: keys.encryption_public, created_at: now };
    const id = sessionDigest(session);
    const slot = { keys, expires_at: now + this.config.session_ttl, attestation: null };
    this.sessions.set(id, slot);
    try {
      const attestation = await this.attest(session);
      requireThat(canonical(attestation.session) === canonical(session), 'attester-session');
      slot.attestation = attestation;
      return attestation;
    } catch (error) { this.sessions.delete(id); throw error; }
  }
  async complete(message) {
    requireThat(exactKeys(message, ['session_digest', 'encrypted']) && isHex(message.session_digest), 'complete-request');
    const slot = this.sessions.get(message.session_digest);
    requireThat(slot?.attestation && this.clock() < slot.expires_at, 'session-missing-or-expired');
    // Claim before any asynchronous operation. Retries create a fresh session.
    this.sessions.delete(message.session_digest);
    const { session } = slot.attestation;
    const plaintext = decrypt(slot.keys.encryption, session.client_key, session, 'request', message.encrypted, 1600000);
    let requestBytes;
    try {
      const input = parseJson(plaintext, 1600000);
      requireThat(exactKeys(input, ['request', 'prompt_salt', 'output_salt', 'zk_blind'])
        && validField(input.zk_blind) && input.zk_blind !== '0', 'private-request');
      requestBytes = decode64(input.request);
      const promptSalt = decode64(input.prompt_salt, 32);
      const outputSalt = decode64(input.output_salt, 32);
      requireThat(promptSalt.length === 32 && outputSalt.length === 32
        && commitPrompt(requestBytes, promptSalt) === session.prompt_commit, 'prompt-opening');
      const output = await this.infer(requestBytes);
      requireThat(Buffer.isBuffer(output) && output.length <= 1048576, 'backend-output');
      const statement = { version: 'veil.inference-statement.v2', session_digest: sessionDigest(session),
        nonce: session.nonce, model: session.model, prompt_commit: session.prompt_commit,
        output_commit: commitOutput(output, outputSalt), gpu_measurement: this.config.gpu_measurement,
        runtime: session.runtime, completed_at: this.clock() };
      requireThat(statement.completed_at >= session.created_at && statement.completed_at < slot.expires_at, 'inference-timeout');
      statement.zk_commitment = await zkCommitment(statement, input.zk_blind);
      const receipt = { version: 'veil.inference-receipt.v2', attestation: slot.attestation,
        statement, signature: signReceipt(statement, slot.keys.signing) };
      return { receipt, encrypted: encrypt(slot.keys.encryption, session.client_key, session,
        'response', output) };
    } finally { plaintext.fill(0); requestBytes?.fill(0); }
  }
}

export function verifyReceipt(api, receipt, expected, policy, now) {
  requireThat(exactKeys(receipt, ['version', 'attestation', 'statement', 'signature'])
    && receipt.version === 'veil.inference-receipt.v2', 'receipt-schema');
  const evidence = verifyAttestation(receipt.attestation, expected, policy, now);
  const s = receipt.attestation.session;
  const r = receipt.statement;
  requireThat(exactKeys(r, statementKeys) && r.version === 'veil.inference-statement.v2'
    && ['session_digest', 'nonce', 'model', 'prompt_commit', 'output_commit', 'gpu_measurement'].every(k => isHex(r[k]))
    && isTime(r.completed_at) && validField(r.zk_commitment), 'statement-schema');
  checkReceiptSignature(r, receipt.signature, s.signing_key);
  requireThat(r.session_digest === sessionDigest(s) && r.nonce === s.nonce && r.model === s.model
    && r.prompt_commit === s.prompt_commit && r.runtime === s.runtime
    && r.gpu_measurement === evidence.gpu.measurement, 'statement-binding');
  requireThat(r.completed_at >= evidence.iat && r.completed_at >= evidence.nbf
    && r.completed_at <= now && r.completed_at < evidence.exp, 'completion-time');
  const publicReceipt = { model: r.model, prompt_commit: r.prompt_commit, output_commit: r.output_commit };
  const relationPolicy = { model: policy.model, runtime: policy.runtime,
    gpu_measurement: policy.gpu_measurement, workload_measurement: workloadMeasurement(policy),
    max_age_seconds: policy.max_age_seconds };
  const claims = { gpu: { measurement: evidence.gpu.measurement, nonce: s.nonce,
    attested: true, cc_enabled: true, debug_enabled: false },
  workload: { ...publicReceipt, gpu_measurement: evidence.gpu.measurement,
    measurement: evidence.cpu.measurement, nonce: s.nonce, runtime: s.runtime,
    completed: true, vm_attested: true, vm_confidential: true, vm_debug_enabled: false },
  issued_at: evidence.iat, not_before: evidence.nbf, expires_at: evidence.exp };
  const prepared = prepareRelation(api, { receipt: publicReceipt, policy: relationPolicy,
    nonce: expected.nonce, now, claims, authenticated: true, token: receipt.attestation });
  const code = api.receiptCode(prepared.instance, prepared.evidence);
  requireThat(code === 0, `relation-${rejectionCodes[code] ?? 'unknown'}`);
  return { accepted: true, assurance: 'attested-workload', statement_digest: prepared.statementDigest };
}

export function beginClient(policy, store, request, now = unixTime()) {
  validatePolicy(policy);
  requireThat(Buffer.isBuffer(request) && request.length <= 1048576, 'request-size');
  const keys = sessionKeys();
  const promptSalt = randomBytes(32);
  const outputSalt = randomBytes(32);
  const blind = randomBlind();
  const expected = store.issue({ model: policy.model, audience: policy.audience,
    prompt_commit: commitPrompt(request, promptSalt), client_key: keys.encryption_public }, now, policy.max_age_seconds);
  return { expected, keys, promptSalt, outputSalt, blind, request, policy, store };
}
export function sealRequest(client, attestation, now = unixTime()) {
  client.store.check(client.expected, now);
  verifyAttestation(attestation, client.expected, client.policy, now);
  client.attestation = attestation;
  return { session_digest: sessionDigest(attestation.session), encrypted: encrypt(client.keys.encryption,
    attestation.session.encryption_key, attestation.session, 'request', Buffer.from(canonical({
      request: client.request.toString('base64url'), prompt_salt: client.promptSalt.toString('base64url'),
      output_salt: client.outputSalt.toString('base64url'), zk_blind: client.blind }))) };
}
export async function finishClient(api, client, response, { now, verifyProof, proof } = {}) {
  requireThat(exactKeys(response, ['receipt', 'encrypted']) && client.attestation
    && canonical(response.receipt.attestation) === canonical(client.attestation), 'response-session');
  const startedAt = now ?? unixTime();
  const result = verifyReceipt(api, response.receipt, client.expected, client.policy, startedAt);
  const s = client.attestation.session;
  const output = decrypt(client.keys.encryption, s.encryption_key, s, 'response', response.encrypted);
  requireThat(commitOutput(output, client.outputSalt) === response.receipt.statement.output_commit, 'output-opening');
  requireThat(await zkCommitment(response.receipt.statement, client.blind)
    === response.receipt.statement.zk_commitment, 'zk-opening');
  if (client.policy.zk.required || proof !== undefined) {
    requireThat(typeof verifyProof === 'function' && proof !== undefined, 'zk-proof-required');
    requireThat(await verifyProof(response.receipt.statement, proof, client.policy.zk.verification_key_sha256), 'zk-proof');
  }
  // Proof verification can be slow. Recheck freshness at the acceptance point.
  // Explicit time is reserved for deterministic simulation callers.
  const acceptedAt = now ?? unixTime();
  verifyReceipt(api, response.receipt, client.expected, client.policy, acceptedAt);
  client.store.consume(client.expected, response.receipt, acceptedAt);
  return { ...result, output, receipt: response.receipt };
}

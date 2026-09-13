import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonical } from '../core.mjs';
import { beginClient, finishClient, InferenceRunner, sealRequest } from '../protocol.mjs';
import { ChallengeStore } from '../state.mjs';
import { loadReceiptTwin } from '../cli.mjs';
import { fixture, NOW } from './fixtures.mjs';

const directory = mkdtempSync(join(tmpdir(), 'veil-demo-'));
try {
  const f = fixture();
  const runner = new InferenceRunner({ audience: f.policy.audience, model: f.policy.model,
    runtime: f.policy.runtime, gpu_measurement: f.policy.gpu_measurement, session_ttl: 300, max_sessions: 4 }, {
    attest: f.attest, clock: () => NOW, infer: async () => Buffer.from('{"answer":"synthetic demo output"}') });
  const client = beginClient(f.policy, new ChallengeStore(join(directory, 'state')), Buffer.from('synthetic demo input'), NOW);
  const attestation = await runner.begin(client.expected);
  const response = await runner.complete(sealRequest(client, attestation, NOW));
  const result = await finishClient(await loadReceiptTwin(), client, response, { now: NOW });
  console.log(canonical({ accepted: result.accepted, evidence: 'simulation', transport: 'X25519-HKDF-AES256GCM',
    receipt: result.receipt.statement, note: 'Synthetic attestation keys and backend. No hardware assurance.' }));
} finally { rmSync(directory, { recursive: true, force: true }); }

import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { inferenceBackend } from '../adapters.mjs';
import { canonical, parseJson, postJson } from '../core.mjs';
import { beginClient, finishClient, InferenceRunner, sealRequest } from '../protocol.mjs';
import { ChallengeStore } from '../state.mjs';
import { createReceiptServer } from '../server.mjs';
import { loadReceiptTwin } from '../cli.mjs';
import { fixture, NOW } from './fixtures.mjs';

test('HTTP client, encrypted service and NIM-compatible adapter preserve committed request bytes', async () => {
  const scratch = mkdtempSync(join(tmpdir(), 'veil-http-'));
  const request = Buffer.from('{ "stream": false, "messages": [{"role":"user","content":"private input"}], "model": "test" }');
  let saw;
  const backend = createServer(async (req, res) => {
    const parts = []; for await (const part of req) parts.push(part);
    saw = Buffer.concat(parts);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(canonical({ object: 'chat.completion', model: 'test', choices: [{
      message: { role: 'assistant', content: 'private output' }, finish_reason: 'stop' }] }));
  });
  backend.listen(0, '127.0.0.1'); await once(backend, 'listening');
  const f = fixture();
  const runner = new InferenceRunner({ audience: f.policy.audience, model: f.policy.model, runtime: f.policy.runtime,
    gpu_measurement: f.policy.gpu_measurement, session_ttl: 300, max_sessions: 2 }, {
    attest: f.attest, clock: () => NOW, infer: inferenceBackend(`http://127.0.0.1:${backend.address().port}/v1/chat/completions`, 'test') });
  const service = createReceiptServer(runner);
  service.listen(0, '127.0.0.1'); await once(service, 'listening');
  try {
    const url = `http://127.0.0.1:${service.address().port}`;
    const client = beginClient(f.policy, new ChallengeStore(join(scratch, 'state')), request, NOW);
    const attestation = parseJson(await postJson(url + '/v2/session', client.expected));
    const response = parseJson(await postJson(url + '/v2/inference', sealRequest(client, attestation, NOW)));
    const accepted = await finishClient(await loadReceiptTwin(), client, response, { now: NOW });
    assert.deepEqual(saw, request);
    assert.equal(parseJson(accepted.output).choices[0].message.content, 'private output');
    const duplicate = await fetch(url + '/v2/session', { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: '{"nonce":0,"nonce":1}' });
    assert.equal(duplicate.status, 400);
    assert.equal((await duplicate.json()).code, 'json-object');
    assert.equal((await fetch(url + '/unknown')).status, 404);
  } finally {
    service.closeAllConnections(); backend.closeAllConnections();
    await Promise.all([new Promise(r => service.close(r)), new Promise(r => backend.close(r))]);
    rmSync(scratch, { recursive: true, force: true });
  }
});
test('backend adapter rejects remote routing and unsupported request modes', async () => {
  assert.throws(() => inferenceBackend('https://example.com/v1/chat/completions', 'test'), /url/);
  const backend = inferenceBackend('http://127.0.0.1:1/v1/chat/completions', 'test');
  for (const patch of [{ model: 'wrong' }, { stream: true }, { tools: [] }, { messages: [{ role: 'user', content: [{ image_url: 'https://example.com' }] }] }]) {
    const request = { model: 'test', stream: false, messages: [{ role: 'user', content: 'x' }], ...patch };
    await assert.rejects(backend(Buffer.from(canonical(request))), /inference-/);
  }
});

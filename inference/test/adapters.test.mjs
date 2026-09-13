import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { once } from 'node:events';
import { hardwareAttester } from '../adapters.mjs';
import { canonical, sha256 } from '../core.mjs';
import { gpuNonce, reportData, runtimeData, verifyAttestation } from '../attestation.mjs';
import { sessionKeys } from '../crypto.mjs';
import { fixture, NOW } from './fixtures.mjs';

test('hardware adapter connects fixed NVAT argv, 64-byte TDX evidence and Trustee REST', async () => {
  const root = mkdtempSync(join(tmpdir(), 'veil-adapter-'));
  const f = fixture();
  const keys = sessionKeys();
  const expected = { nonce: sha256('test-nonce'), model: f.policy.model,
    prompt_commit: sha256('test-prompt'), client_key: sessionKeys().encryption_public, audience: f.policy.audience };
  const session = { version: 'veil.inference-session.v2', ...expected, runtime: 'nim', created_at: NOW,
    signing_key: keys.signing_public, encryption_key: keys.encryption_public };
  const evidence = await f.attest(session);
  let received;
  const server = createServer(async (request, response) => {
    const chunks = []; for await (const chunk of request) chunks.push(chunk);
    received = { method: request.method, url: request.url, body: JSON.parse(Buffer.concat(chunks)) };
    response.end(evidence.cpu);
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const executable = (name, source) => {
    const path = join(root, name);
    writeFileSync(path, `#!${process.execPath}\n${source}\n`, { mode: 0o700 });
    return path;
  };
  try {
    const argv = ['attest', '--device', 'gpu', '--gpu-evidence-source', 'nvml', '--verifier', 'remote',
      '--nonce', gpuNonce(session), '--format', 'json'];
    const config = {
      nvattest: executable('nvat.cjs', `require('node:assert/strict').deepEqual(process.argv.slice(2), ${JSON.stringify(argv)});
process.stdout.write(${JSON.stringify(canonical({ result_code: 0, detached_eat: evidence.gpu }))});`),
      evidence_getter: executable('tdx.cjs', `const chunks=[]; process.stdin.on('data', c=>chunks.push(c));
process.stdin.on('end',()=>{require('node:assert/strict').equal(Buffer.concat(chunks).toString('hex'),
${JSON.stringify(reportData(runtimeData(session, evidence.gpu)).padEnd(128, '0'))}); console.log('Tdx:{"quote":"test-only"}');});`),
      cc_check: executable('cc.cjs', 'console.log(JSON.stringify({cc:true,debug:false,production:true,ready:true,gpus:1}));'),
      trustee_url: `http://127.0.0.1:${server.address().port}/attestation`, policy_id: f.policy.cpu.policy_id,
    };
    const result = await hardwareAttester(config)(session);
    assert.equal(canonical(result), canonical(evidence));
    assert.equal(verifyAttestation(result, expected, f.policy, NOW).gpu.measurement, f.policy.gpu_measurement);
    assert.equal(received.method, 'POST'); assert.equal(received.url, '/attestation');
    assert.deepEqual(received.body, { verification_requests: [{ tee: 'tdx',
      evidence: Buffer.from('{"quote":"test-only"}').toString('base64url'),
      runtime_data: { structured: runtimeData(session, evidence.gpu) }, runtime_data_hash_algorithm: 'sha256' }],
    policy_ids: [f.policy.cpu.policy_id] });
    config.cc_check = executable('off.cjs', 'console.log(JSON.stringify({cc:false,debug:false,production:true,ready:true,gpus:1}));');
    await assert.rejects(() => hardwareAttester(config)(session), { code: 'gpu-mode' });
    config.cc_check = executable('error.cjs', 'console.error("private diagnostic"); process.exit(1);');
    await assert.rejects(() => hardwareAttester(config)(session), error => error.code === 'attestation-command'
      && !error.message.includes('private diagnostic'));
  } finally {
    server.close(); server.closeAllConnections();
    await once(server, 'close'); rmSync(root, { recursive: true, force: true });
  }
});

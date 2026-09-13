import { execFile } from 'node:child_process';
import { boundedResponse, canonical, exactKeys, isObject, parseJson, postJson, ReceiptError, requireThat, secureUrl } from './core.mjs';
import { gpuNonce, reportData, runtimeData } from './attestation.mjs';

function execute(binary, args, input) {
  return new Promise((resolve, reject) => {
    // argv is fixed by this adapter. Quotes, prompts and secrets are never logged.
    const child = execFile(binary, args, { timeout: 120000, maxBuffer: 1048576,
      encoding: 'buffer', killSignal: 'SIGKILL', env: process.env }, (error, stdout) => {
      if (error) reject(new ReceiptError('attestation-command'));
      else resolve(stdout);
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input);
  });
}

export async function checkGpuMode(binary) {
  const mode = parseJson(await execute(binary, [], Buffer.alloc(0)));
  requireThat(exactKeys(mode, ['cc', 'debug', 'production', 'ready', 'gpus'])
    && mode.cc === true && mode.debug === false && mode.production === true
    && mode.ready === true && mode.gpus === 1, 'gpu-mode');
}

export function hardwareAttester({ nvattest, evidence_getter, cc_check, trustee_url, policy_id }) {
  requireThat([nvattest, evidence_getter, cc_check].every(x => typeof x === 'string' && x.startsWith('/'))
    && typeof policy_id === 'string' && policy_id.length > 0, 'attester-config');
  const endpoint = secureUrl(trustee_url);
  requireThat(endpoint.pathname === '/attestation', 'trustee-endpoint');
  return async session => {
    await checkGpuMode(cc_check);
    const result = parseJson(await execute(nvattest, ['attest', '--device', 'gpu',
      '--gpu-evidence-source', 'nvml', '--verifier', 'remote', '--nonce', gpuNonce(session), '--format', 'json']));
    requireThat(result.result_code === 0 && Array.isArray(result.detached_eat), 'nvat-result');
    const gpu = result.detached_eat;
    const data = runtimeData(session, gpu);
    const report = Buffer.from(reportData(data).padEnd(128, '0'), 'hex');
    const output = (await execute(evidence_getter, ['stdio'], report)).toString('utf8').trim();
    requireThat(output.startsWith('Tdx:') && !output.includes('\n'), 'cpu-evidence-format');
    const evidence = parseJson(Buffer.from(output.slice(4)));
    requireThat(isObject(evidence), 'cpu-evidence-schema');
    const token = (await postJson(endpoint.href, {
      verification_requests: [{ tee: 'tdx', evidence: Buffer.from(canonical(evidence)).toString('base64url'),
        runtime_data: { structured: data }, runtime_data_hash_algorithm: 'sha256' }],
      policy_ids: [policy_id],
    }, 120000)).toString('utf8').trim();
    requireThat(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token), 'trustee-token');
    return { session, gpu, cpu: token };
  };
}

export function inferenceBackend(url, modelId) {
  const endpoint = secureUrl(url, { loopbackOnly: true });
  requireThat(endpoint.pathname === '/v1/chat/completions', 'backend-endpoint');
  return async bytes => {
    const request = parseJson(bytes);
    requireThat(isObject(request) && request.model === modelId && request.stream === false
      && Array.isArray(request.messages) && request.messages.length > 0
      && request.messages.length <= 256 && request.messages.every(m => exactKeys(m, ['role', 'content'])
        && ['system', 'user', 'assistant'].includes(m.role) && typeof m.content === 'string'), 'inference-request');
    // Only text chat is supported. Exclude arbitrary upstream routing, remote
    // multimodal URLs, tool execution and caller-selected model loading.
    requireThat(Object.keys(request).every(k => ['model', 'stream', 'messages', 'max_tokens',
      'temperature', 'top_p', 'seed', 'stop'].includes(k)), 'inference-options');
    const response = await boundedResponse(await fetch(endpoint, { method: 'POST', redirect: 'error',
      headers: { 'content-type': 'application/json' }, body: bytes, signal: AbortSignal.timeout(120000) }));
    const parsed = parseJson(response);
    requireThat(isObject(parsed) && parsed.object === 'chat.completion' && parsed.model === modelId
      && Array.isArray(parsed.choices) && parsed.choices.length > 0
      && parsed.choices.every(c => c.message?.role === 'assistant' && typeof c.message?.content === 'string'
        && ['stop', 'length'].includes(c.finish_reason)), 'inference-incomplete');
    return response;
  };
}

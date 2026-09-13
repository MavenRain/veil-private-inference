import { spawn, execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { canonical, exactKeys, isObject, readJson, requireThat, secureUrl } from './core.mjs';
import { checkGpuMode, hardwareAttester, inferenceBackend } from './adapters.mjs';
import { verifyManifest } from './model.mjs';
import { InferenceRunner } from './protocol.mjs';
import { createReceiptServer } from './server.mjs';

export function validateRunnerConfig(config) {
  requireThat(exactKeys(config, ['version', 'listen', 'port', 'model_root', 'manifest', 'backend_url',
    'runner', 'attester']) && config.version === 'veil.runner-config.v2'
    && ['127.0.0.1', '0.0.0.0', '::1'].includes(config.listen)
    && Number.isInteger(config.port) && config.port >= 1024 && config.port <= 65535
    && [config.model_root, config.manifest].every(p => typeof p === 'string' && p.startsWith('/')), 'server-config');
  new InferenceRunner(config.runner, { attest: null, infer: null });
  hardwareAttester(config.attester);
  inferenceBackend(config.backend_url, 'config-validation');
  return config;
}

export function validateWorkload(w) {
  requireThat(exactKeys(w, ['version', 'service', 'backend_argv', 'backend_env', 'ready_url',
    'startup_timeout_seconds', 'mount_guest_configfs']) && w.version === 'veil.workload.v2', 'workload-config');
  validateRunnerConfig(w.service);
  requireThat(Array.isArray(w.backend_argv) && w.backend_argv.length > 0 && w.backend_argv.length <= 128
    && w.backend_argv[0].startsWith('/') && w.backend_argv.every(x => typeof x === 'string'
      && x.length > 0 && x.length <= 4096 && !x.includes('\0')), 'backend-argv');
  requireThat(isObject(w.backend_env) && Object.keys(w.backend_env).length <= 64
    && Object.entries(w.backend_env).every(([k, v]) => /^[A-Z][A-Z0-9_]*$/.test(k)
      && typeof v === 'string' && v.length <= 4096 && !v.includes('\0'))
    && w.backend_env.HF_HUB_OFFLINE === '1' && w.backend_env.TRANSFORMERS_OFFLINE === '1', 'backend-environment');
  const ready = secureUrl(w.ready_url, { loopbackOnly: true });
  requireThat(ready.origin === new URL(w.service.backend_url).origin
    && Number.isInteger(w.startup_timeout_seconds) && w.startup_timeout_seconds >= 1
    && w.startup_timeout_seconds <= 3600 && typeof w.mount_guest_configfs === 'boolean', 'backend-readiness');
  return w;
}

export async function launchWorkload(w, { signal, checkPlatform = checkGpuMode } = {}) {
  validateWorkload(w);
  const c = w.service;
  // All artifacts, configuration and executables must be in the approved image.
  const manifest = verifyManifest(c.model_root, readJson(c.manifest, 4000000), c.runner.model);
  requireThat(manifest.runtime === c.runner.runtime, 'manifest-runtime');
  if (w.mount_guest_configfs && !existsSync('/sys/kernel/config/tsm/report')) {
    requireThat(process.platform === 'linux', 'tdx-platform');
    execFileSync('/bin/mount', ['-t', 'configfs', 'configfs', '/sys/kernel/config'], { stdio: 'ignore', timeout: 10000 });
  }
  await checkPlatform(c.attester.cc_check);
  // Backend logs can contain prompts. Discard both streams at the process boundary.
  const child = spawn(w.backend_argv[0], w.backend_argv.slice(1), {
    stdio: 'ignore', env: { ...process.env, ...w.backend_env }, detached: process.platform !== 'win32' });
  let exited = false, server;
  child.once('error', () => { exited = true; server?.close(); server?.closeAllConnections(); });
  child.once('exit', () => { exited = true; server?.close(); server?.closeAllConnections(); });
  const stop = () => {
    server?.close(); server?.closeAllConnections();
    // Kill the entire backend process group, including worker subprocesses.
    if (child.pid) try { process.kill(process.platform === 'win32' ? child.pid : -child.pid, 'SIGKILL'); } catch {}
  };
  signal?.addEventListener('abort', stop, { once: true });
  try {
    const deadline = Date.now() + w.startup_timeout_seconds * 1000;
    let ready = false;
    while (Date.now() < deadline && !ready) {
      requireThat(!exited && !signal?.aborted, 'backend-start');
      try {
        const response = await fetch(w.ready_url, { redirect: 'error', signal: AbortSignal.timeout(2000) });
        ready = response.ok;
        await response.body?.cancel();
      } catch {}
      if (!ready) await delay(250);
    }
    requireThat(ready && !exited && !signal?.aborted, 'backend-start');
    server = createReceiptServer(new InferenceRunner(c.runner, {
      attest: hardwareAttester(c.attester), infer: async bytes => {
        await checkGpuMode(c.attester.cc_check);
        const result = await inferenceBackend(c.backend_url, manifest.model_id)(bytes);
        await checkGpuMode(c.attester.cc_check);
        return result;
      } }));
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(c.port, c.listen, resolve); });
    server.once('close', stop);
    return { server, stop };
  } catch (error) { stop(); throw error; }
}

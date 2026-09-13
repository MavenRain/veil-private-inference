import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildContext, finalize, initDataInfo, resources } from '../deploy/bundle.mjs';
import { validateWorkload, launchWorkload } from '../workload.mjs';
import { createManifest, modelHash } from '../model.mjs';
import { canonical, sha256 } from '../core.mjs';
import { fixture } from './fixtures.mjs';

function config() {
  const { policy } = fixture();
  const workload = { version: 'veil.workload.v2', service: {
    version: 'veil.runner-config.v2', listen: '0.0.0.0', port: 8081,
    model_root: '/opt/veil/model', manifest: '/opt/veil/model-manifest.json',
    backend_url: 'http://127.0.0.1:8000/v1/chat/completions',
    runner: { audience: policy.audience, model: policy.model, runtime: policy.runtime,
      gpu_measurement: policy.gpu_measurement, session_ttl: 300, max_sessions: 8 },
    attester: { nvattest: '/opt/nvat/bin/nvattest', evidence_getter: '/opt/nvat/bin/evidence_getter',
      cc_check: '/opt/nvat/bin/veil-gpu-cc-check',
      trustee_url: 'https://trustee.example/attestation', policy_id: policy.cpu.policy_id },
  }, backend_argv: ['/usr/bin/backend', '--host', '127.0.0.1'],
  backend_env: { HF_HUB_OFFLINE: '1', TRANSFORMERS_OFFLINE: '1' },
  ready_url: 'http://127.0.0.1:8000/v1/health/ready', startup_timeout_seconds: 600, mount_guest_configfs: true };
  return { policy, c: { version: 'veil.deployment.v2', name: 'veil', namespace: 'veil',
    image: 'registry.example/veil@sha256:' + 'ab'.repeat(32), attestation_egress_cidrs: ['192.0.2.0/24'],
    gateway_label: 'veil-gateway', workload } };
}

function sealed() {
  const { c, policy } = config();
  const raw = Buffer.from('version="0.1.0"\nalgorithm="sha384"\n[data]\n"policy.rego"="reviewed policy"\n"aa.toml"="reviewed AA"\n"cdh.toml"="reviewed CDH"\n');
  const pod = resources(c).pod;
  pod.metadata.annotations['io.katacontainers.config.hypervisor.cc_init_data'] = gzipSync(raw).toString('base64');
  const info = initDataInfo(raw);
  policy.cpu.init_data = info.digest;
  const approval = { version: 'veil.deployment-approval.v2', image: c.image,
    pod_spec_sha256: sha256(canonical(pod.spec)), agent_policy_sha256: info.agent_policy_sha256,
    init_data: info.digest, reviewer: 'fixture only',
    agent_api_review: 'deny-exec-copy-stream-policy-update;exact-container-spec' };
  return { c, policy, pod, raw, approval };
}

test('deployment requires digest pins, confidential runtime and restricted network', () => {
  const { c } = config();
  const r = resources(c);
  assert.equal(r.pod.spec.runtimeClassName, 'kata-qemu-nvidia-gpu-tdx');
  assert.equal(r.pod.spec.containers[0].resources.limits['nvidia.com/pgpu'], '1');
  assert.equal(r.pod.spec.automountServiceAccountToken, false);
  for (const image of ['registry/image:latest', 'registry/image@sha256:' + '0'.repeat(64)])
    assert.throws(() => resources({ ...c, image }), /deployment-config/);
  assert.throws(() => resources({ ...c, attestation_egress_cidrs: ['0.0.0.0/0'] }), /attestation-egress/);
});

test('finalizer binds exact TOML, reviewed agent policy, image, pod and verifier policy', () => {
  const { c, policy, pod, raw, approval } = sealed();
  const result = finalize(c, pod, raw, policy, approval);
  assert.equal(result.manifest.init_data, createHash('sha384').update(raw).digest('hex'));
  assert.equal(result.manifest.hardware_validated, false);
  for (const field of ['image', 'pod_spec_sha256', 'agent_policy_sha256', 'init_data'])
    assert.throws(() => finalize(c, pod, raw, policy, { ...approval, [field]: 'bad' }), /deployment-approval/);
  assert.throws(() => finalize(c, pod, Buffer.concat([raw, Buffer.from('\n')]), policy, approval), /init-data-annotation/);
  const changed = structuredClone(pod);
  changed.spec.containers[0].command = ['/bin/sh'];
  assert.throws(() => finalize(c, changed, raw, policy, approval), /generated-pod-drift/);
  const other = structuredClone(policy); other.cpu.init_data = '01'.repeat(48);
  assert.throws(() => finalize(c, pod, raw, other, approval), /deployment-policy-binding/);
});

test('private build context includes verified model and excludes local keys and dependencies', () => {
  const dir = mkdtempSync(join(tmpdir(), 'veil-context-'));
  try {
    const model = join(dir, 'input'); mkdirSync(model); writeFileSync(join(model, 'weights'), 'fixture');
    const manifest = createManifest(model, 'nim', 'fixture');
    const { c } = config(); c.workload.service.runner.model = modelHash(manifest);
    buildContext(c.workload, model, manifest, join(dir, 'context'));
    assert.equal(readFileSync(join(dir, 'context/model/weights'), 'utf8'), 'fixture');
    assert.throws(() => readFileSync(join(dir, 'context/veil/inference/node_modules/package.json')));
    assert.equal(JSON.parse(readFileSync(join(dir, 'context/veil/workload.json'))).version, 'veil.workload.v2');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('launcher rejects remote routing and a backend that exits before readiness', async () => {
  const { c } = config();
  const w = c.workload;
  w.ready_url = 'https://remote.example/ready';
  assert.throws(() => validateWorkload(w), { code: 'url' });
  const dir = mkdtempSync(join(tmpdir(), 'veil-start-'));
  try {
    mkdirSync(join(dir, 'model')); writeFileSync(join(dir, 'model/weights'), 'fixture');
    const manifest = createManifest(join(dir, 'model'), 'nim', 'fixture');
    writeFileSync(join(dir, 'manifest.json'), canonical(manifest));
    w.service.model_root = join(dir, 'model'); w.service.manifest = join(dir, 'manifest.json');
    w.service.runner.model = modelHash(manifest);
    w.ready_url = 'http://127.0.0.1:8000/v1/health/ready'; w.mount_guest_configfs = false;
    w.backend_argv = [process.execPath, '-e', 'process.exit(1)']; w.startup_timeout_seconds = 1;
    await assert.rejects(() => launchWorkload(w, { checkPlatform: async () => {} }), /backend-start/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

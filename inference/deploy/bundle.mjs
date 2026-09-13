import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { canonical, exactKeys, parseJson, readBytes, readJson, ReceiptError,
  requireThat, sha256, writePrivate } from '../core.mjs';
import { validatePolicy } from '../attestation.mjs';
import { validateWorkload } from '../workload.mjs';
import { verifyManifest } from '../model.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const annotation = 'io.katacontainers.config.hypervisor.cc_init_data';
export const pinnedImage = s => typeof s === 'string'
  && /^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$/.test(s) && !/@sha256:0+$/.test(s);
const dnsName = s => typeof s === 'string' && /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(s);

export function validateDeployment(c) {
  requireThat(exactKeys(c, ['version', 'name', 'namespace', 'image', 'attestation_egress_cidrs',
    'gateway_label', 'workload']) && c.version === 'veil.deployment.v2'
    && dnsName(c.name) && dnsName(c.namespace) && dnsName(c.gateway_label) && pinnedImage(c.image), 'deployment-config');
  validateWorkload(c.workload);
  requireThat(c.workload.service.port === 8081 && c.workload.service.listen === '0.0.0.0'
    && c.workload.service.model_root === '/opt/veil/model'
    && c.workload.service.manifest === '/opt/veil/model-manifest.json'
    && c.workload.service.attester.nvattest === '/opt/nvat/bin/nvattest'
    && c.workload.service.attester.evidence_getter === '/opt/nvat/bin/evidence_getter'
    && c.workload.service.attester.cc_check === '/opt/nvat/bin/veil-gpu-cc-check'
    && c.workload.mount_guest_configfs === true, 'deployment-paths');
  requireThat(Array.isArray(c.attestation_egress_cidrs) && c.attestation_egress_cidrs.length > 0
    && c.attestation_egress_cidrs.length <= 32 && c.attestation_egress_cidrs.every(s => {
      const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(s);
      return m && m[1].split('.').every(n => Number(n) <= 255) && Number(m[2]) >= 8 && Number(m[2]) <= 32;
    }), 'attestation-egress');
  requireThat(new URL(c.workload.service.attester.trustee_url).protocol === 'https:', 'production-trustee-tls');
  return c;
}

export function resources(c) {
  validateDeployment(c);
  const labels = { app: c.name };
  const metadata = { name: c.name, namespace: c.namespace, labels };
  const pod = { apiVersion: 'v1', kind: 'Pod', metadata: { ...metadata, annotations: {} }, spec: {
    runtimeClassName: 'kata-qemu-nvidia-gpu-tdx', restartPolicy: 'Never', automountServiceAccountToken: false,
    nodeSelector: { 'nvidia.com/cc.mode': 'on', 'nvidia.com/cc.mode.state': 'on',
      'nvidia.com/cc.ready.state': 'true', 'nvidia.com/gpu.workload.config': 'vm-passthrough' },
    containers: [{ name: 'receipt', image: c.image, imagePullPolicy: 'Always',
      command: ['/usr/local/bin/node', '/opt/veil/inference/deploy/launch.mjs'], args: [],
      // Privilege is inside the Kata TDX guest, needed to mount guest TSM configfs.
      // No hostPath, hostPID, hostNetwork, sidecars or host plaintext storage.
      securityContext: { privileged: true, runAsUser: 0, readOnlyRootFilesystem: true },
      ports: [{ name: 'receipt', containerPort: 8081 }],
      readinessProbe: { httpGet: { path: '/healthz', port: 'receipt' }, periodSeconds: 5 },
      resources: { limits: { 'nvidia.com/pgpu': '1', cpu: '16', memory: '64Gi' } },
      volumeMounts: [{ name: 'scratch', mountPath: '/tmp' }, { name: 'shm', mountPath: '/dev/shm' }],
    }], volumes: [{ name: 'scratch', emptyDir: { medium: 'Memory', sizeLimit: '8Gi' } },
      { name: 'shm', emptyDir: { medium: 'Memory', sizeLimit: '8Gi' } }],
  } };
  const service = { apiVersion: 'v1', kind: 'Service', metadata, spec: {
    type: 'ClusterIP', selector: labels, ports: [{ port: 8081, targetPort: 'receipt', name: 'receipt' }] } };
  const network = { apiVersion: 'networking.k8s.io/v1', kind: 'NetworkPolicy', metadata, spec: {
    podSelector: { matchLabels: labels }, policyTypes: ['Ingress', 'Egress'],
    ingress: [{ from: [{ podSelector: { matchLabels: { app: c.gateway_label } } }],
      ports: [{ protocol: 'TCP', port: 8081 }] }],
    egress: [{ to: c.attestation_egress_cidrs.map(cidr => ({ ipBlock: { cidr } })),
      ports: [{ protocol: 'TCP', port: 443 }] },
    { to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } },
      podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }],
      ports: [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }] }],
  } };
  return { pod, service, network };
}

export function initDataInfo(raw) {
  const result = spawnSync(process.env.VEIL_PYTHON ?? 'python3', ['-I', join(root, 'deploy/initdata.py')],
    { input: raw, timeout: 10000, maxBuffer: 3000000 });
  requireThat(result.status === 0, 'init-data-toml');
  const init = parseJson(result.stdout, 3000000);
  requireThat(['policy.rego', 'aa.toml', 'cdh.toml'].every(k => typeof init.data[k] === 'string'
    && init.data[k].length > 0), 'init-data-components');
  return { init, digest: createHash(init.algorithm).update(raw).digest('hex').padEnd(96, '0'),
    agent_policy_sha256: sha256(init.data['policy.rego']) };
}

export function finalize(c, pod, raw, policy, approval) {
  validatePolicy(policy);
  const expected = resources(c).pod;
  requireThat(pod.kind === 'Pod' && pod.apiVersion === 'v1'
    && exactKeys(pod, ['apiVersion', 'kind', 'metadata', 'spec'])
    && exactKeys(pod.metadata, ['name', 'namespace', 'labels', 'annotations'])
    && exactKeys(pod.metadata.annotations, [annotation])
    && canonical(pod.metadata.labels) === canonical(expected.metadata.labels)
    && pod.metadata?.name === c.name && pod.metadata?.namespace === c.namespace
    && canonical(pod.spec) === canonical(expected.spec), 'generated-pod-drift');
  const compressed = pod.metadata.annotations?.[annotation];
  requireThat(typeof compressed === 'string' && compressed.length <= 3000000
    && gunzipSync(Buffer.from(compressed, 'base64'), { maxOutputLength: 2000000 }).equals(raw), 'init-data-annotation');
  const info = initDataInfo(raw);
  requireThat(exactKeys(approval, ['version', 'image', 'pod_spec_sha256', 'agent_policy_sha256',
    'init_data', 'reviewer', 'agent_api_review']) && approval.version === 'veil.deployment-approval.v2'
    && typeof approval.reviewer === 'string' && approval.reviewer.length > 0
    && approval.agent_api_review === 'deny-exec-copy-stream-policy-update;exact-container-spec'
    && approval.image === c.image && approval.pod_spec_sha256 === sha256(canonical(pod.spec))
    && approval.agent_policy_sha256 === info.agent_policy_sha256 && approval.init_data === info.digest, 'deployment-approval');
  requireThat(policy.cpu.init_data === info.digest && policy.model === c.workload.service.runner.model
    && policy.runtime === c.workload.service.runner.runtime && policy.audience === c.workload.service.runner.audience
    && policy.gpu_measurement === c.workload.service.runner.gpu_measurement
    && policy.cpu.policy_id === c.workload.service.attester.policy_id, 'deployment-policy-binding');
  return { ...resources(c), pod, manifest: { version: 'veil.deployment-manifest.v2', image: c.image,
    init_data: info.digest, agent_policy_sha256: info.agent_policy_sha256,
    pod_sha256: sha256(canonical(pod)), policy_sha256: sha256(canonical(policy)),
    workload_sha256: sha256(canonical(c.workload)), hardware_validated: false } };
}

export function buildContext(workload, modelRoot, manifest, out) {
  validateWorkload(workload);
  verifyManifest(modelRoot, manifest, workload.service.runner.model);
  requireThat(workload.service.model_root === '/opt/veil/model'
    && workload.service.manifest === '/opt/veil/model-manifest.json', 'context-paths');
  mkdirSync(out, { mode: 0o700 });
  const target = join(out, 'veil/inference');
  mkdirSync(target, { recursive: true, mode: 0o700 });
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (entry.isFile() && (entry.name.endsWith('.mjs') || ['package.json', 'package-lock.json'].includes(entry.name)))
      cpSync(join(root, entry.name), join(target, entry.name), { errorOnExist: true, force: false });
  }
  for (const dir of ['zk', 'deploy']) cpSync(join(root, dir), join(target, dir), { recursive: true, errorOnExist: true, force: false });
  mkdirSync(join(target, 'artifacts'), { mode: 0o700 });
  cpSync(join(root, 'artifacts/receipt.wasm'), join(target, 'artifacts/receipt.wasm'));
  mkdirSync(join(out, 'veil/examples/private-inference'), { recursive: true, mode: 0o700 });
  cpSync(join(root, '../examples/private-inference/host.mjs'), join(out, 'veil/examples/private-inference/host.mjs'));
  writePrivate(join(out, 'veil/workload.json'), canonical(workload) + '\n');
  writePrivate(join(out, 'veil/model-manifest.json'), canonical(manifest) + '\n');
  cpSync(modelRoot, join(out, 'model'), { recursive: true, errorOnExist: true, force: false });
  cpSync(join(root, 'deploy/Dockerfile'), join(out, 'Dockerfile'));
  // Detect changes while making the context copy as well as at container startup.
  verifyManifest(join(out, 'model'), manifest, workload.service.runner.model);
}

async function main([command, ...args]) {
  if (command === 'context' && args.length === 4) {
    buildContext(readJson(args[0]), resolve(args[1]), readJson(args[2], 4000000), resolve(args[3]));
  } else if (command === 'prepare' && args.length === 2) {
    const result = resources(readJson(args[0]));
    mkdirSync(args[1], { mode: 0o700 });
    for (const [name, value] of Object.entries(result)) writePrivate(join(args[1], `${name}.json`), canonical(value) + '\n');
  } else if (command === 'inspect-initdata' && args.length === 2) {
    const pod = readJson(args[0], 4000000), info = initDataInfo(readBytes(args[1], 2000000));
    console.log(canonical({ image: pod.spec.containers[0].image, pod_spec_sha256: sha256(canonical(pod.spec)),
      agent_policy_sha256: info.agent_policy_sha256, init_data: info.digest }));
    return;
  } else if (command === 'finalize' && args.length === 6) {
    const result = finalize(readJson(args[0]), readJson(args[1], 4000000), readBytes(args[2], 2000000),
      readJson(args[3]), readJson(args[4]));
    mkdirSync(args[5], { mode: 0o700 });
    for (const [name, value] of Object.entries(result)) writePrivate(join(args[5], `${name}.json`), canonical(value) + '\n');
  } else {
    console.log('Usage: node inference/deploy/bundle.mjs\n'
      + '  context WORKLOAD MODEL_DIR MODEL_MANIFEST OUT\n  prepare DEPLOYMENT OUT\n'
      + '  inspect-initdata GENERATED_POD INITDATA_TOML\n'
      + '  finalize DEPLOYMENT GENERATED_POD INITDATA_TOML POLICY APPROVAL OUT');
    process.exitCode = command === '--help' ? 0 : 2;
    return;
  }
  console.log(canonical({ packaged: true, hardware_validated: false }));
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    console.error(canonical({ packaged: false, code: error instanceof ReceiptError ? error.code : 'deployment-failed' }));
    process.exitCode = 1;
  });
}

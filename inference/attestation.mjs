import { canonical, exactKeys, isHex, isObject, isTime, requireThat, sha256, taggedHash } from './core.mjs';
import { importPublic, verifyJwt } from './crypto.mjs';

export const gpuFlags = Object.freeze([
  'x-nvidia-gpu-attestation-report-cert-chain-fwid-match',
  'x-nvidia-gpu-attestation-report-parsed', 'x-nvidia-gpu-attestation-report-signature-verified',
  'x-nvidia-gpu-arch-check',
  'x-nvidia-gpu-attestation-report-nonce-match', 'x-nvidia-gpu-vbios-index-no-conflict',
  ...['driver', 'vbios'].flatMap(kind => ['fetched', 'measurements-available',
    'schema-validated', 'signature-verified', 'version-match'].map(flag => `x-nvidia-gpu-${kind}-rim-${flag}`)),
]);
export const gpuChains = Object.freeze(['attestation-report', 'driver-rim', 'vbios-rim']);
export const EAR_PROFILE = 'tag:github.com,2024:confidential-containers/Trustee';

export function validatePolicy(p) {
  requireThat(exactKeys(p, ['version', 'audience', 'model', 'runtime', 'max_age_seconds',
    'gpu_measurement', 'gpu', 'cpu', 'zk']) && p.version === 'veil.inference-policy.v2', 'policy-schema');
  requireThat(typeof p.audience === 'string' && p.audience.length > 0 && p.audience.length <= 128
    && isHex(p.model) && isHex(p.gpu_measurement) && ['nim', 'tensorrt-llm'].includes(p.runtime)
    && isTime(p.max_age_seconds) && p.max_age_seconds > 0 && p.max_age_seconds <= 3600, 'policy-values');
  requireThat(exactKeys(p.gpu, ['issuer', 'keys', 'hwmodel', 'driver', 'vbios'])
    && p.gpu.issuer === 'https://nras.attestation.nvidia.com'
    && [p.gpu.hwmodel, p.gpu.driver, p.gpu.vbios].every(x => typeof x === 'string' && x.length > 0), 'gpu-policy');
  requireThat(exactKeys(p.cpu, ['keys', 'policy_id', 'init_data'])
    && typeof p.cpu.policy_id === 'string' && p.cpu.policy_id.length > 0
    && [32, 48, 64].some(n => isHex(p.cpu.init_data, n))
    && !/^0+$/.test(p.cpu.init_data), 'cpu-policy');
  for (const keys of [p.gpu.keys, p.cpu.keys]) requireThat(Array.isArray(keys)
    && keys.length > 0 && keys.length <= 16 && keys.every(k => isObject(k)
      && k.d === undefined && ['ES256', 'ES384', 'RS256', 'RS384'].includes(k.alg)), 'policy-keys');
  requireThat(exactKeys(p.zk, ['required', 'verification_key_sha256'])
    && typeof p.zk.required === 'boolean'
    && (p.zk.verification_key_sha256 === null || isHex(p.zk.verification_key_sha256))
    && (!p.zk.required || isHex(p.zk.verification_key_sha256)), 'zk-policy');
  return p;
}

export function validateSession(s) {
  requireThat(exactKeys(s, ['version', 'audience', 'nonce', 'model', 'prompt_commit', 'runtime',
    'client_key', 'signing_key', 'encryption_key', 'created_at'])
    && s.version === 'veil.inference-session.v2' && typeof s.audience === 'string'
    && [s.nonce, s.model, s.prompt_commit].every(x => isHex(x))
    && ['nim', 'tensorrt-llm'].includes(s.runtime) && isTime(s.created_at), 'session-schema');
  importPublic(s.client_key, 'X25519');
  importPublic(s.signing_key, 'Ed25519');
  importPublic(s.encryption_key, 'X25519');
  return s;
}
export const gpuNonce = session => taggedHash('gpu-session/v2', canonical(session));
export const runtimeData = (session, gpu) => ({ version: 'veil.attested-key.v2',
  session, gpu_evidence_sha256: sha256(canonical(gpu)) });
export const reportData = data => sha256(canonical(data));
export const workloadMeasurement = p => taggedHash('workload-init-data/v2', p.cpu.init_data);

// G names this precise, stable signed claim bundle. It is not a raw quote hash
// or a hardware PCR. The remote verifier authenticates the underlying firmware.
export function gpuMeasurement(c) {
  const bundle = { profile: 'nras-hopper-v3', hwmodel: c.hwmodel, ueid: c.ueid,
    driver: c['x-nvidia-gpu-driver-version'], vbios: c['x-nvidia-gpu-vbios-version'],
    measres: c.measres, secboot: c.secboot, dbgstat: c.dbgstat };
  requireThat([bundle.hwmodel, bundle.ueid, bundle.driver, bundle.vbios].every(x =>
    typeof x === 'string' && x.length > 0 && x.length <= 256), 'gpu-identity');
  return taggedHash('gpu-measurement/v2', canonical(bundle));
}

export function verifyGpu(eat, session, p, now) {
  requireThat(Array.isArray(eat) && eat.length === 2 && Array.isArray(eat[0])
    && eat[0].length === 2 && eat[0][0] === 'JWT'
    && exactKeys(eat[1], ['GPU-0']), 'gpu-eat-format');
  const trust = { keys: p.gpu.keys, issuer: p.gpu.issuer, now, maxAge: p.max_age_seconds };
  const overall = verifyJwt(eat[0][1], trust);
  requireThat(overall['x-nvidia-ver'] === '3.0' && overall['x-nvidia-overall-att-result'] === true
    && overall.eat_nonce === gpuNonce(session) && exactKeys(overall.submods, ['GPU-0']), 'gpu-overall');
  const digest = overall.submods['GPU-0'];
  requireThat(Array.isArray(digest) && digest.length === 2 && digest[0] === 'DIGEST'
    && Array.isArray(digest[1]) && digest[1].length === 2
    && ['SHA256', 'SHA-256'].includes(digest[1][0])
    && digest[1][1] === sha256(eat[1]['GPU-0']), 'gpu-submodule-binding');
  const c = verifyJwt(eat[1]['GPU-0'], trust);
  requireThat(c.eat_nonce === gpuNonce(session), 'gpu-child-nonce');
  requireThat(gpuFlags.every(k => c[k] === true) && gpuChains.every(k => {
    const chain = c[`x-nvidia-gpu-${k}-cert-chain`];
    return isObject(chain) && chain['x-nvidia-cert-status'] === 'valid'
      && chain['x-nvidia-cert-ocsp-status'] === 'good';
  }), 'gpu-firmware');
  requireThat(c.secboot === true && c.dbgstat === 'disabled' && c.measres === 'success', 'gpu-security');
  requireThat(c.hwmodel === p.gpu.hwmodel && c['x-nvidia-gpu-driver-version'] === p.gpu.driver
    && c['x-nvidia-gpu-vbios-version'] === p.gpu.vbios, 'gpu-version-policy');
  const measurement = gpuMeasurement(c);
  requireThat(measurement === p.gpu_measurement, 'gpu-measurement-policy');
  return { measurement, iat: Math.max(c.iat, overall.iat),
    nbf: Math.max(c.nbf ?? c.iat, overall.nbf ?? overall.iat, c.iat, overall.iat), exp: Math.min(c.exp, overall.exp) };
}

export function verifyCpu(jwt, session, gpu, p, now) {
  const c = verifyJwt(jwt, { keys: p.cpu.keys, profile: EAR_PROFILE, now, maxAge: p.max_age_seconds });
  requireThat(c['ear.verifier-id']?.developer === 'https://confidentialcontainers.org'
    && exactKeys(c.submods, ['cpu0']), 'cpu-profile');
  const cpu = c.submods.cpu0;
  const vector = cpu['ear.trustworthiness-vector'];
  requireThat(cpu['ear.status'] === 'affirming' && cpu['ear.appraisal-policy-id'] === p.cpu.policy_id
    && isObject(vector) && [2, 3, 4].includes(vector.executables)
    && vector.hardware === 2 && vector.configuration === 2
    && Object.values(vector).every(x => Number.isInteger(x) && x >= 0 && x < 32), 'cpu-appraisal');
  const a = cpu['ear.veraison.annotated-evidence'];
  const data = runtimeData(session, gpu);
  requireThat(isObject(a) && a.init_data === p.cpu.init_data
    && canonical(a.runtime_data_claims) === canonical(data)
    && a.report_data === reportData(data).padEnd(128, '0'), 'cpu-key-binding');
  requireThat(a.tdx?.td_attributes?.debug === false, 'cpu-debug');
  return { measurement: workloadMeasurement(p), iat: c.iat, nbf: Math.max(c.nbf ?? c.iat, c.iat), exp: c.exp };
}

export function verifyAttestation(attestation, expected, policy, now) {
  const p = validatePolicy(policy);
  requireThat(exactKeys(attestation, ['session', 'gpu', 'cpu']), 'attestation-schema');
  const s = validateSession(attestation.session);
  requireThat(exactKeys(expected, ['nonce', 'model', 'prompt_commit', 'client_key', 'audience'])
    && ['nonce', 'model', 'prompt_commit', 'client_key', 'audience'].every(k =>
      canonical(s[k]) === canonical(expected[k]))
    && s.audience === p.audience && s.model === p.model && s.runtime === p.runtime, 'session-binding');
  requireThat(s.created_at <= now && now - s.created_at <= p.max_age_seconds, 'session-time');
  const gpu = verifyGpu(attestation.gpu, s, p, now);
  const cpu = verifyCpu(attestation.cpu, s, attestation.gpu, p, now);
  requireThat(gpu.iat >= s.created_at && cpu.iat >= s.created_at, 'attestation-before-session');
  return { gpu, cpu, iat: Math.max(gpu.iat, cpu.iat),
    nbf: Math.max(gpu.nbf, cpu.nbf), exp: Math.min(gpu.exp, cpu.exp) };
}

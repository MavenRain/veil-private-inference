import { generateKeyPairSync, sign } from 'node:crypto';
import { canonical, sha256 } from '../core.mjs';
import { EAR_PROFILE, gpuChains, gpuFlags, gpuMeasurement, gpuNonce, reportData, runtimeData } from '../attestation.mjs';

export const NOW = 1900000000;
export function signer() {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  return { key: keys.privateKey, jwk: { ...keys.publicKey.export({ format: 'jwk' }), alg: 'ES256', use: 'sig' } };
}
export function jwt(claims, key, header = { alg: 'ES256', typ: 'JWT' }) {
  const payload = [header, claims].map(x => Buffer.from(canonical(x)).toString('base64url')).join('.');
  return payload + '.' + sign('sha256', Buffer.from(payload), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
}
export function gpuClaims(now = NOW) {
  return { iss: 'https://nras.attestation.nvidia.com', iat: now, nbf: now, exp: now + 300,
    hwmodel: 'GH100 A01', ueid: 'test-device-identity', secboot: true, dbgstat: 'disabled', measres: 'success',
    'x-nvidia-gpu-driver-version': 'test-driver', 'x-nvidia-gpu-vbios-version': 'test-vbios',
    ...Object.fromEntries(gpuFlags.map(k => [k, true])),
    ...Object.fromEntries(gpuChains.map(k => [`x-nvidia-gpu-${k}-cert-chain`, {
      'x-nvidia-cert-status': 'valid', 'x-nvidia-cert-ocsp-status': 'good' }])) };
}
export function fixture({ now = NOW, model = sha256('test-model'), runtime = 'nim' } = {}) {
  const gpuSigner = signer();
  const cpuSigner = signer();
  const claims = gpuClaims(now);
  const policy = { version: 'veil.inference-policy.v2', audience: 'veil-tests', model, runtime,
    max_age_seconds: 300, gpu_measurement: gpuMeasurement(claims),
    gpu: { issuer: claims.iss, keys: [gpuSigner.jwk], hwmodel: claims.hwmodel,
      driver: claims['x-nvidia-gpu-driver-version'], vbios: claims['x-nvidia-gpu-vbios-version'] },
    cpu: { keys: [cpuSigner.jwk], policy_id: 'veil-tdx-v2', init_data: sha256('test-init-data') },
    zk: { required: false, verification_key_sha256: null } };
  const attest = async (session, mutate = {}) => {
    const childClaims = structuredClone(claims);
    childClaims.eat_nonce = gpuNonce(session);
    mutate.gpu?.(childClaims);
    const child = jwt(childClaims, gpuSigner.key);
    const overall = { iss: claims.iss, iat: now, nbf: now, exp: now + 300,
      'x-nvidia-ver': '3.0', 'x-nvidia-overall-att-result': true, eat_nonce: gpuNonce(session),
      submods: { 'GPU-0': ['DIGEST', ['SHA-256', sha256(child)]] } };
    mutate.overall?.(overall);
    const gpu = [['JWT', jwt(overall, gpuSigner.key)], { 'GPU-0': child }];
    const data = runtimeData(session, gpu);
    const cpuClaims = { eat_profile: EAR_PROFILE, iat: now, exp: now + 300,
      'ear.verifier-id': { developer: 'https://confidentialcontainers.org', build: 'test-fixture' },
      submods: { cpu0: { 'ear.status': 'affirming', 'ear.appraisal-policy-id': policy.cpu.policy_id,
        'ear.trustworthiness-vector': { hardware: 2, executables: 3, configuration: 2 },
        'ear.veraison.annotated-evidence': { init_data: policy.cpu.init_data,
          runtime_data_claims: data, report_data: reportData(data).padEnd(128, '0'),
          tdx: { td_attributes: { debug: false } } } } } };
    mutate.cpu?.(cpuClaims);
    return { session, gpu, cpu: jwt(cpuClaims, cpuSigner.key) };
  };
  return { policy, attest, gpuSigner, cpuSigner };
}

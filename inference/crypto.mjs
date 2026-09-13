import { constants, createCipheriv, createDecipheriv, createPublicKey, diffieHellman,
  generateKeyPairSync, hkdfSync, randomBytes, sign, verify } from 'node:crypto';
import { canonical, decode64, exactKeys, isObject, isTime, parseJson, ReceiptError,
  requireThat, taggedHash } from './core.mjs';

export function publicJwk(key, curve) {
  const jwk = key.export({ format: 'jwk' });
  requireThat(jwk.kty === 'OKP' && jwk.crv === curve, 'key-type');
  return { kty: 'OKP', crv: curve, x: jwk.x };
}
export function importPublic(jwk, curve) {
  requireThat(exactKeys(jwk, ['kty', 'crv', 'x']) && jwk.kty === 'OKP'
    && jwk.crv === curve && decode64(jwk.x, 32).length === 32, 'key-type');
  try { return createPublicKey({ key: jwk, format: 'jwk' }); }
  catch { throw new ReceiptError('key-type'); }
}
export function sessionKeys() {
  const signing = generateKeyPairSync('ed25519');
  const encryption = generateKeyPairSync('x25519');
  return { signing: signing.privateKey, encryption: encryption.privateKey,
    signing_public: publicJwk(signing.publicKey, 'Ed25519'),
    encryption_public: publicJwk(encryption.publicKey, 'X25519') };
}
export function signReceipt(statement, key) {
  return sign(null, Buffer.from(`veil/workload-receipt/v2\0${canonical(statement)}`), key).toString('base64url');
}
export function checkReceiptSignature(statement, signature, publicKey) {
  const bytes = decode64(signature, 64);
  requireThat(bytes.length === 64 && verify(null,
    Buffer.from(`veil/workload-receipt/v2\0${canonical(statement)}`),
    importPublic(publicKey, 'Ed25519'), bytes), 'workload-signature');
}

const algorithms = Object.freeze({
  ES256: { digest: 'sha256', type: 'ec', curve: 'prime256v1', length: 64 },
  ES384: { digest: 'sha384', type: 'ec', curve: 'secp384r1', length: 96 },
  RS256: { digest: 'sha256', type: 'rsa' },
  RS384: { digest: 'sha384', type: 'rsa' },
});

// Trust keys are supplied by the relying party. Embedded jwk, x5c and jku
// headers never establish a trust root. No network access occurs in this path.
export function verifyJwt(jwt, { keys, issuer, profile, now, maxAge }) {
  requireThat(typeof jwt === 'string' && jwt.length <= 262144, 'jwt-size');
  const parts = jwt.split('.');
  requireThat(parts.length === 3, 'jwt-format');
  const header = parseJson(decode64(parts[0], 4096), 4096);
  const claims = parseJson(decode64(parts[1], 196608), 196608);
  requireThat(isObject(header) && isObject(claims) && Object.hasOwn(algorithms, header.alg), 'jwt-algorithm');
  requireThat(header.crit === undefined && header.b64 === undefined
    && header.jku === undefined && header.jwk === undefined, 'jwt-header');
  const alg = algorithms[header.alg];
  const signature = decode64(parts[2], 1024);
  const input = Buffer.from(`${parts[0]}.${parts[1]}`);
  requireThat(Array.isArray(keys) && keys.length > 0 && keys.length <= 16, 'trust-keys');
  const accepted = keys.some(jwk => {
    if (!isObject(jwk) || jwk.d !== undefined || jwk.alg !== header.alg
        || (jwk.use !== undefined && jwk.use !== 'sig')) return false;
    try {
      const key = createPublicKey({ key: jwk, format: 'jwk' });
      if (key.asymmetricKeyType !== alg.type) return false;
      if (alg.type === 'ec' && (key.asymmetricKeyDetails.namedCurve !== alg.curve || signature.length !== alg.length)) return false;
      if (alg.type === 'rsa' && key.asymmetricKeyDetails.modulusLength < 2048) return false;
      return verify(alg.digest, input, alg.type === 'ec'
        ? { key, dsaEncoding: 'ieee-p1363' } : { key, padding: constants.RSA_PKCS1_PADDING }, signature);
    } catch { return false; }
  });
  requireThat(accepted, 'jwt-signature');
  if (issuer !== undefined) requireThat(claims.iss === issuer, 'jwt-issuer');
  if (profile !== undefined) requireThat(claims.eat_profile === profile, 'jwt-profile');
  requireThat(isTime(now) && isTime(maxAge) && maxAge > 0
    && isTime(claims.iat) && isTime(claims.exp) && claims.iat <= now
    && now < claims.exp && claims.iat < claims.exp && now - claims.iat <= maxAge, 'jwt-time');
  if (claims.nbf !== undefined) requireThat(isTime(claims.nbf)
    && claims.nbf <= now && claims.nbf < claims.exp, 'jwt-time');
  return claims;
}

function cipherKey(privateKey, peerKey, session, direction) {
  const shared = diffieHellman({ privateKey, publicKey: importPublic(peerKey, 'X25519') });
  try {
    return Buffer.from(hkdfSync('sha256', shared,
      Buffer.from(taggedHash('session/v2', canonical(session)), 'hex'),
      Buffer.from(`veil/transport/v2/${direction}`), 32));
  } finally { shared.fill(0); }
}
export function encrypt(privateKey, peerKey, session, direction, plaintext) {
  requireThat(Buffer.isBuffer(plaintext) && ['request', 'response'].includes(direction), 'encryption-input');
  const key = cipherKey(privateKey, peerKey, session, direction);
  try {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(canonical({ session, direction })));
    return { nonce: nonce.toString('base64url'),
      ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]).toString('base64url'),
      tag: cipher.getAuthTag().toString('base64url') };
  } finally { key.fill(0); }
}
export function decrypt(privateKey, peerKey, session, direction, message, limit = 1048576) {
  requireThat(exactKeys(message, ['nonce', 'ciphertext', 'tag'])
    && ['request', 'response'].includes(direction), 'encrypted-message');
  const nonce = decode64(message.nonce, 12);
  const tag = decode64(message.tag, 16);
  const ciphertext = decode64(message.ciphertext, limit);
  requireThat(nonce.length === 12 && tag.length === 16, 'encrypted-message');
  const key = cipherKey(privateKey, peerKey, session, direction);
  try {
    const cipher = createDecipheriv('aes-256-gcm', key, nonce);
    cipher.setAAD(Buffer.from(canonical({ session, direction })));
    cipher.setAuthTag(tag);
    return Buffer.concat([cipher.update(ciphertext), cipher.final()]);
  } catch { throw new ReceiptError('decryption'); }
  finally { key.fill(0); }
}

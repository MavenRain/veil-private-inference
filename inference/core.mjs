import { closeSync, constants, fstatSync, fsyncSync, openSync, readSync, writeFileSync } from 'node:fs';
export { canonical, commitOutput, commitPrompt, sha256, taggedHash } from '../examples/private-inference/host.mjs';

export class ReceiptError extends Error {
  constructor(code) { super(code); this.name = 'ReceiptError'; this.code = code; }
}
export const requireThat = (condition, code) => { if (!condition) throw new ReceiptError(code); };
export const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export const exactKeys = (value, names) => isObject(value)
  && Object.keys(value).sort().join(',') === [...names].sort().join(',');
export const isHex = (value, bytes = 32) => typeof value === 'string'
  && value.length === bytes * 2 && /^[0-9a-f]+$/.test(value);
export const isTime = value => Number.isSafeInteger(value) && value >= 0;
export const unixTime = () => Math.floor(Date.now() / 1000);

export function decode64(text, limit = 1048576) {
  requireThat(typeof text === 'string' && text.length <= Math.ceil(limit * 4 / 3)
    && /^[A-Za-z0-9_-]*$/.test(text), 'base64url');
  const bytes = Buffer.from(text, 'base64url');
  requireThat(bytes.length <= limit && bytes.toString('base64url') === text, 'base64url');
  return bytes;
}

// JSON.parse alone discards duplicate keys. Parse structure before exposing
// signed or network data, with explicit bounds on nesting and container size.
export function parseJson(bytes, limit = 1048576) {
  requireThat(Buffer.isBuffer(bytes) && bytes.length <= limit, 'json-size');
  const text = bytes.toString('utf8');
  requireThat(Buffer.from(text).equals(bytes), 'json-utf8');
  let at = 0;
  let nodes = 0;
  const ws = () => { while (/[\x20\x09\x0a\x0d]/.test(text[at] ?? 'x')) at++; };
  const string = () => {
    requireThat(text[at] === '"', 'json-string');
    const start = at++;
    while (at < text.length) {
      const ch = text[at++];
      if (ch === '\\') { at++; continue; }
      if (ch === '"') {
        try { return JSON.parse(text.slice(start, at)); } catch { throw new ReceiptError('json-string'); }
      }
    }
    throw new ReceiptError('json-string');
  };
  const value = depth => {
    requireThat(depth <= 32 && ++nodes <= 16384, 'json-complexity');
    ws();
    if (text[at] === '"') return string();
    if (text[at] === '{') {
      at++; ws();
      const result = Object.create(null);
      if (text[at] === '}') { at++; return result; }
      for (;;) {
        ws(); const key = string(); ws();
        requireThat(!Object.hasOwn(result, key) && text[at++] === ':', 'json-object');
        result[key] = value(depth + 1); ws();
        const separator = text[at++];
        if (separator === '}') return result;
        requireThat(separator === ',', 'json-object');
      }
    }
    if (text[at] === '[') {
      at++; ws();
      const result = [];
      if (text[at] === ']') { at++; return result; }
      for (;;) {
        result.push(value(depth + 1)); ws();
        const separator = text[at++];
        if (separator === ']') return result;
        requireThat(separator === ',', 'json-array');
      }
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(at));
    requireThat(token !== null, 'json-value');
    at += token[0].length;
    const result = JSON.parse(token[0]);
    requireThat(typeof result !== 'number' || Number.isFinite(result), 'json-number');
    return result;
  };
  const result = value(0); ws();
  requireThat(at === text.length, 'json-trailing-data');
  return result;
}

export function readBytes(path, limit = 1048576) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    requireThat(fstatSync(fd).isFile(), 'input-not-file');
    const bytes = Buffer.alloc(limit + 1);
    let used = 0;
    while (used < bytes.length) {
      const n = readSync(fd, bytes, used, bytes.length - used, null);
      if (n === 0) break;
      used += n;
    }
    requireThat(used <= limit, 'input-size');
    return bytes.subarray(0, used);
  } finally { closeSync(fd); }
}
export const readJson = (path, limit) => parseJson(readBytes(path, limit), limit);

export function writePrivate(path, bytes) {
  const fd = openSync(path, 'wx', 0o600);
  try { writeFileSync(fd, bytes); fsyncSync(fd); } finally { closeSync(fd); }
}

export function secureUrl(value, { loopbackOnly = false } = {}) {
  let url;
  try { url = new URL(value); } catch { throw new ReceiptError('url'); }
  const loopback = ['127.0.0.1', '[::1]'].includes(url.hostname);
  requireThat(!url.username && !url.password && !url.hash && !url.search
    && (url.protocol === 'https:' || (url.protocol === 'http:' && loopback))
    && (!loopbackOnly || loopback), 'url');
  return url;
}

export async function boundedResponse(response, limit = 1048576) {
  requireThat(response.ok && response.body !== null, 'http-status');
  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      requireThat(length <= limit, 'http-size');
      chunks.push(value);
    }
    return Buffer.concat(chunks, length);
  } finally { await reader.cancel().catch(() => {}); }
}

export async function postJson(url, body, timeoutMs = 30000, limit = 1048576) {
  const response = await fetch(secureUrl(url), { method: 'POST', redirect: 'error',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs) });
  return boundedResponse(response, limit);
}

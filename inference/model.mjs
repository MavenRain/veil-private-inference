import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { canonical, exactKeys, isHex, isTime, requireThat, taggedHash } from './core.mjs';

function safePath(root, name) {
  requireThat(typeof name === 'string' && name.length <= 1024 && name.split('/').every(
    part => /^[A-Za-z0-9_.-]+$/.test(part) && part !== '.' && part !== '..'), 'model-path');
  let path = root;
  requireThat(lstatSync(root).isDirectory() && !lstatSync(root).isSymbolicLink(), 'model-root');
  for (const part of name.split('/')) {
    path = join(path, part);
    requireThat(!lstatSync(path).isSymbolicLink(), 'model-symlink');
  }
  return path;
}
function fileDigest(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(fd);
    requireThat(before.isFile(), 'model-file');
    const hash = createHash('sha256');
    const buffer = Buffer.alloc(1024 * 1024);
    let size = 0;
    for (;;) {
      const n = readSync(fd, buffer, 0, buffer.length, null);
      if (n === 0) break;
      size += n; hash.update(buffer.subarray(0, n));
    }
    const after = fstatSync(fd);
    requireThat(size === before.size && size === after.size && before.mtimeMs === after.mtimeMs
      && before.ctimeMs === after.ctimeMs, 'model-changed');
    return { size, sha256: hash.digest('hex') };
  } finally { closeSync(fd); }
}
function allFiles(root, prefix = '') {
  return readdirSync(join(root, prefix), { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0).flatMap(entry => {
    requireThat(!entry.isSymbolicLink() && (entry.isFile() || entry.isDirectory()), 'model-file-kind');
    const name = prefix + entry.name;
    safePath(root, name);
    return entry.isDirectory() ? allFiles(root, name + '/') : [name];
  });
}
export function createManifest(root, runtime, model_id) {
  requireThat(['nim', 'tensorrt-llm'].includes(runtime) && typeof model_id === 'string'
    && model_id.length > 0 && model_id.length <= 256, 'model-runtime');
  root = resolve(root);
  const files = allFiles(root).map(path => ({ path, ...fileDigest(safePath(root, path)) }));
  requireThat(files.length > 0 && files.length <= 10000, 'model-file-count');
  return { version: 'veil.model-manifest.v2', runtime, model_id, files };
}
export const modelHash = manifest => taggedHash('model-manifest/v2', canonical(manifest));
export function verifyManifest(root, manifest, expectedHash) {
  requireThat(exactKeys(manifest, ['version', 'runtime', 'model_id', 'files'])
    && manifest.version === 'veil.model-manifest.v2' && isHex(expectedHash)
    && modelHash(manifest) === expectedHash && Array.isArray(manifest.files)
    && manifest.files.length > 0 && manifest.files.length <= 10000, 'model-manifest');
  const names = manifest.files.map(file => {
    requireThat(exactKeys(file, ['path', 'size', 'sha256']) && isTime(file.size)
      && isHex(file.sha256), 'model-file-schema');
    const actual = fileDigest(safePath(resolve(root), file.path));
    requireThat(actual.sha256 === file.sha256 && actual.size === file.size, 'model-integrity');
    return file.path;
  });
  requireThat(canonical(names) === canonical(allFiles(resolve(root))), 'model-file-set');
  requireThat(['nim', 'tensorrt-llm'].includes(manifest.runtime)
    && typeof manifest.model_id === 'string' && manifest.model_id.length > 0, 'model-runtime');
  return manifest;
}

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { requireThat, sha256, writePrivate } from '../core.mjs';

const spec = JSON.parse(readFileSync(new URL('./srs.json', import.meta.url)));
const destination = process.argv[2] ?? fileURLToPath(new URL('../../_build/ppot_0080_14.ptau', import.meta.url));
const verify = bytes => requireThat(bytes.length === spec.size && sha256(bytes) === spec.sha256
  && createHash('blake2b512').update(bytes).digest('hex') === spec.blake2b512, 'srs-checksum');
if (existsSync(destination)) {
  verify(readFileSync(destination));
} else {
  const response = await fetch(spec.url, { redirect: 'error', signal: AbortSignal.timeout(120000) });
  requireThat(response.ok, 'srs-download');
  const chunks = []; let length = 0;
  for await (const chunk of response.body) {
    length += chunk.length; requireThat(length <= spec.size, 'srs-size'); chunks.push(chunk);
  }
  const bytes = Buffer.concat(chunks); verify(bytes); writePrivate(destination, bytes);
}
console.log('published SRS downloaded and pinned SHA-256 and BLAKE2b checksums verified');

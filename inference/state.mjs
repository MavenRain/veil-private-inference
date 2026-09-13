import { randomBytes } from 'node:crypto';
import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { canonical, isHex, isTime, readJson, requireThat, taggedHash, writePrivate } from './core.mjs';

export class ChallengeStore {
  constructor(path) {
    this.path = resolve(path);
    mkdirSync(this.path, { recursive: true, mode: 0o700 });
    const stat = lstatSync(this.path);
    requireThat(stat.isDirectory() && !stat.isSymbolicLink() && (stat.mode & 0o077) === 0
      && (process.getuid === undefined || stat.uid === process.getuid()), 'state-directory');
  }
  sync() {
    const fd = openSync(this.path, 'r');
    try { fsyncSync(fd); } finally { closeSync(fd); }
  }
  issue(expected, now, ttl) {
    requireThat(isTime(now) && isTime(ttl) && ttl > 0 && ttl <= 3600, 'challenge-time');
    const nonce = randomBytes(32).toString('hex');
    const challenge = { ...expected, nonce };
    writePrivate(join(this.path, `${nonce}.issued`), canonical({ challenge, created_at: now, expires_at: now + ttl }));
    this.sync();
    return challenge;
  }
  check(challenge, now) {
    requireThat(isHex(challenge.nonce) && isTime(now), 'challenge');
    const issued = readJson(join(this.path, `${challenge.nonce}.issued`), 8192);
    requireThat(canonical(issued.challenge) === canonical(challenge)
      && issued.created_at <= now && now < issued.expires_at, 'challenge-expired-or-mismatch');
    return issued;
  }
  consume(challenge, receipt, now) {
    this.check(challenge, now);
    try {
      writePrivate(join(this.path, `${challenge.nonce}.spent`), canonical({
        accepted_at: now, receipt_digest: taggedHash('accepted-receipt/v2', canonical(receipt)) }));
    } catch (error) {
      requireThat(error.code !== 'EEXIST', 'challenge-replayed');
      throw error;
    }
    this.sync();
  }
}

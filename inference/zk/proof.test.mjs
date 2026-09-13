import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolve } from 'node:path';
import { sha256, readBytes } from '../core.mjs';
import { commitment, FIELD, randomBlind, tuple } from './binding.mjs';
import { defaultArtifacts, prove, verifyProof } from './proof.mjs';

test('real PLONK proof accepts and rejects every changed digest and a wrong key', async () => {
  const statement = Object.fromEntries(['model', 'prompt_commit', 'output_commit', 'gpu_measurement', 'nonce'].map(k => [k, sha256(k)]));
  const blind = randomBlind();
  statement.zk_commitment = await commitment(statement, blind);
  const bundle = await prove(statement, blind);
  const pin = sha256(readBytes(resolve(defaultArtifacts, 'verification_key.json')));
  assert.equal(await verifyProof(statement, bundle, pin), true);
  for (const key of ['model', 'prompt_commit', 'output_commit', 'gpu_measurement', 'nonce']) {
    assert.equal(await verifyProof({ ...statement, [key]: sha256('changed') }, bundle, pin), false);
  }
  assert.equal(await verifyProof(statement, bundle, sha256('wrong-key')), false);
  const bad = structuredClone(bundle); bad.proof.eval_a = '0';
  assert.equal(await verifyProof(statement, bad, pin), false);
  await assert.rejects(prove(statement, (BigInt(blind) + 1n).toString()), /zk-opening/);
  await assert.rejects(commitment(statement, FIELD.toString()), /zk-blinding/);
  assert.ok(tuple(statement).every(x => BigInt(x) < 2n ** 128n));
});

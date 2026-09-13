import { randomBytes } from 'node:crypto';
import { buildPoseidon } from 'circomlibjs';
import { isHex, requireThat } from '../core.mjs';

export const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const validField = x => typeof x === 'string' && /^(0|[1-9][0-9]{0,76})$/.test(x) && BigInt(x) < FIELD;
export function randomBlind() {
  for (;;) {
    const n = BigInt('0x' + randomBytes(32).toString('hex'));
    if (n > 0n && n < FIELD) return n.toString();
  }
}
export function tuple(statement) {
  return ['model', 'prompt_commit', 'output_commit', 'gpu_measurement', 'nonce'].flatMap(key => {
    requireThat(isHex(statement[key]), 'zk-digest');
    return [statement[key].slice(0, 32), statement[key].slice(32)].map(limb => BigInt('0x' + limb).toString());
  });
}
let poseidonPromise;
export async function commitment(statement, blind) {
  requireThat(validField(blind), 'zk-blinding');
  const poseidon = await (poseidonPromise ??= buildPoseidon());
  return poseidon.F.toObject(poseidon([1447381324n, ...tuple(statement).map(BigInt), BigInt(blind)])).toString();
}
export function publicSignals(statement) {
  requireThat(validField(statement.zk_commitment), 'zk-commitment');
  return [...tuple(statement), statement.zk_commitment];
}

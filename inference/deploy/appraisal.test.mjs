import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { appraisal } from './appraisal.mjs';

test('real Rego evaluator rejects changed TDX measurements, debug and stale TCB', () => {
  const directory = mkdtempSync(join(tmpdir(), 'veil-opa-'));
  try {
    const fields = ['mr_td', 'mr_seam', 'rtmr_0', 'rtmr_1', 'rtmr_2', 'rtmr_3', 'init_data'];
    const refs = { ...Object.fromEntries(fields.map((key, i) => [key, (i + 1).toString(16).padStart(2, '0').repeat(48)])),
      xfam: '0100000000000000', minimum_tcb_date: '2025-08-13T00:00:00Z' };
    writeFileSync(join(directory, 'policy.rego'), appraisal(refs));
    const input = { init_data: refs.init_data, tdx: { td_attributes: { debug: false },
      tcb_status: 'UpToDate', collateral_expiration_status: '0', tcb_date: '2026-01-01T00:00:00Z',
      quote: { header: { tee_type: '81000000', vendor_id: '939a7233f79c4ca9940a0db3957f0607' },
        body: { ...refs } } } };
    const evaluate = value => {
      writeFileSync(join(directory, 'input.json'), JSON.stringify(value));
      const result = spawnSync(process.env.OPA ?? resolve('../_build/opa'), ['eval', '--format=json',
        '--data', join(directory, 'policy.rego'), '--input', join(directory, 'input.json'), 'data.policy.trust_claims'],
      { encoding: 'utf8', timeout: 10000 });
      assert.equal(result.status, 0, result.stderr);
      return JSON.parse(result.stdout).result[0].expressions[0].value;
    };
    const good = evaluate(input);
    assert.equal(good.executables, 3); assert.equal(good.hardware, 2); assert.equal(good.configuration, 2);
    for (const field of fields.slice(0, -1)) {
      const bad = structuredClone(input); bad.tdx.quote.body[field] = '00'.repeat(48);
      const result = evaluate(bad); assert.ok(result.executables > 31 || result.hardware > 31, field);
    }
    for (const edit of [x => { x.tdx.td_attributes.debug = true; },
      x => { x.init_data = '00'.repeat(48); }, x => { x.tdx.quote.body.xfam = '00'.repeat(8); }]) {
      const bad = structuredClone(input); edit(bad); assert.ok(evaluate(bad).configuration > 31);
    }
    for (const edit of [x => { x.tdx.tcb_status = 'OutOfDate'; },
      x => { x.tdx.collateral_expiration_status = '1'; }, x => { x.tdx.tcb_date = '2024-01-01T00:00:00Z'; }]) {
      const bad = structuredClone(input); edit(bad); assert.ok(evaluate(bad).hardware > 31);
    }
    assert.ok(evaluate({}).hardware > 31);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

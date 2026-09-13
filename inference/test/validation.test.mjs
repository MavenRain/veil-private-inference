import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { parentGateReport } from '../validation.mjs';

// Follow the actual parent gate inventory so adding or dropping a gate requires
// an explicit update to the release evidence parser.
const gates = [...readFileSync(new URL('../../dev/gates.sh', import.meta.url), 'utf8')
  .matchAll(/^\s*(?:if ! )?leg (?:FAST|MED|SLOW|SUITE) ([A-Z0-9-]+) /gm)].map((x) => x[1]);
function transcript(failures = {}) {
  return [...Object.values(failures).map((x) => x.diagnostic), ...gates.map((name) =>
    `MEASURE ${name} tier=MED elapsed_ms=1.000 exit=${failures[name]?.exit ?? 0}`),
  Object.keys(failures).length ? 'GATES-FAIL' : 'GATES-OK'].join('\n') + '\n';
}
const timeFailure = { exit: 1, diagnostic: 'FAIL M0-TIME median_ms=319.375 bound_ms=150 load1=60.699 samples=3x5' };

test('complete successful parent gate is recorded without a qualification', () => {
  const result = parentGateReport(transcript(), 0);
  assert.equal(gates.length, 28);
  assert.equal(result.status, 'passed');
  assert.equal(result.passed.length, 28);
  assert.deepEqual(result.failed, []);
});

test('only the original timing bounds qualify a failed candidate', () => {
  const result = parentGateReport(transcript({ 'M0-TIME': timeFailure,
    'M0-RATIO': { exit: 1, diagnostic: 'FAIL M0-RATIO kanon_ms=47.774 kanon_lines=1000 tot_ms=103.662 tot_lines=8138 ratio=3.750505 bound=2.000 load1=73.863' },
    'M1-CORPUS': { exit: 1, diagnostic: 'FAIL M1-CORPUS elapsed_ms=1526.212 bound_ms=713 lines=1000 main=814 load1=65.231' } }), 1);
  assert.equal(result.status, 'performance-unvalidated');
  assert.equal(result.failed.length, 3);
  assert.equal(result.passed.length, 25);
  assert.equal(result.exit_code, 1);
});

test('functional failure and timing timeout cannot qualify a candidate', () => {
  for (const failures of [{ BUILD: { exit: 1, diagnostic: 'FAIL BUILD' } },
    { 'M0-TIME': { ...timeFailure, exit: 124 } },
    { 'M0-TIME': { ...timeFailure, diagnostic: timeFailure.diagnostic.replace('bound_ms=150', 'bound_ms=200') } }]) {
    assert.equal(parentGateReport(transcript(failures), 1).status, 'failed');
  }
});

test('missing, duplicated and unknown gates cannot be accepted', () => {
  const good = transcript();
  for (const log of [good.replace(/^MEASURE BUILD[^\n]*\n/m, ''),
    good.replace('GATES-OK', 'MEASURE BUILD tier=MED elapsed_ms=1.000 exit=0\nGATES-OK'),
    good.replace('MEASURE BUILD ', 'MEASURE UNKNOWN ')]) assert.throws(() => parentGateReport(log, 0));
});

test('inconsistent exit status or incomplete transcript cannot be accepted', () => {
  assert.throws(() => parentGateReport(transcript(), 1));
  assert.throws(() => parentGateReport(transcript(), 124));
  assert.throws(() => parentGateReport(transcript().replace('GATES-OK', ''), 0));
  assert.throws(() => parentGateReport(transcript({ 'M0-TIME': timeFailure }), 0));
  assert.throws(() => parentGateReport('FAIL BUILD\n' + transcript(), 0));
});

import { sha256 } from './core.mjs';

const GATES = ['BUILD', 'CARRY', 'R0-COUNT', 'R0-AUDIT', 'SUITE-KERNEL', 'SUITE-WASM',
  'ENCODER-SUBSET', 'AXIOMS', 'M0-E2E', 'M0-TIME', 'M0-RATIO', 'TRUSTED-LINES',
  'CIRCUIT', 'ZK', 'FHC', 'MPC', 'HOST', 'HOST-NAT', 'PRIVATE-INFERENCE',
  'DENOMINATORS', 'HOUSE', 'PIN', 'POSITIVITY', 'M1-CORPUS', 'M1-SUITE',
  'AGREEMENT', 'REACTOR', 'RUNTIME'];
const TIMING_FAILURES = {
  'M0-TIME': /^FAIL M0-TIME median_ms=[\d.]+ bound_ms=150 load1=[\d.]+ samples=3x5$/,
  'M0-RATIO': /^FAIL M0-RATIO kanon_ms=[\d.]+ kanon_lines=1000 tot_ms=[\d.]+ tot_lines=8138 ratio=[\d.]+ bound=2\.000 load1=[\d.]+$/,
  'M1-CORPUS': /^FAIL M1-CORPUS elapsed_ms=[\d.]+ bound_ms=713 lines=1000 main=814 load1=[\d.]+$/,
};

// A failed timing bound can produce an explicitly qualified candidate. Missing
// gates, timeouts and functional failures never qualify for that exception.
export function parentGateReport(log, exitCode) {
  if (typeof log !== 'string' || log.length > 8 * 1024 * 1024 || ![0, 1].includes(exitCode)) {
    throw new Error('incomplete-parent-gate');
  }
  const lines = log.split(/\r?\n/).map((line) => line.trim());
  const measurements = lines.flatMap((line) => {
    const match = /^MEASURE ([A-Z0-9-]+) tier=[A-Z]+ elapsed_ms=([\d.]+) exit=(\d+)$/.exec(line);
    return match ? [{ name: match[1], elapsed_ms: Number(match[2]), exit_code: Number(match[3]) }] : [];
  });
  if (measurements.length !== GATES.length || GATES.some((name) => measurements.filter((x) => x.name === name).length !== 1)
      || measurements.some((x) => !Number.isFinite(x.elapsed_ms))) throw new Error('incomplete-parent-gate');
  const failed = measurements.filter((x) => x.exit_code !== 0).map((x) => ({ ...x,
    diagnostic: lines.filter((line) => line.startsWith(`FAIL ${x.name} `) || line === `FAIL ${x.name}`).join('\n') }));
  const complete = lines.filter(Boolean).at(-1);
  if (complete !== (failed.length ? 'GATES-FAIL' : 'GATES-OK') || exitCode !== (failed.length ? 1 : 0)) {
    throw new Error('inconsistent-parent-gate');
  }
  const diagnostics = lines.filter((line) => line.startsWith('FAIL '));
  if (failed.length === 0 && diagnostics.length !== 0) throw new Error('inconsistent-parent-gate');
  const timingOnly = failed.length > 0 && diagnostics.length === failed.length
    && failed.every((x) => x.exit_code === 1 && TIMING_FAILURES[x.name]?.test(x.diagnostic));
  return { exit_code: exitCode, status: failed.length === 0 ? 'passed' : timingOnly ? 'performance-unvalidated' : 'failed',
    log_sha256: sha256(Buffer.from(log)), passed: measurements.filter((x) => x.exit_code === 0).map((x) => x.name), failed };
}

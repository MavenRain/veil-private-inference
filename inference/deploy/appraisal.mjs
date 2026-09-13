import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { canonical, exactKeys, isHex, readJson, requireThat, writePrivate } from '../core.mjs';

export function appraisal(refs) {
  const digests = ['mr_td', 'mr_seam', 'rtmr_0', 'rtmr_1', 'rtmr_2', 'rtmr_3', 'init_data'];
  requireThat(exactKeys(refs, [...digests, 'xfam', 'minimum_tcb_date'])
    && digests.every(k => isHex(refs[k], 48) && !/^0+$/.test(refs[k]))
    && isHex(refs.xfam, 8) && /^\d{4}-\d\d-\d\dT00:00:00Z$/.test(refs.minimum_tcb_date)
    && Number.isFinite(Date.parse(refs.minimum_tcb_date)), 'tdx-reference-values');
  return `package policy
import rego.v1

# Values are approved by the workload owner before accepting receipts.
refs := ${canonical(refs)}
default executables := 33
default hardware := 97
default configuration := 36

executables := 3 if {
    input.tdx.quote.body.rtmr_0 == refs.rtmr_0
    input.tdx.quote.body.rtmr_1 == refs.rtmr_1
    input.tdx.quote.body.rtmr_2 == refs.rtmr_2
    input.tdx.quote.body.rtmr_3 == refs.rtmr_3
}
hardware := 2 if {
    input.tdx.quote.header.tee_type == "81000000"
    input.tdx.quote.header.vendor_id == "939a7233f79c4ca9940a0db3957f0607"
    input.tdx.quote.body.mr_td == refs.mr_td
    input.tdx.quote.body.mr_seam == refs.mr_seam
    input.tdx.tcb_status == "UpToDate"
    input.tdx.collateral_expiration_status == "0"
    time.parse_rfc3339_ns(input.tdx.tcb_date) >= time.parse_rfc3339_ns(refs.minimum_tcb_date)
}
configuration := 2 if {
    input.tdx.td_attributes.debug == false
    input.tdx.quote.body.xfam == refs.xfam
    input.init_data == refs.init_data
}
trust_claims := {
    "executables": executables, "hardware": hardware, "configuration": configuration,
    "file-system": 0, "instance-identity": 0, "runtime-opaque": 0,
    "storage-opaque": 0, "sourced-data": 0,
}
`;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    requireThat(process.argv.length === 4, 'usage: appraisal.mjs TDX_REFERENCES OUTPUT_REGO');
    writePrivate(process.argv[3], appraisal(readJson(process.argv[2])));
  } catch (error) { console.error(error.code ?? 'appraisal-config'); process.exitCode = 1; }
}

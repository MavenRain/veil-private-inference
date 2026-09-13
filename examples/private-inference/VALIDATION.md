# Validation record

Validated on 2026-09-12 in `veil-private-inference`, based on veil revision
`addeb7a814c65e2c965e56a79d92f18cb704dd99`, on branch
`feat/private-inference-receipt`. Node runtime: v23.10.0.

| Check | Result |
| --- | --- |
| Compiler build with `zsh dev/dune.sh build bin/kanon.exe` | Passed |
| Receipt suite before adding the circuit-disclosure test | 59 tests passed |
| Final receipt suite in the `PRIVATE-INFERENCE` gate | Passed, 60 registered tests, no skips |
| Full `zsh dev/gates.sh` | 28 passing gates, exit 0, `GATES-OK` |
| `node examples/private-inference/receipt.mjs demo` | Exit 0; matching receipt accepted; altered output rejected as `output-binding` |
| `zsh -n dev/gates.sh` | Passed |
| `git diff --check` | Passed |

The final suite includes circuit-fragment admission and an empty axiom list for
`relation.kan`. Building the twin also type-checks `proof.kan` and its conditional
`SZk` declaration. Negative tests use authentic mock signatures over incorrect
claims, as well as forged and malformed tokens, so signature rejection cannot
mask missing relation checks. The type-negative fixture is rejected by the real
compiler. The CLI tests cover offline fixtures, acceptance, rejection, explicit
mock selection, invalid files, bounded input sizes and exit codes.

The full gate run covers the existing kernel, Wasm, shape, host, reactor and
runtime suites. Its agreement leg passed 7445 cases. Existing gate thresholds
and commands were preserved; the receipt suite is an additional gate.

Local complete captures are retained under the working copy:

- Compiler build: `.kanon-exec/run-AyVZWu`
- Initial 59-test receipt run: `.kanon-exec/run-INaxzB`
- Final full gate run: `.kanon-exec/run-gkUGmt`
- Final demo: `.kanon-exec/run-YlwKPi`

The gate stdout has SHA-256
`a8017883ba5268081df01a8256d1b6deb86b117e27740d876534b306b8245764`.
Read captures with `kanon-project capture ARTIFACT --budget 4000` or
`kanon-exec read ARTIFACT` with selectors. Captures are local artifacts and are
not part of the source change.

The `kanonx` review packet indexed all three new Kanon files. Its repository-wide
coverage flag remains incomplete because three existing negative byte-literal
fixtures intentionally cannot be parsed. The compiler and repository gates
validate those fixtures directly.

This evidence covers the mock protocol and plaintext execution only. No NVIDIA
SDK, GPU, confidential VM, real inference process, ZK prover, FHE implementation
or NVFlare round was used. The adapter authentication result is trusted host
input to the relation, and nonce consumption belongs to the relying party.

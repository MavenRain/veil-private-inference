# Release validation

The source base is `addeb7a814c65e2c965e56a79d92f18cb704dd99`. Compiler and kernel
implementation files are unchanged. The parent gate adds the original receipt
milestone without removing any existing gate or changing timing thresholds.

The final machine-readable result is `inference/validation.json` in the archive
and `inference/artifacts/software-validation.json` in the build checkout. It
records source/artifact hashes, the parent gate outcome, and the actual NVFlare
simulation report. `RELEASE-MANIFEST.json` inventories every archived file by
SHA-256 and byte count. The adjacent `SHA256SUMS` lets you check the archive bytes
against the locally produced checksum; distribute that checksum through a trusted
release channel. It is not a publisher signature.

| Validation | Exercised behavior |
| --- | --- |
| Original receipt milestone | 60 positive and negative checks against the compiled plaintext twin |
| Receipt/deployment suite | 46 tests, including signature/trust/freshness failures, replay and concurrency, encrypted HTTP, actual adapter argv/wire formats, model mutations, deployment policy changes, and validation evidence refusal |
| PLONK | Actual proof generation and verification; changed M/P/O/G/nonce, wrong key, altered proof, and wrong opening rejected |
| OPA | Generated TDX policy evaluated by OPA 1.0.1; altered measurements, debug mode and unacceptable TCB rejected |
| Native GPU guard | C compiled with warnings as errors; NVML ABI fixture exercises production success, CC off, debug, simulation mode, multiple GPUs, not ready, and API failure |
| Python privacy | Nine unit tests cover actual BFV encrypted equality and mutation, NVFlare configuration, DP accounting, round replay, and production export without secret keys |
| NVFlare integration | Actual server and two clients, three rounds, six accepted receipts, three encrypted checkpoints, epsilon 3 per client, no server secret context |
| Parent functionality | Kernel/Wasm suites, all 7,445 agreement cases, host shapes, runtime, and the receipt milestone |

The Node checks use generated signing keys and synthetic attestation/backend
fixtures. The native guard uses a compiled NVML fixture. These exercise the
software protocol without substituting for hardware acceptance. The BFV, CKKS,
PLONK and OPA operations use their real implementations.

The final complete command finished at `2026-09-13T04:15:25.008Z` with
`PRIVATE-INFERENCE-RELEASE-OK` and exit code 0. All application checks and all 28
parent gates passed. The previously affected timing checks finished as follows:

| Gate | Observed | Required | Reported load1 |
| --- | --- | --- | --- |
| M0-TIME | 126.271 ms median | At most 150 ms | 25.611 |
| M0-RATIO | 1.507377 | At most 2.000 | See parent log |
| M1-CORPUS | 213.636 ms | At most 713 ms | 24.681 |

Earlier runs failed timing bounds under heavy load. No thresholds were relaxed
and those failures were not reclassified as passes. The final run independently
passed every bound, so this archive is `software-validated`. Its machine-readable
report and included `inference/artifacts/parent-gates.log` record the exact outcome.
That log's SHA-256 is
`ad1937a87dc051e65131fe52f6b316ab19b915478078a24920c1c038385f6b66`.
The validation used Node `v23.10.0`, Python `3.13.2`, Circom `2.2.3`, and the
checked-in Node/Python dependency locks. The full command's captured stdout
SHA-256 is `bbded6e5ce702ac7b3de9d8b9f17b4a14839b74c50ad915f129a906430ea0025`.

The strict release command is:

```sh
OPA=/absolute/path/to/opa bash dev/private-inference-release.sh
```

It completes the application checks after a parent timing failure and still exits
nonzero. Default packaging refuses that result. The explicit
`--allow-performance-failures` packaging flag accepts only the three original
timing-bound failures, produces a candidate filename, and preserves
`performance-unvalidated` in both manifests. It cannot waive functional failures,
timeouts, absent gates, or changed thresholds.

The PLONK verification key SHA-256 is
`d15933d467afc3bc87bb8c46551ff7c3727334bc3db96d91b31701288698cc08`.
The PSE prepared SRS download matched the pinned SHA-256 and BLAKE2b values in
[zk/srs.json](zk/srs.json). A full ceremony transcript audit did not complete and
is not claimed. Proof checks establish the tested circuit behavior, subject to
the ceremony assumptions in [SECURITY.md](SECURITY.md).

No confidential GPU VM, cluster target or licensed inference image was available.
The vendor container recipes have not been built, live NVAT/NRAS/TDX inference
has not run, and secure production NVFlare/KBS provisioning has not been accepted.
The complete software and deployment preparation steps are in
[DEPLOYMENT.md](DEPLOYMENT.md). Final production acceptance requires those image
builds, independently approved measurements/keys, a restrictive reviewed Kata
agent policy, and the listed positive and negative hardware tests.

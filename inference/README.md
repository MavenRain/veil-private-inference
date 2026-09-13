# veil private inference receipts 0.2.0

A typed receipt binds a model artifact digest **M**, a salted prompt commitment
**P**, a salted output commitment **O**, and an approved GPU claim digest **G**.
The software includes confidential inference transport, attestation verification,
real ZK and homomorphic backends, and an executable NVFlare privacy protocol.
The deployment profile targets one H100 GPU in an Intel TDX confidential VM.
Hardware acceptance and vendor-image builds have not been performed here.

| Component | Implemented behavior |
| --- | --- |
| veil | Typed receipt relation and plaintext Wasm twin; FHC shape and federated round relation |
| Inference | Attest before releasing the prompt; X25519/AES-GCM transport; Ed25519 receipt; persistent client replay protection |
| Attestation | NVAT CLI/NVML evidence, signed NRAS detached EAT, CPU Trustee EAR, independently pinned verifier keys and launch policy |
| ZK | Circom/Poseidon circuit and snarkjs PLONK proof of the blinded public tuple |
| FHE | TenSEAL BFV circuit comparing all 1,024 bits of M/P/O/G under encryption |
| Federation | Real NVFlare SVT DP filters, CKKS encrypted aggregation, three rounds, per-client privacy accounting and veil receipts |
| Deployment | Source-pinned tool builds, immutable workload context, native NVML CC guard, Kata Pod/Service/NetworkPolicy generator and policy finalizer |

Start with the CPU demo from the repository root. Node 22 or newer is required.
The release archive includes the compiled Wasm and PLONK artifacts. A source
checkout must build the veil compiler using the parent repository instructions,
then run `node inference/build.mjs` once.

```sh
npm ci --prefix inference --ignore-scripts
npm --prefix inference run demo
npm --prefix inference test
npm --prefix inference run test:zk
```

The demo uses generated test signing keys and a synthetic backend, and reports
`simulation`. The production CLI has no mock attestation fallback.
The original small, dependency-free milestone remains available in
[examples/private-inference](../examples/private-inference/README.md).

Install the Python backends with Python 3.13 and the checked-in uv lock:

```sh
uv sync --project inference --locked --python 3.13
inference/.venv/bin/python -P -m unittest veil_privacy.test_fhe veil_privacy.test_federation
inference/.venv/bin/python -P -m veil_privacy.federation simulate inference/artifacts/my-federation
```

Use a new output directory for each run. The simulator starts a real server and
two client processes using local sockets. Its report must show three rounds,
six accepted receipts, three encrypted checkpoints, and no server secret key.
The four-parameter trainer uses synthetic local updates; replace that executor
and re-establish sensitivity bounds before training another model.

Try exact encrypted receipt equality with the public sample tuple:

```sh
inference/.venv/bin/python -P -m veil_privacy.fhe keygen inference/artifacts/bfv-keys
inference/.venv/bin/python -P -m veil_privacy.fhe encrypt inference/artifacts/bfv-keys/public.tenseal inference/samples/tuple.json inference/artifacts/request.bfv.json
inference/.venv/bin/python -P -m veil_privacy.fhe evaluate inference/artifacts/bfv-keys/public.tenseal inference/artifacts/request.bfv.json inference/samples/tuple.json inference/artifacts/result.bfv.json
inference/.venv/bin/python -P -m veil_privacy.fhe decrypt inference/artifacts/bfv-keys/secret.tenseal inference/artifacts/bfv-keys/public.tenseal inference/artifacts/request.bfv.json inference/samples/tuple.json inference/artifacts/result.bfv.json
```

The evaluator receives the public context. Keep `secret.tenseal` at the client.
This circuit returns a Hamming distance, with zero meaning equality. Its output
is explicitly labeled `encrypted-evaluation-only`: encryption does not prove
that an adversarial evaluator performed the requested computation.

To rebuild the ZK artifacts, install Circom 2.2.3, then run:

```sh
node inference/zk/fetch-srs.mjs
npm --prefix inference run zk:setup
npm --prefix inference run test:zk
node inference/cli.mjs zk-key
```

The public circuit inputs are the ten 128-bit limbs of M/P/O/G/nonce and a
Poseidon commitment. The private witness is a random BN254 field blinding value.
The proof binds these inputs to the commitment signed by the attested workload.
It does not prove TensorRT matrix arithmetic or replace CPU/GPU attestation.
See [the security model](SECURITY.md) for the precise claims and setup assumptions.

For a deployed service, first follow [DEPLOYMENT.md](DEPLOYMENT.md). Prepare a
trusted policy and a text chat request using the deployed model ID, then run:

```sh
node inference/cli.mjs infer policy.json request.json client-state https://veil.example receipt-run-001
```

The client verifies CPU and GPU evidence before encrypting the exact request
bytes. It verifies the signed result, output opening, and required ZK proof,
then atomically consumes its challenge. A successful result directory contains
`output.json`, `receipt.json`, `challenge.json`, private commitment openings, and
`proof.json` when required. Directories are private and output files use mode
0600. Keep openings and plaintext out of shared receipt bundles.

`verify` is a fresh acceptance operation against a previously issued local
challenge. Reusing the state directory from a completed `infer` correctly
rejects the receipt as replayed. It is not an archival inspection command.
The exported `verifyReceipt` function performs stateless verification without
consuming a challenge, and its caller must supply independently trusted context.

For the complete local release gate, install the parent compiler toolchain,
OPA 1.x, Circom, locked Node/Python dependencies and built ZK artifacts:

```sh
OPA=/absolute/path/to/opa bash dev/private-inference-release.sh
python3 -P inference/package_release.py
```

The gate preserves the parent repository's checks and adds the native GPU guard,
receipt/adversarial tests, real proof checks, real homomorphic tests, policy
evaluation, and the NVFlare simulation. It is also the CI entry point for a runner
with this toolchain. The archive excludes environments, downloaded dependencies,
generated keys, private openings, local model weights and simulator workspaces.
It includes the parent's pinned `vendor/tot` source tree and its license. Git
metadata and local submodule URLs are omitted. Run the complete parent regression
gate and release builder from a Git checkout with its initialized submodule;
the extracted archive supports the application demo, client and privacy backends.
If only the parent's original timing bounds fail, the gate still exits nonzero
and records those failures. To package that exact, explicitly qualified result:

```sh
python3 -P inference/package_release.py --allow-performance-failures
```

This creates an archive ending in `-candidate.tar.gz`, with
`status: performance-unvalidated` in its manifest. Missing checks, timeouts and
functional failures cannot use this exception. The default packager requires all
software gates to pass. Both forms preserve the pending hardware/image status.
See [VALIDATION.md](VALIDATION.md) for the recorded validation and remaining
deployment acceptance steps.

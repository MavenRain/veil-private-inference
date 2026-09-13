# Receipt security model

The receipt asserts that approved workload software processed a committed
request using an approved model and produced a committed output while its CPU
and GPU attestation checks passed. This claim depends on the hardware, measured
guest, driver, attestation services, inference engine and receipt service.

The relying party supplies its own model, GPU, launch-policy and verification-key
pins. Neither a token header nor a receipt establishes a trust root. NRAS and
Trustee JWT signatures are checked with explicit algorithm/curve matching and
freshness checks. The top NRAS token binds the exact child token by SHA-256;
both tokens bind the session nonce. Invalid firmware, certificate status,
debug flags or measurements fail before prompt release.

CPU evidence binds the canonical session and GPU evidence digest to TDX report
data. The session includes the client's key, workload signing/encryption keys,
audience, M, P and a random challenge. Trustee EAR must affirm the independently
approved application policy and init-data digest. The approved Kata guest must
enforce that init-data's exact container and API policy. A valid GPU token alone
cannot establish application identity or execution.

The native NVML guard requires a production environment, CC enabled, devtools
disabled, one GPU, and ready state. The measured launcher checks this before
loading model data. It is checked again during attestation and around inference.
This guard is a local assertion by measured software, not a new signed NRAS
claim. Host Kubernetes labels are scheduling hints, not cryptographic evidence.

M hashes a domain-separated manifest of every model artifact path, length and
SHA-256 digest, including weights, tokenizer and TensorRT engines. File hashing
rejects symlinks, changing files and extra/missing artifacts. The deployment
packages model artifacts into the approved image with a read-only root. An
ordinary host-controlled read-only PVC does not provide integrity against a
malicious host. Do not substitute one for the immutable model image.

P and O are domain-separated SHA-256 commitments to exact request/response bytes
and independent random 32-byte salts. The outer JSON transport carries only
ciphertext and the public attestation/receipt. Request and response keys use
separate HKDF domains and AES-256-GCM associated data binds the full session.
Duplicate JSON keys and ambiguous encodings are rejected. Ed25519 signs the
entire statement, including the session digest and completion time.

G is a domain-separated digest of a specified signed NRAS claim bundle:
profile, hardware model, UEID, driver, VBIOS, measurement result, secure boot and
debug status. G is not a raw GPU quote hash or a PCR value. NRAS verifies the
underlying firmware evidence; the client separately pins approved versions and G.
The public receipt therefore exposes device/version metadata, timing, lengths
and commitments. It does not promise metadata anonymity or traffic padding.

Client challenges are CSPRNG values, persisted before use. Acceptance atomically
creates a spent record using exclusive creation and fsync, preventing duplicate
acceptance across concurrent processes and restarts. The state directory is part
of the client's trusted storage. Restoring a maliciously rolled-back client
filesystem can restore spent challenges; use durable non-rollback storage where
that threat matters. Server sessions are short lived, single-use, memory-only,
and are lost on restart. Retry by issuing a fresh challenge.

The PLONK circuit proves knowledge of a field blinding value opening a Poseidon
commitment to the public M/P/O/G/nonce tuple. Limb range constraints preserve
exact 256-bit digest identities. The verifier checks every public signal and
pins the verification key bytes. This is a small binding proof. Neither a full
inference execution trace nor SHA-256 prompt openings are proved in this circuit.
The attested workload and client check those byte commitments outside the circuit.

PLONK uses BN254 and the published PSE perpetual-powers-of-tau prepared SRS. The
release pins both SHA-256 and BLAKE2b checksums of the downloaded file and its
generated artifacts. Soundness still assumes a valid ceremony with destroyed
toxic waste, correct snarkjs/Circom implementation and the circuit's stated
relation. A full ceremony transcript audit is separate from the normal release
gate. The plaintext SZk twin has no cryptographic soundness claim.

The BFV backend implements a depth-one sum of squared bit differences over
1,024 bits, with degree 4096 and plaintext modulus 1,032,193. Honest inputs yield
an exact integer in [0, 1024], without modular aliases. Use contexts generated
by this release. Encryption protects the tuple from an evaluator without the
secret key. Context and task hashes prevent accidental substitution, but they
are not evaluator signatures or proofs. Malicious ciphertext construction,
malicious evaluation and chosen-ciphertext decryption-oracle access require a
separate integrity protocol. Do not expose the decryptor as a public oracle.

Federation uses real NVFlare CKKS aggregation. Clients share one decryption key;
the server receives only the public context. Production job exports omit secret
keys, and clients load a hash-pinned private context from `/run/veil-keys`.
This is not threshold HE or MPC: a colluding client and server can defeat its
key-separation assumption. The server is trusted to execute the approved
aggregation workflow, and mTLS authenticates client identities.

SVT applies to exactly one four-element WEIGHT_DIFF array with one local step.
Each update is clipped to L1 norm 0.005. Under whole-client replacement adjacency,
sensitivity is bounded by 0.01. Each round spends epsilon 0.5 on selection and
0.5 on release; basic composition gives epsilon 3 per client across three rounds.
These are the upstream mechanism's accounting parameters, not an independent DP
audit. NVFlare uses NumPy randomness. Changing adjacency, training shape, clipping,
filters or repeated runs requires a new privacy analysis and cross-run budget.
The current ledger enforces one run and does not support resume or a global
lifetime privacy accountant.

Federated receipts bind authenticated peer, run nonce, round, parent model,
encrypted update digest and claimed privacy spend. They rely on approved client
code actually running the filters. For the TEE layer, provision client TLS/HE
keys through Trustee KBS only after approved CPU/GPU and workload attestation.
The software simulation reports its reduced assurance explicitly.

The release does not claim protection from hardware side channels, compromised
vendor signing keys, bugs in approved model runtimes, rollback of trusted client
storage, malicious authorized key holders, or leakage in model outputs. No H200,
Blackwell, AMD SNP, multi-GPU, production federation or live NIM compatibility
claim follows from the CPU tests.

# Release review

Verdict: the software and deployment preparation package is ready for release
review. The complete software gate passes, including all parent timing bounds.
No unresolved correctness or security defect was found in the reviewed
implementation. This is a development review, not an independent audit or
hardware certification.

CI weakening was checked first. `dev/gates.sh` adds the receipt milestone and
preserves every parent check and threshold. The new full release script runs
the application checks after a parent failure to retain useful evidence, then
returns the parent's nonzero exit status. Default packaging refuses failed
validation. The explicit candidate option accepts only recognized original
timing-bound failures, labels the archive and manifests accordingly, and cannot
accept missing/duplicated checks, timeouts or functional failures. Regression
tests exercise these distinctions.

The review covered the typed relation and normalization boundary, duplicate-key
JSON refusal, model artifact identity, pinned JWT verification, detached NRAS
token binding, CPU report/init-data binding, session encryption, challenge
persistence and concurrent acceptance, backend isolation, GPU mode checks,
PLONK public-input binding, BFV claims, NVFlare key distribution and accounting,
deployment finalization, and public archive contents.

The following issues found during development were resolved before final
validation:

- P1: NVAT evidence collection can accept either CC or PPCIe mode. The native
  measured guard now explicitly requires production CC, devtools off, a single
  GPU, and ready state before backend startup and around inference.
- P1: An NVFlare job is visible to the server. Production exports now contain
  public contexts only; clients load a hash-pinned secret context from a separate
  attested provisioning path. The export test checks that no secret file ships.
- P2: A slow proof verifier could cross the evidence expiration time. Client
  acceptance now rechecks real time after proof verification before consuming
  the challenge. A regression test advances time during verification.

Validation is recorded in [VALIDATION.md](VALIDATION.md). Application tests and
real cryptographic operations pass. Production hardware acceptance still requires
performing the image-build and hardware acceptance steps in
[DEPLOYMENT.md](DEPLOYMENT.md). The ceremony assumptions, honest-evaluator FHE
boundary, shared-key federation limits and lack of an independent DP audit are
stated in [SECURITY.md](SECURITY.md).

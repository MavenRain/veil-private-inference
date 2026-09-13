# Confidential deployment package

This package targets a single Hopper H100 passed through to an Intel TDX Kata
guest, with Linux TSM reports, a trusted external Trustee EAR service and NRAS.
It contains build recipes and a manifest generator. No GPU VM, registry
credentials or cluster target was supplied, so no image was built or deployed
and no live hardware attestation was accepted.

Use the NVIDIA supported platform matrix to select a compatible Kata, GPU
Operator, driver, Trustee and guest-kernel combination. The initial profile is
`kata-qemu-nvidia-gpu-tdx` with `nvidia.com/pgpu: 1`. The native guard must observe
production CC mode, devtools off and GPU ready before the backend starts. The
platform's attestation bootstrap must establish GPU ready state; the receipt
service never sets that state optimistically. Source revisions used by the
adapter/build recipes are recorded in [deploy/sources.json](deploy/sources.json).
[NVIDIA deployment documentation](https://docs.nvidia.com/datacenter/cloud-native/confidential-containers/latest/deployment.html)
and [workload configuration](https://docs.nvidia.com/datacenter/cloud-native/confidential-containers/latest/configure-workloads.html)
describe the platform prerequisites.

Prepare a licensed NIM or TensorRT-LLM image based on Ubuntu 24.04, containing the
fixed runtime and all required model artifacts. Select the exact backend argv
from that image's documented interface. It must serve the pinned model on
`127.0.0.1:8000`, use only `/opt/veil/model`, avoid lazy downloads, and keep scratch
data in guest RAM. Bake the matching tokenizer and TensorRT engine/profile into
the model directory. The example does not invent a universal NIM entrypoint or
an image digest, because both depend on the chosen model and licensed image.

Build tool binaries with approved Linux amd64 image digests. Node must be 22 or
newer; the Rust image must support the pinned upstream workspace (edition 2024).
Use Ubuntu 24.04 for `UBUNTU_IMAGE`. Pin the complete `name@sha256:...` references:

```sh
docker build --platform linux/amd64 --pull -f inference/deploy/Dockerfile.tools \
  --build-arg NODE_IMAGE="$NODE_IMAGE" --build-arg RUST_IMAGE="$RUST_IMAGE" \
  --build-arg UBUNTU_IMAGE="$UBUNTU_IMAGE" -t veil-attestation-tools:0.2.0 .
```

Builds download public source/dependencies. The NVAT and guest-components commits
are pinned; apt and upstream transitive dependencies still require your normal
SBOM/provenance and vulnerability review. Record the resulting tool image digest.
The tool image includes NVAT, a CPU-only TDX `evidence_getter`, Node and the native
CC guard. It must never substitute a host-provided evidence binary at runtime.

Create the model manifest in a trusted build environment:

```sh
node inference/cli.mjs manifest /trusted/model nim YOUR_MODEL_ID model-manifest.json
```

Fill [deployment.example.json](deploy/deployment.example.json), replacing every
placeholder. The example address `192.0.2.1` is documentation-only. Set the actual
NRAS, certificate/RIM and Trustee HTTPS egress ranges, a gateway pod label and a
namespace. Extract its `workload` object to `workload.json`. M is the digest
printed by `manifest`. Obtain G from an independently approved device/firmware
inventory using the `gpuMeasurement` function, never by trusting an unverified
token. Set the audience and Trustee policy ID consistently.

```sh
node inference/deploy/bundle.mjs context workload.json /trusted/model model-manifest.json build-context
docker build --platform linux/amd64 --pull \
  --build-arg NODE_IMAGE="$NODE_IMAGE" --build-arg TOOLS_IMAGE="$TOOLS_IMAGE" \
  --build-arg INFERENCE_IMAGE="$INFERENCE_IMAGE" -t veil-workload:0.2.0 build-context
```

The context is private and contains model artifacts. The image build checks the
manifest and backend executable. Publish that image through your registry's
normal reviewed release process, record its digest, and set `deployment.image`
to that immutable reference. The resulting image contains model files, receipt
code, configuration and attestation tools. Mounting an external ConfigMap or
untrusted host model volume would break this trust model.

Generate the initial deployment resources:

```sh
node inference/deploy/bundle.mjs prepare deployment.json deployment-draft
```

The Pod runs a privileged process inside the Kata TDX guest so it can mount guest
configfs for TSM quotes. It has no hostPath mounts, host namespaces, service
account token or sidecars. The root filesystem is read-only; `/tmp` and
`/dev/shm` are memory volumes. Privilege is acceptable here only with the approved
confidential runtime and restrictive measured agent policy. Confirm that the
selected Kata release exposes the guest TSM and GPU interfaces correctly in the
hardware acceptance run. Do not replace the runtime class with a normal container
runtime. Backend stdout/stderr are discarded; receipt logs contain fixed status
codes. Keep host-accessible core dumps and guest debug consoles disabled.

Use the release-matched Kata `genpolicy` tool in a trusted build environment.
Start from [initdata.example.toml](deploy/initdata.example.toml), configure trusted
KBS certificates and image-pull resources, and supply your reviewed rules/settings:

```sh
genpolicy -u -y deployment-draft/pod.json -p rules.rego -j genpolicy-settings.json --initdata-path=initdata.toml
kubectl create --dry-run=client -f deployment-draft/pod.json -o json > generated-pod.json
```

`genpolicy` may rewrite JSON as YAML. The conversion above restores JSON for the
finalizer. Save the exact uncompressed TOML from the generated
`io.katacontainers.config.hypervisor.cc_init_data` annotation as `final-initdata.toml`:

```sh
python3 -I -c 'import base64,gzip,json,pathlib; p=json.loads(pathlib.Path("generated-pod.json").read_text()); pathlib.Path("final-initdata.toml").write_bytes(gzip.decompress(base64.b64decode(p["metadata"]["annotations"]["io.katacontainers.config.hypervisor.cc_init_data"])))'
```

Review the complete generated `policy.rego`. Require exact approved image,
command, environment, mounts and devices. Deny arbitrary ExecProcess,
CopyFile, ReadStream, WriteStream and policy replacement requests, and reject
additional containers. A default-deny line alone is insufficient if another
rule permits the operation. Test these rules with your release-matched agent
policy evaluator. The finalizer checks approved hashes; it is not a semantic
Rego security auditor. The upstream [NIM example](https://confidentialcontainers.org/docs/examples/nvidia-nim-confidential-gpu-attestation/)
shows the genpolicy/init-data/KBS flow; its SNP measurement values must not be
copied into this TDX profile.

Derive and record the final measurements:

```sh
node inference/deploy/bundle.mjs inspect-initdata generated-pod.json final-initdata.toml
```

The init-data digest hashes the original TOML bytes using its declared algorithm
and pads to TDX's 48-byte MRCONFIGID width. SHA-384 is recommended for this profile.
Whitespace changes affect the digest. This follows the [Trustee init-data specification](https://github.com/confidential-containers/trustee/blob/main/kbs/docs/initdata.md).
Fill [tdx-references.example.json](deploy/tdx-references.example.json) with approved
TDX launch/RTMR values, attributes, init-data and minimum TCB recovery date. Derive
these from your trusted build/launch measurement process. Do not enroll arbitrary
observed values from an untrusted first connection.

```sh
node inference/deploy/appraisal.mjs tdx-references.json veil-tdx-v2.rego
```

Install that policy under `veil-tdx-v2` on your trusted Trustee REST attestation
service. Its generated appraisal requires exact measurements, production TCB,
fresh collateral and debug off. The service must actually verify Intel quotes
and enforce the policy, using its protected signing key. Expose `/attestation`
over HTTPS and restrict policy-management endpoints to administrators. The
[Trustee REST protocol](https://github.com/confidential-containers/trustee/blob/512fed65642015b849f38fb13bfdec7806639987/attestation-service/docs/restful-as.md)
documents policy installation and signing configuration.

Fill [policy.example.json](deploy/policy.example.json) with independently
authenticated NRAS/Trustee public JWKs, explicit algorithms, the approved
firmware values, M/G/init-data and the output of `node inference/cli.mjs zk-key`.
Templates intentionally fail validation until these values are supplied. Pin
Trustee certificates in the guest trust store. If NRAS needs an API key, provision
`NV_ATTESTATION_SERVICE_KEY` through the guest's attested secret-delivery path;
never place it in a host-visible environment manifest. The service inherits
that protected process environment. Some NRAS accounts do not require a key.

Create `approval.json` from the inspected values and the completed agent API review:

```json
{
  "version": "veil.deployment-approval.v2",
  "image": "YOUR_APPROVED_IMAGE_AT_DIGEST",
  "pod_spec_sha256": "INSPECTED_SPEC_SHA256",
  "agent_policy_sha256": "REVIEWED_POLICY_SHA256",
  "init_data": "APPROVED_INIT_DATA_DIGEST",
  "reviewer": "YOUR_RELEASE_REVIEW_ID",
  "agent_api_review": "deny-exec-copy-stream-policy-update;exact-container-spec"
}
```

```sh
node inference/deploy/bundle.mjs finalize deployment.json generated-pod.json final-initdata.toml policy.json approval.json deployment-final
```

Keep the final policy and approval under your release-signing/provenance process.
Only `pod.json`, `service.json` and `network.json` are Kubernetes objects;
`manifest.json` records hashes and deliberately says `hardware_validated: false`.
Create the namespace and a TLS gateway matching the configured label through
your normal platform deployment. Only the receipt service port is exposed.
Apply those three Kubernetes resources after the deployment review. The client
requires HTTPS outside IP loopback, even though its payload is also encrypted
end to end to the attested workload key.

Hardware acceptance must record one successful inference and reject modified
M/P/O/G, replayed/expired evidence, unknown signing keys, CC-off/devtools mode,
changed init-data/model image, and unauthorized guest exec/log requests. Confirm
that no prompt reaches the backend when preflight fails and that no private
model artifact leaves the confidential guest. Save the real receipt and release
hashes with the target's platform version matrix. This is still pending.

For NVFlare, install the locked Python package and Node on the server and each
attested client. Generate CKKS key material on a trusted provisioning machine,
then export the production job:

```sh
inference/.venv/bin/python -P -m veil_privacy.federation keygen private-federation-keys
inference/.venv/bin/python -P -m veil_privacy.federation export federated-job --keys private-federation-keys
```

The job contains three public contexts and no secret context. Provision each
client's hash-pinned `secret.tenseal` into a private, guest-memory-backed
`/run/veil-keys/secret.tenseal`, outside the submitted job. Trustee KBS must release
HE and client mTLS keys only to approved CPU/GPU and measured client images.
The standard NVFlare secure startup kits establish mTLS and site identities
`site-1` and `site-2`. Submit only `federated-job/jobs/veil-private-rounds` through
the NVFlare administration workflow. Never submit `private-federation-keys` or
a simulator directory. Secure production federation and KBS key release require
their own acceptance run; the CPU simulator verifies the actual filters and
aggregation protocol without claiming those deployment properties.

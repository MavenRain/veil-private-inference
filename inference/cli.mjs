#!/usr/bin/env node
import { mkdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical, exactKeys, parseJson, postJson, readBytes, readJson, ReceiptError,
  requireThat, secureUrl, sha256, unixTime, writePrivate } from './core.mjs';
import { checkGpuMode, hardwareAttester, inferenceBackend } from './adapters.mjs';
import { createManifest, modelHash, verifyManifest } from './model.mjs';
import { InferenceRunner, beginClient, sealRequest, finishClient, verifyReceipt } from './protocol.mjs';
import { ChallengeStore } from './state.mjs';
import { createReceiptServer } from './server.mjs';
import { loadTwin } from '../examples/private-inference/host.mjs';
import { defaultArtifacts, prove, verifyProof } from './zk/proof.mjs';
import { validateRunnerConfig } from './workload.mjs';

export async function loadReceiptTwin() {
  const artifact = fileURLToPath(new URL('./artifacts/receipt.wasm', import.meta.url));
  let bytes;
  try { bytes = readFileSync(artifact); } catch (error) {
    if (error.code === 'ENOENT') return loadTwin();
    throw error;
  }
  const module = await WebAssembly.compile(bytes);
  requireThat(WebAssembly.Module.imports(module).length === 0, 'wasm-imports');
  return (await WebAssembly.instantiate(module)).exports;
}
async function main(args) {
  const [command, ...rest] = args;
  if (command === 'manifest' && rest.length === 4) {
    const [root, runtime, modelId, output] = rest;
    const manifest = createManifest(root, runtime, modelId);
    writePrivate(output, canonical(manifest) + '\n');
    console.log(canonical({ model: modelHash(manifest) }));
  } else if (command === 'serve' && rest.length === 1) {
    const config = validateRunnerConfig(readJson(rest[0]));
    const manifest = verifyManifest(config.model_root, readJson(config.manifest, 4000000), config.runner.model);
    requireThat(manifest.runtime === config.runner.runtime, 'manifest-runtime');
    const runner = new InferenceRunner(config.runner, {
      attest: hardwareAttester(config.attester), infer: async bytes => {
        await checkGpuMode(config.attester.cc_check);
        const output = await inferenceBackend(config.backend_url, manifest.model_id)(bytes);
        await checkGpuMode(config.attester.cc_check);
        return output;
      } });
    const server = createReceiptServer(runner);
    server.listen(config.port, config.listen, () => console.log(canonical({ ready: true, mode: 'hardware', port: config.port })));
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
      server.close(); server.closeAllConnections();
    });
  } else if (command === 'infer' && rest.length === 5) {
    const [policyFile, requestFile, statePath, endpoint, outputPath] = rest;
    // Reserve private output storage before issuing or consuming a challenge.
    mkdirSync(outputPath, { mode: 0o700 });
    const policy = readJson(policyFile);
    const url = secureUrl(endpoint);
    requireThat(url.pathname === '/', 'service-url');
    const store = new ChallengeStore(statePath);
    const client = beginClient(policy, store, readBytes(requestFile));
    const attestation = parseJson(await postJson(new URL('/v2/session', url).href, client.expected, 120000, 2000000), 2000000);
    const message = sealRequest(client, attestation);
    const response = parseJson(await postJson(new URL('/v2/inference', url).href, message, 150000, 4000000), 4000000);
    const api = await loadReceiptTwin();
    verifyReceipt(api, response.receipt, client.expected, policy, unixTime());
    const proof = policy.zk.required ? await prove(response.receipt.statement, client.blind) : undefined;
    const accepted = await finishClient(api, client, response, { proof, verifyProof });
    writePrivate(resolve(outputPath, 'output.json'), accepted.output);
    writePrivate(resolve(outputPath, 'receipt.json'), canonical(accepted.receipt) + '\n');
    writePrivate(resolve(outputPath, 'challenge.json'), canonical(client.expected) + '\n');
    writePrivate(resolve(outputPath, 'openings.private.json'), canonical({
      prompt_salt: client.promptSalt.toString('base64url'), output_salt: client.outputSalt.toString('base64url'),
      zk_blind: client.blind }) + '\n');
    if (proof) writePrivate(resolve(outputPath, 'proof.json'), canonical(proof) + '\n');
    console.log(canonical({ accepted: true, assurance: accepted.assurance, zk: Boolean(proof) }));
  } else if (command === 'verify' && (rest.length === 4 || rest.length === 5)) {
    const [receiptFile, policyFile, challengeFile, statePath, proofFile] = rest;
    const receipt = readJson(receiptFile, 2000000);
    const policy = readJson(policyFile);
    const challenge = readJson(challengeFile);
    const now = unixTime();
    const result = verifyReceipt(await loadReceiptTwin(), receipt, challenge, policy, now);
    if (policy.zk.required || proofFile) requireThat(proofFile && await verifyProof(receipt.statement,
      readJson(proofFile), policy.zk.verification_key_sha256), 'zk-proof');
    new ChallengeStore(statePath).consume(challenge, receipt, now);
    console.log(canonical(result));
  } else if (command === 'prove' && rest.length === 3) {
    const [receiptFile, openingsFile, output] = rest;
    const receipt = readJson(receiptFile, 2000000);
    const proof = await prove(receipt.statement, readJson(openingsFile).zk_blind);
    writePrivate(output, canonical(proof) + '\n');
  } else if (command === 'zk-key' && rest.length === 0) {
    console.log(sha256(readBytes(resolve(defaultArtifacts, 'verification_key.json'))));
  } else {
    console.log('Usage:\n  node inference/cli.mjs manifest MODEL_DIR nim|tensorrt-llm MODEL_ID OUTPUT\n'
      + '  node inference/cli.mjs serve CONFIG\n'
      + '  node inference/cli.mjs infer POLICY REQUEST STATE_DIR HTTPS_ENDPOINT OUTPUT_DIR\n'
      + '  node inference/cli.mjs verify RECEIPT POLICY CHALLENGE STATE_DIR [PROOF]\n'
      + '  node inference/cli.mjs prove RECEIPT PRIVATE_OPENINGS OUTPUT\n'
      + '  node inference/cli.mjs zk-key');
    process.exitCode = command === '--help' ? 0 : 2;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    console.error(canonical({ accepted: false, code: error instanceof ReceiptError ? error.code : 'operation-failed' }));
    process.exitCode = 1;
  });
}

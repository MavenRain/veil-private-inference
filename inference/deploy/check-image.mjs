import { existsSync } from 'node:fs';
import { readJson, requireThat } from '../core.mjs';
import { validateWorkload } from '../workload.mjs';
import { verifyManifest } from '../model.mjs';

const workload = validateWorkload(readJson('/opt/veil/workload.json'));
verifyManifest(workload.service.model_root, readJson(workload.service.manifest, 4000000), workload.service.runner.model);
requireThat(existsSync(workload.backend_argv[0]), 'backend-executable');
console.log('immutable workload configuration and model manifest checked');

import { readJson, canonical, ReceiptError } from '../core.mjs';
import { launchWorkload } from '../workload.mjs';

const controller = new AbortController();
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => controller.abort());
try {
  const workload = await launchWorkload(readJson('/opt/veil/workload.json'), { signal: controller.signal });
  console.log(canonical({ ready: true, mode: 'hardware', port: workload.server.address().port }));
} catch (error) {
  console.error(canonical({ ready: false, code: error instanceof ReceiptError ? error.code : 'workload-start' }));
  process.exitCode = 1;
}

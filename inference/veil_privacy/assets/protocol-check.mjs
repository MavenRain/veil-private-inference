import { readFileSync } from 'node:fs';
const names = ['round', 'expected', 'party', 'parties', 'spent', 'cost', 'budget', 'encrypted', 'dp', 'bound'];
try {
  const request = JSON.parse(readFileSync(0, 'utf8'));
  if (Object.keys(request).sort().join() !== [...names].sort().join()
      || names.some(k => !Number.isSafeInteger(request[k]) || request[k] < 0 || request[k] > 1000000)) throw Error();
  const module = await WebAssembly.compile(readFileSync(new URL('./privacy.wasm', import.meta.url)));
  if (WebAssembly.Module.imports(module).length) throw Error();
  const api = (await WebAssembly.instantiate(module)).exports;
  console.log(JSON.stringify({ code: api.federatedRoundCode(...names.map(k => request[k])) }));
} catch { console.log('{"code":99}'); process.exitCode = 1; }

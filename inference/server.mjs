import { createServer } from 'node:http';
import { canonical, parseJson, ReceiptError, requireThat } from './core.mjs';

export function createReceiptServer(runner) {
  const server = createServer({ requestTimeout: 150000, headersTimeout: 10000,
    maxHeaderSize: 8192, keepAliveTimeout: 1000 }, async (request, response) => {
    const send = (status, value) => {
      response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store',
        'x-content-type-options': 'nosniff' });
      response.end(canonical(value));
    };
    try {
      if (request.method === 'GET' && request.url === '/healthz') return send(200, { ready: true });
      requireThat(request.method === 'POST' && ['/v2/session', '/v2/inference'].includes(request.url), 'route');
      requireThat(request.headers['content-type'] === 'application/json'
        && !request.headers['content-encoding'], 'content-type');
      const limit = request.url === '/v2/session' ? 8192 : 2300000;
      let length = 0; const parts = [];
      for await (const chunk of request) {
        length += chunk.length;
        requireThat(length <= limit, 'request-size');
        parts.push(chunk);
      }
      const body = parseJson(Buffer.concat(parts, length), limit);
      const result = request.url === '/v2/session' ? await runner.begin(body) : await runner.complete(body);
      send(200, result);
    } catch (error) {
      // Expose only our fixed error identifiers, never native errors or data.
      const code = error instanceof ReceiptError ? error.code : 'operation-failed';
      send(code === 'route' ? 404 : 400, { accepted: false, code });
    }
  });
  server.maxConnections = 128;
  return server;
}

import http from 'node:http';
import net from 'node:net';
import { Resolver } from 'node:dns/promises';
import { pipeline } from 'node:stream';
import { WebSocketServer, createWebSocketStream } from 'ws';
import { isPublicIPv4, validateDnsName, validateWebDestination } from '../../shared/public-web';

/** No application secrets, storage identity, grant keys or Redis in this
 * process. Its ingress is restricted to the gateway security group. */
export function createPublicEgressRelay(options: {
  connect?: (ip: string, port: number) => net.Socket;
  resolve?: (name: string) => Promise<Array<{ address: string; ttl: number }>>;
} = {}): http.Server {
  const resolver = new Resolver({ timeout: 3000, tries: 2 });
  const resolve = options.resolve ?? (name => resolver.resolve4(name, { ttl: true }));
  const peers = new Set<import('ws').WebSocket>();
  const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') { res.writeHead(200).end('ok'); return; }
    if (req.method !== 'POST' || req.url !== '/dns') { res.writeHead(404).end(); return; }
    const timer = setTimeout(() => req.destroy(), 5000);
    try {
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (Buffer.byteLength(body) > 512) throw new Error('DNS request too large');
      }
      const query = JSON.parse(body);
      if (query.type !== 'A' || Object.keys(query).some(k => k !== 'name' && k !== 'type')) throw new Error('Invalid DNS query');
      const answers = await resolve(validateDnsName(query.name));
      // Reject the entire mixed answer; never choose a safe member of a
      // private/public set and later permit a different connection target.
      if (!answers.length || answers.length > 32 || answers.some(a => !isPublicIPv4(a.address))) {
        res.writeHead(403).end(); return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ answers: answers.map(a => ({ address: a.address, ttl: Math.min(60, Math.max(1, a.ttl)) })) }));
    } catch { res.writeHead(403).end(); }
    finally { clearTimeout(timer); }
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  const ws = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024, perMessageDeflate: false });
  server.on('upgrade', (req, socket, head) => {
    if (req.url !== '/tunnel') { socket.destroy(); return; }
    ws.handleUpgrade(req, socket, head, peer => {
      peers.add(peer);
      let upstream: net.Socket | undefined;
      const deadline = setTimeout(() => peer.terminate(), 600_000);
      const opening = setTimeout(() => peer.terminate(), 5000);
      peer.once('close', () => {
        clearTimeout(deadline); clearTimeout(opening); upstream?.destroy(); peers.delete(peer);
      });
      peer.on('error', () => peer.terminate());
      peer.once('message', (bytes, binary) => {
        try {
          if (binary || bytes.toString().length > 512) throw new Error('Invalid tunnel opening');
          const { ip, port } = validateWebDestination(JSON.parse(bytes.toString()));
          upstream = options.connect ? options.connect(ip, port) : net.connect({ host: ip, port, family: 4 });
          upstream.setTimeout(30_000, () => peer.terminate());
          upstream.once('error', () => peer.terminate());
          upstream.once('connect', () => {
            clearTimeout(opening);
            peer.send(JSON.stringify({ opened: true }), error => {
              if (error) { peer.terminate(); return; }
              const stream = createWebSocketStream(peer, { highWaterMark: 64 * 1024 });
              pipeline(stream, upstream!, error => { if (error) peer.terminate(); });
              pipeline(upstream!, stream, error => { if (error) peer.terminate(); else peer.close(); });
            });
          });
        } catch { peer.terminate(); }
      });
    });
  });
  server.on('close', () => { resolver.cancel(); for (const peer of peers) peer.terminate(); ws.close(); });
  return server;
}

if (require.main === module) {
  const server = createPublicEgressRelay();
  server.listen(Number(process.env.PORT ?? 3191), '0.0.0.0');
  const stop = (): void => { server.close(); server.closeAllConnections(); setTimeout(() => process.exit(0), 1000).unref(); };
  process.once('SIGTERM', stop); process.once('SIGINT', stop);
}

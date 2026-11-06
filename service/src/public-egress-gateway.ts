import http from 'node:http';
import { Transform, pipeline } from 'node:stream';
import { randomUUID } from 'node:crypto';
import WebSocket, { WebSocketServer, createWebSocketStream } from 'ws';
import type { Express } from 'express';
import { isPublicIPv4, validateDnsName, validatePublicWeb, validateWebDestination } from '../../shared/public-web';
import { EGRESS_GRANT_HEADER, openEgressGrant, type EgressGrantClaims } from './egress-grant';
import { checkEgressGrantActive, recordPublicWeb } from './egress-ledger';

export function installPublicWebGateway(app: Express, options: { relayUrl: string; secret: string }): {
  attach: (server: http.Server) => void; close: () => void;
} {
  const relay = options.relayUrl ? new URL(options.relayUrl) : undefined;
  if (relay && (!['http:', 'https:'].includes(relay.protocol) || relay.pathname !== '/'
    || relay.username || relay.password || relay.search || relay.hash)) throw new Error('Invalid public egress relay origin');
  if (relay && process.env.CODEAPI_HARDENED_SANDBOX_MODE === 'true' && relay.protocol !== 'https:') throw new Error('Hardened public egress requires TLS');
  const peers = new Set<WebSocket>();
  async function authorize(token: unknown): Promise<EgressGrantClaims> {
    if (!relay || typeof token !== 'string') throw new Error('Public web unavailable');
    const grant = openEgressGrant(token, options.secret);
    validatePublicWeb(grant.network);
    if (!grant.network || grant.legacy_grant) throw new Error('Public web denied');
    await checkEgressGrantActive(grant);
    return grant;
  }
  app.get('/network/ready', async (req, res) => {
    try {
      await authorize(req.header(EGRESS_GRANT_HEADER));
      const response = await fetch(new URL('/health', relay!), { redirect: 'error', signal: AbortSignal.timeout(3000) });
      if (!response.ok) throw new Error('Relay unavailable');
      await response.body?.cancel();
      return res.json({ mode: 'public-web', policy_version: 1 });
    } catch { return res.status(403).json({ error: 'Public web unavailable' }); }
  });
  app.post('/network/dns', async (req, res) => {
    try {
      const grant = await authorize(req.header(EGRESS_GRANT_HEADER));
      // This route installs its bounded parser itself; callers cannot make
      // an unbounded parse or forward other gateway credentials to the relay.
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (Buffer.byteLength(body) > 512) throw new Error('Invalid DNS request');
      }
      const query = JSON.parse(body);
      if (query.type !== 'A' || Object.keys(query).some(k => k !== 'name' && k !== 'type')) throw new Error('Invalid DNS request');
      const name = validateDnsName(query.name);
      await recordPublicWeb(grant, 'dns', '', 0);
      const response = await fetch(new URL('/dns', relay!), {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name, type: 'A' }), redirect: 'error', signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error('DNS denied');
      const text = await response.text();
      if (text.length > 4096) throw new Error('Invalid DNS response');
      const answer = JSON.parse(text);
      if (!Array.isArray(answer.answers) || !answer.answers.length || answer.answers.length > 32
        || answer.answers.some((a: { address: string; ttl: number }) => !isPublicIPv4(a.address) || !Number.isInteger(a.ttl) || a.ttl < 1 || a.ttl > 60)) {
        throw new Error('DNS denied');
      }
      await checkEgressGrantActive(grant);
      return res.json(answer);
    } catch { return res.status(403).json({ error: 'Public web DNS denied' }); }
  });
  const ws = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024, perMessageDeflate: false });
  const close = (): void => { for (const peer of peers) peer.terminate(); ws.close(); };
  return {
    close,
    attach(server) {
      server.on('upgrade', (req, socket, head) => {
        if (req.url !== '/network/tunnel') { socket.destroy(); return; }
        const timer = setTimeout(() => socket.destroy(), 5000);
        void authorize(req.headers[EGRESS_GRANT_HEADER.toLowerCase()]).then(grant => {
          clearTimeout(timer);
          if (socket.destroyed) return;
          ws.handleUpgrade(req, socket, head, peer => {
            peers.add(peer);
            const connection = randomUUID();
            let reserved = false;
            let remote: WebSocket | undefined;
            let closed = false;
            let streaming = false;
            const stop = (): void => {
              if (closed) return;
              closed = true; clearTimeout(opening); clearTimeout(deadline); clearInterval(heartbeat);
              peer.terminate(); remote?.terminate(); peers.delete(peer);
              // Redis leases expire too, so a crashed gateway cannot retain a
              // concurrency slot for the entire execution.
              if (reserved) void recordPublicWeb(grant, 'close', connection, 0).catch(() => {});
            };
            const opening = setTimeout(stop, 5000);
            const deadline = setTimeout(stop, Math.max(1, grant.exp * 1000 - Date.now()));
            const heartbeat = setInterval(() => {
              void (reserved ? recordPublicWeb(grant, 'renew', connection, 0) : checkEgressGrantActive(grant)).catch(stop);
            }, 1000);
            peer.once('close', stop); peer.once('error', stop);
            peer.once('message', (bytes, binary) => {
              void (async () => {
                if (binary || bytes.toString().length > 512) throw new Error('Invalid tunnel opening');
                const destination = validateWebDestination(JSON.parse(bytes.toString()));
                await recordPublicWeb(grant, 'open', connection, 0);
                reserved = true;
                if (closed) { await recordPublicWeb(grant, 'close', connection, 0); return; }
                const url = new URL('/tunnel', relay!); url.protocol = relay!.protocol === 'https:' ? 'wss:' : 'ws:';
                remote = new WebSocket(url, { maxPayload: 64 * 1024, perMessageDeflate: false, handshakeTimeout: 5000 });
                remote.once('error', stop); remote.once('close', () => { if (!streaming) stop(); });
                remote.once('open', () => remote!.send(JSON.stringify(destination)));
                remote.once('message', (response, isBinary) => {
                  if (isBinary || response.toString() !== '{"opened":true}') { stop(); return; }
                  clearTimeout(opening);
                  peer.send('{"opened":true}', error => {
                    if (error || closed) { stop(); return; }
                    streaming = true;
                    const left = createWebSocketStream(peer, { highWaterMark: 64 * 1024 });
                    const right = createWebSocketStream(remote!, { highWaterMark: 64 * 1024 });
                    const charge = (): Transform => new Transform({
                      highWaterMark: 64 * 1024,
                      transform(chunk: Buffer, _encoding, callback) {
                        void recordPublicWeb(grant, 'bytes', connection, chunk.length).then(() => callback(null, chunk), () => callback(new Error('Public web budget denied')));
                      },
                    });
                    pipeline(left, charge(), right, stop);
                    pipeline(right, charge(), left, error => { if (error) stop(); else peer.close(); });
                  });
                });
              })().catch(stop);
            });
          });
        }, () => { clearTimeout(timer); socket.destroy(); });
      });
    },
  };
}

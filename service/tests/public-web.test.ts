import { describe, test, expect, afterAll } from 'bun:test';
import express from 'express';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import Redis from 'ioredis';
import WebSocket from 'ws';
import { DEFAULT_PUBLIC_WEB, isPublicIPv4, validatePublicWeb, validateWebDestination } from '../../shared/public-web';
import { createPublicEgressRelay } from '../src/public-egress-relay';

// Run separately from other suites: this gate requires the real Lua ledger.
process.env.CODEAPI_EGRESS_LEDGER_REQUIRED = 'true';
process.env.REDIS_HOST = '127.0.0.1';
process.env.REDIS_PORT = process.env.PUBLIC_WEB_TEST_REDIS_PORT ?? '6388';
const { createEgressLedger, recordPublicWeb, revokeEgressLedger, setEgressLedgerRedisForTest } = await import('../src/egress-ledger');
const { sealEgressGrant, openEgressGrant } = await import('../src/egress-grant');
const { installPublicWebGateway } = await import('../src/public-egress-gateway');
const redis = new Redis({ host: '127.0.0.1', port: Number(process.env.REDIS_PORT), maxRetriesPerRequest: 0 });
setEgressLedgerRedisForTest(redis);
const secret = 'public-web-test-secret-32-bytes-long';
const ids: string[] = [];
const servers: http.Server[] = [];
afterAll(async () => {
  for (const server of servers) { server.closeAllConnections(); server.close(); }
  for (const id of ids) await redis.del(`codeapi:egress:grant:${id}`);
  redis.disconnect(); setEgressLedgerRedisForTest(null);
});

async function grant(overrides: Partial<typeof DEFAULT_PUBLIC_WEB> = {}, compact = false) {
  const { env } = await import('../src/config');
  env.EGRESS_LEDGER_COMPACT = compact;
  const id = randomUUID(); ids.push(id);
  const claims = { v: 1 as const, typ: 'grant' as const, grant_id: id, exec_id: id, tenant_id: 'test', user_id: 'test', session_key: id,
    input_files: [], read_sessions: [], output_session_id: id, max_upload_bytes: 10, max_output_files: 1, max_requests: 1000,
    iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60, network: { ...DEFAULT_PUBLIC_WEB, ...overrides } };
  await createEgressLedger(claims);
  return { claims, token: sealEgressGrant(claims, secret) };
}

describe('public destination and capability policy', () => {
  test('denies private, special, metadata, encoded and IPv6 destinations', () => {
    for (const ip of ['0.0.0.0', '10.64.0.1', '100.64.1.1', '127.0.0.1', '169.254.169.254', '169.254.170.2',
      '172.16.0.1', '192.168.1.1', '198.18.1.1', '192.0.2.1', '224.0.0.1', '255.255.255.255',
      '2130706433', '0x7f000001', '0177.0.0.1', '127.1', '::1', '::ffff:8.8.8.8']) {
      expect(isPublicIPv4(ip)).toBe(false);
      expect(() => validateWebDestination({ ip, port: 443 })).toThrow();
    }
    expect(isPublicIPv4('8.8.8.8')).toBe(true);
    expect(() => validateWebDestination({ ip: '8.8.8.8', port: 22 })).toThrow();
    expect(() => validateWebDestination({ ip: '8.8.8.8', port: 443, hostname: 'private' })).toThrow();
  });
  test('rejects malformed limits, escalation and unknown policy versions', () => {
    expect(() => validatePublicWeb(undefined)).not.toThrow();
    for (const value of [{ ...DEFAULT_PUBLIC_WEB, max_bytes: Infinity }, { ...DEFAULT_PUBLIC_WEB, max_connections: 17 },
      { ...DEFAULT_PUBLIC_WEB, policy_version: 2 }, { ...DEFAULT_PUBLIC_WEB, bypass: true }, { ...DEFAULT_PUBLIC_WEB, max_attempts: 0 }]) {
      expect(() => validatePublicWeb(value)).toThrow();
    }
  });
  test('sealing preserves network capability without granting legacy tokens access', async () => {
    const g = await grant(); expect(openEgressGrant(g.token, secret).network).toEqual(DEFAULT_PUBLIC_WEB);
    const old = { ...g.claims, network: undefined };
    expect(openEgressGrant(sealEgressGrant(old, secret), secret).network).toBeUndefined();
  });
});

for (const compact of [false, true]) describe(`atomic network ledger (${compact ? 'hash' : 'JSON'})`, () => {
  test('concurrency admission is atomic and closing does not refund attempts', async () => {
    const g = await grant({ max_connections: 1, max_attempts: 2 }, compact);
    const results = await Promise.allSettled(['one', 'two'].map(id => recordPublicWeb(g.claims, 'open', id, 0)));
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    const winner = results[0].status === 'fulfilled' ? 'one' : 'two';
    await recordPublicWeb(g.claims, 'close', winner, 0);
    await expect(recordPublicWeb(g.claims, 'open', 'three', 0)).rejects.toThrow();
  });
  test('combined upload/download byte budget cannot be raced', async () => {
    const g = await grant({ max_bytes: 10 }, compact);
    await recordPublicWeb(g.claims, 'open', 'connection', 0);
    const results = await Promise.allSettled([1, 2].map(() => recordPublicWeb(g.claims, 'bytes', 'connection', 6)));
    expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
    await expect(recordPublicWeb(g.claims, 'bytes', 'connection', -1)).rejects.toThrow();
    await expect(recordPublicWeb(g.claims, 'bytes', 'not-open', 1)).rejects.toThrow();
  });
  test('DNS budget and grant revocation fail closed', async () => {
    const g = await grant({ max_attempts: 1 }, compact);
    await recordPublicWeb(g.claims, 'dns', '', 0);
    await expect(recordPublicWeb(g.claims, 'dns', '', 0)).rejects.toThrow();
    await recordPublicWeb(g.claims, 'open', 'connection', 0);
    await revokeEgressLedger(g.claims.grant_id, 'test-cancel');
    await expect(recordPublicWeb(g.claims, 'renew', 'connection', 0)).rejects.toThrow();
    await expect(recordPublicWeb(g.claims, 'bytes', 'connection', 1)).rejects.toThrow();
  });
  test('idempotent admission cannot reset spent budgets', async () => {
    const g = await grant({ max_bytes: 1 }, compact);
    await recordPublicWeb(g.claims, 'open', 'connection', 0);
    await recordPublicWeb(g.claims, 'bytes', 'connection', 1);
    await createEgressLedger(g.claims);
    await expect(recordPublicWeb(g.claims, 'bytes', 'connection', 1)).rejects.toThrow();
  });
});

async function listen(server: http.Server): Promise<string> {
  servers.push(server); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  return `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
}

test('gateway authenticates DNS, rejects private/mixed answers and streams through a pinned public target', async () => {
  const fixture = http.createServer((req, res) => res.end('public-web-fixture:' + req.url));
  const fixtureUrl = await listen(fixture);
  const calls: Array<{ ip: string; port: number }> = [];
  const relay = createPublicEgressRelay({
    resolve: async name => name === 'private.example' ? [{ address: '10.64.0.1', ttl: 30 }]
      : name === 'mixed.example' ? [{ address: '8.8.8.8', ttl: 30 }, { address: '127.0.0.1', ttl: 30 }]
      : [{ address: '8.8.8.8', ttl: 30 }],
    connect: (ip, port) => { calls.push({ ip, port }); return net.connect(Number(new URL(fixtureUrl).port), '127.0.0.1'); },
  });
  const relayUrl = await listen(relay);
  const app = express(); const web = installPublicWebGateway(app, { relayUrl, secret });
  const server = http.createServer(app); web.attach(server); const gateway = await listen(server);
  const g = await grant();
  const query = (name: string, token = g.token) => fetch(gateway + '/network/dns', { method: 'POST',
    headers: { 'X-CodeAPI-Egress-Grant': token }, body: JSON.stringify({ name, type: 'A' }) });
  expect((await query('public.example', 'invalid')).status).toBe(403);
  expect((await query('private.example')).status).toBe(403);
  expect((await query('mixed.example')).status).toBe(403);
  expect((await query('public.example')).status).toBe(200);
  const peer = new WebSocket(gateway.replace('http:', 'ws:') + '/network/tunnel', { headers: { 'X-CodeAPI-Egress-Grant': g.token } });
  const deadline = setTimeout(() => peer.terminate(), 5000);
  await once(peer, 'open'); peer.send(JSON.stringify({ ip: '8.8.8.8', port: 80 }));
  const [opened] = await once(peer, 'message'); expect(opened.toString()).toBe('{"opened":true}');
  let response = '';
  peer.on('message', bytes => { response += bytes.toString(); });
  const closed = once(peer, 'close');
  peer.send(Buffer.from('GET /proof HTTP/1.1\r\nHost: public.example\r\nConnection: close\r\n\r\n'));
  await closed; clearTimeout(deadline);
  expect(response).toContain('public-web-fixture:/proof'); expect(calls).toEqual([{ ip: '8.8.8.8', port: 80 }]);
  web.close();
}, 15_000);

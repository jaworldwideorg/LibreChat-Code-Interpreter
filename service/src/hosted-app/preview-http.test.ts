import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import express from 'express';
import RedisMock from 'ioredis-mock';
import type { Server } from 'node:http';
import { env } from '../config';
import { acquireRuntimeSessionLock, resetRedisForTests, setRedisForTests, writeRuntimeSessionRecord } from '../runtime-session/registry';
import { hostedAppPreviewGateway } from './preview-gateway';
import { hostedAppPreviewOwnerBinding, verifyHostedAppPreviewAccess } from './preview-access';
import { createPreviewGrant } from './preview-grant';

const runtimeId = `happ_${'a'.repeat(40)}`;
const host = `happ-${'a'.repeat(40)}.apps.example.test`;
const key = Buffer.alloc(32, 5);
const owner = { tenantId: 'fixture-tenant', canonicalUserId: 'fixture-owner' };
let server: Server;
let url: string;
let mock: InstanceType<typeof RedisMock>;
const saved = { enabled: env.HOSTED_APPS_ENABLED, preview: env.HOSTED_APP_PREVIEW_ORIGIN,
  parent: env.HOSTED_APP_PARENT_ORIGIN, key: env.HOSTED_APP_PREVIEW_SIGNING_KEY };

beforeEach(async () => {
  env.HOSTED_APPS_ENABLED = true;env.HOSTED_APP_PREVIEW_ORIGIN = 'https://apps.example.test';
  env.HOSTED_APP_PARENT_ORIGIN = 'https://chat.example.test';env.HOSTED_APP_PREVIEW_SIGNING_KEY = key.toString('base64');
  mock = new RedisMock();await mock.flushall();setRedisForTests(mock);
  const lock = await acquireRuntimeSessionLock(runtimeId);
  if (lock == null) throw new Error('Fixture lock failed');
  await writeRuntimeSessionRecord({ runtime_session_id: runtimeId, tenant_id: owner.tenantId,
    canonical_user_id: owner.canonicalUserId, state: 'RUNNING', generation: 1, last_seen_at: Date.now(),
    microvm_id: 'fixture-vm', endpoint: 'https://unreachable.example.test', hard_deadline_at: Date.now() + 600_000,
    hosted_app: { source_runtime_session_id: 'fixture-source', app_id: 'demo', revision: 'rev-1',
      spec_fingerprint: 'fixture', checkpoint_key: 'fixture-checkpoint', spec: {
        adapter: 'resident', app_id: 'demo', revision: 'rev-1', language: 'node', version: '22',
        entrypoint: 'server.js', cwd: '.', args: [], env: {},
      } },
  }, lock);
  const app = express();app.use((_req, res, next) => { res.setHeader('Connection', 'close');next(); });
  app.use(hostedAppPreviewGateway);app.use((_req, res) => res.status(404).send('Fallback'));
  await new Promise<void>((resolve) => { server = app.listen(0, '127.0.0.1', resolve); });
  const address = server.address();if (address == null || typeof address === 'string') throw new Error('Fixture address failed');
  url = `http://127.0.0.1:${address.port}`;
});
afterEach(async () => {
  server.closeAllConnections();await new Promise<void>((resolve) => server.close(() => resolve()));
  resetRedisForTests();mock.disconnect();env.HOSTED_APPS_ENABLED = saved.enabled;
  env.HOSTED_APP_PREVIEW_ORIGIN = saved.preview;env.HOSTED_APP_PARENT_ORIGIN = saved.parent;env.HOSTED_APP_PREVIEW_SIGNING_KEY = saved.key;
});

async function challenge(): Promise<{ cookie: string; token: string }> {
  const response = await fetch(`${url}/__codeapi/challenge`, { headers: { Host: host } });
  const cookie = response.headers.getSetCookie().find((value) => value.startsWith('__Host-codeapi-preview-browser='))?.split(';')[0];
  const body = await response.text();const token = /challenge:"([A-Za-z0-9_.-]+)"/.exec(body)?.[1];
  if (cookie == null || token == null) throw new Error('Fixture challenge missing');
  return { cookie, token };
}
function grant(token: string, binding = hostedAppPreviewOwnerBinding(owner, key)): string {
  return createPreviewGrant(token, { hostedAppRuntimeId: runtimeId, revision: 'rev-1', ownerBinding: binding, expiresAt: Date.now() + 120_000 }, key);
}
function redeem(token: string, cookie: string): ReturnType<typeof fetch> {
  return fetch(`${url}/__codeapi/authorize?token=${encodeURIComponent(token)}`, { headers: { Host: host, Cookie: cookie } });
}

describe('preview HTTP security boundary', () => {
  test('a grant cannot transfer browsers or replay after the matching browser uses it', async () => {
    const first = await challenge();const second = await challenge();const token = grant(first.token);
    expect((await redeem(token, second.cookie)).status).toBe(401);
    const response = await redeem(token, first.cookie);expect(response.status).toBe(200);
    expect(response.headers.getSetCookie()).toHaveLength(2);
    const session = response.headers.getSetCookie().find((value) => value.startsWith('__Host-codeapi-app='));
    if (session == null) throw new Error('Session cookie missing');
    const claims = verifyHostedAppPreviewAccess(decodeURIComponent(session.split(';')[0]?.split('=')[1] ?? ''), key);
    expect(claims.purpose).toBe('session');expect(claims.grantId).toBeUndefined();
    expect((await redeem(token, first.cookie)).status).toBe(401);
  });
  test('wrong owner and revision cannot issue a browser session', async () => {
    const browser = await challenge();
    expect((await redeem(grant(browser.token, hostedAppPreviewOwnerBinding({ ...owner, canonicalUserId: 'other-owner' }, key)), browser.cookie)).status).toBe(403);
    const token = createPreviewGrant(browser.token, { hostedAppRuntimeId: runtimeId, revision: 'rev-2', ownerBinding: hostedAppPreviewOwnerBinding(owner, key), expiresAt: Date.now() + 120_000 }, key);
    expect((await redeem(token, browser.cookie)).status).toBe(409);
  });
  test('bare viewer and app hosts never expose privileged API routes', async () => {
    expect((await fetch(`${url}/v1/health`, { headers: { Host: 'apps.example.test' } })).status).toBe(404);
    expect((await fetch(`${url}/v1/health`, { headers: { Host: host } })).status).toBe(401);
    const response = await fetch(`${url}/viewer/${runtimeId}?channel=${'a'.repeat(32)}`, { headers: { Host: 'apps.example.test' } });
    expect(response.status).toBe(200);
    const body = await response.text();expect(body).toContain('sandbox="allow-scripts allow-forms allow-same-origin"');
    expect(body).toContain('event.source!==window.parent');expect(body).toContain('event.origin!==parentOrigin');
    expect(response.headers.get('content-security-policy')).toContain('frame-ancestors https://chat.example.test');
    expect(response.headers.get('content-security-policy')).toContain(`frame-src https://${host}`);
  });
  test('disabled previews still isolate cached wildcard and viewer DNS from API routes', async () => {
    env.HOSTED_APPS_ENABLED = false;
    for (const hostname of [host, 'apps.example.test']) {
      const response = await fetch(`${url}/v1/health`, { headers: { Host: hostname } });
      expect(response.status).toBe(404);expect(await response.text()).not.toContain('Fallback');
    }
  });
});

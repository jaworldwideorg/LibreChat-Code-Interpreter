import { describe, expect, test } from 'bun:test';
import { assertPreviewBrowser, createPreviewBrowserChallenge, createPreviewGrant } from './preview-grant';
import { signHostedAppPreviewAccess, verifyHostedAppPreviewAccess } from './preview-access';

const key = Buffer.alloc(32, 7);
const runtimeId = `happ_${'a'.repeat(40)}`;
const nonce = Buffer.alloc(32, 3).toString('base64url');
const claims = { hostedAppRuntimeId: runtimeId, ownerBinding: Buffer.alloc(32, 4).toString('base64url'), revision: 'rev-1', expiresAt: 1_500_000 };

describe('browser-bound preview grants', () => {
  test('requires the exact challenged browser and separates grant/session purposes', () => {
    const challenge = createPreviewBrowserChallenge(runtimeId, key, nonce, 1_000_000);
    const token = createPreviewGrant(challenge.token, claims, key, 1_000_000);
    const grant = verifyHostedAppPreviewAccess(token, key, 1_000_000);
    expect(grant.expiresAt).toBe(1_300_000);
    expect(grant.grantId).toMatch(/^[a-f0-9]{32}$/);
    expect(() => assertPreviewBrowser(grant, nonce, 'grant', key)).not.toThrow();
    expect(() => assertPreviewBrowser(grant, Buffer.alloc(32, 2).toString('base64url'), 'grant', key)).toThrow();
    expect(() => assertPreviewBrowser(grant, undefined, 'grant', key)).toThrow();
    expect(() => assertPreviewBrowser(grant, nonce, 'session', key)).toThrow();
    const session = verifyHostedAppPreviewAccess(signHostedAppPreviewAccess({ ...grant, purpose: 'session', grantId: undefined }, key), key, 1_000_000);
    expect(() => assertPreviewBrowser(session, nonce, 'session', key)).not.toThrow();
    expect(() => assertPreviewBrowser(session, nonce, 'grant', key)).toThrow();
  });
  test('rejects cross-app, expired and old transferable challenges', () => {
    const challenge = createPreviewBrowserChallenge(runtimeId, key, nonce, 1_000_000);
    expect(() => createPreviewGrant(challenge.token, { ...claims, hostedAppRuntimeId: `happ_${'b'.repeat(40)}` }, key, 1_000_000)).toThrow();
    expect(() => createPreviewGrant(challenge.token, claims, key, 1_300_000)).toThrow();
    expect(() => createPreviewGrant(signHostedAppPreviewAccess(claims, key), claims, key, 1_000_000)).toThrow();
    expect(() => assertPreviewBrowser(claims, nonce, 'session', key)).toThrow();
  });
});

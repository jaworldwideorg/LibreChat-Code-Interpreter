import { createHmac, randomBytes } from 'node:crypto';
import {
  HostedAppPreviewAccessError,
  verifyHostedAppPreviewAccess,
  signHostedAppPreviewAccess,
} from './preview-access';
import type { HostedAppPreviewClaims } from './preview-access';

export const HOSTED_APP_BROWSER_COOKIE = '__Host-codeapi-preview-browser';
export const PREVIEW_GRANT_TTL_MS = 5 * 60_000;
export const PREVIEW_BROWSER_TTL_MS = 60 * 60_000;

export function previewBrowserBinding(nonce: string, key: Buffer): string {
  if (!/^[A-Za-z0-9_-]{43}$/.test(nonce) || key.length !== 32) {
    throw new HostedAppPreviewAccessError('invalid preview browser binding');
  }
  return createHmac('sha256', key).update('hosted-app-browser-v1\0').update(nonce).digest('base64url');
}

export function createPreviewBrowserChallenge(runtimeId: string, key: Buffer, nonce = randomBytes(32).toString('base64url'), now = Date.now()): { nonce: string; token: string } {
  const binding = previewBrowserBinding(nonce, key);
  return {
    nonce,
    token: signHostedAppPreviewAccess({ hostedAppRuntimeId: runtimeId, revision: 'challenge',
      ownerBinding: binding, browserBinding: binding, purpose: 'challenge', expiresAt: now + PREVIEW_GRANT_TTL_MS }, key),
  };
}

/** The challenge proves browser cookie possession; the authenticated API must
 * separately verify the current app's owner and immutable revision. */
export function createPreviewGrant(challenge: string, claims: Omit<HostedAppPreviewClaims, 'purpose' | 'browserBinding' | 'grantId'>, key: Buffer, now = Date.now()): string {
  const browser = verifyHostedAppPreviewAccess(challenge, key, now);
  if (browser.purpose !== 'challenge' || browser.browserBinding == null || browser.hostedAppRuntimeId !== claims.hostedAppRuntimeId) {
    throw new HostedAppPreviewAccessError('preview challenge does not match app');
  }
  return signHostedAppPreviewAccess({ ...claims, expiresAt: Math.min(claims.expiresAt, browser.expiresAt, now + PREVIEW_GRANT_TTL_MS),
    purpose: 'grant', browserBinding: browser.browserBinding, grantId: randomBytes(16).toString('hex') }, key);
}

export function assertPreviewBrowser(claims: HostedAppPreviewClaims, nonce: string | undefined, purpose: 'grant' | 'session', key: Buffer): void {
  if (claims.purpose !== purpose || nonce == null || claims.browserBinding == null || claims.browserBinding !== previewBrowserBinding(nonce, key)
    || (purpose === 'grant' && claims.grantId == null)) {
    throw new HostedAppPreviewAccessError('preview does not match browser');
  }
}

import { expect, test } from 'bun:test';
import { runInNewContext } from 'node:vm';
import type { Request, Response } from 'express';
import { sendHostedAppPreviewViewer } from './preview-viewer';

test('the executed viewer broker only authorizes its initial checked handoff', () => {
  let html = '';
  const headers = new Map<string, string>();
  const res = { setHeader(name: string, value: string) { headers.set(name, value); },
    status() { return this; }, type() { return this; }, send(value: string) { html = value; return this; },
  } as unknown as Response;
  const runtimeId = `happ_${'a'.repeat(40)}`;
  sendHostedAppPreviewViewer({ query: { channel: 'b'.repeat(32) } } as unknown as Request,
    res, runtimeId, 'https://apps.example.test', 'https://chat.example.test');
  const script = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(html)?.[1];
  if (script == null) throw new Error('Viewer script missing');
  type Event = { source: object; origin: string; data: { type: string; challenge?: string; channel?: string; authorizationUrl?: string } };
  let receive: ((event: Event) => void) | undefined;
  const messages: Array<{ value: object; origin: string }> = [];
  const parent = { postMessage(value: object, origin: string): void { messages.push({ value, origin }); } };
  const frame = { contentWindow: {}, src: '' };
  runInNewContext(script, { URL, document: { querySelector: () => frame },
    window: { parent, addEventListener(_name: string, handler: (event: Event) => void) { receive = handler; } },
  });
  if (receive == null) throw new Error('Viewer receiver missing');
  const appOrigin = `https://happ-${'a'.repeat(40)}.apps.example.test`;
  const challenge = { source: frame.contentWindow, origin: appOrigin,
    data: { type: 'codeapi.preview.challenge', challenge: 'signed.challenge' } };
  receive({ ...challenge, origin: 'https://attacker.example.test' });expect(messages).toHaveLength(0);
  receive({ ...challenge, source: {} });expect(messages).toHaveLength(0);
  receive({ ...challenge, data: { ...challenge.data, challenge: 'x'.repeat(1025) } });expect(messages).toHaveLength(0);
  receive(challenge);receive(challenge);expect(messages).toHaveLength(1);
  expect(messages[0]?.origin).toBe('https://chat.example.test');
  const authorize = { source: parent, origin: 'https://chat.example.test', data: {
    type: 'codeapi.preview.authorize', channel: 'b'.repeat(32), authorizationUrl: `${appOrigin}/__codeapi/authorize?token=one`,
  } };
  receive({ ...authorize, origin: 'https://attacker.example.test' });expect(frame.src).toContain('/challenge');
  receive({ ...authorize, data: { ...authorize.data, authorizationUrl: 'https://attacker.example.test/__codeapi/authorize' } });expect(frame.src).toContain('/challenge');
  receive(authorize);expect(frame.src).toContain('token=one');
  receive({ ...authorize, data: { ...authorize.data, authorizationUrl: `${appOrigin}/__codeapi/authorize?token=two` } });
  receive(challenge);expect(frame.src).toContain('token=one');expect(messages).toHaveLength(1);
  expect(headers.get('Origin-Agent-Cluster')).toBe('?1');
});

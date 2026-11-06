import { test, expect } from 'bun:test';
import { parseDnsQuestion, dnsReply } from './public-web-helper';
import { initializePublicWebNamespace } from './public-web-namespace';
import * as fs from 'node:fs/promises';
import { publicWebSeccompPolicy } from './nsjail';

function question(name = 'example.com', type = 1): Buffer {
  const head = Buffer.alloc(12); head.writeUInt16BE(42); head.writeUInt16BE(0x100, 2); head.writeUInt16BE(1, 4);
  const end = Buffer.alloc(5); end.writeUInt16BE(type, 1); end.writeUInt16BE(1, 3);
  return Buffer.concat([head, ...name.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])), end]);
}
test('DNS parser rejects compression/truncation and only builds public A answers', () => {
  const query = question(); expect(parseDnsQuestion(query).name).toBe('example.com');
  expect(dnsReply(query, [{ address: '8.8.8.8', ttl: 30 }]).readUInt16BE(6)).toBe(1);
  expect(() => dnsReply(query, [{ address: '127.0.0.1', ttl: 30 }])).toThrow();
  expect(() => parseDnsQuestion(query.subarray(0, query.length - 1))).toThrow();
  const compressed = Buffer.from(query); compressed[12] = 0xC0;
  expect(() => parseDnsQuestion(compressed)).toThrow();
  expect(dnsReply(question('example.com', 28), []).readUInt16BE(6)).toBe(0);
});
test('public policy keeps Unix, raw, IPv6, descriptor and namespace denials', () => {
  const policy = publicWebSeccompPolicy();
  expect(policy).toContain('domain != AF_INET'); expect(policy).toContain('(type & 15) != 1');
  expect(policy).toContain('bind, listen, accept, accept4');
  expect(policy).toContain('socketpair'); expect(policy).toContain('sendmsg, sendmmsg');
  expect(policy).toContain('unshare, setns, seccomp'); expect(policy).toContain('domain == AF_VSOCK');
});
test('namespace prerequisite failures reject startup and cleanup is mandatory', async () => {
  const operations: string[] = [];
  await initializePublicWebNamespace({
    createNetworkNamespace: value => { operations.push('create:' + value); },
    deleteNetworkNamespace: value => { operations.push('delete:' + value); },
  });
  expect(operations).toHaveLength(2);
  expect(operations[0].slice(7)).toBe(operations[1].slice(7));
  await expect(initializePublicWebNamespace({
    createNetworkNamespace: () => { throw new Error('Routing unavailable'); },
    deleteNetworkNamespace: () => { throw new Error('Unexpected deletion'); },
  })).rejects.toThrow('Routing unavailable');
  let retained = '';
  await expect(initializePublicWebNamespace({
    createNetworkNamespace: value => { retained = value; },
    deleteNetworkNamespace: () => { throw new Error('Detach failed'); },
  })).rejects.toThrow('Detach failed');
  expect(await fs.stat(retained.replace('/netns', ''))).toBeDefined();
  await fs.rm(retained.replace('/netns', ''), { recursive: true });
});

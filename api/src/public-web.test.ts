import { test, expect } from 'bun:test';
import { parseDnsQuestion, dnsReply } from './public-web-helper';
import { initializePublicWebFirewall, installPublicWebFirewall } from './public-web-firewall';
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
test('baseline rejects the UID range in both families and admission never enables direct egress', async () => {
  const calls: string[][] = [];
  const command = async (binary: string, args: string[]) => { calls.push([binary, ...args]); };
  await initializePublicWebFirewall(200000, 8, command);
  expect(calls).toHaveLength(2); expect(calls[1][0]).toContain('ip6tables');
  calls.length = 0;
  const close = await installPublicWebFirewall(200001, '127.64.0.1', 40000, command);
  expect(calls.some(c => c.includes('DNAT') && c.includes('127.64.0.1:40000'))).toBe(true);
  expect(calls.some(c => c.includes('10.0.0.0/8') && c.includes('MARK'))).toBe(true);
  const allowances = calls.filter(c => c.includes('ACCEPT'));
  expect(allowances).toHaveLength(3); expect(allowances.every(c => c.includes('127.64.0.1'))).toBe(true);
  await close();
  const removed = calls.filter(c => c.includes('-D'));
  expect(removed[0]).toContain('filter'); expect(removed).toHaveLength(3);
});
test('partial installation and missing IPv6 support reject admission', async () => {
  await expect(initializePublicWebFirewall(200000, 8, async binary => {
    if (binary.includes('ip6tables')) throw new Error('Missing IPv6 guard');
  })).rejects.toThrow();
  const calls: string[][] = [];
  await expect(installPublicWebFirewall(200002, '127.64.0.2', 40000, async (_binary, args) => {
    calls.push(args); if (args.includes('DNAT')) throw new Error('Missing NAT');
  })).rejects.toThrow();
  expect(calls.some(c => c.includes('ACCEPT'))).toBe(false);
  expect(calls.filter(c => c.includes('-X'))).toHaveLength(3);
});

test('legacy IPv6 owner match still protects every UID when ranges are unsupported', async () => {
  const protectedUids: string[] = [];
  await initializePublicWebFirewall(200000, 3, async (binary, args) => {
    if (!binary.includes('ip6tables')) return;
    const uid = args[args.indexOf('--uid-owner') + 1];
    if (uid.includes('-')) throw new Error('Unsupported owner range');
    protectedUids.push(uid);
  });
  expect(protectedUids).toEqual(['200000', '200001', '200002']);
});

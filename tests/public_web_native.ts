// Run in nsjail-ipc-test as root under sandbox-supervisor-policy.
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { once } from 'node:events';
import { randomUUID } from 'node:crypto';
import { DEFAULT_PUBLIC_WEB, type PublicWebCapability } from '../shared/public-web';
import { createPublicEgressRelay } from '../service/src/public-egress-relay';
import { spawnPipeProcess } from '../api/src/pipe-process';
import { initializePublicWebNamespace } from '../api/src/public-web-namespace';

process.env.CODEAPI_EGRESS_LEDGER_REQUIRED = 'true';
process.env.SANDBOX_NETWORK_MODE = 'public-web';
process.env.SANDBOX_JOB_UID_BASE = '200000';
process.env.SANDBOX_USE_CGROUPV2 = 'false';
process.env.SANDBOX_RLIMIT_AS = '16384';
process.env.NSJAIL_PATH = '/nsjail/nsjail';
if (process.env.PUBLIC_WEB_NATIVE_STRACE === '1') {
  await fs.writeFile('/tmp/public-web-strace', '#!/bin/sh\nexec /usr/bin/strace -f -o /tmp/public-web-trace /nsjail/nsjail "$@"\n', { mode: 0o755 });
  process.env.NSJAIL_PATH = '/tmp/public-web-strace';
}
process.env.PUBLIC_WEB_HELPER_BUNDLE = '/work/api/.build/public-web-helper.cjs';
process.env.NSJAIL_CONFIG = '/tmp/public-web-sandbox.cfg';
const configText = (await fs.readFile('/work/api/config/sandbox.cfg', 'utf8')).replace(/^cgroup_.*\n/gm, '');
await fs.writeFile('/tmp/public-web-sandbox.cfg', configText);
const { createPublicWebLease } = await import('../api/src/public-web-lease');
const { execute } = await import('../api/src/nsjail');
const { config } = await import('../api/src/config');
const { createEgressLedger, revokeEgressLedger } = await import('../service/src/egress-ledger');
const { sealEgressGrant } = await import('../service/src/egress-grant');
const { installPublicWebGateway } = await import('../service/src/public-egress-gateway');

const openssl = spawnPipeProcess('/usr/bin/openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
  '-subj', '/CN=public.example', '-addext', 'subjectAltName=DNS:public.example', '-keyout', '/tmp/public-web-key.pem', '-out', '/tmp/public-web-ca.pem']);
openssl.stdin.end(); openssl.stdout.resume(); openssl.stderr.resume();
assert.equal((await once(openssl, 'close'))[0], 0);
const fixtureHandler: http.RequestListener = async (req, res) => {
  if (req.url === '/idle') { setTimeout(() => res.end('late'), 1000); return; }
  if (req.url === '/redirect-private') { res.writeHead(302, { location: 'http://127.0.0.1/private' }).end(); return; }
  if (req.url === '/redirect') { res.writeHead(302, { location: '/proof' }).end(); return; }
  let bytes = 0; for await (const chunk of req) bytes += chunk.length;
  res.end(`public-web-proof:${req.method}:${bytes}`);
};
let privateHits = 0;
const privateFixture = http.createServer((_req,res)=>{ privateHits++; res.end('private-listener'); });
privateFixture.listen(80,'127.0.0.1'); await once(privateFixture,'listening');
const fixture = http.createServer(fixtureHandler);
const tlsFixture = https.createServer({ key: await fs.readFile('/tmp/public-web-key.pem'), cert: await fs.readFile('/tmp/public-web-ca.pem') }, fixtureHandler);
const resolutions = new Map<string, number>();
const relay = createPublicEgressRelay({
  resolve: async name => {
    const seen = resolutions.get(name) ?? 0; resolutions.set(name, seen + 1);
    if (name === 'private.example' || (name.endsWith('.rebind.example') && seen > 0)) return [{ address: '10.64.0.1', ttl: 30 }];
    if (name === 'mixed.example') return [{ address: '93.184.216.34', ttl: 30 }, { address: '10.64.0.1', ttl: 30 }];
    return [{ address: '93.184.216.34', ttl: 30 }];
  },
  connect: (_ip, port) => net.connect(((port === 443 ? tlsFixture.address() : fixture.address()) as net.AddressInfo).port, '127.0.0.1'),
});
for (const server of [fixture, tlsFixture, relay]) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); }
const app = (await import('express')).default();
const secret = 'public-web-native-secret-32-bytes-long';
const web = installPublicWebGateway(app, { relayUrl: `http://127.0.0.1:${(relay.address() as net.AddressInfo).port}`, secret });
const gateway = http.createServer(app); web.attach(gateway); gateway.listen(0, '127.0.0.1'); await once(gateway, 'listening');
config.egress_gateway_url = `http://127.0.0.1:${(gateway.address() as net.AddressInfo).port}`;
await initializePublicWebNamespace();
await fs.mkdir('/tmp/public-web-packages');
const tests: Array<[string, string[], string]> = [
  ['python', ['/usr/bin/python3', '/mnt/data/main.py'], `import urllib.request, requests, socket, os, stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
for fd in range(3,64):
 try: assert not stat.S_ISSOCK(os.fstat(fd).st_mode), 'inherited socket'
 except OSError: pass
for key in list(os.environ):
 if 'proxy' in key.lower(): del os.environ[key]
assert Path('/etc/resolv.conf').exists()
d=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); d.settimeout(2); d.sendto(bytes.fromhex('002a01000001000000000000067075626c6963076578616d706c650000010001'), ('127.0.0.1',53)); assert d.recv(512)[3] == 128
assert urllib.request.urlopen('http://public.example/proof').read() == b'public-web-proof:GET:0'
assert urllib.request.urlopen('https://public.example/redirect').read() == b'public-web-proof:GET:0'
assert requests.post('https://public.example/proof', data=b'abc').content == b'public-web-proof:POST:3'
assert urllib.request.urlopen('http://93.184.216.34/proof').read() == b'public-web-proof:GET:0'
with ThreadPoolExecutor(max_workers=8) as pool:
 assert all(pool.map(lambda _: urllib.request.urlopen('http://public.example/proof').read() == b'public-web-proof:GET:0', range(8)))
external=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); external.settimeout(.2)
try:
 external.sendto(b'no-external-dns',('8.8.8.8',53)); external.recv(512)
except OSError: pass
else: raise AssertionError('external DNS allowed')
finally: external.close()
inbound=socket.socket()
try: inbound.bind(('0.0.0.0',0))
except PermissionError: pass
else: raise AssertionError('inbound bind allowed')
finally: inbound.close()
name=os.urandom(6).hex()+'.rebind.example'
assert socket.gethostbyname(name)=='93.184.216.34'
try: socket.gethostbyname(name)
except OSError: pass
else: raise AssertionError('DNS rebinding accepted')
for url in ['http://mixed.example', 'http://private.example', 'http://127.0.0.1', 'http://169.254.169.254', 'http://public.example:22', 'http://public.example/redirect-private', 'https://bad.example']:
 try:
  urllib.request.urlopen(url, timeout=2).read()
 except Exception:
  pass
 else:
  raise AssertionError('private or invalid TLS request allowed: ' + url)
for family,kind in [(socket.AF_UNIX,socket.SOCK_STREAM),(socket.AF_INET,socket.SOCK_RAW),(socket.AF_INET6,socket.SOCK_STREAM)]:
 try: socket.socket(family,kind)
 except PermissionError: pass
 else: raise AssertionError('forbidden socket allowed')
s=socket.socket(); s.settimeout(2)
try: s.connect(('93.184.216.34',22))
except OSError: pass
else: raise AssertionError('direct port bypass')
print('python-public-web-ok')`],
  ['javascript', ['/usr/local/bin/bun', '/mnt/data/main.js'], `
const response = await fetch('https://public.example/proof', {method:'PUT',body:'abc',signal:AbortSignal.timeout(5000)});
if (await response.text() !== 'public-web-proof:PUT:3') throw Error('fetch failed');
try { await fetch('http://127.0.0.1'); throw Error('private allowed'); } catch(e) { if(e.message === 'private allowed') throw e; }
console.log('javascript-public-web-ok');`],
  ['typescript', ['/usr/local/bin/bun', '/mnt/data/main.ts'], `const url: string = 'https://public.example/proof'; const response = await fetch(url, {signal:AbortSignal.timeout(5000)});
if(await response.text() !== 'public-web-proof:GET:0') throw Error('typescript failed');
console.log('typescript-public-web-ok');`],
  ['node', ['/usr/local/bin/node', '/mnt/data/main.mjs'], `const response = await fetch('https://public.example/proof', {signal:AbortSignal.timeout(5000)});
if(await response.text() !== 'public-web-proof:GET:0') throw Error('node failed');
console.log('node-public-web-ok');`],
  ['shell', ['/bin/bash', '/mnt/data/main.sh'], `set -eu
test "$(curl -fsS --max-time 5 https://public.example/proof)" = 'public-web-proof:GET:0'
! curl -fsS --max-time 2 http://169.254.169.254
echo shell-public-web-ok`],
];
try {
  const runLanguage = async (slot: number, definition: [string, string[], string], limits: Partial<PublicWebCapability> = {}, cancel = false, crash = false): Promise<void> => {
    const [name, command, source] = definition;
    const identity = { slot, uid: 200000 + slot, gid: 200000 + slot, perJobUid: true };
    const id = randomUUID(); const now = Math.floor(Date.now() / 1000);
    const grant = { v: 1 as const, typ: 'grant' as const, grant_id: id, exec_id: id, tenant_id: 'test', user_id: 'test', session_key: id,
      input_files: [], read_sessions: [], output_session_id: id, max_upload_bytes: 0, max_output_files: 0, max_requests: 1000,
      iat: now, exp: now + 120, network: { ...DEFAULT_PUBLIC_WEB, ...limits } };
    await createEgressLedger(grant);
    const originalBundle = process.env.PUBLIC_WEB_HELPER_BUNDLE;
    if (crash) {
      const source = await fs.readFile(originalBundle!, 'utf8');
      await fs.writeFile('/tmp/public-web-crashing-helper.cjs', `const originalWrite=process.stdout.write.bind(process.stdout);process.stdout.write=function(...args){if(String(args[0]).includes('"ready":true'))setTimeout(()=>process.exit(125),500);return originalWrite(...args);};\n` + source, { mode: 0o600 });
      process.env.PUBLIC_WEB_HELPER_BUNDLE = '/tmp/public-web-crashing-helper.cjs';
    }
    let lease;
    try { lease = await createPublicWebLease(identity, grant.network, sealEgressGrant(grant, secret)); }
    finally { process.env.PUBLIC_WEB_HELPER_BUNDLE = originalBundle; }
    const directory = `/tmp/public-web-job-${slot}-${id}`;
    await fs.mkdir(directory, { mode: 0o711 }); await fs.chown(directory, identity.uid, identity.gid);
    await fs.writeFile(`${directory}/${command[1].split('/').pop()}`, source, { mode: 0o444 });
    await fs.copyFile('/tmp/public-web-ca.pem', directory + '/ca.pem'); await fs.chmod(directory + '/ca.pem', 0o444);
    try {
      const wrapper = `/tmp/public-web-packages/run-${name}`;
      await fs.writeFile(wrapper, `#!/bin/bash\n${command[0]} \"$@\"\n`, { mode: 0o555 });
      const execution = execute({ command: ['/bin/bash', wrapper, ...command.slice(1)], envVars: { SSL_CERT_FILE: '/mnt/data/ca.pem', REQUESTS_CA_BUNDLE: '/mnt/data/ca.pem',
        CURL_CA_BUNDLE: '/mnt/data/ca.pem', NODE_EXTRA_CA_CERTS: '/mnt/data/ca.pem', RES_OPTIONS: 'single-request' },
        submissionDir: directory, pkgdir: '/tmp/public-web-packages', timeout: name === 'javascript' ? 10_000 : 30_000, memoryLimit: 0,
        outputMaxSize: 8192, identity, publicWebResolverFile: lease.resolverFile, publicWebNamespacePath: lease.namespacePath });
      let cancelled: Promise<void> | undefined;
      const timer = cancel ? setTimeout(() => { cancelled = lease.close(); void cancelled.catch(() => {}); }, 250) : undefined;
      const result = await execution;
      if (timer) clearTimeout(timer);
      if (cancel || crash) {
        if (crash) assert.throws(() => lease.assertHealthy());
        if (cancel) assert.ok(cancelled, 'Cancellation did not run');
        await cancelled;
        assert.notEqual(result.code, 0, 'Cancelled job completed successfully');
        assert.ok(!result.stdout.includes('unexpected-completion'));
        console.log(JSON.stringify({ cancellation: cancel, helperCrash: crash, drained: true }));
        return;
      }
      assert.equal(result.code, 0, `${name}: ${result.stdout} ${result.stderr}`);
      assert.match(result.stdout, new RegExp(name + '-public-web-ok'));
      console.log(JSON.stringify({ language: name, publicWeb: true, privateDenied: true }));
    } finally { await revokeEgressLedger(id, 'test-complete'); await lease.close(); }
  };
  await Promise.all(tests.map((definition, slot) => runLanguage(slot, definition)));
  await runLanguage(0, tests[0]); // Same identity, a newly-created namespace.
  await runLanguage(1, ['attempt-limit', ['/usr/bin/python3', '/mnt/data/main.py'], `import urllib.request
successes=0
for _ in range(5):
 try: urllib.request.urlopen('http://93.184.216.34/proof',timeout=2).read(); successes+=1
 except OSError: pass
assert successes==3, successes
print('attempt-limit-public-web-ok')`], { max_attempts: 3 });
  await runLanguage(1, ['private-attempt-limit', ['/usr/bin/python3', '/mnt/data/main.py'], `import urllib.request
for _ in range(3):
 try: urllib.request.urlopen('http://127.0.0.1',timeout=2).read()
 except OSError: pass
 else: raise AssertionError('private request succeeded')
try: urllib.request.urlopen('http://93.184.216.34/proof',timeout=2).read()
except OSError: pass
else: raise AssertionError('denied attempts bypassed the budget')
print('private-attempt-limit-public-web-ok')`], { max_attempts: 3 });
  await runLanguage(1, ['connection-limit', ['/usr/bin/python3', '/mnt/data/main.py'], `import urllib.request,socket,time
first=socket.socket();first.connect(('93.184.216.34',80));first.sendall(b'GET /idle HTTP/1.1\\r\\nHost: public.example\\r\\nConnection: close\\r\\n\\r\\n')
try: urllib.request.urlopen('http://93.184.216.34/proof',timeout=2).read()
except OSError: pass
else: raise AssertionError('simultaneous connection limit bypassed')
first.close()
for _ in range(20):
 try: assert urllib.request.urlopen('http://93.184.216.34/proof',timeout=2).read();break
 except OSError: time.sleep(.05)
else: raise AssertionError('connection capacity did not recover')
print('connection-limit-public-web-ok')`], { max_connections: 1 });
  await runLanguage(1, ['byte-limit', ['/usr/bin/python3', '/mnt/data/main.py'], `import urllib.request
try: urllib.request.urlopen('http://93.184.216.34/proof',timeout=2).read()
except OSError: pass
else: raise AssertionError('traffic limit bypassed')
print('byte-limit-public-web-ok')`], { max_bytes: 1 });
  await runLanguage(1, ['idle-limit', ['/usr/bin/python3', '/mnt/data/main.py'], `import urllib.request
try: urllib.request.urlopen('http://93.184.216.34/idle',timeout=2).read()
except OSError: pass
else: raise AssertionError('idle limit bypassed')
assert urllib.request.urlopen('http://93.184.216.34/proof',timeout=2).read()
print('idle-limit-public-web-ok')`], { idle_timeout_ms: 500 });
  await runLanguage(2, ['cancel', ['/usr/bin/python3', '/mnt/data/main.py'], `import time
print('started',flush=True)
time.sleep(30)
print('unexpected-completion')`], {}, true);
  await runLanguage(2, tests[2]);
  await runLanguage(2, ['helper-crash', ['/usr/bin/python3', '/mnt/data/main.py'], `import time
time.sleep(30)
print('unexpected-completion')`], {}, false, true);
  await runLanguage(2, tests[2]);
  assert.equal(privateHits, 0, 'Private listener received a request');
  console.log('PASS: native transparent public web under real supervisor/NsJail filters');
} catch (error) {
  console.error(error); process.exitCode = 1;
  if (process.env.PUBLIC_WEB_NATIVE_STRACE === '1') { const lines = (await fs.readFile('/tmp/public-web-trace', 'utf8')).split('\n'); console.error(lines.filter(line=>/(socket|connect|sendto|sendmsg|sendmmsg|bind\(|clone|EPERM|SIGSYS)/.test(line)).slice(-100).join('\n')); }
} finally {
  web.close(); for (const server of [gateway, relay, fixture, tlsFixture, privateFixture]) { server.closeAllConnections(); server.close(); }
  process.exit(process.exitCode ?? 0);
}

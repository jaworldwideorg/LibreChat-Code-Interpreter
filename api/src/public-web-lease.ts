import * as fs from 'node:fs/promises';
import path from 'node:path';
import { spawnPipeProcess } from './pipe-process';
import { config } from './config';
import { publicWebNamespaceNative } from './public-web-namespace';
import { validatePublicWeb, type PublicWebCapability } from '../../shared/public-web';
import type { SandboxJobIdentity } from './workspace-isolation';

export class PublicWebCleanupError extends Error {}

/** Root /proc sees the outside UID even when the job has its own user/PID
 * namespaces. Drain every descendant before detaching the network namespace or
 * returning this UID to the pool; cgroup support is absent on Lambda today. */
export async function drainPublicWebUid(uid: number): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt++) {
    let found = false;
    for (const entry of await fs.readdir('/proc')) {
      if (!/^\d+$/.test(entry)) continue;
      try {
        const status = await fs.readFile(`/proc/${entry}/status`, 'utf8');
        const values = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m.exec(status);
        if (!values || !values.slice(1).some(value => Number(value) === uid)) continue;
        // Zombie processes cannot hold sockets; their parent will reap them.
        if (/^State:\s+Z/m.test(status)) continue;
        found = true; process.kill(Number(entry), 'SIGKILL');
      } catch (error) {
        if (!['ENOENT', 'ESRCH'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
      }
    }
    if (!found) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('Public web job identity did not drain');
}

export interface PublicWebLease {
  resolverFile: string;
  namespacePath: string;
  assertHealthy: () => void;
  close: () => Promise<void>;
}

export async function createPublicWebLease(identity: SandboxJobIdentity, network: PublicWebCapability, grant: string): Promise<PublicWebLease> {
  validatePublicWeb(network);
  if (config.network_mode !== 'public-web' || !identity.perJobUid || identity.uid < config.job_uid_base || !grant) {
    throw new Error('Public web runner admission denied');
  }
  const slot = identity.uid - config.job_uid_base;
  if (slot < 0 || slot >= config.job_uid_count) throw new Error('Public web UID slot out of range');
  const address = '127.0.0.1';
  const directory = `/tmp/codeapi-network-${identity.uid}`;
  const native = publicWebNamespaceNative();
  try { await fs.mkdir(directory, { mode: 0o711 }); }
  catch (error) { throw new PublicWebCleanupError('Public web identity path unavailable', { cause: error }); }
  const namespacePath = path.join(directory, 'netns');
  const resolverFile = path.join(directory, 'resolv.conf');
  let created = false;
  const removeNamespace = async (): Promise<void> => {
    if (created) { native.deleteNetworkNamespace(namespacePath); created = false; }
    await fs.rm(directory, { recursive: true });
  };
  let helper: ReturnType<typeof spawnPipeProcess>;
  try {
    native.createNetworkNamespace(namespacePath);
    created = true;
    await fs.writeFile(resolverFile, `nameserver ${address}\noptions single-request timeout:2 attempts:2\n`, { mode: 0o444, flag: 'wx' });
    helper = spawnPipeProcess(process.env.PUBLIC_WEB_PIPE_BRIDGE ?? '/usr/local/bin/tool-call-pipe-bridge', [
      '--broker', process.env.PUBLIC_WEB_NODE ?? '/usr/local/bin/node',
      process.env.PUBLIC_WEB_HELPER_BUNDLE ?? path.resolve(__dirname, '..', '.build', 'public-web-helper.cjs'),
    ]);
  } catch (error) {
    try { await removeNamespace(); }
    catch (cleanup) { throw new PublicWebCleanupError('Public web setup cleanup failed', { cause: cleanup }); }
    throw error;
  }
  let failed = false;
  let closing = false;
  // Drain stderr without ever returning privileged configuration to the job.
  helper.stderr.resume();
  helper.once('error', () => { failed = true; });
  helper.once('exit', () => {
    if (!closing) { failed = true; void drainPublicWebUid(identity.uid).catch(() => {}); }
  });
  const close = async (): Promise<void> => {
    if (closing) return;
    closing = true;
    // Closing the only proxy/resolver sockets denies new traffic. The
    // namespace has no interface or route to the host, even during failure.
    // Any failure propagates to Job.cleanup, which retains the UID slot.
    const errors: unknown[] = [];
    let exited: Promise<void> | undefined;
    if (helper.exitCode === null && helper.signalCode === null) {
      exited = new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => { helper.kill('SIGKILL'); reject(new Error('Public web helper did not drain')); }, 5000);
        helper.once('exit', () => { clearTimeout(timeout); resolve(); });
      });
      void exited.catch(() => {});
      helper.kill('SIGTERM');
    }
    try { await drainPublicWebUid(identity.uid); } catch (error) { errors.push(error); }
    try { await exited; } catch (error) { errors.push(error); }
    if (errors.length) throw new PublicWebCleanupError('Public web cleanup failed; identity retained');
    try { await removeNamespace(); }
    catch (error) { throw new PublicWebCleanupError('Public web namespace cleanup failed; identity retained', { cause: error }); }
  };
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('Public web helper admission timed out')), 10_000);
      let text = '';
      const fail = (): void => { clearTimeout(timer); reject(new Error('Public web helper unavailable')); };
      helper.once('error', fail); helper.once('exit', fail);
      helper.stdout.on('data', chunk => {
        text += chunk.toString();
        if (text.length > 128) { fail(); return; }
        if (text.includes('\n')) {
          clearTimeout(timer);
          try { if (JSON.parse(text).ready !== true) throw new Error('Invalid helper'); resolve(); } catch { fail(); }
        }
      });
      helper.stdin.end(JSON.stringify({ namespacePath, gateway: config.egress_gateway_url, grant, network }));
    });
    if (failed) throw new Error('Public web helper failed');
    return { resolverFile, namespacePath, assertHealthy: () => { if (failed || closing) throw new Error('Public web helper unavailable'); }, close };
  } catch (error) { await close(); throw error; }
}

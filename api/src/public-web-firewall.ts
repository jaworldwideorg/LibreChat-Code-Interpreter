import { spawnPipeProcess } from './pipe-process';
import { NON_PUBLIC_IPV4 } from '../../shared/public-web';

export type FirewallCommand = (binary: string, args: string[]) => Promise<unknown>;
const run: FirewallCommand = (binary, args) => new Promise<void>((resolve, reject) => {
  const child = spawnPipeProcess(binary, ['-w', '5', ...args]);
  const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Firewall command timed out')); }, 6000);
  let errorText = '';
  child.stdout.resume(); child.stderr.on('data', bytes => { if (errorText.length < 4096) errorText += bytes.toString(); });
  child.once('error', error => { clearTimeout(timer); reject(error); });
  child.once('close', code => { clearTimeout(timer); if (code === 0) resolve(); else reject(new Error(`Firewall command failed: ${errorText.slice(0, 4096)}`)); });
  child.stdin.end();
});
const V4 = '/usr/sbin/iptables-legacy';
const V6 = '/usr/sbin/ip6tables-legacy';
const DENIED_MARK = '0x434f4401';

async function ensure(binary: string, args: string[], check: FirewallCommand): Promise<void> {
  try { await check(binary, args); } catch {
    await check(binary, args.map(arg => arg === '-C' ? '-I' : arg));
  }
}

export async function initializePublicWebFirewall(uidBase: number, uidCount: number, command = run): Promise<void> {
  if (!Number.isSafeInteger(uidBase) || uidBase < 65536 || !Number.isSafeInteger(uidCount) || uidCount < 1) {
    throw new Error('Invalid public web UID range');
  }
  // These reject rules are installed even in off mode. A failed helper or
  // missing per-UID rule cannot expose the VM network after namespace escape.
  const range = `${uidBase}-${uidBase + uidCount - 1}`;
  for (const binary of [V4, V6]) {
    await ensure(binary, ['-t', 'filter', '-C', 'OUTPUT', '-m', 'owner', '--uid-owner', range, '-j', 'REJECT'], command);
  }
}

export async function installPublicWebFirewall(uid: number, address: string, port: number, command = run): Promise<() => Promise<void>> {
  if (!Number.isSafeInteger(uid) || uid < 65536 || !/^127\.64\.\d{1,3}\.\d{1,3}$/.test(address)
    || !Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Invalid public web listener');
  const name = `CW${uid}`;
  const installed: Array<[string, string[]]> = [];
  const add = async (table: string, args: string[], undo: string[]): Promise<void> => {
    await command(V4, ['-t', table, ...args]); installed.unshift([V4, ['-t', table, ...undo]]);
  };
  const close = async (): Promise<void> => {
    // Disable admission first. Keep a failed rule tracked for retry and
    // never report successful cleanup while any allowance remains.
    const failures: unknown[] = [];
    for (const [binary, args] of installed) {
      try { await command(binary, args); } catch (error) { failures.push(error); }
    }
    if (failures.length) throw new Error('Public web firewall cleanup failed');
    installed.length = 0;
  };
  try {
    for (const table of ['filter', 'nat', 'mangle']) {
      await add(table, ['-N', name], ['-X', name]);
      // Flush before deleting the new chain, after removing its jump.
      installed.unshift([V4, ['-t', table, '-F', name]]);
    }
    const owner = ['-m', 'owner', '--uid-owner', String(uid)];
    // Validate the original destination before NAT changes it to loopback.
    await command(V4, ['-t', 'mangle', '-A', name, '-d', address, '-p', 'udp', '--dport', '53', '-j', 'RETURN']);
    await command(V4, ['-t', 'mangle', '-A', name, '-d', address, '-p', 'tcp', '--dport', '53', '-j', 'RETURN']);
    for (const cidr of NON_PUBLIC_IPV4) await command(V4, ['-t', 'mangle', '-A', name, '-d', cidr, '-j', 'MARK', '--set-mark', DENIED_MARK]);
    await command(V4, ['-t', 'mangle', '-A', name, '-p', 'tcp', '-m', 'multiport', '--dports', '80,443', '-j', 'RETURN']);
    await command(V4, ['-t', 'mangle', '-A', name, '-j', 'MARK', '--set-mark', DENIED_MARK]);
    await command(V4, ['-t', 'nat', '-A', name, '-m', 'mark', '--mark', DENIED_MARK, '-j', 'RETURN']);
    await command(V4, ['-t', 'nat', '-A', name, '-p', 'tcp', '-m', 'multiport', '--dports', '80,443', '-j', 'DNAT', '--to-destination', `${address}:${port}`]);
    // Reject denied originals before any allowance. This produces a useful
    // connection error instead of silently blackholing a client's request.
    await command(V4, ['-t', 'filter', '-A', name, '-m', 'mark', '--mark', DENIED_MARK, '-j', 'REJECT']);
    for (const [protocol, destPort] of [['tcp', String(port)], ['tcp', '53'], ['udp', '53']]) {
      await command(V4, ['-t', 'filter', '-A', name, '-d', address, '-p', protocol, '--dport', destPort, '-j', 'ACCEPT']);
    }
    await command(V4, ['-t', 'filter', '-A', name, '-j', 'REJECT']);
    // Filter allowance goes in last; the permanent range reject protects
    // every intermediate state during setup.
    for (const table of ['mangle', 'nat', 'filter']) {
      await add(table, ['-I', 'OUTPUT', '1', ...owner, '-j', name], ['-D', 'OUTPUT', ...owner, '-j', name]);
    }
    return close;
  } catch (error) { await close(); throw error; }
}

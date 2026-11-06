import { isIP } from 'node:net';

export interface PublicWebCapability {
  mode: 'public-web';
  policy_version: 1;
  max_connections: number;
  max_attempts: number;
  max_bytes: number;
  idle_timeout_ms: number;
}

export const DEFAULT_PUBLIC_WEB: Readonly<PublicWebCapability> = Object.freeze({
  mode: 'public-web', policy_version: 1, max_connections: 16,
  max_attempts: 128, max_bytes: 64 * 1024 * 1024, idle_timeout_ms: 30_000,
});

export function validatePublicWeb(value: unknown): asserts value is PublicWebCapability | undefined {
  if (value === undefined) return;
  const v = value as PublicWebCapability;
  if (!v || typeof v !== 'object' || Array.isArray(v) || v.mode !== 'public-web' || v.policy_version !== 1
    || Object.keys(v).some(key => !Object.prototype.hasOwnProperty.call(DEFAULT_PUBLIC_WEB, key))) throw new Error('Invalid public-web capability');
  for (const key of ['max_connections', 'max_attempts', 'max_bytes', 'idle_timeout_ms'] as const) {
    if (!Number.isSafeInteger(v[key]) || v[key] < 1 || v[key] > DEFAULT_PUBLIC_WEB[key]) {
      throw new Error('Invalid public-web limit');
    }
  }
}

export function publicWebMode(raw: string | undefined): 'off' | 'public-web' {
  if (raw === undefined || raw === 'off') return 'off';
  if (raw === 'public-web') return raw;
  throw new Error('Network mode must be off or public-web');
}

// Conservative IPv4 policy: special-purpose blocks are not web destinations,
// including globally reachable exceptions within otherwise reserved blocks.
export const NON_PUBLIC_IPV4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
  '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
  '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
] as const;

function ipv4Number(ip: string): number {
  return ip.split('.').reduce((value, octet) => (value * 256) + Number(octet), 0);
}

export function isPublicIPv4(ip: unknown): ip is string {
  if (typeof ip !== 'string' || isIP(ip) !== 4) return false;
  const value = ipv4Number(ip);
  return !NON_PUBLIC_IPV4.some(cidr => {
    const [base, bits] = cidr.split('/');
    const size = 2 ** (32 - Number(bits));
    return Math.floor(value / size) === Math.floor(ipv4Number(base) / size);
  });
}

export function validateWebDestination(value: unknown): { ip: string; port: 80 | 443 } {
  const v = value as { ip?: unknown; port?: unknown };
  if (!v || !isPublicIPv4(v.ip) || (v.port !== 80 && v.port !== 443)
    || Object.keys(v).some(k => k !== 'ip' && k !== 'port')) throw new Error('Public web destination denied');
  return { ip: v.ip, port: v.port };
}

export function validateDnsName(value: unknown): string {
  if (typeof value !== 'string' || value.length > 253 || !value.length
    || value.split('.').some(label => !/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label))) {
    throw new Error('Invalid DNS name');
  }
  return value.toLowerCase();
}

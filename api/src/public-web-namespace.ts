import * as fs from 'node:fs/promises';
import path from 'node:path';

export interface PublicWebNamespaceNative {
  createNetworkNamespace(path: string): void;
  deleteNetworkNamespace(path: string): void;
}

export function publicWebNamespaceNative(): PublicWebNamespaceNative {
  const native = require(process.env.SANDBOX_PIPE_ADDON || path.resolve(__dirname, '..', '.build', 'anonymous-pipes.node'));
  if (typeof native.createNetworkNamespace !== 'function' || typeof native.deleteNetworkNamespace !== 'function'
    || typeof native.namespaceListeners !== 'function' || typeof native.namespaceProbe !== 'function') {
    throw new Error('Public web namespace transport unavailable');
  }
  return native;
}

/** Probe the kernel before admitting jobs. The namespace has only loopback;
 * its local route cannot carry packets into the host or the physical network. */
export async function initializePublicWebNamespace(native = publicWebNamespaceNative()): Promise<void> {
  const directory = `/tmp/codeapi-network-${Date.now()}`;
  await fs.mkdir(directory, { mode: 0o711 });
  const namespacePath = path.join(directory, 'netns');
  let created = false;
  try {
    native.createNetworkNamespace(namespacePath);
    created = true;
    native.deleteNetworkNamespace(namespacePath);
    created = false;
  } finally {
    // A failed detach remains available for diagnosis and must fail startup.
    if (!created) await fs.rm(directory, { recursive: true });
  }
}

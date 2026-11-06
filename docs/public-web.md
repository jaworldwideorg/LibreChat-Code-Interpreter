# Transparent public web access

`CODEAPI_NETWORK_MODE=public-web` on the API/worker authorizes a bounded network
capability in signed execution claims. `SANDBOX_NETWORK_MODE=public-web` enables
the matching runner implementation. Both default to `off`. Existing execution
requests and language clients need no additional parameters or proxy settings.

Each network-enabled job keeps its own root-owned network namespace, containing
only loopback. A local IPv4 route delivers connections to trusted proxy sockets
on ports 80/443. Those sockets belong to the job namespace; their root-owned
helper stays in the host namespace to open authenticated gateway tunnels. There
is no interface connecting the job to the host or physical network. DNS listens
only on the job's loopback resolver. IPv6 socket creation and inbound listeners
remain denied. Filesystem, user, process and syscall isolation still apply.

The helper authenticates against the private gateway before admission and
probes routing and original-destination recovery via `getsockname`. The gateway uses the same durable
execution ledger as file/tool grants, with atomic network accounting and
revocation. A separate relay has no application credentials or task role and
revalidates every destination before making a pinned IPv4 connection.

TLS is transported unchanged. Clients retain their normal certificate checks.
Private/special addresses and redirects into those addresses are rejected;
DNS answers containing any non-public address are rejected as a whole.

Limits per execution: 16 concurrent connections, 128 attempts, 128 DNS queries,
64 MiB combined upload/download, and 30 seconds idle. Execution expiry and
cancellation remain authoritative. HTTP methods are unrestricted. The boundary
permits TCP transports on web ports; it does not inspect encrypted protocols.

## Runner prerequisites

The image needs Linux network namespaces, namespace bind mounts and the IPv4
local route type. Startup probes these prerequisites before admitting jobs.
Per-job setup checks the namespace owner/type, proxy sockets and actual original
destination recovery. Public mode requires signed admission, per-job UIDs and a
configured gateway. Missing prerequisites reject admission. Helpers start on
authorized executions after snapshot restore. Cleanup closes the helpers,
drains descendants and detaches the namespace before returning the UID to the
pool. Failed setup cleanup or teardown quarantines the UID.

The AWS managed kernel rejected both legacy owner matches and native nftables;
its TUN device is also unavailable. The namespace/local-route primitive passed
in the real Lambda MicroVM under the unchanged supervisor filter. The obsolete
public-web firewall backend was removed. No netfilter modules, NAT, userspace
TCP stack or syscall-policy exceptions are required by public web access.

Packaged curl uses Debian security-backported sources with synchronous libc
DNS, avoiding socketpair-based resolver IPC. jq 1.8.2 is checksum-pinned so
Bash tool-input canonicalization agrees with the server's numeric contract.

## Verification and release

`api/src/public-web.test.ts` covers DNS framing, syscall policy and namespace
prerequisite failures. Run the real Redis suite separately:

```sh
cd service
PUBLIC_WEB_TEST_REDIS_PORT=6388 bun test tests/public-web.test.ts
```

`.github/workflows/public-web.yml` builds the native test image on amd64 and
arm64 and runs `tests/public_web_native.ts` under the inherited supervisor and
actual NsJail filters. It exercises unchanged Python, Bun JS/TS, Node and curl
clients, certificate rejection, redirects, private destinations and a controlled
private listener. The test uses the same shell launch shape as packaged runtimes.

Production acceptance additionally requires the isolated AWS candidate lane,
real Lambda MicroVM executions and artifact byte checks, the original JA icon
retrieval, ownership/cancellation/tool canaries and LibreChat browser downloads.
Keep runner 2.0 until these gates pass. Release matched immutable controls and
runner images; drain consumers during replacement and rollback. Record safe
image identities and test receipts under protected `private/` storage.

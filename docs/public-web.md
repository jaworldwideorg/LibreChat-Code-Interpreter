# Transparent public web access

`CODEAPI_NETWORK_MODE=public-web` on the API/worker authorizes a bounded network
capability in signed execution claims. `SANDBOX_NETWORK_MODE=public-web` enables
the matching runner implementation. Both default to `off`. Existing execution
requests and language clients need no additional parameters or proxy settings.

Network-enabled jobs share the VM network namespace. Root-owned rules identify
each job by its outside UID, reject all traffic without an active policy, and
redirect public IPv4 TCP ports 80/443 to a private per-job proxy. DNS is limited
to the job's local resolver. IPv6 and other ports remain denied. Filesystem,
user, process, capability and the remaining syscall restrictions still apply.

The helper authenticates against the private gateway before admission and
probes native original-destination recovery. The gateway uses the same durable
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

The image needs IPv4/IPv6 legacy netfilter, owner/mark matches, IPv4 NAT and
conntrack original-destination support. Public mode requires signed admission,
per-job UIDs and a configured gateway. Missing prerequisites reject admission.
Helpers start on authorized executions after snapshot restore. Cleanup removes
allowances, drains descendants and closes helpers before returning the UID to
the pool. Failed cleanup retains the UID.

Packaged curl uses Debian security-backported sources with synchronous libc
DNS, avoiding socketpair-based resolver IPC. jq 1.8.2 is checksum-pinned so
Bash tool-input canonicalization agrees with the server's numeric contract.

## Verification and release

`api/src/public-web.test.ts` covers DNS framing, syscall policy and firewall
admission failure. Run the real Redis suite separately:

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

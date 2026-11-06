import net from 'node:net';
import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import {
    tcpWebSocketStream,
    bridgeTcpStreams,
    TCP_STREAM_PROTOCOL,
    TCP_STREAM_OPENED,
} from '../../shared/websocket-tcp';
import { closeSync } from 'node:fs';
import WebSocket from 'ws';
import {
    isPublicIPv4,
    validateDnsName,
    validateWebDestination,
    type PublicWebCapability,
} from '../../shared/public-web';

export function parseDnsQuestion(packet: Buffer): {
    name: string;
    type: number;
    question: Buffer;
    id: number;
} {
    if (
        packet.length < 17 ||
        packet.length > 512 ||
        packet.readUInt16BE(4) !== 1 ||
        (packet[2] & 0xf8) !== 0
    )
        throw new Error('Invalid DNS question');
    const labels: string[] = [];
    let cursor = 12;
    for (;;) {
        if (cursor >= packet.length) throw new Error('Truncated DNS question');
        const size = packet[cursor++];
        if (!size) break;
        if (size > 63 || cursor + size > packet.length)
            throw new Error('Invalid DNS label');
        labels.push(packet.subarray(cursor, cursor + size).toString('ascii'));
        cursor += size;
    }
    if (
        cursor + 4 > packet.length ||
        packet.readUInt16BE(cursor + 2) !== 1 ||
        packet.readUInt16BE(6) !== 0 ||
        packet.readUInt16BE(8) !== 0
    )
        throw new Error('Invalid DNS class');
    const end = cursor + 4;
    const additional = packet.readUInt16BE(10);
    if (additional > 1 || (additional === 0 && end !== packet.length))
        throw new Error('Invalid DNS records');
    if (additional === 1) {
        // c-ares/Bun send a bounded EDNS OPT record. Consume it locally; only
        // the validated hostname is forwarded, never option data or extensions.
        if (
            end + 11 > packet.length ||
            packet[end] !== 0 ||
            packet.readUInt16BE(end + 1) !== 41 ||
            packet[end + 6] !== 0 ||
            end + 11 + packet.readUInt16BE(end + 9) !== packet.length
        )
            throw new Error('Invalid EDNS');
    }
    return {
        name: validateDnsName(labels.join('.')),
        type: packet.readUInt16BE(cursor),
        question: packet.subarray(12, end),
        id: packet.readUInt16BE(0),
    };
}

export function dnsReply(
    packet: Buffer,
    addresses: Array<{ address: string; ttl: number }>,
    code = 0,
): Buffer {
    const query = parseDnsQuestion(packet);
    const head = Buffer.alloc(12);
    head.writeUInt16BE(query.id, 0);
    head.writeUInt16BE(0x8180 | code, 2);
    head.writeUInt16BE(1, 4);
    head.writeUInt16BE(addresses.length, 6);
    const answers = addresses.map(answer => {
        if (!isPublicIPv4(answer.address))
            throw new Error('Private DNS answer');
        const bytes = Buffer.alloc(16);
        bytes.writeUInt16BE(0xc00c, 0);
        bytes.writeUInt16BE(1, 2);
        bytes.writeUInt16BE(1, 4);
        bytes.writeUInt32BE(Math.max(1, Math.min(60, answer.ttl)), 6);
        bytes.writeUInt16BE(4, 10);
        answer.address.split('.').forEach((octet, index) => {
            bytes[index + 12] = Number(octet);
        });
        return bytes;
    });
    return Buffer.concat([head, query.question, ...answers]);
}

export async function startPublicWebHelper(options: {
    namespacePath: string;
    gateway: string;
    grant: string;
    network: PublicWebCapability;
    originalDestination: (fd: number) => { ip: string; port: number };
    sendDatagram: (
        fd: number,
        address: string,
        port: number,
        bytes: Buffer,
    ) => void;
    namespaceListeners: (path: string) => [number, number, number, number];
    namespaceProbe: (path: string) => number;
}): Promise<{ close: () => Promise<void> }> {
    const gateway = new URL(options.gateway);
    if (
        !['http:', 'https:'].includes(gateway.protocol) ||
        gateway.username ||
        gateway.password ||
        gateway.pathname !== '/'
    )
        throw new Error('Invalid gateway');
    // Admission proves authentication and relay availability without issuing
    // a public DNS query or charging the user's connection/traffic budget.
    await new Promise<void>((resolve, reject) => {
        const transport = gateway.protocol === 'https:' ? https : http;
        const request = transport.get(
            new URL('/network/ready', gateway),
            {
                headers: { 'X-CodeAPI-Egress-Grant': options.grant },
                agent: false,
            },
            response => {
                let body = '';
                response.on('data', bytes => {
                    body += bytes;
                    if (body.length > 512)
                        request.destroy(
                            new Error('Invalid admission response'),
                        );
                });
                response.on('end', () => {
                    try {
                        const value = JSON.parse(body);
                        if (
                            response.statusCode !== 200 ||
                            value.mode !== 'public-web' ||
                            value.policy_version !== 1 ||
                            value.stream_protocol !== TCP_STREAM_PROTOCOL
                        )
                            throw new Error('Public web admission denied');
                        resolve();
                    } catch (error) {
                        reject(error);
                    }
                });
                response.on('error', reject);
                response.on('aborted', () =>
                    reject(new Error('Public web admission aborted')),
                );
            },
        );
        request.setTimeout(5000, () =>
            request.destroy(new Error('Public web admission timed out')),
        );
        request.once('error', reject);
    });
    const sockets = new Set<net.Socket>();
    const peers = new Set<WebSocket>();
    let closing = false;
    let probing = true;
    let recovered = false;
    let activeDns = 0;
    let dnsAttempts = 0;
    let connectionAttempts = 0;
    let activeConnections = 0;
    const unclaimedDescriptors = new Set<number>();
    async function answer(packet: Buffer): Promise<Buffer> {
        const query = parseDnsQuestion(packet);
        // Return NODATA for AAAA; normal dual-stack clients select the A result.
        if (query.type !== 1) return dnsReply(packet, []);
        if (
            closing ||
            activeDns >= 16 ||
            ++dnsAttempts > options.network.max_attempts
        )
            return dnsReply(packet, [], 2);
        activeDns++;
        try {
            const data = JSON.stringify({ name: query.name, type: 'A' });
            const transport = gateway.protocol === 'https:' ? https : http;
            const text = await new Promise<string>((resolve, reject) => {
                const request = transport.request(
                    new URL('/network/dns', gateway),
                    {
                        method: 'POST',
                        headers: {
                            'content-type': 'application/json',
                            'content-length': Buffer.byteLength(data),
                            'X-CodeAPI-Egress-Grant': options.grant,
                        },
                        agent: false,
                    },
                    response => {
                        let value = '';
                        response.on('data', bytes => {
                            value += bytes;
                            if (value.length > 4096)
                                request.destroy(
                                    new Error('DNS answer too large'),
                                );
                        });
                        response.on('end', () =>
                            response.statusCode === 200
                                ? resolve(value)
                                : reject(new Error('DNS denied')),
                        );
                        response.on('error', reject);
                        response.on('aborted', () =>
                            reject(new Error('DNS aborted')),
                        );
                    },
                );
                request.setTimeout(5000, () =>
                    request.destroy(new Error('DNS timeout')),
                );
                request.on('error', reject);
                request.end(data);
            });
            const result = JSON.parse(text);
            if (
                !Array.isArray(result.answers) ||
                result.answers.length > 32 ||
                result.answers.some(
                    (a: { address: string; ttl: number }) =>
                        !isPublicIPv4(a.address) || !Number.isInteger(a.ttl),
                )
            )
                throw new Error('Invalid DNS response');
            return dnsReply(packet, result.answers);
        } catch {
            return dnsReply(packet, [], 2);
        } finally {
            activeDns--;
        }
    }
    const dnsUdp = dgram.createSocket('udp4');
    dnsUdp.on('message', (packet, remote) => {
        void answer(packet)
            .then(reply => {
                if (closing) return;
                if (reply.length > 512) {
                    reply = dnsReply(packet, []);
                    reply[2] |= 2; // TC: retry over TCP.
                }
                const fd = (
                    dnsUdp as dgram.Socket & { _handle?: { fd: number } }
                )._handle?.fd;
                if (fd === undefined)
                    throw new Error('DNS descriptor unavailable');
                options.sendDatagram(fd, remote.address, remote.port, reply);
            })
            .catch(() => {});
    });
    const dnsTcp = net.createServer(socket => {
        sockets.add(socket);
        socket.setTimeout(5000, () => socket.destroy());
        socket.once('close', () => sockets.delete(socket));
        socket.on('error', () => socket.destroy());
        let bytes = Buffer.alloc(0);
        socket.on('data', chunk => {
            bytes = Buffer.concat([bytes, Buffer.from(chunk)]);
            if (
                bytes.length > 514 ||
                (bytes.length >= 2 && bytes.readUInt16BE(0) > 512)
            ) {
                socket.destroy();
                return;
            }
            if (
                bytes.length >= 2 &&
                bytes.length === bytes.readUInt16BE(0) + 2
            ) {
                socket.pause();
                void answer(bytes.subarray(2)).then(
                    reply => {
                        const length = Buffer.alloc(2);
                        length.writeUInt16BE(reply.length);
                        socket.end(Buffer.concat([length, reply]));
                    },
                    () => socket.destroy(),
                );
            }
        });
    });
    const proxyConnection = (socket: net.Socket): void => {
        sockets.add(socket);
        socket.once('close', () => sockets.delete(socket));
        socket.on('error', () => socket.destroy());
        try {
            const fd = (socket as net.Socket & { _handle?: { fd: number } })
                ._handle?.fd;
            if (fd === undefined) throw new Error('Missing native socket');
            const original = options.originalDestination(fd);
            if (probing) {
                recovered =
                    original.ip === '93.184.216.34' && original.port === 443;
                socket.end();
                return;
            }
            // Count private/rejected destinations and pending gateway handshakes
            // too. Stop listening when the local attempt budget is exhausted, so
            // repeated denied connections cannot keep consuming helper work.
            connectionAttempts++;
            if (connectionAttempts >= options.network.max_attempts) {
                for (const server of proxies)
                    if (server.listening) server.close();
            }
            if (
                connectionAttempts > options.network.max_attempts ||
                activeConnections >= options.network.max_connections
            ) {
                socket.destroy();
                return;
            }
            activeConnections++;
            socket.once('close', () => {
                activeConnections--;
            });
            const destination = validateWebDestination(original);
            const url = new URL('/network/tunnel', gateway);
            url.protocol = gateway.protocol === 'https:' ? 'wss:' : 'ws:';
            const peer = new WebSocket(url, {
                headers: { 'X-CodeAPI-Egress-Grant': options.grant },
                perMessageDeflate: false,
                maxPayload: 64 * 1024,
                handshakeTimeout: 5000,
            });
            peers.add(peer);
            let streaming = false;
            const timer = setTimeout(() => {
                peer.terminate();
                socket.destroy();
            }, 5000);
            socket.setTimeout(options.network.idle_timeout_ms, () =>
                socket.destroy(),
            );
            const stop = (): void => {
                clearTimeout(timer);
                peer.terminate();
                socket.destroy();
                peers.delete(peer);
            };
            peer.once('close', () => {
                if (!streaming) stop();
            });
            peer.once('error', stop);
            socket.once('close', stop);
            peer.once('open', () => peer.send(JSON.stringify(destination)));
            peer.once('message', (bytes, binary) => {
                if (binary || bytes.toString() !== TCP_STREAM_OPENED) {
                    stop();
                    return;
                }
                clearTimeout(timer);
                streaming = true;
                const stream = tcpWebSocketStream(peer);
                bridgeTcpStreams(socket, stream, stop);
            });
        } catch {
            socket.destroy();
        }
    };
    const proxies = [
        net.createServer(
            { pauseOnConnect: true, allowHalfOpen: true },
            proxyConnection,
        ),
        net.createServer(
            { pauseOnConnect: true, allowHalfOpen: true },
            proxyConnection,
        ),
    ];
    const listen = (server: net.Server, fd: number): Promise<void> =>
        new Promise((resolve, reject) => {
            server.once('error', reject);
            server.listen({ fd }, () => {
                unclaimedDescriptors.delete(fd);
                server.removeListener('error', reject);
                resolve();
            });
        });
    const close = async (): Promise<void> => {
        if (closing) return;
        closing = true;
        for (const peer of peers) peer.terminate();
        for (const socket of sockets) socket.destroy();
        try {
            dnsUdp.close();
        } catch {}
        for (const fd of unclaimedDescriptors) {
            try {
                closeSync(fd);
            } catch (error) {
                if ((error as NodeJS.ErrnoException).code !== 'EBADF')
                    throw error;
            }
        }
        unclaimedDescriptors.clear();
        await Promise.all(
            [dnsTcp, ...proxies].map(
                server =>
                    new Promise<void>(resolve => server.close(() => resolve())),
            ),
        );
    };
    try {
        // The descriptors belong to the job namespace, while this trusted
        // process remains in the host namespace for authenticated gateway I/O.
        const fds = options.namespaceListeners(options.namespacePath);
        for (const fd of fds) unclaimedDescriptors.add(fd);
        await new Promise<void>((resolve, reject) => {
            dnsUdp.once('error', reject);
            dnsUdp.bind({ fd: fds[2] }, () => {
                unclaimedDescriptors.delete(fds[2]);
                dnsUdp.removeListener('error', reject);
                resolve();
            });
        });
        await listen(dnsTcp, fds[3]);
        await listen(proxies[0], fds[0]);
        await listen(proxies[1], fds[1]);
        await new Promise<void>((resolve, reject) => {
            const client = new net.Socket({
                fd: options.namespaceProbe(options.namespacePath),
                readable: true,
                writable: true,
            });
            client.setTimeout(1000, () =>
                client.destroy(
                    new Error('Original destination probe timed out'),
                ),
            );
            client.once('error', reject);
            client.resume();
            client.once('close', () =>
                recovered
                    ? resolve()
                    : reject(
                          new Error(
                              'Original destination recovery unavailable',
                          ),
                      ),
            );
        });
        probing = false;
        dnsUdp.on('error', () => {
            void close();
            process.exitCode = 125;
        });
        return { close };
    } catch (error) {
        await close();
        throw error;
    }
}

if (require.main === module) {
    // One bounded private stdin message. Credentials never enter argv, the
    // user environment, mounted files, or the snapshotted TLS process state.
    void (async () => {
        let input = '';
        for await (const chunk of process.stdin) {
            input += chunk;
            if (input.length > 128 * 1024)
                throw new Error('Helper configuration too large');
        }
        const native = require(
            process.env.SANDBOX_PIPE_ADDON ||
                '/usr/local/lib/anonymous-pipes.node',
        );
        if (
            typeof native.originalDestination !== 'function' ||
            typeof native.sendDatagram !== 'function' ||
            typeof native.namespaceListeners !== 'function' ||
            typeof native.namespaceProbe !== 'function'
        )
            throw new Error('Public web native transport unavailable');
        const helper = await startPublicWebHelper({
            ...JSON.parse(input),
            originalDestination: native.originalDestination,
            sendDatagram: native.sendDatagram,
            namespaceListeners: native.namespaceListeners,
            namespaceProbe: native.namespaceProbe,
        });
        process.stdout.write(JSON.stringify({ ready: true }) + '\n');
        const stop = (): void => {
            void helper.close().then(() => process.exit(0));
        };
        process.once('SIGTERM', stop);
        process.once('SIGINT', stop);
    })().catch(() => {
        process.stderr.write('Public web helper failed\n');
        process.exit(125);
    });
}

import { test, expect } from 'bun:test';
import net from 'node:net';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import WebSocket from 'ws';
import { createPublicEgressRelay } from './public-egress-relay';
import {
    tcpWebSocketStream,
    TCP_STREAM_OPENED,
} from '../../shared/websocket-tcp';

test('large response drains after client half-close and immediate upstream EOF', async () => {
    const upload = Buffer.alloc(2 * 1024 * 1024, 31);
    const response = Buffer.alloc(8 * 1024 * 1024, 42);
    let uploadedHash = '';
    const sockets = new Set<net.Socket>();
    const fixture = net.createServer({ allowHalfOpen: true }, socket => {
        sockets.add(socket);
        socket.once('close', () => sockets.delete(socket));
        const hash = createHash('sha256');
        socket.on('data', bytes => hash.update(bytes));
        socket.once('end', () => {
            uploadedHash = hash.digest('hex');
            socket.end(response);
        });
    });
    fixture.listen(0, '127.0.0.1');
    await once(fixture, 'listening');
    const relay = createPublicEgressRelay({
        connect: () =>
            net.connect({
                host: '127.0.0.1',
                port: (fixture.address() as net.AddressInfo).port,
                allowHalfOpen: true,
            }),
    });
    relay.listen(0, '127.0.0.1');
    await once(relay, 'listening');
    const peer = new WebSocket(
        `ws://127.0.0.1:${(relay.address() as net.AddressInfo).port}/tunnel`,
    );
    try {
        await once(peer, 'open');
        const opening = once(peer, 'message');
        peer.send(JSON.stringify({ ip: '93.184.216.34', port: 80 }));
        expect((await opening)[0].toString()).toBe(TCP_STREAM_OPENED);
        const stream = tcpWebSocketStream(peer);
        const chunks: Buffer[] = [];
        const reading = (async () => {
            for await (const bytes of stream) chunks.push(Buffer.from(bytes));
        })();
        stream.end(upload);
        await reading;
        expect(uploadedHash).toBe(
            createHash('sha256').update(upload).digest('hex'),
        );
        expect(Buffer.concat(chunks).equals(response)).toBe(true);
    } finally {
        peer.terminate();
        for (const socket of sockets) socket.destroy();
        fixture.close();
        relay.closeAllConnections();
        relay.close();
    }
}, 15_000);

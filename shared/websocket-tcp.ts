import { Duplex, Transform, pipeline } from 'node:stream';

interface WebSocketPeer {
    readyState: number;
    resume(): void;
    pause(): void;
    close(): void;
    terminate(): void;
    send(data: string | Buffer, callback: (error?: Error) => void): void;
    send(
        data: Buffer,
        options: { binary: boolean },
        callback: (error?: Error) => void,
    ): void;
    on(
        event: 'message',
        listener: (
            data: Buffer | ArrayBuffer | Buffer[],
            binary: boolean,
        ) => void,
    ): unknown;
    once(event: 'error', listener: (error: Error) => void): unknown;
    once(event: 'close', listener: () => void): unknown;
}

export const TCP_STREAM_PROTOCOL = 'tcp-eof-v1';
export const TCP_STREAM_OPENED = JSON.stringify({
    opened: true,
    stream_protocol: TCP_STREAM_PROTOCOL,
});
const EOF = '{"eof":true}';

/** WebSocket close is a full close, whereas TCP has two independent EOFs.
 * Preserve both halves until buffered response/upload data has drained. */
export function tcpWebSocketStream(peer: WebSocketPeer): Duplex {
    let localEof = false;
    let remoteEof = false;
    const closeWhenDrained = (): void => {
        if (
            localEof &&
            remoteEof &&
            stream.readableEnded &&
            stream.writableFinished &&
            peer.readyState === 1
        )
            peer.close();
    };
    const stream = new Duplex({
        allowHalfOpen: true,
        readableHighWaterMark: 64 * 1024,
        writableHighWaterMark: 64 * 1024,
        read() {
            peer.resume();
        },
        write(chunk: Buffer, _encoding, callback) {
            let offset = 0;
            const send = (): void => {
                if (offset >= chunk.length) {
                    callback();
                    return;
                }
                const bytes = chunk.subarray(offset, offset + 64 * 1024);
                offset += bytes.length;
                peer.send(bytes, { binary: true }, error =>
                    error ? callback(error) : send(),
                );
            };
            send();
        },
        final(callback) {
            peer.send(EOF, error => {
                if (!error) localEof = true;
                callback(error);
                closeWhenDrained();
            });
        },
        destroy(error, callback) {
            if (error || !localEof || !remoteEof) peer.terminate();
            else if (peer.readyState === 1) peer.close();
            callback(error);
        },
    });
    peer.on('message', (data, binary) => {
        if (!binary) {
            if (data.toString() !== EOF || remoteEof) {
                stream.destroy(new Error('Invalid TCP stream control'));
                return;
            }
            remoteEof = true;
            stream.push(null);
            closeWhenDrained();
            return;
        }
        if (remoteEof) {
            stream.destroy(new Error('TCP data after EOF'));
            return;
        }
        const bytes = Buffer.isBuffer(data)
            ? data
            : Array.isArray(data)
              ? Buffer.concat(data)
              : Buffer.from(data);
        if (!stream.push(bytes)) peer.pause();
    });
    peer.once('error', error => stream.destroy(error));
    peer.once('close', () => {
        if (!localEof || !remoteEof)
            stream.destroy(new Error('TCP tunnel closed before EOF'));
    });
    stream.once('end', closeWhenDrained);
    stream.once('finish', closeWhenDrained);
    return stream;
}

export function bridgeTcpStreams(
    left: Duplex,
    right: Duplex,
    done: (error?: Error | null) => void,
    charge?: () => Transform,
): void {
    let completed = 0;
    let stopped = false;
    const finish = (error?: NodeJS.ErrnoException | null): void => {
        if (stopped) return;
        if (error || ++completed === 2) {
            stopped = true;
            done(error);
        }
    };
    if (charge) {
        pipeline(left, charge(), right, finish);
        pipeline(right, charge(), left, finish);
    } else {
        pipeline(left, right, finish);
        pipeline(right, left, finish);
    }
}

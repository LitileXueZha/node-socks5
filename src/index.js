/* eslint max-classes-per-file: "off" */
import tls from 'tls';
import http from 'http';
import https from 'https';
import Socks5Socket from './Socks5Socket.js';

export { AUTH, CMD } from './constants.js';

/**
 * For more reliable network requests, consider use `agent`.
 */
export function createConnection(options, callback) {
    const { protocol, hostname, port } = options;
    const socket = new Socks5Socket();
    socket.on('error', callback);
    if (protocol === 'http:') {
        socket.establish(hostname, port).catch(callback);
        socket.once('established', () => callback(null, socket));
        return;
    }

    // For HTTPS requests
    const tlsPort = port === 80 ? 443 : port;
    const servername = options.servername || hostname;
    socket.establish(hostname, tlsPort).catch(callback);
    socket.once('established', () => {
        callback(null, tls.connect({ socket, servername }));
    });
}

/**
 * Create a HTTP agent with SOCKS5 proxy
 *
 * To specify the proxy server address, set `options.proxy`. Example:
 * ```
 * new Socks5HTTPAgent({ proxy: 'socks://host[:port]' });
 * new Socks5HTTPSAgent({
 *   proxy: {
 *      hostname: '',
 *      port: 1080,
 *   }
 * });
 * ```
 *
 * Or set env variable `SOCKS_PROXY`, otherwise it's `socks://127.0.0.1:1080`
 *
 * Other options are same with original `http.Agent` or `https.Agent`.
 */
export class Socks5HTTPAgent extends http.Agent {
    constructor(options) {
        super(options);
        this.proxy = options?.proxy;
    }

    createConnection(options, callback) {
        const socket = new Socks5Socket(this.proxy);
        socket.on('error', callback);
        socket.establish(options.hostname, options.port).catch(callback);
        socket.once('established', () => callback(null, socket));
    }
}

/**
 * Same with `Socks5HTTPAgent` but for HTTPS requests.
 */
export class Socks5HTTPSAgent extends https.Agent {
    constructor(options) {
        super(options);
        this._proxy = options?.proxy;
        /**
         * Original https.Agent enable sessions when create connection,
         * patch it instead of override.
         *
         * See node lib/https.js for details.
         */
        this._ccMonkey = super.createConnection;
    }

    createConnection(options, callback) {
        const socket = new Socks5Socket(this._proxy);
        socket.on('error', callback);
        socket.establish(options.hostname, options.port).catch(callback);
        socket.once('established', () => {
            options.socket = socket;
            // callback(null, tls.connect({ socket }));
            callback(null, this._ccMonkey(options));
        });
    }
}

export { Socks5Socket };

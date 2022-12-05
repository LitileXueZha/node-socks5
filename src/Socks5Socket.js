import net from 'net';
import udp from 'dgram';
import {
    CNNC_GREETING,
    CNNC_AUTH,
    CNNC_SENT,
    CNNC_ESTABLISHED,
    AUTH,
    CMD,
    CAUTH_DENY, OAUTH_GRANTED,
    STATUS, STATUS_TEXT,
} from './constants.js';
import {
    Socks5Handshake,
    Socks5Authentication,
    Socks5Request,
    parser,
    Socks5UDPHeader,
} from './Socks5Packets.js';


const PROXY_URL = process.env.SOCKS_PROXY
    || 'socks://127.0.0.1:1080';

class Socks5Socket extends net.Socket {
    constructor(proxy = PROXY_URL) {
        const { proxyAddress, socketOptions } = normalizeOptions(proxy);
        super(socketOptions);

        this._proxyAddress = proxyAddress;
        this.status = null;
        this._bindAddress = {};
        this._remoteAddress = {};
        this.udpAssociate = null;
        this.onDataResponse = this.onDataResponse.bind(this);
        this.setMaxListeners(20);
    }

    async establish(hostname, port, command = CMD.CONNECT) {
        if (this.status === null) {
            this._initHandshake();
            await this._onceAsync('finishHandshake');
        }

        this._bindAddress = {};
        this._remoteAddress.host = hostname;
        this._remoteAddress.port = port;
        this.write(Socks5Request({ hostname, port, command }));
        this.status = CNNC_SENT;

        await this._onceAsync('established');
        this.status = CNNC_ESTABLISHED;
    }

    send(data, callback) {
        const { address, port } = this._bindAddress;
        const { host, family } = parser.address(address);
        if (!this.udpAssociate) {
            this.udpAssociate = udp.createSocket('udp4');
            this.udpAssociate.on('message', (msg) => {
                const res = parser.udp(msg);
                this.emit('message', res.data);
            });
        }
        const { host: destAddress, port: destPort } = this._remoteAddress;
        this.udpAssociate.send(
            [Socks5UDPHeader(destAddress, destPort), Buffer.from(data)],
            port,
            host,
            callback,
        );
    }

    close() {
        this.udpAssociate?.removeAllListeners('message');
        this.udpAssociate?.close();
        this.destroy();
    }

    getBindAddress() {
        const { address, port } = this._bindAddress;
        if (!address) {
            return null;
        }
        const { host, family } = parser.address(address);
        return { address: host, family, port };
    }

    _initHandshake() {
        this.connect(this._proxyAddress);
        this.on('connect', () => {
            this.on('data', this.onDataResponse);
            this.write(Socks5Handshake());
            this.status = CNNC_GREETING;
        });
    }

    onDataResponse(chunk) {
        // If the connection is established, we don't need to do anything.
        if (this.status === CNNC_ESTABLISHED) {
            return;
        }

        switch (this.status) {
        case CNNC_GREETING: {
            // Sever reply a handshake packet after client greeting
            const { cauth } = parser.handshake(chunk);
            switch (cauth) {
            case CAUTH_DENY:
                throw new Error('no acceptable methods');
            case AUTH.NONE:
                /**
                 * Just finish this handshake if there is no auth,
                 * then it's ready to create a tcp request.
                 *
                 * See details in `establish()`
                 */
                this.emit('finishHandshake');
                break;
            case AUTH.USERPWD:
                this._auth();
                break;
            default:
                throw new Error(`currently unsupport authentication method: ${cauth}`);
            }
            break;
        }
        case CNNC_AUTH: {
            const { status } = parser.authentication(chunk);
            if (status !== OAUTH_GRANTED) {
                throw new Error('failed authentication');
            }
            // Only finish handshake after auth successful
            this.emit('finishHandshake');
            break;
        }
        case CNNC_SENT: {
            const { statusCode, bindAddress, bindPort } = parser.response(chunk);
            if (statusCode !== STATUS.GRANTED) {
                throw new Error(STATUS_TEXT[statusCode]);
            }
            this._bindAddress = { address: bindAddress, port: bindPort };
            this.emit('established');
            break;
        }
        default:
            break;
        }
    }

    _auth() {
        // TODO:
        this.write(Socks5Authentication(this._authInfo));
        this.status = CNNC_AUTH;
    }

    _onceAsync(eventName) {
        return new Promise((resolve, reject) => {
            this.once('error', reject);
            this.once('timeout', reject);
            this.once('close', reject);
            this.once(eventName, () => {
                this.off('error', reject);
                this.off('timeout', reject);
                this.off('close', reject);
                resolve();
            });
        });
    }
}

function normalizeOptions(options) {
    if (typeof options === 'string') {
        options = { proxy: options };
    }

    let { proxy, ...socketOptions } = options;
    if (typeof proxy === 'string') {
        if (proxy.indexOf('socks://') < 0) {
            proxy = `socks://${proxy}`;
        }
        proxy = new URL(proxy);
    }
    const { hostname, port = 80 } = proxy;
    if (typeof hostname !== 'string') {
        throw new Error('invalid hostname');
    }

    return {
        proxyAddress: { host: hostname, port: +port },
        socketOptions,
    };
}

export default Socks5Socket;

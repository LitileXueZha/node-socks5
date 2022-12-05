/**
 * SOCKS v5 protocol
 *
 * @link https://en.wikipedia.org/wiki/SOCKS#SOCKS5
 * @link https://datatracker.ietf.org/doc/html/rfc1928
 * @link https://datatracker.ietf.org/doc/html/rfc1929
 */
import net from 'net';
import {
    ADDRESS_TYPE,
    AUTH_DEFAULTS,
    RSV,
    VER, VER_AUTH_USERPWD,
    UDP_RSV, UDP_FRAG,
} from './constants.js';


/**
 * SOCKS v5 handshake (client greeting)
 *
 *           VER  NAUTH  AUTH
 * ------------------------------
 * Bytes     1    1      variable
 */
export function Socks5Handshake(methods = AUTH_DEFAULTS) {
    const nAuth = methods.length;
    const buff = Buffer.allocUnsafe(2 + nAuth);
    buff.writeUInt8(VER);
    buff.writeUInt8(nAuth, 1);
    for (let i = 0; i < nAuth; i++) {
        buff.writeUInt8(methods[i], i + 2);
    }
    return buff;
}

/**
 * SOCKS v5 authentication (username/password)
 *
 *          VER  IDLEN   ID      PWLEN   PW
 * --------------------------------------------
 * Bytes    1    1      (1-255)  1      (1-255)
 */
export function Socks5Authentication(username, password) {
    const user = Buffer.from(username);
    const pwd = Buffer.from(password);
    const uLen = user.byteLength;
    const pLen = pwd.byteLength;
    if (uLen > 255 || pLen > 255) {
        throw new Error('username or password too long');
    }
    const buff = Buffer.allocUnsafe(3 + uLen + pLen);
    buff.writeUInt8(VER_AUTH_USERPWD);
    buff.writeUInt8(uLen, 1);
    buff.write(username, 2);
    buff.writeUInt8(pLen, 2 + uLen);
    buff.write(password, 3 + uLen);
    return buff;
}

/**
 * SOCKS v5 request
 *
 *          VER  CMD  RSV  ADDRTYP  ADDR      PORT
 * -----------------------------------------------
 * Bytes    1    1    1    1        variable  2
 */
export function Socks5Request(options) {
    const { hostname, port, command } = options;
    const buffAddr = Socks5Address(hostname);
    const buff = Buffer.allocUnsafe(5 + buffAddr.byteLength);
    buff.writeUInt8(VER);
    buff.writeUInt8(command, 1);
    buff.writeUInt8(RSV, 2);
    buffAddr.copy(buff, 3);
    buff.writeUInt16BE(port, 3 + buffAddr.byteLength);
    return buff;
}

/**
 * SOCKS v5 address
 *
 *           ADDRTYP  ADDR
 * ---------------------------
 * Bytes     1        variable
 *
 * IPv4    4 bytes
 * domain  1 byte of name length followed by 1-255 bytes
 * IPv6   16 bytes
 */
function Socks5Address(hostname) {
    const family = net.isIP(hostname);
    switch (family) {
    case 4: {
        const pieces = hostname.split('.');
        const buff = Buffer.allocUnsafe(5); // 1 + 4
        buff.writeUInt8(ADDRESS_TYPE.IPv4);
        for (let i = 0, len = pieces.length; i < len; i++) {
            buff.writeUInt8(pieces[i], i + 1);
        }
        return buff;
    }
    case 6: {
        const buff = Buffer.allocUnsafe(17); // 1 + 16
        const removeScopedHost = hostname.split('%')[0];
        const pieces = removeScopedHost.split(':');
        const colons = 8; // 8 groups of hexadecimal
        let missing = colons - pieces.length;
        buff.writeUInt8(ADDRESS_TYPE.IPv6);
        let offset = 1;
        for (let i = 0, len = pieces.length; i < len; i++) {
            if (pieces[i] === '') {
                // Skipped if "::" only at start or tail
                if (pieces[i + 1] === '') {
                    missing++;
                    continue;
                }
                for (let j = 0; j < missing + 1; j++) {
                    buff.writeUInt16BE(0, offset);
                    offset += 2;
                }
                continue;
            }
            buff.writeUInt16BE(parseInt(pieces[i], 16), offset);
            offset += 2;
        }
        return buff;
    }
    // domain
    default: {
        const len = Buffer.from(hostname).byteLength;
        if (len > 255) {
            throw new Error('hostname too long');
        }
        const buff = Buffer.allocUnsafe(2 + len);
        buff.writeUInt8(ADDRESS_TYPE.DOMAIN);
        buff.writeUInt8(len, 1);
        buff.write(hostname, 2);
        return buff;
    }
    }
}

function parseAddress(buff) {
    let host = [];
    let family = 0;
    const addressType = buff[0];
    const len = buff.length;
    switch (addressType) {
    case ADDRESS_TYPE.IPv4:
        family = 4;
        for (let i = 1; i < len; i++) {
            host.push(buff[i]);
        }
        host = host.join('.');
        break;
    case ADDRESS_TYPE.IPv6:
        family = 6;
        for (let i = 1; i < len; i += 2) {
            host.push(buff.readUInt16BE(i));
        }
        host.join(':');
        break;
    case ADDRESS_TYPE.DOMAIN:
        host = buff.subarray(1).toString();
        break;
    default:
        throw new Error('invalid address type');
    }
    return { host, family };
}

/**
 * SOCKS v5 handshake - server
 *
 *           VER  CAUTH
 * --------------------
 * Bytes     1    1
 */
function parseServerHandshake(buff) {
    const version = buff[0];
    const cauth = buff[1];

    if (version !== VER) {
        throw new Error('unmatched Socks5 version');
    }
    return { version, cauth };
}

/**
 * SOCKS v5 authentication (username/password) - server
 *
 *           VER  STATUS
 * ---------------------
 * Bytes     1    1
 */
function parseServerAuthentication(buff) {
    const version = buff[0];
    const status = buff[1];

    if (version !== VER_AUTH_USERPWD) {
        throw new Error('unknown authentication version');
    }
    return { version, status };
}

/**
 * SOCKS v5 response - server
 *
 *          VER  STATUS  RSV  ADDRTYP  BIND.ADDR  BIND.PORT
 * --------------------------------------------------------
 * Bytes    1    1       1    1        variable   2
 */
function parseServerResponse(buff) {
    const version = buff[0];
    const statusCode = buff[1];

    if (version !== VER) {
        throw new Error('unmatched Socks5 version');
    }
    const bindAddress = buff.subarray(3, buff.byteLength - 2);
    const bindPort = buff.readUInt16BE(buff.byteLength - 2);
    return {
        version, statusCode, bindAddress, bindPort,
    };
}

export const parser = {
    handshake: parseServerHandshake,
    authentication: parseServerAuthentication,
    response: parseServerResponse,
    udp: parseServerUDPResponse,
    address: parseAddress,
};

/**
 * SOCKS v5 UDP datagram
 *
 *          RSV  FRAG  ADDRTYP  BIND.ADDR  BIND.PORT  DATA
 * -------------------------------------------------------
 * Bytes    2    1     1        variable   2
 */
export function Socks5UDPHeader(address, port) {
    const buffAddr = Socks5Address(address);
    const buff = Buffer.allocUnsafe(5 + buffAddr.byteLength);
    buff.writeUInt16BE(UDP_RSV);
    buff.writeUInt8(UDP_FRAG, 2);
    buffAddr.copy(buff, 3);
    buff.writeUInt16BE(port, 3 + buffAddr.byteLength);
    return buff;
}

function parseServerUDPResponse(buff) {
    const addressType = buff[3];
    let offset = 4;
    switch (addressType) {
    case ADDRESS_TYPE.IPv4:
        offset += 4;
        break;
    case ADDRESS_TYPE.IPv6:
        offset += 16;
        break;
    case ADDRESS_TYPE.DOMAIN:
        offset += 1;
        offset += buff[4];
        break;
    default:
        throw new Error('invalid address type');
    }
    const bindAddress = buff.subarray(3, offset);
    const bindPort = buff.readUInt16BE(offset);
    offset += 2;
    const data = buff.subarray(offset);
    return { data, bindAddress, bindPort };
}

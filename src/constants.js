export const VER = 0x05;
export const AUTH = {
    NONE: 0x00,
    USERPWD: 0x02,
};
export const AUTH_DEFAULTS = [AUTH.NONE, AUTH.USERPWD];
export const VER_AUTH_USERPWD = 0x01;
export const CAUTH_DENY = 0xff;
export const OAUTH_GRANTED = 0x00;
export const ADDRESS_TYPE = {
    IPv4: 0x01,
    DOMAIN: 0x03,
    IPv6: 0x04,
};
export const CMD = {
    CONNECT: 0x01,
    BIND: 0x02,
    UDP: 0x03,
};
export const RSV = 0x00;
export const UDP_RSV = 0x0000; // 2 Bytes
export const UDP_FRAG = 0x00;
export const STATUS = {
    GRANTED: 0x00,
    FAILURE: 0x01,
    DISALLOWED: 0x02,
    NETWORK_ERR: 0x03,
    HOST_ERR: 0x04,
    CNNC_REFUSED: 0x05,
    EXPIRED: 0x06,
    UNSUPPORT: 0x07,
    ADDRTYPE_UNSUPPORT: 0x08,
};
export const STATUS_TEXT = {
    0x00: 'request granted',
    0x01: 'general failure',
    0x02: 'connection not allowed by ruleset',
    0x03: 'network unreachable',
    0x04: 'host unreachable',
    0x05: 'connection refused by destination host',
    0x06: 'TTL expired',
    0x07: 'command not supported / protocol error',
    0x08: 'address type not supported',
};

export const CNNC_GREETING = 'GREETING';
export const CNNC_AUTH = 'AUTH';
export const CNNC_SENT = 'SENT';
export const CNNC_ESTABLISHED = 'ESTABLISHED';

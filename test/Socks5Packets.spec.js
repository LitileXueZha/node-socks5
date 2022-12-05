import { describe, it } from 'mocha';
import { expect } from 'chai';
import { parser, Socks5Authentication, Socks5Request } from '../src/Socks5Packets.js';
import { CMD } from '../src/constants.js';

describe('Socks5Packets', () => {
    it('should create a DOMAIN packet', () => {
        const buff = Buffer.from([
            0x05, 0x01, 0x00, 0x03,
            0x07, ...Buffer.from('123.com'),
            0x00, 0x50,
        ]);
        const packet = Socks5Request({
            hostname: '123.com',
            port: 80,
            command: CMD.CONNECT,
        });
        const equals = buff.equals(packet);
        expect(equals).to.equal(true);
    });
    it('should create a IPv4 packet', () => {
        const buff = Buffer.from([
            0x05, 0x02, 0x00, 0x01,
            0x7f, 0x00, 0x00, 0x01,
            0x01, 0xbb,
        ]);
        const packet = Socks5Request({
            hostname: '127.0.0.1',
            port: 443,
            command: CMD.BIND,
        });
        const equals = buff.equals(packet);
        expect(equals).to.equal(true);
    });
    it('should create a IPv6 packet', () => {
        const buff = Buffer.from([
            0x05, 0x03, 0x00, 0x04,
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x38,
        ]);
        const packet = Socks5Request({
            hostname: 'fe80::',
            port: 1080,
            command: CMD.UDP,
        });
        const equals = buff.equals(packet);
        expect(equals).to.equal(true);
    });
    it('should create/parse authentication packets', () => {
        const buff = Buffer.from([
            0x01,
            0x03, ...Buffer.from('foo'),
            0x03, ...Buffer.from('bar'),
        ]);
        const packet = Socks5Authentication('foo', 'bar');
        expect(buff.equals(packet)).to.equal(true);
        const chunk = Buffer.from([0x01, 0x00]);
        const res = parser.authentication(chunk);
        expect(res).to.deep.equal({ version: 1, status: 0 });
    });
});

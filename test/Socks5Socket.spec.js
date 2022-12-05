import http from 'http';
import https from 'https';
import net from 'net';
import udp from 'dgram';
import fs from 'fs';
import { before, describe, it, after } from 'mocha';
import { expect } from 'chai';
import Socks5Socket from '../src/Socks5Socket.js';
import { createConnection, Socks5HTTPAgent, Socks5HTTPSAgent } from '../src/index.js';
import { CMD } from '../src/constants.js';

describe('Socks5Socket', () => {
    it('should create a new instance', () => {
        let socket;
        socket = new Socks5Socket();
        expect(socket).to.instanceOf(net.Socket);
        socket = new Socks5Socket('example.org:1080');
        expect(socket._proxyAddress).to.deep.equal({
            host: 'example.org',
            port: 1080,
        });
        socket = new Socks5Socket({
            proxy: { hostname: 'a.com', port: 80 },
            allowHalfOpen: true,
            keepAlive: true,
        });
        expect(socket._proxyAddress).to.deep.equal({ host: 'a.com', port: 80 });
        expect(socket.allowHalfOpen).to.equal(true);
    });
    it('should throw error with invalid options', () => {
        expect(() => new Socks5Socket(null)).to.throw();
        expect(() => new Socks5Socket({ proxy: true })).to.throw();
    });

    /**
     * To enable below tests, use a production socks5 proxy
     * server and set the env SOCKS_PROXY
     */
    describe('Using a production SOCKS5 proxy', () => {
        before(function () {
            // Not found a socks proxy, skipped e2e tests
            if (process.env.SOCKS_PROXY === undefined) {
                this.skip();
            }
        });
        it('should generate 204 with createConnection', async () => {
            const [res, ress] = await Promise.all([
                gen204.call(http, 'http://www.google.com/generate_204'),
                gen204.call(https, 'https://www.google.com/generate_204'),
            ]);
            expect(res).to.equal(204);
            expect(ress).to.equal(204);
        });
        before(createHTTP);
        it('should ok with Socks5HTTPAgent', async function () {
            const url = `http://127.0.0.1:${this.http.port}`;
            const agent = new Socks5HTTPAgent();
            const res = await ok.call(http, url, { agent });
            expect(res).to.equal('ok');
        });
        before(createIpv6HTTPS);
        it('should ok with Socks5HTTPSAgent - IPv6', async function () {
            const url = `https://[::1]:${this.https.port}`;
            const agent = new Socks5HTTPSAgent();
            const res = await ok.call(https, url, { agent, rejectUnauthorized: false });
            expect(res).to.equal('ok');
        });
        before(createUDP);
        it('should ok with UDP', async function () {
            const socket = new Socks5Socket();
            await socket.establish('127.0.0.1', this.udp.port, CMD.UDP);
            await new Promise((resolve) => {
                socket.on('message', (data) => {
                    socket.close();
                    expect(data.toString()).to.equal('ok');
                    resolve();
                });
                socket.send('a');
            });
        });
        after(stop);
    });
});

function gen204(url) {
    return new Promise((resolve, reject) => {
        const req = this.request(url, { createConnection });
        req.on('error', reject);
        req.on('response', (res) => {
            // res.on('end', resolve);
            res.resume();
            resolve(res.statusCode);
        });
        req.end();
    });
}

function ok(url, options) {
    return new Promise((resolve, reject) => {
        const req = this.request(url, options);
        req.on('error', reject);
        req.on('response', (res) => {
            let buff;
            res.on('data', (chunk) => { buff = chunk; });
            res.on('end', () => {
                resolve(buff.toString());
            });
        });
        req.end();
    });
}

function stop() {
    this.http?.close();
    this.https?.close();
    this.udp?.close();
}

function createHTTP(done) {
    const server = http.createServer((req, res) => {
        res.end('ok');
    });
    server.listen(0, () => {
        this.http = server;
        this.http.port = server.address().port;
        done();
    });
}

function createIpv6HTTPS(done) {
    const tls = {
        key: fs.readFileSync(new URL('key.pem', import.meta.url)),
        cert: fs.readFileSync(new URL('cert.pem', import.meta.url)),
    };
    const server = https.createServer(tls, (req, res) => {
        res.end('ok');
    });
    server.listen({ ipv6Only: true, port: 0 }, () => {
        this.https = server;
        this.https.port = server.address().port;
        done();
    });
}

function createUDP(done) {
    const server = udp.createSocket('udp4');
    server.on('message', (msg, remote) => {
        server.send('ok', remote.port, remote.address);
    });
    server.on('listening', () => {
        this.udp = server;
        this.udp.port = server.address().port;
        done();
    });
    server.bind(0);
}

# node-socks5

Simple SOCKS5 client implementation in nodejs.

## Install and Usage

```shell
$ npm install socks-v5 --save
```

The quickest method to try it is `createConnection`, but this is **not recommended**, because use *agent* is more reliable and this also needs you set `process.env.SOCKS_PROXY`.

```javascript
const { createConnection } = require('socks-v5');

http.request('http://site.org', { createConnection }); // or
https.request('https://ipv6.site.org', { createConnection });
```

Use the agent:

```javascript
const { Socks5HTTPAgent, Socks5HTTPSAgent } = require('socks-v5');

http.request(url, { agent: new Socks5HTTPAgent() });
// For HTTPS requests
const agent = new Socks5HTTPSAgent({ proxy: 'socks://127.0.0.1:1080' });
https.request(url, { agent });
```

### `options.proxy`

If not specified, it will read `SOCKS_PROXY` from environments, otherwise default `socks://127.0.0.1:1080`.

You can also set the proxy url through agent options:

```javascript
new Socks5HTTPAgent(); // read from process.env.SOCKS_PROXY

new Socks5HTTPAgent({ proxy: '' }); // string
new Socks5HTTPSAgent({ proxy: { hostname, port } }); // object
```

Other options is same with `http.Agent` or `https.Agent`.

### `Socks5Socket`

Underlying implementation, manipulate socket by yourself.

```javascript
const { Socks5Socket } = require('socks-v5');

const socket = new Socks5Socket();
await socket.establish(hostname, port, command);
// Do something...
```

## UDP Associate

See example in [test/Socks5Socket.spec.js](test/Socks5Socket.spec.js)

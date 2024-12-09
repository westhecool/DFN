(function () { // wrap in a function to avoid global scope pollution
    const isBrowser = typeof window !== 'undefined';
    const messages = {
        OK: 0,
        ERROR: 1,
        MALFORMED_REQUEST: 2,
        UNKNOWN_COMMAND: 3,
        GET_FILE_METADATA: 4,
        FILE_METADATA: 5,
        GET_FILE_PART: 6,
        FILE_PART: 7,
        GET_FILE_PROGRESS: 8,
        FILE_PROGRESS: 9,
        UNKNOWN_FILE: 10,
        PROGRESS_REPORT: 11, // unused
    };
    const defaultEncryptionKey = hexToBuffer('881f2b97e1b8138ca35e84c7114936099e1029e62e5b801d7ad993becded09bb');
    const partSize = 10 * 1024 * 1024; // do not change this.
    var undiciRequest = null;
    if (!isBrowser) {
        try {
            undiciRequest = require('undici').request;
        } catch (e) {
            console.warn('Failed to import undici, falling back to fetch.');
            undiciRequest = null;
        }
    }
    function bitArrayToBytes(bits) { // Compacts an array of 1s and 0s into bytes
        // Ensure the length is a multiple of 8 by padding with zeros
        while (bits.length % 8 !== 0) {
            bits.push(0);
        }

        // Group into 8 bits and convert each group to a byte
        const byteArray = [];
        for (let i = 0; i < bits.length; i += 8) {
            const byte = bits.slice(i, i + 8);
            let byteValue = 0;
            for (let j = 0; j < 8; j++) {
                byteValue |= (byte[j] << (7 - j)); // Combine bits into a byte
            }
            byteArray.push(byteValue);
        }

        if (isBrowser) {
            return new Uint8Array(byteArray);
        } else {
            return Buffer.from(byteArray);
        }
    }
    function bytesToBitArray(byteArray) {
        const bits = [];

        // Process each byte in the array
        for (const byte of byteArray) {
            for (let i = 7; i >= 0; i--) {
                bits.push((byte >> i) & 1); // Extract each bit (from MSB to LSB)
            }
        }

        return bits;
    }
    function writeUInt32BE(buffer, value, offset = 0) {
        if (isBrowser) {
            const view = new DataView(buffer.buffer);
            view.setUint32(offset, value, false); // 'false' specifies big-endian
            return new Uint8Array(view.buffer);
        } else {
            buffer = Buffer.from(buffer);
            buffer.writeUInt32BE(value, offset);
            return buffer;
        }
    }
    function readUInt32BE(buffer, offset = 0) {
        if (isBrowser) {
            const view = new DataView(buffer.buffer || buffer);
            return view.getUint32(offset, false); // 'false' specifies big-endian
        } else {
            buffer = Buffer.from(buffer);
            return buffer.readUInt32BE(offset);
        }
    }
    function concatBuffers(buffers) {
        if (isBrowser) {
            const totalLength = buffers.reduce((sum, arr) => sum + arr.length, 0);
            const result = new Uint8Array(totalLength);
            var offset = 0;
            buffers.forEach(arr => {
                result.set(arr, offset);
                offset += arr.length;
            });
            return result;
        } else {
            return Buffer.concat(buffers);
        }
    }
    function bufferToHex(buffer) {
        return Array.from(buffer).map(byte => byte.toString(16).padStart(2, '0')).join('');
    }
    function hexToBuffer(hex) {
        if (hex.length % 2 !== 0) {
            throw new Error('Hexadecimal string must have an even number of characters.');
        }
        const length = hex.length / 2;
        const uint8Array = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            uint8Array[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        if (isBrowser) {
            return uint8Array;
        } else {
            return Buffer.from(uint8Array);
        }
    }
    async function hash(data) {
        if (typeof data === 'string') (new TextEncoder()).encode(data);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return bufferToHex(new Uint8Array(hash));
    }
    async function postRequest(url, data, headers = {}) {
        if (undiciRequest) {
            const { statusCode, headers, trailers, body } = await undiciRequest(url, { method: 'POST', body: data });
            return { statusCode, headers, body: Buffer.from(await body.arrayBuffer()) };
        } else {
            const response = await fetch(url, {
                method: 'POST',
                body: data,
                headers: headers
            });
            var body = await response.arrayBuffer();
            if (isBrowser) {
                body = new Uint8Array(body);
            } else {
                body = Buffer.from(body);
            }
            return { statusCode: response.status, headers: response.headers, body };
        }
    }
    class DFNTracker {
        constructor(trackerUrl, serverHostname = null) {
            this.hostname = serverHostname;
            this.url = trackerUrl;
            this.pingInterval = null;
        }
        async findPeers(files) {
            if (!Array.isArray(files)) throw new Error('Files must be an array.');
            const response = await fetch(this.url + '/find-peers', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(files)
            });
            const data = await response.json();
            if (response.status !== 200) {
                throw new Error('Failed to find peers: ' + data.error);
            }
            return data;
        }
        async announceFiles(files) {
            if (!this.hostname) throw new Error('Hostname is not set.');
            if (!Array.isArray(files)) throw new Error('Files must be an array.');
            const response = await fetch(this.url + '/announce-files', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ hostname: this.hostname, files })
            });
            const data = await response.json();
            if (response.status !== 200) {
                throw new Error('Failed to announce files: ' + data.error);
            }
            if (!this.pingInterval) this.pingInterval = setInterval(async () => await this.ping(), 20000); // ping the tracker every 20 seconds to let it know we are still seeding
            return data;
        }
        async ping() {
            if (!this.hostname) throw new Error('Hostname is not set.');
            const response = await fetch(this.url + '/ping', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ hostname: this.hostname })
            });
            const data = await response.json();
            if (response.status !== 200) {
                throw new Error('Failed to ping: ' + data.error);
            }
            return data;
        }
        async disconnect() {
            if (!this.hostname) throw new Error('Hostname is not set.');
            if (this.pingInterval) clearInterval(this.pingInterval);
            const response = await fetch(this.url + '/disconnect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ hostname: this.hostname })
            });
            const data = await response.json();
            if (response.status !== 200) {
                throw new Error('Failed to announce disconnect: ' + data.error);
            }
            return data;
        }
    }
    class DFNClient {
        constructor(url) {
            this.url = url;
        }
        async query(message, data = null) {
            if (data === null) {
                if (isBrowser) {
                    data = new Uint8Array(0);
                } else {
                    data = Buffer.alloc(0);
                }
            }
            const c = writeUInt32BE(new Uint8Array(4), message);
            const { statusCode, headers, body } = (await postRequest(this.url, concatBuffers([c, data])));
            if (statusCode === 429) {
                throw new Error('Cloudflare is likely rate limiting the tunnel');
            } else if (statusCode !== 200) {
                throw new Error('Got unexpected http code: ' + statusCode);
            }
            if (body.length < 4) {
                reject(new Error('Invalid length'));
                return;
            }
            const rmessage = readUInt32BE(body, 0);
            var rdata;
            if (isBrowser) {
                rdata = body.slice(4);
            } else {
                rdata = body.subarray(4);
            }
            return { message: rmessage, data: rdata };
        }
        // nice functions
        async getFileMetadata(fileHash) {
            if (typeof fileHash === 'string') fileHash = hexToBuffer(fileHash);
            const r = await this.query(messages.GET_FILE_METADATA, fileHash);
            if (r.message !== messages.FILE_METADATA) throw new Error('Invalid response: ' + r.message);
            if (isBrowser) {
                return JSON.parse((new TextDecoder()).decode(r.data));
            } else {
                return JSON.parse(r.data.toString());
            }
        }
        async getFileProgress(fileHash) {
            if (typeof fileHash === 'string') fileHash = hexToBuffer(fileHash);
            const r = await this.query(messages.GET_FILE_PROGRESS, fileHash);
            if (r.message !== messages.FILE_PROGRESS) throw new Error('Invalid response: ' + r.message);
            var progress;
            if (isBrowser) {
                progress = bytesToBitArray(r.data.slice(4));
                while (progress.length > readUInt32BE(r.data.slice(0, 4), 0)) progress.pop(); // remove any trailing 0s
            } else {
                progress = bytesToBitArray(r.data.subarray(4));
                while (progress.length > readUInt32BE(r.data.subarray(0, 4), 0)) progress.pop(); // remove any trailing 0s
            }
            return progress;
        }
        async getFilePart(fileHash, partIndex) {
            if (typeof fileHash === 'string') fileHash = hexToBuffer(fileHash);
            const index = writeUInt32BE(new Uint8Array(4), partIndex);
            const r = await this.query(messages.GET_FILE_PART, concatBuffers([fileHash, index]));
            if (r.message !== messages.FILE_PART) throw new Error('Invalid response: ' + r.message);
            return r.data;
        }
    }
    const helperFunctions = { bitArrayToBytes, bytesToBitArray, writeUInt32BE, readUInt32BE, concatBuffers, bufferToHex, hexToBuffer, hash };
    if (isBrowser) {
        window.DFNClient = DFNClient;
        window.DFNTracker = DFNTracker;
        window.DFNMessages = messages;
        window.DFNPartSize = partSize;
        window.DFNHelperFunctions = helperFunctions;
    } else {
        // Server (nodejs) only functions
        const http = require('http');
        const { EventEmitter } = require('events');
        const fs = require('fs');
        const CP = require('child_process');
        const { createHash } = require('crypto');
        async function hashFile(file, progress = null) {
            if (isBrowser) throw new Error('hashFile is not currently not supported in the browser.');
            return new Promise(async (resolve, reject) => {
                var parts = [];
                const fullHash = createHash('sha256');
                const f = fs.createReadStream(file, { highWaterMark: partSize });
                const fsize = (await fs.promises.stat(file)).size;
                var done = 0;
                var lastProgress = 0;
                var hashing = false;
                f.on('data', async function (chunk) {
                    hashing = true;
                    fullHash.update(chunk);
                    parts.push(await hash(chunk));
                    done += chunk.length;
                    if (progress) {
                        const p = Number(((done / fsize) * 100).toFixed(2));
                        if (p > lastProgress) {
                            lastProgress = p;
                            progress(p);
                        }
                    }
                    hashing = false;
                });
                f.once('end', async function () {
                    while (hashing) await new Promise((resolve) => setTimeout(resolve, 10));
                    resolve({ hash: fullHash.digest('hex'), parts: parts });
                });
            });
        }
        helperFunctions.hashFile = hashFile;
        class Cloudflared {
            _cloudflaredExeName() {
                if (process.platform === 'win32') {
                    return __dirname + '\\cloudflared.exe';
                } else {
                    return __dirname + '/cloudflared';
                }
            }
            constructor() {
                this.process = null;
                this.hostname = null;
                this.running = false;
                this.exited = false;
            }
            _archMap(a) {
                switch (a) {
                    case 'ia32':
                        return '386';
                    case 'x64':
                        return 'amd64';
                    default:
                        return a;
                }
            }
            async download() {
                if (process.platform === 'win32') {
                    const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-${this._archMap(process.arch)}.exe`;
                    const request = await fetch(url, { redirect: 'follow' });
                    if (request.status !== 200) throw new Error('Failed to download cloudflared');
                    const data = await request.arrayBuffer();
                    await fs.promises.writeFile(this._cloudflaredExeName(), Buffer.from(data));
                } else if (process.platform === 'linux') {
                    const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${this._archMap(process.arch)}`;
                    const request = await fetch(url, { redirect: 'follow' });
                    if (request.status !== 200) throw new Error('Failed to download cloudflared');
                    const data = await request.arrayBuffer();
                    await fs.promises.writeFile(this._cloudflaredExeName(), Buffer.from(data));
                    await fs.promises.chmod(this._cloudflaredExeName(), 0o755); // make it executable
                } else {
                    throw new Error('Platform not implemented');
                }
            }
            async run(port, host = 'localhost', logging = false) {
                if (!fs.existsSync(this._cloudflaredExeName())) {
                    console.info('[CF]: Downloading cloudflared...');
                    await this.download();
                }
                if (this.process) {
                    try {
                        this.process.kill();
                    } catch (e) { }
                }
                this.hostname = null;
                this.exited = false;
                this.running = true;
                this.process = CP.spawn(this._cloudflaredExeName(), ['tunnel', '--url', `http://${host}:${port}`]);
                this.process.stdout.on('data', (data) => {
                    if (logging) console.log('[CF][OUT]:', data.toString().trim());
                });
                this.process.stderr.on('data', (data) => {
                    const match = data.toString().match(/https\:\/\/(.*)\.trycloudflare\.com/i);
                    if (match) {
                        this.hostname = match[1] + '.trycloudflare.com';
                    }
                    if (logging) console.log('[CF][ERR]:', data.toString().trim());
                });
                this.process.on('exit', (code, signal) => {
                    this.exited = true;
                    this.running = false;
                    console.warn(`[CF]: Exited with code ${code} and signal ${signal}.`);
                });
                await new Promise(async (resolve, reject) => {
                    while (!this.hostname) {
                        await new Promise(resolve => setTimeout(resolve, 100));
                    }
                    resolve();
                });
                return this.hostname;
            }
            kill() {
                if (this.process) {
                    try {
                        this.process.kill();
                    } catch (e) { }
                    this.process = null;
                    this.hostname = null;
                    this.exited = false;
                    this.running = false;
                }
            }
        }
        class DFNServer extends EventEmitter {
            constructor() {
                super();
                this.listenPort = null;
                this.hostname = null;
                this._cloudflared = new Cloudflared();
                this.httpServer = http.createServer();
                this._corsHeaders = {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Credentials': 'true',
                    'Access-Control-Allow-Methods': '*',
                    'Access-Control-Allow-Headers': '*',
                    'Access-Control-Expose-Headers': '*',
                };
                const _this = this;
                this.httpServer.on('request', function request(req, res) {
                    if (req.method === 'OPTIONS') res.writeHead(200, this._corsHeaders); // Send cors headers
                    else if (req.method === 'POST') {
                        var body = Buffer.alloc(0);
                        req.on('data', function (data) {
                            body = Buffer.concat([body, data]);
                        });
                        req.once('end', function () {
                            if (body.length < 4) {
                                _this.emit('error', `Error while processing message: invalid length`);
                                _this._sendResponse(res, messages.MALFORMED_REQUEST, Buffer.from("Invalid length"));
                                return;
                            }
                            var d;
                            try {
                                d = Buffer.from(body);
                            } catch (error) {
                                _this.emit('error', `Error while processing message: Decryption error: ${error.message}`);
                                _this._sendResponse(res, messages.MALFORMED_REQUEST, Buffer.from("Decryption error"));
                                return;
                            }
                            try {
                                const message = d.readUInt32BE(0);
                                const data = d.subarray(4);
                                if (message === messages.GET_FILE_METADATA) {
                                    _this.emit('file-meta-request', data.toString('hex'), (meta) => {
                                        _this._sendResponse(res, messages.FILE_METADATA, Buffer.from(JSON.stringify(meta)));
                                    }, (error) => {
                                        _this._sendResponse(res, error);
                                    });
                                } else if (message === messages.GET_FILE_PROGRESS) {
                                    _this.emit('file-progress-request', data.toString('hex'), (progress) => {
                                        progress = Array.from(progress); // copy the array because the function may modify it accidentally
                                        const len = Buffer.alloc(4);
                                        len.writeUInt32BE(progress.length, 0);
                                        _this._sendResponse(res, messages.FILE_PROGRESS, Buffer.concat([len, bitArrayToBytes(progress)]));
                                    }, (error) => {
                                        _this._sendResponse(res, error);
                                    });
                                } else if (message === messages.GET_FILE_PART) {
                                    _this.emit('file-part-request', data.subarray(0, 32).toString('hex'), data.readUInt32BE(32), (part) => {
                                        _this._sendResponse(res, messages.FILE_PART, part);
                                    }, (error) => {
                                        _this._sendResponse(res, error);
                                    });
                                } else {
                                    _this._sendResponse(res, messages.UNKNOWN_COMMAND);
                                }
                            } catch (error) {
                                _this.emit('error', `Error while processing message: ${error.message}`);
                                _this._sendResponse(res, messages.ERROR, Buffer.from("Unknown error"));
                            }
                        });
                    } else {
                        res.writeHead(405, { 'Content-Type': 'text/plain', ...this._corsHeaders });
                        res.end('Method Not Implemented');
                    }
                });
            }
            _sendResponse(res, message, data = Buffer.alloc(0)) {
                res.writeHead(200, { 'Content-Type': 'application/octet-stream', ...this._corsHeaders });
                const c = Buffer.alloc(4);
                c.writeUInt32BE(message, 0);
                res.end(Buffer.concat([c, data]));
            }
            async start() {
                this.httpServer.listen(0);
                this.listenPort = this.httpServer.address().port;
                this.hostname = await this._cloudflared.run(this.listenPort);
            }
            stop() {
                this._cloudflared.kill();
                this.httpServer.close();
            }
        }
        module.exports = { Client: DFNClient, Server: DFNServer, Tracker: DFNTracker, messages, partSize, HelperFunctions: helperFunctions };
    }
})(); 
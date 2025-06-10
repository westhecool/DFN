let exports = {};
const isBrowser = typeof window !== 'undefined' && typeof window.document !== 'undefined';
const VERSION = '0.0.1';
exports.VERSION = VERSION;
const TRACKERMESSAGES = {
    OK: 0,
    ERROR: 1,
    ERROR_MALFORMED_REQUEST: 2,
    ERROR_UNKNOWN_MESSAGE: 3,
    ERROR_INTERNAL_SERVER: 4,
    ERROR_ADDRESS_ALREADY_SET: 5,
    ANNOUNCE_ADDRESS: 6, // tell the tracker our public address
    ANNOUNCE_WANT: 7, // tell the tracker what files we are looking for
    ANNOUNCE_HAVE: 8, // tell the tracker what files we have and are seeding
    PEER: 9
};
exports.TRACKERMESSAGES = TRACKERMESSAGES;
// 32 bit message code space
const PROTOCOLMESSAGES = {
    PING: 0,
    PONG: 1,
    OK: 2,
    ERROR: 3,
    PUBKEY: 4,
    ENCRYPTED_REQUEST: 5,
    ENCRYPTED_RESPONSE: 6,
    ENCRYPTED_ANNOUNCE: 7,
    ERROR_MALFORMED_REQUEST: 8,
    ERROR_UNKNOWN_MESSAGE: 9,
    ERROR_INTERNAL_SERVER: 10
};
exports.PROTOCOLMESSAGES = PROTOCOLMESSAGES;
const MESSAGE_REQUEST_OFFSET = 0;
const MESSAGE_RESPONSE_OFFSET = Math.floor(0xFFFFFFFF / 3);
const MESSAGE_ERROR_OFFSET = Math.floor((0xFFFFFFFF / 3) * 2);
const MESSAGES = {
    REQ_PING: MESSAGE_REQUEST_OFFSET + 0,
    REQ_VERSION: MESSAGE_REQUEST_OFFSET + 1,
    REQ_FILE_INFO: MESSAGE_REQUEST_OFFSET + 2,
    REQ_FILE_PART: MESSAGE_REQUEST_OFFSET + 3,
    REQ_FILE_PROGRESSES: MESSAGE_REQUEST_OFFSET + 4,
    REQ_FILE_DOWNLOAD_LIST: MESSAGE_REQUEST_OFFSET + 5,
    RES_OK: MESSAGE_RESPONSE_OFFSET + 0,
    ERR_GENERAL: MESSAGE_ERROR_OFFSET + 0,
    ERR_INTERNAL_SERVER: MESSAGE_ERROR_OFFSET + 1,
    ERR_MALFORMED_REQUEST: MESSAGE_ERROR_OFFSET + 2,
    ERR_UNKNOWN_MESSAGE: MESSAGE_ERROR_OFFSET + 3,
    ERR_UNKNOWN_FILE: MESSAGE_ERROR_OFFSET + 4, // the peer does not have the requested file
    ERR_UNKNOWN_FILE_PART: MESSAGE_ERROR_OFFSET + 5, // the peer does not have the requested part of the file (yet)
    ERR_INVALID_PART_INDEX: MESSAGE_ERROR_OFFSET + 6, // the peer sent an invalid part index (eg. part index out of bounds)
    ERR_UNKNOWN_FILE_DOWNLOAD_LIST: MESSAGE_ERROR_OFFSET + 7
};
exports.MESSAGES = MESSAGES;
const DEFAULT_PART_SIZE = 1024 * 1024 * 10; // 10MB (do not change this)
exports.DEFAULT_PART_SIZE = DEFAULT_PART_SIZE;
const DEFAULT_TRACKERS = ['wss://dfn-tracker.westhedev.xyz/'];
exports.DEFAULT_TRACKERS = DEFAULT_TRACKERS;

// helper functions
// base64 encode, decode
function b64e(buffer) {
    if (isBrowser) {
        const bytes = new Uint8Array(buffer);
        const chunkSize = 0x8000; // prevents "too many arguments" error
        let binary = '';
        for (let i = 0; i < bytes.length; i += chunkSize) {
            binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
        }
        return btoa(binary);
    } else {
        return Buffer.from(buffer).toString('base64');
    }
}
function b64d(base64) {
    if (isBrowser) {
        const binary = atob(base64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    } else {
        return Buffer.from(base64, 'base64');
    }
}
// base16 (hex) encode, decode
function b16e(buffer) {
    if (isBrowser) {
        const bytes = new Uint8Array(buffer);
        const hex = new Array(bytes.length * 2);
        for (let i = 0; i < bytes.length; i++) {
            const byte = bytes[i];
            hex[i * 2] = byte.toString(16).padStart(2, '0')[0];
            hex[i * 2 + 1] = byte.toString(16).padStart(2, '0')[1];
        }
        return hex.join('');
    } else {
        return Buffer.from(buffer).toString('hex');
    }
}
function b16d(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error('Hex strings must have an even number of characters.');
    }
    if (isBrowser) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    } else {
        return Buffer.from(hex, 'hex');
    }
}
function bitsToBytes(bits) {
    if (!Array.isArray(bits)) throw new Error('bits must be an array.');
    while (bits.length % 8 !== 0) {
        bits.push(0);
    }
    bits.filter((bit) => {
        if (bit !== 0 && bit !== 1) throw new Error('bits must only contain 0s and 1s.');
    });
    const byteArray = [];
    for (let i = 0; i < bits.length; i += 8) {
        const byte = bits.slice(i, i + 8);
        let byteValue = 0;
        for (let j = 0; j < 8; j++) {
            byteValue |= (byte[j] << (7 - j));
        }
        byteArray.push(byteValue);
    }
    if (isBrowser) {
        return new Uint8Array(byteArray);
    } else {
        return Buffer.from(byteArray);
    }
}
function bytesToBits(byteArray) {
    if ((typeof Buffer !== 'undefined') && (byteArray instanceof Buffer)) byteArray = new Uint8Array(byteArray); // convert nodejs's Buffer class to Uint8Array automatically
    else if (!(byteArray instanceof Uint8Array)) throw new Error('byteArray must be Uint8Array.');
    const bits = [];
    for (const byte of byteArray) {
        for (let i = 7; i >= 0; i--) {
            bits.push((byte >> i) & 1); // extract each bit (from MSB to LSB)
        }
    }
    return bits;
}
function concatBuffers(buffers) {
    if (isBrowser) {
        const totalLength = buffers.reduce((sum, arr) => sum + arr.length, 0);
        const result = new Uint8Array(totalLength);
        let offset = 0;
        buffers.forEach(arr => {
            if (!(arr instanceof Uint8Array)) throw new Error('Buffer must be Uint8Array.');
            result.set(arr, offset);
            offset += arr.length;
        });
        return result;
    } else {
        return Buffer.concat(buffers);
    }
}
function getMessageName(code) { // try to find a message by code (useful for debugging)
    return Object.keys(MESSAGES).find(key => MESSAGES[key] == code) || '<unknown message>';
}
async function hash(data, algo = 'SHA-256', hex = true) {
    if (typeof data === 'string') data = (new TextEncoder()).encode(data);
    const hash = new Uint8Array(await crypto.subtle.digest(algo, data));
    return hex ? b16e(hash) : hash;
}
exports.functions = { b64e, b64d, b16e, b16d, bitsToBytes, bytesToBits, concatBuffers, getMessageName, hash };

// classes
class Encryption {
    constructor() {
        if (!crypto || !crypto.subtle) throw new Error('Encryption not supported in this environment. (if in a browser, make sure you are loading the site over HTTPS)');
    }
    RSAPublicKey = 'spki';
    RSAPrivateKey = 'pkcs8';
    async RSAMakeKey() {
        const key = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]), // commonly used public exponent
                hash: 'SHA-256'
            },
            true,
            ['encrypt', 'decrypt']
        );

        const privateKey = b64e(await crypto.subtle.exportKey(
            this.RSAPrivateKey,
            key.privateKey
        ));
        const publicKey = b64e(await crypto.subtle.exportKey(
            this.RSAPublicKey,
            key.publicKey
        ));

        return { privateKey, publicKey };
    }
    async RSAImportKey(key, type) {
        if (typeof key === 'string') key = b64d(key);
        return await crypto.subtle.importKey(
            type,
            key,
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256'
            },
            true,
            type == this.RSAPublicKey ? ['encrypt'] : ['decrypt']
        );
    }
    async RSAEncrypt(publicKey, buffer) {
        if (!(publicKey instanceof CryptoKey)) publicKey = await this.RSAImportKey(publicKey, this.RSAPublicKey);
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'RSA-OAEP'
            },
            publicKey,
            buffer
        );
        return new Uint8Array(encrypted);
    }
    async RSADecrypt(privateKey, buffer) {
        if (!(privateKey instanceof CryptoKey)) privateKey = await this.RSAImportKey(privateKey, this.RSAPrivateKey);
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'RSA-OAEP'
            },
            privateKey,
            buffer
        );
        return new Uint8Array(decrypted);
    }
    async AESMakeKey() {
        return b16e(crypto.getRandomValues(new Uint8Array(32)));
    }
    async AESImportKey(key) {
        if (typeof key === 'string') key = b16d(key);
        return await crypto.subtle.importKey(
            'raw',
            key,
            {
                name: 'AES-GCM',
                length: key.byteLength * 8
            },
            true,
            ['encrypt', 'decrypt']
        );
    }
    async AESEncrypt(key, buffer) {
        if (!(key instanceof CryptoKey)) key = await this.AESImportKey(key);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv
            },
            key,
            buffer
        );
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);
        return combined;
    }
    async AESDecrypt(key, buffer) {
        if (!(key instanceof CryptoKey)) key = await this.AESImportKey(key);
        if (isBrowser && !(buffer instanceof Uint8Array)) buffer = new Uint8Array(buffer);
        const iv = buffer.subarray(0, 12);
        const encrypted = buffer.subarray(12);
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv
            },
            key,
            encrypted
        );
        return new Uint8Array(decrypted);
    }
    async encryptPayload(publicKey, payload) {
        const key = await this.AESMakeKey();
        const encryptedKey = await this.RSAEncrypt(publicKey, b16d(key));
        const encrypted = await this.AESEncrypt(key, payload);
        const combined = new Uint8Array(encryptedKey.byteLength + encrypted.byteLength);
        combined.set(new Uint8Array(encryptedKey), 0);
        combined.set(new Uint8Array(encrypted), encryptedKey.byteLength);
        return combined;
    }
    async decryptPayload(privateKey, payload) {
        if (isBrowser && !(payload instanceof Uint8Array)) payload = new Uint8Array(payload);
        const key = payload.subarray(0, 256);
        const encrypted = payload.subarray(256);
        const decryptedKey = await this.RSADecrypt(privateKey, key);
        const decrypted = await this.AESDecrypt(decryptedKey, encrypted);
        return new Uint8Array(decrypted);
    }
}
const encryption = new Encryption(); // defnine a global encryption object
exports.encryption = encryption;

// BinMap v1.0.0 from https://github.com/westhecool/BinMap (bundled to maintain a single file library)
class BinMap {
    constructor({ stringEncoding } = {}) {
        this.stringEncoding = stringEncoding || 'utf-8';
        this.textEncoder = new TextEncoder(this.stringEncoding);
        this.textDecoder = new TextDecoder(this.stringEncoding);
    }
    TYPES = {
        NULL: 0,
        STRING: 1,
        NUMBER: 2,
        BOOLEAN: 3,
        BINARY: 4,
        OBJECT: 5,
        ARRAY: 6
    }
    _isBinary(object) {
        return (
            object instanceof ArrayBuffer ||
            ArrayBuffer.isView(object) || // TypedArrays and DataView
            object?.buffer instanceof ArrayBuffer // slices of a TypedArray
        );
    }
    _create(type, key, value = new Uint8Array(0)) {
        if (typeof key === 'string') key = this.textEncoder.encode(key);
        if (!(value instanceof Uint8Array)) throw new Error('Value must be Uint8Array.');
        const headerSize = 1 + 4 + key.length + 4;
        const buferSize = headerSize + value.length;
        let header = new Uint8Array(headerSize);
        header.set(key, 5);
        header = new DataView(header.buffer);
        header.setUint8(0, type);
        header.setUint32(1, key.length, true);
        header.setUint32(5 + key.length, value.length, true);
        return concatBuffers([new Uint8Array(header.buffer), value]);
    }
    _serializeObject(object) {
        const buffers = [];
        for (const key in object) { // using "in" will always enumerate the keys of the object as a string (regardless if it is a array or not)
            switch (typeof object[key]) {
                case 'object': {
                    if (object[key] === null) {
                        buffers.push(this._create(this.TYPES.NULL, key));
                    } else if (this._isBinary(object[key])) {
                        let value;
                        if (ArrayBuffer.isView(object[key])) { // TypedArrays and DataView (nodejs Buffer included)
                            value = object[key].buffer.slice(object[key].byteOffset || 0, (object[key].byteOffset || 0) + object[key].byteLength);
                        } else {
                            value = object[key].buffer || object[key]; // possable bad handling of slices if object[key] is a uncommon TypedArray but not detected
                        }
                        buffers.push(this._create(this.TYPES.BINARY, key, new Uint8Array(value)));
                    } else {
                        buffers.push(this._create(Array.isArray(object[key]) ? this.TYPES.ARRAY : this.TYPES.OBJECT, key, this._serializeObject(object[key])));
                    }
                    break;
                }
                case 'string': {
                    buffers.push(this._create(this.TYPES.STRING, key, this.textEncoder.encode(object[key])));
                    break;
                }
                case 'number': {
                    const view = new DataView(new ArrayBuffer(8));
                    view.setBigUint64(0, BigInt(object[key]), true);
                    buffers.push(this._create(this.TYPES.NUMBER, key, new Uint8Array(view.buffer)));
                    break;
                }
                case 'bigint': {
                    const view = new DataView(new ArrayBuffer(8));
                    view.setBigUint64(0, object[key], true);
                    buffers.push(this._create(this.TYPES.NUMBER, key, new Uint8Array(view.buffer)));
                    break;
                }
                case 'boolean': {
                    let view = new DataView(new ArrayBuffer(1));
                    view.setUint8(0, object[key] ? 1 : 0);
                    buffers.push(this._create(this.TYPES.BOOLEAN, key, new Uint8Array(view.buffer)));
                    break;
                }
                case 'undefined': { // skip over undefined values
                    continue;
                    break;
                }
                default: {
                    throw new Error('Unsupported type: ' + typeof object[key]);
                    break;
                }
            }
        }
        return concatBuffers(buffers);
    }
    serialize(object) {
        if (!(object instanceof Object)) throw new Error('Object must be a Object.');
        const rootType = Array.isArray(object) ? this.TYPES.ARRAY : this.TYPES.OBJECT; // type of the root/base object
        return concatBuffers([new Uint8Array([rootType]), this._serializeObject(object)]);
    }
    _deserializeObject(type, buffer) {
        const view = new DataView(buffer.buffer);
        let object = {};
        let position = 0;
        while (position < buffer.byteLength) {
            const type = view.getUint8(position);
            position += 1;
            const keyLength = view.getUint32(position, true);
            position += 4;
            const key = this.textDecoder.decode(buffer.slice(position, position + keyLength));
            position += keyLength;
            const valueLength = view.getUint32(position, true);
            position += 4;
            const value = buffer.slice(position, position + valueLength);
            position += valueLength;
            switch (type) {
                case this.TYPES.NULL: {
                    object[key] = null;
                    break;
                }
                case this.TYPES.STRING: {
                    object[key] = this.textDecoder.decode(value);
                    break;
                }
                case this.TYPES.NUMBER: {
                    const view = new DataView(value.buffer);
                    const number = view.getBigUint64(0, true);
                    if (number <= Number.MAX_SAFE_INTEGER) object[key] = Number(number);
                    else object[key] = number;
                    break;
                }
                case this.TYPES.BOOLEAN: {
                    object[key] = value[0] == 1;
                    break;
                }
                case this.TYPES.BINARY: {
                    object[key] = (typeof Buffer !== 'undefined') ? Buffer.from(value) : value;
                    break;
                }
                case this.TYPES.OBJECT: {
                    object[key] = this._deserializeObject(this.TYPES.OBJECT, value);
                    break;
                }
                case this.TYPES.ARRAY: {
                    object[key] = this._deserializeObject(this.TYPES.ARRAY, value);
                    break;
                }
                default: {
                    throw new Error('Unsupported type: ' + type);
                    break;
                }
            }
        }
        if (type == this.TYPES.ARRAY) {
            const array = [];
            for (const key in object) array[parseInt(key)] = object[key];
            return array;
        } else return object;
    }
    deserialize(buffer) {
        if ((typeof Buffer !== 'undefined') && buffer instanceof Buffer) buffer = new Uint8Array(buffer); // convert nodejs's Buffer class to Uint8Array automatically
        if (!(buffer instanceof Uint8Array)) throw new Error('Buffer must be Uint8Array.');
        const rootType = buffer[0];
        return this._deserializeObject(rootType, buffer.slice(1));
    }
}
const binmap = new BinMap(); // define a global binmap object
exports.binmap = binmap;

class Serializer {
    constructor() {
        this.map = new BinMap();
        this.textEncoder = new TextEncoder('utf-8');
        this.textDecoder = new TextDecoder('utf-8');
    }
    serialize(object) {
        if (!this.validate(object)) throw new Error('Invalid object.');
        // "distributed file list download list file"
        return concatBuffers([this.textEncoder.encode('DFNDLF'), this.map.serialize(object)])
    }
    deserialize(buffer) {
        if (this.textDecoder.decode(buffer.subarray(0, 6)) != 'DFNDLF') throw new Error('Corrupted file.');
        const object = this.map.deserialize(buffer.subarray(6));
        if (!object.version == 1) throw new Error('Unsupported version.');
        if (!this.validate(object)) throw new Error('Corrupted file.');
        return object;
    }
    validate(object) {
        if (!object || typeof object !== 'object' || !object.content || typeof object.content !== 'object' || !object.name || typeof object.name !== 'string' || !object.size || typeof object.size !== 'number' || !object.version || typeof object.version !== 'number' || !object.created || typeof object.created !== 'number') return false;
        if (object.content.type == 'file') return this.validateFile(object.content);
        else if (object.content.type == 'folder') return this.validateFolder(object.content);
        else return false;
    }
    validateFile(object) {
        return !(!object || typeof object !== 'object' || Array.isArray(object) || object.type != 'file' || !object.path || typeof object.path !== 'string' || !object.info || typeof object.info !== 'object' || !object.info.partsCount || typeof object.info.partsCount !== 'number' || !object.info.partSize || typeof object.info.partSize !== 'number' || !object.info.parts || !object.info.size || typeof object.info.size !== 'number' || !object.hashId || typeof object.hashId !== 'string');
    }
    validateFolder(object) {
        if ((!object || typeof object !== 'object' || Array.isArray(object) || object.type != 'folder' || !object.files || typeof object.files !== 'object' || Array.isArray(object.files) || !object.path || typeof object.path !== 'string' || !object.size || typeof object.size !== 'number')) return false;
        for (const key in object.files) {
            if (!object.files[key] || typeof object.files[key] !== 'object') return false;
            if (object.files[key].type == 'file') {
                if (!this.validateFile(object.files[key])) return false;
            }
            else if (object.files[key].type == 'folder') {
                if (!this.validateFolder(object.files[key])) return false;
            }
            else return false;
        }
        return true;
    }
}
const serializer = new Serializer(); // defnine a global serializer object
exports.serializer = serializer;

async function decodeDownloadList(buffer) {
    return serializer.deserialize(buffer);
}
exports.decodeDownloadList = decodeDownloadList;

if (!isBrowser) global.WebSocket = (await import('ws')).WebSocket;

class ProtocolClient {
    constructor(url) {
        if (!url) throw new Error('url is required');
        this.onAnnounce = null;
        this.keys = null;
        this.remotePublicKey = null;
        this.url = url.replace('http://', 'ws://').replace('https://', 'wss://');
        this.ws = null;
        this.open = false;
        this.textDecoder = new TextDecoder();
        this.textEncoder = new TextEncoder();
        this._pingInterval = null;
    }
    async _getBuffer(event) {
        if (typeof Buffer !== 'undefined') {
            if (event instanceof Buffer) return new Uint8Array(event);
            else if (event.data instanceof Buffer) return new Uint8Array(event.data);
        }
        if (event.data instanceof Blob) {
            return new Uint8Array(await event.data.arrayBuffer());
        }
        throw new Error('Unsupported WebSocket implementation.');
    }
    connect(timeout = 30000) {
        return new Promise(async (resolve, reject) => {
            let el;
            let ml;
            let resloved = false;
            let timeoutN;
            try {
                if (this.open) await this.disconnect(); // reconnect
                this.keys = null;
                this.remotePublicKey = null;
                this.ws = null;
                this.open = false;
                this._pingInterval = null;
                this.keys = await encryption.RSAMakeKey();
                this.keys.publicKey = b64d(this.keys.publicKey);
                this.keys.privateKey = await encryption.RSAImportKey(this.keys.privateKey, encryption.RSAPrivateKey); // import to avoid having to import every time we process a message
                this.ws = new WebSocket(this.url); // TODO: better error handling if the tunnel gets rate limited (will happen if the server already has too many connections (200+))
                if (typeof this.ws.setMaxListeners === 'function') this.ws.setMaxListeners(0);
                this.open = false;
                ml = async (e) => {
                    const buf = await this._getBuffer(e);
                    if (buf.length < 4) return;
                    const view = new DataView(buf.buffer);
                    const bmsg = view.getUint32(0, true);
                    if (bmsg == PROTOCOLMESSAGES.PUBKEY && !resloved) {
                        resloved = true;
                        remove();
                        this.remotePublicKey = await encryption.RSAImportKey(buf.subarray(4), encryption.RSAPublicKey);
                        const sview = new DataView(new ArrayBuffer(4));
                        sview.setUint32(0, PROTOCOLMESSAGES.PUBKEY, true);
                        this.ws.send(concatBuffers([new Uint8Array(sview.buffer), this.keys.publicKey]));
                        this.open = true;
                        this.ws.addEventListener('message', async (e) => {
                            if (typeof this.onAnnounce === 'function') {
                                const buf = await this._getBuffer(e);
                                if (buf.length < 4) return;
                                const view = new DataView(buf.buffer);
                                const bmsg = view.getUint32(0, true);
                                if (bmsg == PROTOCOLMESSAGES.ENCRYPTED_ANNOUNCE) {
                                    // base message + RSA payload + AES block size
                                    if (buf.length < (4 + 256 + 16)) return;
                                    const payload = await encryption.decryptPayload(this.keys.privateKey, buf.subarray(4));
                                    if (payload.length < 8) return;
                                    const payloadview = new DataView(payload.buffer);
                                    const responseVersion = payloadview.getUint32(0, true); // not used yet (reserved for future use)
                                    const message = payloadview.getUint32(4, true);
                                    const data = payload.slice(8);
                                    this.onAnnounce(message, data);
                                }
                            }
                        });
                        this._pingInterval = setInterval(async () => {
                            if (!this.open) {
                                if (this._pingInterval) clearInterval(this._pingInterval);
                                this._pingInterval = null;
                                return;
                            }
                            try {
                                await this.ping();
                            } catch (e) { }
                        }, 30000); // keep connection alive
                        resolve();
                    }
                };
                el = async (e) => {
                    if (!resloved) {
                        resloved = true;
                        remove();
                        try {
                            await this.disconnect();
                        } catch (e) { }
                        this.open = false;
                        reject(e);
                    }
                };
                const add = () => {
                    this.ws.addEventListener('message', ml);
                    this.ws.addEventListener('error', el);
                };
                const remove = () => {
                    if (timeoutN) clearTimeout(timeoutN);
                    try {
                        this.ws.removeEventListener('message', ml);
                    } catch (e) { }
                    try {
                        this.ws.removeEventListener('error', el);
                    } catch (e) { }
                };
                this.ws.addEventListener('close', () => {
                    this.open = false;
                });
                add();
                timeoutN = setTimeout(async () => {
                    if (!resloved) {
                        resloved = true;
                        remove();
                        try {
                            await this.disconnect();
                        } catch (e) { }
                        this.open = false;
                        reject(new Error('Timed out waiting for connection to be established.'));
                    }
                }, timeout);
            } catch (e) {
                if (!resloved) {
                    resloved = true;
                    try {
                        remove();
                    } catch (e) { }
                    reject(e);
                }
            }
        });
    }
    query(message, data = null, timeout = 10000) {
        return new Promise(async (resolve, reject) => {
            let resloved = false;
            let timeoutN;
            let ml;
            try {
                if (!this.open) throw new Error('Connection closed.');
                if (typeof message !== 'number') throw new Error('Message must be a number.');
                if (data === null) data = new Uint8Array(0);
                if ((typeof Buffer !== 'undefined') && (data instanceof Buffer)) data = new Uint8Array(data); // convert nodejs's Buffer class to Uint8Array automatically
                if (!(data instanceof Uint8Array)) throw new Error('Data must be Uint8Array.');
                let resloved = false;
                const header = new Uint8Array(12); // header: request version (4) + request id (4) + message code (4)
                header.set(crypto.getRandomValues(new Uint8Array(4)), 4); // request id
                const sview = new DataView(header.buffer);
                sview.setUint32(0, 1, true); // request version - not used yet (reserved for future use)
                const reqId = sview.getUint32(4, true); // get request id as a number
                sview.setUint32(8, message, true); // message code
                const payload = concatBuffers([header, data]);
                const encrypted = await encryption.encryptPayload(this.remotePublicKey, payload);
                ml = async (e) => {
                    try {
                        const buf = await this._getBuffer(e);
                        if (buf.length < 4) return;
                        const view = new DataView(buf.buffer);
                        const bmsg = view.getUint32(0, true);
                        if (bmsg == PROTOCOLMESSAGES.ENCRYPTED_RESPONSE) {
                            // base message + RSA payload + AES block size
                            if (buf.length < (4 + 256 + 16)) return;
                            const payload = await encryption.decryptPayload(this.keys.privateKey, buf.subarray(4));
                            if (payload.length < 12) return;
                            const payloadview = new DataView(payload.buffer);
                            const responseVersion = payloadview.getUint32(0, true); // not used yet (reserved for future use)
                            const r_reqId = payloadview.getUint32(4, true);
                            const r_message = payloadview.getUint32(8, true);
                            const r_data = payload.slice(12);
                            if (r_reqId == reqId) {
                                if (!resloved) {
                                    resloved = true;
                                    if (timeoutN) clearTimeout(timeoutN);
                                    this.ws.removeEventListener('message', ml);
                                    resolve({
                                        message: r_message,
                                        data: isBrowser ? r_data : Buffer.from(r_data)
                                    });
                                }
                            }
                        }
                    } catch (e) { } // errors that can occur when running this.stop() #2
                };
                this.ws.addEventListener('message', ml);
                const sview2 = new DataView(new ArrayBuffer(4));
                sview2.setUint32(0, PROTOCOLMESSAGES.ENCRYPTED_REQUEST, true);
                this.ws.send(concatBuffers([new Uint8Array(sview2.buffer), encrypted]));
                timeoutN = setTimeout(() => {
                    if (!resloved) {
                        resloved = true;
                        try {
                            this.ws.removeEventListener('message', ml);
                        } catch (e) { }
                        reject(new Error('Timed out waiting for response.'));

                    }
                }, timeout);
            } catch (e) {
                if (!resloved) {
                    resloved = true;
                    if (timeoutN) clearTimeout(timeoutN);
                    try {
                        this.ws.removeEventListener('message', ml);
                    } catch (e) { }
                    reject(e);
                }
            }
        });
    }
    async disconnect() {
        if (this._pingInterval) clearInterval(this._pingInterval);
        this._pingInterval = null;
        try {
            this.ws.close();
        } catch (e) { }
        this.keys = null;
        this.remotePublicKey = null;
        this.ws = null;
        this.open = false;
    }
    ping(timeout = 5000) {
        return new Promise((resolve, reject) => {
            let ml;
            let resloved = false;
            let timeoutN;
            try {
                if (!this.open) throw new Error('Connection closed.');
                ml = async (e) => {
                    const buf = await this._getBuffer(e);
                    if (buf.length < 4) return;
                    const view = new DataView(buf.buffer);
                    const bmsg = view.getUint32(0, true);
                    if (bmsg == PROTOCOLMESSAGES.PONG && !resloved) {
                        resloved = true;
                        if (timeoutN) clearTimeout(timeoutN);
                        this.ws.removeEventListener('message', ml);
                        resolve(true);
                    }
                };
                this.ws.addEventListener('message', ml);
                const sview = new DataView(new ArrayBuffer(4));
                sview.setUint32(0, PROTOCOLMESSAGES.PING, true);
                this.ws.send(new Uint8Array(sview.buffer));
                timeoutN = setTimeout(() => {
                    if (!resloved) {
                        resloved = true;
                        try {
                            this.ws.removeEventListener('message', ml);
                        } catch (e) { }
                        reject(new Error('Timed out waiting for ping response.'));
                    }
                }, timeout);
            } catch (e) {
                if (!resloved) {
                    resloved = true;
                    if (timeoutN) clearTimeout(timeoutN);
                    try {
                        this.ws.removeEventListener('message', ml);
                    } catch (e) { }
                    reject(e);
                }
            }
        })
    }
}

class responseError extends Error {
    constructor(message, code, codeName) {
        super(message);
        this.code = code;
        this.codeName = codeName;
    }
}
exports.responseError = responseError;
class Client {
    constructor(url) {
        if (!url) throw new Error('url is required.');
        this.url = url.replace('http://', 'ws://').replace('https://', 'wss://');
        this.socket = new ProtocolClient(this.url);
        this.lastRequest = 0;
    }
    async connect() {
        await this.socket.connect();
        this.lastRequest = Date.now();
    }
    async disconnect() {
        await this.socket.disconnect();
        this.lastRequest = 0;
    }
    async requestVersion() {
        if (!this.socket.open) throw new Error('Socket is not connected.');
        const r = await this.socket.query(MESSAGES.REQ_VERSION);
        if (r.message != MESSAGES.RES_OK) {
            const messageName = getMessageName(r.message);
            throw new responseError(`Got unexpected response from server: ${messageName} (${r.message})`, r.message, messageName);
        }
        this.lastRequest = Date.now();
        return this.textDecoder.decode(r.data);
    }
    async requestFile(hashId) {
        if (!this.socket.open) throw new Error('Socket is not connected.');
        if (!hashId) throw new Error('hashId is required.');
        if (typeof hashId === 'string') hashId = b16d(hashId);
        else hashId = new Uint8Array(hashId);
        const r = await this.socket.query(MESSAGES.REQ_FILE_INFO, hashId);
        if (r.message != MESSAGES.RES_OK) {
            const messageName = getMessageName(r.message);
            throw new responseError(`Got unexpected response from server: ${messageName} (${r.message})`, r.message, messageName);
        }
        this.lastRequest = Date.now();
        return binmap.deserialize(r.data);
    }
    async requestFilePart(hashId, partIndex) {
        if (!this.socket.open) throw new Error('Socket is not connected.');
        if (!hashId) throw new Error('hashId is required.');
        if (typeof hashId === 'string') hashId = b16d(hashId);
        else hashId = new Uint8Array(hashId);
        if (typeof partIndex !== 'number' || partIndex < 0 || partIndex > 0xFFFFFFFF) throw new Error('partIndex is invalid.');
        const index = new DataView(new ArrayBuffer(4));
        index.setUint32(0, partIndex, true);
        const r = await this.socket.query(MESSAGES.REQ_FILE_PART, concatBuffers([hashId, new Uint8Array(index.buffer)]));
        if (r.message != MESSAGES.RES_OK) {
            const messageName = getMessageName(r.message);
            throw new responseError(`Got unexpected response from server: ${messageName} (${r.message})`, r.message, messageName);
        }
        this.lastRequest = Date.now();
        return r.data;
    }
    async requestFileProgresses(hashIds) {
        if (!this.socket.open) throw new Error('Socket is not connected.');
        if (!Array.isArray(hashIds) || hashIds.length == 0) throw new Error('hashId is required.');
        const hashIdsBuffer = hashIds.map(h => {
            if (typeof h === 'string') return b16d(h);
            else throw new Error('hashId is invalid.');
        });
        const r = await this.socket.query(MESSAGES.REQ_FILE_PROGRESSES, concatBuffers(hashIdsBuffer));
        if (r.message != MESSAGES.RES_OK) {
            const messageName = getMessageName(r.message);
            throw new responseError(`Got unexpected response from server: ${messageName} (${r.message})`, r.message, messageName);
        }
        const view = new DataView((new Uint8Array(r.data)).buffer);
        let offset = 0;
        const progresses = {};
        let i = 0;
        while (offset < r.data.length) {
            const arrLength = view.getUint32(offset, true);
            offset += 4;
            if (arrLength == 0) { // does not have the file
                //progresses[hashIds[i]] = null; // do we need to handle this case? or just omit it?
            } else {
                const byteLength = Math.ceil(arrLength / 8);
                progresses[hashIds[i]] = bytesToBits(r.data.subarray(offset, offset + byteLength)).slice(0, arrLength);
                offset += byteLength;
            }
            i++;
        }
        this.lastRequest = Date.now();
        return progresses;
    }
    async requestFileDownloadList(hash) {
        if (!this.socket.open) throw new Error('Socket is not connected.');
        if (!hash) throw new Error('hash is required.');
        if (typeof hash === 'string') hash = b16d(hash);
        else hash = new Uint8Array(hash);
        const r = await this.socket.query(MESSAGES.REQ_FILE_DOWNLOAD_LIST, hash);
        if (r.message != MESSAGES.RES_OK) {
            const messageName = getMessageName(r.message);
            throw new responseError(`Got unexpected response from server: ${messageName} (${r.message})`, r.message, messageName);
        }
        this.lastRequest = Date.now();
        return binmap.deserialize(r.data);
    }
}
exports.Client = Client;

class Tracker {
    constructor(url) {
        if (!url) throw new Error('url is required.');
        this.onpeer = (p) => { };
        this.url = url.replace('http://', 'ws://').replace('https://', 'wss://');
        this.serverAddress = null;
        this.socket = new ProtocolClient(this.url);
    }
    async start() {
        this.serverAddress = null;
        this.socket.onAnnounce = async (message, data) => {
            if (message == TRACKERMESSAGES.PEER) {
                this.onpeer((new TextDecoder('utf-8')).decode(data));
            }
        };
        await this.socket.connect();
    }
    async stop() {
        await this.socket.disconnect();
        this.serverAddress = null;
    }
    async announceWant(files) {
        if (!this.socket.open) throw new Error('Socket is not connected.');
        if (!Array.isArray(files) && !(files instanceof Uint8Array)) throw new Error('Files must be an array or Uint8Array.');
        if (Array.isArray(files)) {
            files = concatBuffers(files.map(f => b16d(f)));
        }
        await this.socket.query(TRACKERMESSAGES.ANNOUNCE_WANT, files);
    }
    async announceServerAddress(serverAddress) {
        if (!this.socket.open) throw new Error('Socket is not connected.');
        if (!serverAddress) throw new Error('Server address was not provided.');
        if (this.serverAddress) throw new Error('Server address was already announced.');
        this.serverAddress = serverAddress;
        await this.socket.query(TRACKERMESSAGES.ANNOUNCE_ADDRESS, (new TextEncoder('utf-8')).encode(this.serverAddress));
    }
    async announceHave(files) {
        if (!this.socket.open) throw new Error('Socket is not connected.');
        if (!this.serverAddress) throw new Error('Unable to announce. Server address was never announced.');
        if (!Array.isArray(files) && !(files instanceof Uint8Array)) throw new Error('Files must be an array or Uint8Array.');
        if (Array.isArray(files)) {
            files = concatBuffers(files.map(f => b16d(f)));
        }
        await this.socket.query(TRACKERMESSAGES.ANNOUNCE_HAVE, files);
    }
}
exports.Tracker = Tracker;

// TODO: both BasePeer and FullPeer need better error handling

class DownloadProgressReport {
    constructor(file) {
        const now = Date.now();
        this.path = file.path || '<memory>';
        this.hashId = file.hashId;
        this.start = file.start;
        this.total = file.size;
        this.received = file.received;
        this.needed = file.size - file.received;
        this.speed = (now - file.start) > 0 ? (file.receivedSinceStart / (now - file.start)) * 1000 : 0;
        this.time = (now - file.start) / 1000;
        this.timeLeft = (file.size - file.received) / this.speed;
        this.percent = (file.received / file.size) * 100;
        this.done = this.percent >= 100;
        this.partsCount = file.progress.length;
        this.partSize = file.partSize;
        this.partsHave = file.progress.map((value, index) => value === 1 ? index : -1).filter(index => index !== -1);
        this.partsHaveCount = this.partsHave.length;
        this.partsNeeded = file.progress.map((value, index) => value === 0 ? index : -1).filter(index => index !== -1);
        this.partsNeededCount = this.partsNeeded.length;
    }
}
exports.DownloadProgressReport = DownloadProgressReport;
class BasePeer { // will be extended later if not running in browser
    constructor({ trackers, maxClients } = {}) {
        if (!Array.isArray(trackers)) trackers = DEFAULT_TRACKERS;
        if (typeof maxClients !== 'number' || maxClients < 1) maxClients = 0;
        this.maxClients = maxClients;
        this.clients = {};
        this.clientsBlacklist = {};
        this.lookingFor = [];
        this.trackers = {};
        this.running = false;
        this.address = null;
        this.lastAnnounce = 0;
        this._clientUpdateLoop = null;
        for (const tracker of trackers) {
            this.trackers[tracker] = new Tracker(tracker);
        }
    }
    async _onPeer(peer) {
        if (peer == this.address) return;
        if (!this.clients[peer]) {
            if (this.maxClients > 0 && Object.keys(this.clients).length >= this.maxClients) return;
            this.clients[peer] = {
                client: new Client(peer),
                files: {},
                running_part_requests: 0
            };
            try {
                await this.clients[peer].client.connect();
                if (this.lookingFor.length > 0) this.clients[peer].files = await this.clients[peer].client.requestFileProgresses(this.lookingFor);
            } catch (e) { }
        }
    }
    async start() {
        if (this.running) await this.stop(); // restart
        this.running = false;
        this.address = null;
        this.lastAnnounce = 0;
        this.lookingFor = [];
        this.clients = {};
        this.clientsBlacklist = {};
        this._clientUpdateLoop = setInterval(async () => {
            for (const tracker in this.trackers) {
                if (!this.trackers[tracker].socket.open) {
                    setTimeout(async () => {
                        try {
                            await this.trackers[tracker].start();
                            await this.announce();
                        } catch (e) { }
                    }, 1000); // remove tracker after x retries?
                }
            }
            for (const client in this.clients) {
                if (!this.clients[client].client.socket.open) {
                    delete this.clients[client];
                    continue;
                }
                if ((Date.now() - this.clients[client].client.lastRequest) >= 60000) { // remove any clients we haven't talked to in 1 minute
                    try {
                        await this.clients[client].client.disconnect();
                    } catch (e) { }
                    delete this.clients[client];
                }
            }
            await this.updateFileProgresses();
        }, 10000);
        for (const tracker in this.trackers) {
            this.trackers[tracker].onpeer = (p) => this._onPeer(p);
            try {
                await this.trackers[tracker].start();
            } catch (e) { }
        }
        this.running = true;
        if (typeof this._serverStart === 'function') await this._serverStart();
    }
    async stop() {
        if (this._clientUpdateLoop) clearInterval(this._clientUpdateLoop);
        this._clientUpdateLoop = null;
        for (const tracker in this.trackers) {
            await this.trackers[tracker].stop();
        }
        for (const client in this.clients) {
            await this.clients[client].client.disconnect();
        }
        this.running = false;
        this.address = null;
        this.lastAnnounce = 0;
        this.lookingFor = [];
        this.clients = {};
        this.clientsBlacklist = {};
        if (typeof this._serverStop === 'function') await this._serverStop();
    }
    async updateFileProgresses() {
        if (!this.running) throw new Error('Peer is not running.');
        if (this.lookingFor.length == 0) return;
        for (const client in this.clients) {
            try {
                if (!this.clients[client].client.socket.open) continue;
                this.clients[client].files = await this.clients[client].client.requestFileProgresses(this.lookingFor);
            } catch (e) { }
        }
    }
    async streamFile(file, cb) {
        if (!this.running) throw new Error('Peer is not running.');
        if (typeof file === 'string') throw new Error('File lookup is not supported yet.');
        if (!serializer.validateFile(file)) throw new Error('Invalid file.');
        if (!typeof cb === 'function') throw new Error('Callback must be a function.');
        let running = 0;
        let writeIndex = 0;
        let readIndex = 0;
        let read = 0;
        let paused = false;
        let aborted = false;
        const start = Date.now();
        const progress = (new Array(file.info.partsCount)).fill(0);
        while (readIndex < file.info.partsCount && !aborted) {
            if (!this.lookingFor.includes(file.hashId)) {
                this.lookingFor.push(file.hashId);
                setTimeout(() => this.announce(), 0);
            }
            for (const client in this.clients) {
                if (aborted) break;
                if (this.clients[client].client.socket.open && this.clients[client].files[file.hashId] && this.clients[client].files[file.hashId][readIndex] && this.clients[client].running_part_requests < 2) { // 2 requests at a time seems the optimal amount for speed and throughput
                    while (paused) await new Promise(r => setTimeout(r, 10));
                    const index = parseInt(readIndex); // recast
                    this.clients[client].running_part_requests++;
                    setTimeout(async () => {
                        if (aborted) {
                            running--;
                            return;
                        }
                        // TODO: error handling here
                        const part = await this.clients[client].client.requestFilePart(file.hashId, index);
                        this.clients[client].running_part_requests--;
                        if (aborted) {
                            running--;
                            return;
                        }
                        if (b16e(file.info.parts.subarray(index * 32, (index + 1) * 32)) !== await hash(part, 'SHA-256')) {
                            throw new Error('Part hash mismatch.');
                        }
                        while ((writeIndex < index || paused) && !aborted) await new Promise(r => setTimeout(r, 10));
                        if (aborted) {
                            running--;
                            return;
                        }
                        read += part.length;
                        running--;
                        progress[index] = 1;
                        cb(part, new DownloadProgressReport({
                            hashId: file.hashId,
                            size: file.info.size,
                            partSize: file.info.partSize,
                            received: read,
                            receivedSinceStart: read,
                            start: start,
                            progress: progress
                        }), (v = true) => paused = Boolean(v), () => aborted = true);
                        writeIndex++;
                    }, 0);
                    readIndex++;
                    running++;
                }
            }
            await new Promise(r => setTimeout(r, 10));
        }
        while (running > 0) await new Promise(r => setTimeout(r, 10));
        if (this.lookingFor.includes(file.hashId)) this.lookingFor.splice(this.lookingFor.indexOf(file.hashId), 1);
        return !aborted;
    }
    async getFileBuffer(file) {
        if (!this.running) throw new Error('Peer is not running.');
        const chunks = [];
        await this.streamFile(file, (c) => chunks.push(c));
        return concatBuffers(chunks);
    }
    async announce() {
        if (!this.running) throw new Error('Peer is not running.');
        for (const tracker in this.trackers) {
            if (!this.trackers[tracker].socket.open) continue;
            try {
                await this.trackers[tracker].announceWant(this.lookingFor);
            } catch (e) { }
        }
        this.lastAnnounce = Date.now();
    }
    async addTracker(tracker) {
        if (!this.running) throw new Error('Peer is not running.');
        if (!this.trackers[tracker]) {
            this.trackers[tracker] = new Tracker(tracker);
            this.trackers[tracker].onpeer = (p) => this._onPeer(p);
            try {
                await this.trackers[tracker].start();
                await this.announce();
            } catch (e) { }
        } else {
            throw new Error('Tracker already exists.');
        }
    }
    async removeTracker(tracker) {
        if (!this.running) throw new Error('Peer is not running.');
        if (this.trackers[tracker]) {
            await this.trackers[tracker].stop();
            delete this.trackers[tracker];
        } else {
            throw new Error('Tracker not found.');
        }
    }
}
if (isBrowser) exports.Peer = BasePeer;

if (!isBrowser) {
    // server only classes
    const pathlib = await import('path');
    const fs = await import('fs');
    const CP = await import('child_process');
    const { EventEmitter } = await import('events');
    const { WebSocketServer } = await import('ws');
    let __dirname; // define __dirname in ESM
    if (process.platform == 'win32') {
        __dirname = pathlib.dirname(import.meta.url.replace('file:///', '').replace(/\//g, '\\'));
    } else {
        __dirname = pathlib.dirname(import.meta.url.replace('file://', ''));
    }

    async function readExactly(fd, length, offset = 0) {
        const buffer = Buffer.alloc(length);
        let totalRead = 0;
        while (totalRead < length) {
            const { bytesRead } = await fd.read(buffer, totalRead, length - totalRead, offset + totalRead);
            if (bytesRead == 0) break; // EOF
            totalRead += bytesRead;
        }
        return buffer.subarray(0, totalRead); // trim (in case of EOF)
    }
    exports.functions.readExactly = readExactly;
    async function writeExactly(fd, buffer, offset = 0) {
        let totalWritten = 0;
        while (totalWritten < buffer.length) {
            const { bytesWritten } = await fd.write(buffer, totalWritten, buffer.length - totalWritten, offset + totalWritten);
            if (bytesWritten == 0) throw new Error('The operating system refused a write request.');
            totalWritten += bytesWritten;
        }
        return totalWritten;
    }
    exports.functions.writeExactly = writeExactly;

    class Cloudflared extends EventEmitter {
        constructor() {
            super();
            this.process = null;
            this.hostname = null;
            this.running = false;
            this.exited = false;
            this.killed = false;
        }
        _cloudflaredExeName() {
            if (process.platform == 'win32') {
                return __dirname + '\\cloudflared.exe';
            } else {
                return __dirname + '/cloudflared';
            }
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
            if (process.platform == 'win32') {
                const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-${this._archMap(process.arch)}.exe`;
                const request = await fetch(url, { redirect: 'follow' });
                if (request.status != 200) throw new Error('Failed to download cloudflared.');
                const data = await request.arrayBuffer();
                await fs.promises.writeFile(this._cloudflaredExeName(), Buffer.from(data));
            } else if (process.platform == 'linux') {
                const url = `https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${this._archMap(process.arch)}`;
                const request = await fetch(url, { redirect: 'follow' });
                if (request.status != 200) throw new Error('Failed to download cloudflared.');
                const data = await request.arrayBuffer();
                await fs.promises.writeFile(this._cloudflaredExeName(), Buffer.from(data));
                await fs.promises.chmod(this._cloudflaredExeName(), 0o755); // make it executable
            } else {
                throw new Error('Platform not implemented.');
            }
        }
        async run({ url, logging, wait, timeout, dnsDelay } = {}) {
            if (!url) throw new Error('URL is required');
            if (typeof logging !== 'boolean') logging = false;
            if (typeof wait !== 'boolean') wait = false;
            if (typeof timeout !== 'number') timeout = 60000;
            if (typeof dnsDelay !== 'number') dnsDelay = 20000; // a delay to wait for cloudflare to set up DNS
            if (!fs.existsSync(this._cloudflaredExeName())) {
                this.emit('downloading')
                if (logging) console.log('[CF]: Downloading cloudflared...');
                await this.download();
                this.emit('downloaded');
            }
            if (this.process) {
                try {
                    this.process.kill();
                } catch (e) { }
            }
            this.process = null;
            this.hostname = null;
            this.killed = false;
            this.exited = false;
            this.running = true;
            this.process = CP.spawn(this._cloudflaredExeName(), ['tunnel', '--url', url]);
            this.process.stdout.on('data', (data) => {
                this.emit('output', data.toString('utf-8').trim());
                if (logging) console.log('[CF][OUT]:', data.toString('utf-8').trim());
            });
            this.process.stderr.on('data', async (data) => {
                const match = data.toString('utf-8').match(/https\:\/\/(.*)\.trycloudflare\.com/i);
                if (match) {
                    await new Promise(r => setTimeout(r, dnsDelay));
                    this.hostname = match[1] + '.trycloudflare.com';
                }
                this.emit('output', data.toString('utf-8').trim());
                if (logging) console.log('[CF][ERR]:', data.toString('utf-8').trim());
            });
            this.process.on('exit', (code, signal) => {
                this.process = null;
                this.hostname = null;
                this.exited = true;
                this.running = false;
                this.emit('exit', code, signal);
                if (logging) console.warn(`[CF]: Exited with code ${code} and signal ${signal}.`);
            });
            if (wait) return this.waitForHostname(timeout);
        }
        async waitForHostname(timeout = 60000) {
            const t = setTimeout(() => {
                if (!this.hostname) {
                    this.kill();
                    throw new Error('Timed out waiting for hostname after ' + timeout + 'ms.');
                }
            }, timeout);
            while (!this.hostname) await new Promise(resolve => setTimeout(resolve, 10));
            clearTimeout(t);
            return this.hostname;
        }
        async kill() {
            if (this.process) {
                try {
                    this.process.kill();
                } catch (e) { }
                this.process = null;
                this.hostname = null;
                this.killed = true;
                this.exited = false;
                this.running = false;
            }
        }
    }
    exports.Cloudflared = Cloudflared;

    class ProtocolServer extends EventEmitter {
        constructor() {
            super();
            this.setMaxListeners(0);
            this.address = null;
            this.wss = null;
            this.keys = null;
        }
        _connectionHandler(ws) {
            // TODO for here:
            // - handle errors better
            // - kick invalid clients
            // - kick clients if they have not sent any valid requests in a while (exlude keep-alive requests)
            const id = b16e(crypto.getRandomValues(new Uint32Array(32)));
            this.emit('connection', id);
            let remotePublicKey = null;
            this.on(`_announce-${id}`, async (message, data) => {
                if (remotePublicKey) {
                    const responseVersion = Buffer.alloc(4);
                    responseVersion.writeUInt32LE(1, 0); // not used yet (reserved for future use)
                    const mcode = Buffer.alloc(4);
                    mcode.writeUInt32LE(message, 0);
                    const payload = Buffer.concat([responseVersion, mcode, data]);
                    const bm = Buffer.alloc(4);
                    bm.writeUInt32LE(PROTOCOLMESSAGES.ENCRYPTED_ANNOUNCE, 0);
                    ws.send(Buffer.concat([bm, await encryption.encryptPayload(remotePublicKey, payload)]));
                }
            });
            ws.on('error', (error) => {
                this.emit('server-error', new Error(`WS connection error: ${error.message}`));
            });
            ws.on('message', async (msg) => {
                if (msg.length <= 4) {
                    const bm = Buffer.alloc(4);
                    bm.writeUInt32LE(PROTOCOLMESSAGES.ERROR_MALFORMED_REQUEST, 0);
                    ws.send(bm);
                    return;
                }
                const bmsg = msg.readUInt32LE(0);
                if (bmsg == PROTOCOLMESSAGES.PING) {
                    const bm = Buffer.alloc(4);
                    bm.writeUInt32LE(PROTOCOLMESSAGES.PONG, 0);
                    ws.send(bm);
                    return;
                } else if (bmsg == PROTOCOLMESSAGES.PUBKEY) {
                    remotePublicKey = await encryption.RSAImportKey(msg.subarray(4), encryption.RSAPublicKey); // save their public key
                    return;
                } else if (bmsg == PROTOCOLMESSAGES.ENCRYPTED_REQUEST) {
                    // base message + RSA payload + AES block size
                    if (msg.length < (4 + 256 + 16)) {
                        // no point in emitting this as a server error because it's a bad request from the client
                        const bm = Buffer.alloc(4);
                        bm.writeUInt32LE(PROTOCOLMESSAGES.ERROR_MALFORMED_REQUEST, 0);
                        ws.send(bm);
                        return;
                    }
                    let payload, requestVersion, reqId, message, data;
                    try {
                        payload = Buffer.from(await encryption.decryptPayload(this.keys.privateKey, msg.subarray(4)));
                        if (payload.length < 12) {
                            // no point in emitting this as a server error because it's a bad request from the client
                            const bm = Buffer.alloc(4);
                            bm.writeUInt32LE(PROTOCOLMESSAGES.ERROR_MALFORMED_REQUEST, 0);
                            ws.send(bm);
                            return;
                        }
                        requestVersion = payload.readUInt32LE(0);
                        reqId = payload.readUInt32LE(4);
                        message = payload.readUInt32LE(8);
                        data = payload.subarray(12);
                    } catch (e) {
                        this.emit('server-error', new Error(`Error while processing incoming message (${reqId || 'unknown'}): ${e.message}`));
                        const bm = Buffer.alloc(4);
                        bm.writeUInt32LE(PROTOCOLMESSAGES.ERROR_INTERNAL_SERVER, 0);
                        try {
                            ws.send(bm);
                        } catch (e) { }
                        return;
                    }
                    this.emit('request', id, message, data, async (data = Buffer.alloc(0), message = MESSAGES.RES_OK) => await this.sendResponse(ws, remotePublicKey, reqId, message, data));
                } else {
                    const bm = Buffer.alloc(4);
                    bm.writeUInt32LE(PROTOCOLMESSAGES.ERROR_UNKNOWN_MESSAGE, 0);
                    ws.send(bm);
                    return;
                }
            });
            ws.on('close', () => {
                this.removeAllListeners(`_announce-${id}`);
                this.emit('disconnection', id);
            });
            const bm = Buffer.alloc(4);
            bm.writeUInt32LE(PROTOCOLMESSAGES.PUBKEY, 0);
            ws.send(Buffer.concat([bm, this.keys.publicKey])); // send our public key
            setTimeout(() => {
                if (remotePublicKey === null) ws.close(); // close the connection if the client doesn't send us their public key after 10 seconds
            }, 10000);
        }
        async start(hostname = '0.0.0.0', port = 0) {
            if (this.address != null) await this.stop(); // restart
            this.address = null;
            this.wss = null;
            this.keys = null;
            this.keys = await encryption.RSAMakeKey();
            this.keys.publicKey = b64d(this.keys.publicKey);
            this.keys.privateKey = await encryption.RSAImportKey(this.keys.privateKey, encryption.RSAPrivateKey);
            this.wss = new WebSocketServer({ port, host: hostname });
            this.wss.on('error', err => this.emit('server-error', new Error(`WS server error: ${err.message}`)));
            this.wss.on('connection', (ws) => this._connectionHandler(ws));
            await new Promise(r => this.wss.once('listening', r));
            this.address = this.wss.address();
        }
        async stop() {
            await new Promise(r => this.wss.close(r));
            this.address = null;
            this.wss = null;
            this.keys = null;
        }
        async sendResponse(ws, key, reqId, message, data = Buffer.alloc(0)) {
            const responseVersion = Buffer.alloc(4);
            responseVersion.writeUInt32LE(1, 0); // not used yet (reserved for future use)
            const rid = Buffer.alloc(4);
            rid.writeUInt32LE(reqId, 0);
            const mcode = Buffer.alloc(4);
            mcode.writeUInt32LE(message, 0);
            const payload = Buffer.concat([responseVersion, rid, mcode, data]);
            const bm = Buffer.alloc(4);
            bm.writeUInt32LE(PROTOCOLMESSAGES.ENCRYPTED_RESPONSE, 0);
            ws.send(Buffer.concat([bm, await encryption.encryptPayload(key, payload)]));
        }
        announce(id, message, data = Buffer.alloc(0)) {
            this.emit(`_announce-${id}`, message, data);
        }
    }

    class Server extends EventEmitter {
        constructor() {
            super();
            this.socket = new ProtocolServer();
            this.socket.on('server-error', err => this.emit('server-error', new Error(`Server protocol error: ${err.message}`)));
            this.socket.on('request', (id, message, data, callback) => this._handler(id, message, data, callback)); // preserve "this"
            this.address = null;
        }
        async start(hostname = '0.0.0.0', port = 0) {
            await this.socket.start(hostname, port);
            this.address = this.socket.address;
        }
        async stop() {
            await this.socket.stop();
            this.address = null;
        }
        _handler(id, message, data, callback) {
            try {
                switch (message) {
                    case MESSAGES.REQ_PING: {
                        callback();
                        return;
                    }
                    case MESSAGES.REQ_VERSION: {
                        callback(Buffer.from(VERSION));
                        return;
                    }
                    case MESSAGES.REQ_FILE_INFO: {
                        let requestReslolved = false;
                        const hashId = b16e(data);
                        this.emit('file-info-request', hashId, async (result, code = MESSAGES.RES_OK) => {
                            if (!result) {
                                this.emit('server-error', `Error while processing incoming message: no result was provided when sending a response`);
                                return;
                            }
                            if (!(result instanceof Object)) {
                                this.emit('server-error', `Error while processing incoming message: result for file request was not a object`);
                                return;
                            }
                            if (!requestReslolved) {
                                callback(binmap.serialize(result), code);
                                requestReslolved = true;
                            } else {
                                this.emit('server-error', `Error while processing incoming message: attempted to send a response to a request that has already been resolved`);
                            }
                        }, async (code = MESSAGES.ERR_GENERAL, message) => {
                            if (!requestReslolved) {
                                callback(Buffer.from(message || ''), code);
                                requestReslolved = true;
                            } else {
                                this.emit('server-error', `Error while processing incoming message: attempted to send a response to a request that has already been resolved`);
                            }
                        });
                        return;
                    }
                    case MESSAGES.REQ_FILE_PART: {
                        let requestReslolved = false;
                        const hashId = b16e(data.subarray(0, 32));
                        const partIndex = data.readUInt32LE(32);
                        this.emit('file-part-request', hashId, partIndex, async (result, code = MESSAGES.RES_OK) => {
                            if (!result) {
                                this.emit('server-error', `Error while processing incoming message: no result was provided when sending a response`);
                                return;
                            }
                            if (!(result instanceof Buffer)) {
                                this.emit('server-error', `Error while processing incoming message: result for file part request was not a buffer`);
                                return;
                            }
                            if (!requestReslolved) {
                                callback(result, code);
                                requestReslolved = true;
                            } else {
                                this.emit('server-error', `Error while processing incoming message: attempted to send a response to a request that has already been resolved`);
                            }
                        }, async (code = MESSAGES.ERR_GENERAL, message) => {
                            if (!requestReslolved) {
                                callback(Buffer.from(message || ''), code);
                                requestReslolved = true;
                            } else {
                                this.emit('server-error', `Error while processing incoming message: attempted to send a response to a request that has already been resolved`);
                            }
                        });
                        return;
                    }
                    case MESSAGES.REQ_FILE_PROGRESSES: {
                        let requestReslolved = false;
                        const hashIds = [];
                        let offset = 0;
                        while (offset < data.length) {
                            hashIds.push(b16e(data.subarray(offset, offset + 32)));
                            offset += 32;
                        }
                        this.emit('file-progress-request', hashIds, async (result, code = MESSAGES.RES_OK) => {
                            if (!result) {
                                this.emit('server-error', `Error while processing incoming message: no result was provided when sending a response`);
                                return;
                            }
                            if (!Array.isArray(result)) {
                                this.emit('server-error', `Error while processing incoming message: result for file request was not a array`);
                                return;
                            }
                            if (!requestReslolved) {
                                const buffers = [];
                                for (const progress of result) {
                                    if (typeof progress === 'object' && progress !== null) {
                                        if (!Array.isArray(progress)) {
                                            this.emit('server-error', `Error while processing incoming message: progress for file request was not a array`);
                                            return;
                                        }
                                        const length = Buffer.alloc(4);
                                        length.writeUInt32LE(progress.length, 0);
                                        buffers.push(length, bitsToBytes(progress));
                                    } else {
                                        const length = Buffer.alloc(4);
                                        length.writeUInt32LE(0, 0); // 0 bytes to indicate we don't have the file
                                        buffers.push(length);
                                    }
                                }
                                callback(Buffer.concat(buffers), code);
                                requestReslolved = true;
                            } else {
                                this.emit('server-error', `Error while processing incoming message: attempted to send a response to a request that has already been resolved`);
                            }
                        }, async (code = MESSAGES.ERR_GENERAL, message) => {
                            if (!requestReslolved) {
                                callback(Buffer.from(message || ''), code);
                                requestReslolved = true;
                            } else {
                                this.emit('server-error', `Error while processing incoming message: attempted to send a response to a request that has already been resolved`);
                            }
                        });
                        return;
                    }
                    case MESSAGES.REQ_FILE_DOWNLOAD_LIST: {
                        let requestReslolved = false;
                        const hash = b16e(data);
                        this.emit('file-download-list-request', hash, async (result, code = MESSAGES.RES_OK) => {
                            if (!result) {
                                this.emit('server-error', `Error while processing incoming message: no result was provided when sending a response`);
                                return;
                            }
                            if (!(result instanceof Object)) {
                                this.emit('server-error', `Error while processing incoming message: result for file download list request was not a object`);
                                return;
                            }
                            if (!requestReslolved) {
                                callback(binmap.serialize(result), code);
                                requestReslolved = true;
                            } else {
                                this.emit('server-error', `Error while processing incoming message: attempted to send a response to a request that has already been resolved`);
                            }
                        }, async (code = MESSAGES.ERR_GENERAL, message) => {
                            if (!requestReslolved) {
                                callback(Buffer.from(message || ''), code);
                                requestReslolved = true;
                            } else {
                                this.emit('server-error', `Error while processing incoming message: attempted to send a response to a request that has already been resolved`);
                            }
                        });
                        return;
                    }
                    default: {
                        callback(Buffer.alloc(0), MESSAGES.ERR_UNKNOWN_MESSAGE);
                        return;
                    }
                }
            } catch (e) {
                this.emit('server-error', new Error(`Error while handling incoming message: ${e.message}`));
                try {
                    callback(Buffer.alloc(0), MESSAGES.ERR_INTERNAL_SERVER);
                } catch (e) { }
                return;
            }
        }
    }
    exports.Server = Server;

    class TrackerServer extends EventEmitter {
        constructor() {
            super();
            this.setMaxListeners(0);
            this.address = null;
            this.peers = {};
            this.socket = new ProtocolServer();
            this.socket.on('server-error', (error) => this.emit('server-error', error));
            this.socket.on('message', (id, data) => this._onMessage(id, data));
            this.socket.on('connection', (id) => this._onConnection(id));
            this.socket.on('disconnection', (id) => this._onDisconnection(id));
            this.socket.on('request', (id, message, data, callback) => this._onRequest(id, message, data, callback));
        }
        async listen(port, hostname = '0.0.0.0') {
            this.peers = {};
            this.address = null;
            await this.socket.start(hostname, port);
            this.address = this.socket.address;
        }
        async stop() {
            await this.socket.stop();
            this.peers = {};
            this.address = null;
        }
        _onConnection(id) {
            this.peers[id] = {
                address: null, files_has: [], files_want: [], listener: (peerId) => {
                    for (const file of this.peers[peerId].files_has) {
                        if (this.peers[id].files_want.includes(file) && this.peers[peerId].address && this.peers[peerId].address != this.peers[id].address) {
                            this.socket.announce(id, TRACKERMESSAGES.PEER, (new TextEncoder('utf-8')).encode(this.peers[peerId].address));
                            break;
                        }
                    }
                }
            };
            this.on('peer-announce', this.peers[id].listener);
        }
        _onDisconnection(id) {
            this.off('peer-announce', this.peers[id].listener);
            delete this.peers[id];
        }
        _onRequest(id, message, data, callback) {
            try {
                switch (message) {
                    case TRACKERMESSAGES.ANNOUNCE_ADDRESS: {
                        if (this.peers[id].address) {
                            callback(Buffer.alloc(0), TRACKERMESSAGES.ERROR_ADDRESS_ALREADY_SET);
                            return;
                        }
                        if (!data.toString('utf-8')) {
                            callback(Buffer.alloc(0), TRACKERMESSAGES.ERROR_MALFORMED_REQUEST);
                            return;
                        }
                        this.peers[id].address = data.toString('utf-8');
                        callback();
                        return;
                    }
                    case TRACKERMESSAGES.ANNOUNCE_WANT: {
                        const files_array = [];
                        for (let i = 0; i < data.length; i += 32) {
                            files_array.push(data.subarray(i, i + 32).toString('hex'));
                        }
                        this.peers[id].files_want = files_array;
                        callback();
                        for (const peer of Object.values(this.peers)) {
                            for (const file of peer.files_has) {
                                if (files_array.includes(file) && peer.address && peer.address !== this.peers[id].address) {
                                    this.socket.announce(id, TRACKERMESSAGES.PEER, (new TextEncoder('utf-8')).encode(peer.address));
                                    break;
                                }
                            }
                        }
                        return;
                    }
                    case TRACKERMESSAGES.ANNOUNCE_HAVE: {
                        const files_array = [];
                        for (let i = 0; i < data.length; i += 32) {
                            files_array.push(data.subarray(i, i + 32).toString('hex'));
                        }
                        this.peers[id].files_has = files_array;
                        if (this.peers[id].address) this.emit('peer-announce', id);
                        callback();
                        return;
                    }
                    default: {
                        callback(Buffer.alloc(0), TRACKERMESSAGES.ERROR_UNKNOWN_MESSAGE);
                        return;
                    }
                }
            } catch (e) {
                this.emit('server-error', e.message);
                try {
                    callback(Buffer.alloc(0), TRACKERMESSAGES.ERROR_INTERNAL_SERVER);
                } catch (e) { }
            }
        }
    }
    exports.TrackerServer = TrackerServer;

    class FullPeer extends BasePeer {
        constructor({ trackers, maxClients, enableSeeding, fileDownloadOrder } = {}) {
            super({ trackers, maxClients });
            if (typeof enableSeeding !== 'boolean') enableSeeding = true;
            if (typeof fileDownloadOrder !== 'string') fileDownloadOrder = 'random';
            if (fileDownloadOrder != 'linear' && fileDownloadOrder != 'random') throw new Error('fileDownloadOrder must be "linear" or "random"');
            this.fileDownloadOrder = fileDownloadOrder;
            this.enableSeeding = enableSeeding;
            this.files = {};
            this.server = new Server();
            this.server.on('file-info-request', (hashId, cb, error) => this._serverOnFileInfoRequest(hashId, cb, error));
            this.server.on('file-progress-request', (hashIds, cb, error) => this._serverOnFileProgressRequest(hashIds, cb, error));
            this.server.on('file-part-request', async (hashId, partIndex, cb, error) => this._serverOnFilePartRequest(hashId, partIndex, cb, error));
            this.cloudflared = new Cloudflared();
            this.downloadsActive = 0;
            this.events = new EventEmitter();
        }
        async _serverStart() {
            this.files = {};
            this.downloadsActive = 0;
            setImmediate(() => this._fileDownloadWorker());
            if (this.enableSeeding) {
                await this.server.start();
                await this.cloudflared.run({ url: `http://127.0.0.1:${this.server.address.port}` });
                setImmediate(async () => {
                    this.address = `wss://${await this.cloudflared.waitForHostname()}`;
                    await this.announce();
                });
            }
        }
        async _serverStop() {
            if (this.enableSeeding) {
                await this.server.stop();
                await this.cloudflared.kill();
            }
            for (const file in this.files) {
                await this.files[file].fd.close();
            }
            this.files = {};
            this.downloadsActive = 0;
        }
        _getFile(hashId) {
            for (const file in this.files) {
                // possibly find the most complete file?
                if (this.files[file].hashId == hashId) {
                    return file;
                }
            }
            return null;
        }
        async _serverOnFileInfoRequest(hashId, cb, error) {
            const file = this._getFile(hashId);
            if (!file) {
                error(MESSAGES.ERR_UNKNOWN_FILE);
                return;
            }
            cb({
                hashId: this.files[file].hashId,
                name: this.files[file].name,
                info: this.files[file].info
            });
        }
        async _serverOnFileProgressRequest(hashIds, cb, error) {
            const arr = [];
            for (const hashId of hashIds) {
                const file = this._getFile(hashId);
                if (!file) {
                    arr.push(null); // we don't have this file
                } else {
                    arr.push(this.files[file].progress);
                }
            }
            cb(arr);
        }
        async _serverOnFilePartRequest(hashId, partIndex, cb, error) {
            const file = this._getFile(hashId);
            if (!file) {
                error(MESSAGES.ERR_UNKNOWN_FILE);
                return;
            }
            if (partIndex >= this.files[file].info.partsCount) {
                error(MESSAGES.ERR_INVALID_PART_INDEX);
                return;
            }
            if (!this.files[file].progress[partIndex]) {
                error(MESSAGES.ERR_UNKNOWN_FILE_PART);
                return;
            }
            try {
                const offset = partIndex * this.files[file].info.partSize;
                let readSize = this.files[file].info.partSize;
                if ((offset + this.files[file].info.partSize) > this.files[file].info.size) readSize = this.files[file].info.size - offset;
                cb(await readExactly(this.files[file].fd, readSize, offset));
            } catch (e) {
                error(MESSAGES.ERR_INTERNAL_SERVER);
                return;
            }
        }
        async _fileDownloadWorker() {
            while (this.running) {
                let downloadsActive = 0;
                try {
                    for (const file in this.files) {
                        if (this.files[file].progress.length != this.files[file].info.partsCount) this.files[file].progress = this.files[file].progress.slice(0, this.files[file].info.partsCount) // hotfix
                        const neededParts = this.files[file].progress.map((value, index) => value === 0 ? index : -1).filter(index => index !== -1);
                        if (neededParts.length > 0) {
                            downloadsActive++;
                            if (!this.lookingFor.includes(this.files[file].hashId)) {
                                this.lookingFor.push(this.files[file].hashId);
                                setImmediate(() => this.announce());
                            }
                            let index;
                            let i;
                            if (this.fileDownloadOrder == 'linear') {
                                i = 0;
                                index = neededParts[i];
                                while (this.files[file].partsActive[index]) {
                                    i++;
                                    if (i >= neededParts.length) {
                                        // give up
                                        index = null;
                                        break;
                                    }
                                    index = neededParts[i];
                                }
                            } else {
                                let tries = 0;
                                i = Math.floor(Math.random() * neededParts.length);
                                index = neededParts[i];
                                while (this.files[file].partsActive[index]) {
                                    tries++;
                                    if (tries > neededParts.length) {
                                        // give up
                                        index = null;
                                        break;
                                    }
                                    i = Math.floor(Math.random() * neededParts.length);
                                    index = neededParts[i];
                                }
                            }
                            if (index !== null) {
                                for (const client in this.clients) {
                                    if (this.clients[client].client.socket.open && this.clients[client].files[this.files[file].hashId] && this.clients[client].files[this.files[file].hashId][index] && this.clients[client].running_part_requests < 2) { // 2 requests at a time seems the optimal amount for speed and throughput
                                        if (!this.files[file].downloadStart) {
                                            this.files[file].downloadStart = Date.now(); // mark start time when we first request a part
                                            this.events.emit('download-started', await this.getFileProgress(file));
                                        }
                                        this.files[file].partsActive[index] = true;
                                        this.clients[client].running_part_requests++;
                                        setImmediate(async () => {
                                            try {
                                                // TODO: error handling here
                                                let part;
                                                try {
                                                    part = await this.clients[client].client.requestFilePart(this.files[file].hashId, index);
                                                } catch (e) {
                                                    try {
                                                        this.clients[client].running_part_requests--;
                                                    } catch (e) { } // client was probably disconnected
                                                    delete this.files[file].partsActive[index];
                                                    return;
                                                }
                                                try {
                                                    this.clients[client].running_part_requests--;
                                                } catch (e) { } // client was probably disconnected
                                                if (b16e(this.files[file].info.parts.subarray(index * 32, (index + 1) * 32)) !== await hash(part, 'SHA-256')) {
                                                    delete this.files[file].partsActive[index];
                                                    return;
                                                }
                                                try {
                                                    await writeExactly(this.files[file].fd, part, index * this.files[file].info.partSize);
                                                } catch (e) {
                                                    delete this.files[file].partsActive[index];
                                                    return;
                                                }
                                                this.files[file].received += part.length;
                                                this.files[file].progress[index] = 1;
                                                if (this.files[file].progress.length != this.files[file].info.partsCount) this.files[file].progress = this.files[file].progress.slice(0, this.files[file].info.partsCount) // TODO: FIX THIS!! - hotfix the array keeps getting bigger somehow - maybe because of async concurrency updating at the same time
                                                delete this.files[file].partsActive[index];
                                                this.events.emit('download-progress', await this.getFileProgress(file));
                                                const fileComplete = this.files[file].progress.every(item => item === 1);
                                                if (fileComplete) {
                                                    if (this.lookingFor.includes(this.files[file].hashId)) this.lookingFor.splice(this.lookingFor.indexOf(this.files[file].hashId), 1);
                                                    this.events.emit('download-complete', await this.getFileProgress(file));
                                                    await this.announce();
                                                }
                                            } catch (e) {
                                                console.error(e); // this error may not be recoverable
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    }
                    this.downloadsActive = downloadsActive;
                } catch (e) { } // errors that can occur when running this.stop() #1
                await new Promise(resolve => setTimeout(resolve, downloadsActive > 0 ? 10 : 1000)); // slow down if nothing is downloading
            }
        }
        async getFileProgress(path) {
            if (!this.files[path]) throw new Error('File not found.');
            return new DownloadProgressReport({
                path: this.files[path].path,
                hashId: this.files[path].hashId,
                size: this.files[path].info.size,
                partSize: this.files[path].info.partSize,
                received: this.files[path].received,
                receivedSinceStart: this.files[path].received - this.files[path].downloadStartBytes,
                start: this.files[path].downloadStart || Date.now(),
                progress: this.files[path].progress
            });
        }
        async announce() {
            if (!this.running) throw new Error('Peer is not running.');
            for (const tracker in this.trackers) {
                if (!this.trackers[tracker].socket.open) continue;
                try {
                    await this.trackers[tracker].announceWant(this.lookingFor);
                } catch (e) { }
                if (this.enableSeeding && this.address) {
                    try {
                        if (!this.trackers[tracker].serverAddress) await this.trackers[tracker].announceServerAddress(this.address);
                    } catch (e) { }
                    const have = [];
                    for (const file in this.files) {
                        have.push(this.files[file].hashId);
                    }
                    try {
                        await this.trackers[tracker].announceHave(have);
                    } catch (e) { }
                }
            }
            this.lastAnnounce = Date.now();
            this.events.emit('announce');
        }
        async add(object, path, progress = (p) => { }) {
            if (!this.running) throw new Error('Peer is not running.');
            path = pathlib.resolve(path || '.');
            const files = [];
            const addFolder = async (object) => {
                if (!fs.existsSync(pathlib.join(path, object.path))) await fs.promises.mkdir(pathlib.join(path, object.path), { recursive: true });
                for (const file in object.files) {
                    if (object.files[file].type == 'file') {
                        files.push(object.files[file]);
                    } else {
                        await addFolder(object.files[file]);
                    }
                }
            }
            if (serializer.validateFile(object)) {
                files.push(object);
            } else if (serializer.validateFolder(object)) {
                await addFolder(object, path);
            } else if (typeof object === 'string') {
                throw new Error('File lookup is not supported yet.');
            } else if (Array.isArray(object)) {
                throw new Error('File lookup is not supported yet.');
            } else {
                throw new Error('Invalid file(s) object.');
            }
            let prossesed = 0;
            if (!fs.existsSync(path)) await fs.promises.mkdir(path, { recursive: true });
            const size = object.type == 'file' ? object.info.size : object.size;
            for (const file of files) {
                const fpath = pathlib.join(path, file.path);
                if (this.files[fpath]) throw new Error(`File is already added: ${fpath}`);
                const f = {
                    hashId: file.hashId,
                    name: pathlib.basename(file.path),
                    info: file.info,
                    path: fpath,
                    downloadStartBytes: 0,
                    downloadStart: null,
                    added: Date.now(),
                    partsActive: {},
                    progress: (new Array(file.info.partsCount)).fill(0)
                };
                if (fs.existsSync(fpath)) {
                    f.fd = await fs.promises.open(fpath, 'r+');
                    let partIndex = 0;
                    for (let i = 0; i < file.info.size; i += file.info.partSize) {
                        const readSize = (i + file.info.partSize) > file.info.size ? (file.info.size - i) : file.info.partSize;
                        try {
                            const correctHash = b16e(file.info.parts.subarray(partIndex * 32, (partIndex + 1) * 32));
                            const h = await hash(await readExactly(f.fd, readSize, i), 'SHA-256');
                            if (h === correctHash) {
                                f.progress[partIndex] = 1;
                                f.downloadStartBytes += readSize;
                            }
                        } catch (e) { }
                        prossesed += readSize;
                        progress((prossesed / size) * 100);
                        partIndex++;
                    }
                } else {
                    f.fd = await fs.promises.open(fpath, 'w+');
                    prossesed += file.info.size;
                    progress((prossesed / size) * 100);
                }
                f.received = f.progress.reduce((sum, item) => sum + (item * file.info.partSize), 0);
                if (f.received > f.info.size) f.received = f.info.size;
                if ((await f.fd.stat()).size != file.info.size) await f.fd.truncate(file.info.size);
                this.files[fpath] = f;
                const fileComplete = f.progress.every(item => item === 1);
                if (!fileComplete && !this.lookingFor.includes(file.hashId)) this.lookingFor.push(file.hashId);
                this.events.emit('file-added', fpath, file.hashId);
            }
            await this.announce();
        }
        async remove(object, path = '.') {
            if (!this.running) throw new Error('Peer is not running.');
            const paths = [];
            if (serializer.validateFile(object)) {
                paths.push(object.path);
            } else if (serializer.validateFolder(object)) {
                for (const file in object.files) {
                    paths.push(object.files[file].path);
                }
            } else if (typeof object === 'string') {
                paths.push(object);
            } else if (Array.isArray(object)) {
                for (const hashId of object) {
                    paths.push(hashId);
                }
            } else {
                throw new Error('Invalid file(s) object.');
            }
            for (const path of paths) {
                if (!path || typeof path !== 'string') throw new Error('Path must be a string.');
                if (this.files[path]) {
                    await this.files[path].fd.close();
                    if (this.lookingFor.includes(this.files[path].hashId)) this.lookingFor.splice(this.lookingFor.indexOf(this.files[path].hashId), 1);
                    this.events.emit('file-removed', path, this.files[path].hashId);
                    delete this.files[path];
                }
            }
            await this.announce();
        }
        async getFiles(type = null) { // returns an array of file paths that we are managing
            if (!this.running) throw new Error('Peer is not running.');
            const arr = [];
            for (const file in this.files) {
                if (type !== null) { // null = get all files
                    const fileComplete = this.files[file].progress.every(item => item === 1);
                    if (fileComplete != Boolean(type)) continue; // else check if file completeness is the same as the wanted type
                }
                arr.push(file);
            }
            return arr;
        }
        async allFilesComplete() {
            if (!this.running) throw new Error('Peer is not running.');
            return (await this.getFiles(false)).length == 0;
        }
    }
    exports.Peer = FullPeer;

    async function generateDownloadList(path, options = {}) {
        path = pathlib.resolve(path);
        if (!fs.existsSync(path)) throw new Error(`File/folder not found: ${path}`);
        if (!options.name) options.name = pathlib.basename(path);
        const stat = await fs.promises.stat(path);
        const object = {
            name: options.name,
            size: 0,
            created: Date.now(),
            version: 1
        };
        if (typeof options.comment === 'string') object.comment = options.comment;
        if (typeof options.createdBy === 'string') object.createdBy = options.createdBy;
        if (stat.isFile()) {
            const info = await generateFileInfo(path, (p) => {
                if (options.logProgress) process.stdout.write(`\rHashing file ${path}... ${p.toFixed(2)}%`);
            });
            if (options.logProgress) process.stdout.write('\n');
            if (info.info.size == 0) throw new Error(`File is empty: ${path}`);
            info.path = options.name;
            object.content = info;
            object.size = info.info.size;
        } else if (stat.isDirectory()) {
            const info = await generateFolderInfo(path, options.name, options);
            if (info.size == 0) throw new Error(`Folder is empty: ${path}`);
            info.path = options.name;
            object.content = info;
            object.size = info.size;
        } else {
            throw new Error(`File/folder is not a file or folder: ${path}`);
        }
        return serializer.serialize(object);
    }
    exports.generateDownloadList = generateDownloadList;

    async function generateFolderInfo(path, relativePath, options = {}) {
        path = pathlib.resolve(path);
        if (!relativePath) relativePath = pathlib.basename(path);
        if (!fs.existsSync(path)) throw new Error(`Folder not found: ${path}`);
        const stat = await fs.promises.stat(path);
        if (!stat.isDirectory()) throw new Error(`Folder is not a folder: ${path}`);
        const files = {};
        let size = 0;
        for (const file of fs.readdirSync(path)) {
            const fpath = pathlib.join(path, file);
            const stat = await fs.promises.stat(fpath);
            if (stat.isDirectory()) {
                const rpath = relativePath + '/' + file;
                const info = await generateFolderInfo(fpath, rpath, options);
                if (info.size > 0) { // empty folders are not supported
                    info.path = rpath;
                    files[rpath] = info;
                    size += info.size;
                }
            } else if (stat.isFile() && stat.size > 0) { // empty files are not supported
                const info = await generateFileInfo(fpath, (p) => {
                    if (options.logProgress) process.stdout.write(`\rHashing file ${fpath}... ${p.toFixed(2)}%`);
                });
                if (options.logProgress) process.stdout.write('\n');
                info.path = relativePath + '/' + file;
                files[info.path] = info;
                size += info.info.size;
            }
        }
        return {
            type: 'folder',
            size,
            files
        };
    }
    exports.functions.generateFolderInfo = generateFolderInfo;

    async function generateFileInfo(path, progress = (p) => { }) {
        path = pathlib.resolve(path);
        if (!fs.existsSync(path)) throw new Error(`File not found: ${path}`);
        const stats = await fs.promises.stat(path);
        if (!stats.isFile()) throw new Error(`File is not a file: ${path}`);
        const info = {
            type: 'file',
            info: {
                size: stats.size,
                partSize: DEFAULT_PART_SIZE, // unused for now. kept for future use
                parts: Buffer.alloc(0)
            }
        };
        info.info.partsCount = Math.ceil(stats.size / info.info.partSize);
        const partHashes = [];
        const fd = await fs.promises.open(path, 'r');
        let partIndex = 0;
        for (let i = 0; i < info.info.size; i += info.info.partSize) {
            const readSize = (i + info.info.partSize) > info.info.size ? (info.info.size - i) : info.info.partSize;
            partHashes.push(await hash(await readExactly(fd, readSize, i), 'SHA-256', false));
            progress(((partIndex + 1) / info.info.partsCount) * 100);
            partIndex++;
        }
        await fd.close();
        info.info.parts = Buffer.concat(partHashes);
        info.hashId = await hash(binmap.serialize(info.info), 'SHA-256');
        return info;
    }
    exports.functions.generateFileInfo = generateFileInfo;
}

export default exports;
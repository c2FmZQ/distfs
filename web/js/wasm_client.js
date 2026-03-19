export class WasmClient {
    worker;
    ready = false;
    onReady;
    constructor(workerScript) {
        this.worker = new Worker(workerScript);
        this.worker.onerror = (e) => {
            console.error("WASM Worker Critical Error:", e);
            this.ready = false;
        };
        this.worker.onmessage = (e) => {
            if (e.data.type === 'ready') {
                this.ready = true;
                if (this.onReady)
                    this.onReady();
            }
        };
    }
    async invoke(action, args) {
        return new Promise((resolve, reject) => {
            const id = Math.random().toString(36).substring(7);
            const handler = (e) => {
                if (e.data.id === id) {
                    this.worker.removeEventListener('message', handler);
                    if (e.data.type === 'success') {
                        resolve(e.data.result);
                    }
                    else {
                        reject(new Error(e.data.error));
                    }
                }
            };
            this.worker.addEventListener('message', handler);
            this.worker.postMessage({ type: 'invoke', action, args, id });
        });
    }
    async init(serverURL, userID, decKey, signKey, serverKey) {
        return this.invoke('init', { serverURL, userID, decKey, signKey, serverKey });
    }
    async listDirectory(path, offset, limit) {
        return this.invoke('listDirectory', { path, offset, limit });
    }
    async statFile(path) {
        return this.invoke('statFile', { path });
    }
    async readFile(path) {
        return this.invoke('readFile', { path });
    }
    async writeFile(path, content) {
        return this.invoke('writeFile', { path, content });
    }
    async mkdir(path) {
        return this.invoke('mkdir', { path });
    }
    async mv(oldPath, newPath) {
        return this.invoke('mv', { oldPath, newPath });
    }
    async rm(path) {
        return this.invoke('rm', { path });
    }
    async setACL(path, aclJSON) {
        return this.invoke('setACL', { path, aclJSON });
    }
    async lookupUser(identifier) {
        return this.invoke('lookupUser', { identifier });
    }
    async getQuota() {
        return this.invoke('getQuota', {});
    }
    async generateKeys() {
        return this.invoke('generateKeys', {});
    }
    async registerUser(serverURL, jwt, signPubKey, encKey) {
        return this.invoke('registerUser', { serverURL, jwt, signPubKey, encKey });
    }
    async fetchServerKey(serverURL) {
        return this.invoke('fetchServerKey', { serverURL });
    }
    async encryptConfig(config, passphrase) {
        return this.invoke('encryptConfig', { config, passphrase });
    }
    async decryptConfig(blob, passphrase) {
        return this.invoke('decryptConfig', { blob, passphrase });
    }
    async pushKeySync(blob) {
        return this.invoke('pushKeySync', { blob });
    }
    async pullKeySync(serverURL, token) {
        return this.invoke('pullKeySync', { serverURL, token });
    }
    postMessage(message, transfer) {
        this.worker.postMessage(message, transfer || []);
    }
    async startDeviceAuth(authEndpoint, tokenEndpoint) {
        return this.invoke('startDeviceAuth', { authEndpoint, tokenEndpoint });
    }
    async pollForToken(authEndpoint, tokenEndpoint, deviceCode, userCode, verificationURI, interval) {
        return this.invoke('pollForToken', { authEndpoint, tokenEndpoint, deviceCode, userCode, verificationURI, interval });
    }
}

// This file defines the TypeScript interfaces for communicating with the WASM Web Worker.
export class WasmClient {
    worker;
    pendingRequests;
    constructor(workerUrl) {
        this.worker = new Worker(workerUrl);
        this.pendingRequests = new Map();
        this.worker.onmessage = (event) => {
            if (event.data.type === 'ready') {
                console.log("WASM Worker is ready.");
                return;
            }
            const { id, type, result, error } = event.data;
            const promise = this.pendingRequests.get(id);
            if (promise) {
                this.pendingRequests.delete(id);
                if (type === 'error' || error) {
                    promise.reject(new Error(error || "Unknown WASM error"));
                }
                else {
                    promise.resolve(result);
                }
            }
            else if (type === 'start-download') {
                // Ignore here, this is handled by Service Worker
            }
        };
    }
    invoke(type, payload = {}) {
        return new Promise((resolve, reject) => {
            const id = Math.random().toString(36).substring(7);
            this.pendingRequests.set(id, { resolve, reject });
            this.worker.postMessage({ type, id, ...payload });
        });
    }
    async generateKeys() {
        return this.invoke('generateKeys');
    }
    async registerUser(serverURL, jwt, signKeyPubHex, encKeyHex) {
        return this.invoke('registerUser', { serverURL, jwt, signKeyPubHex, encKeyHex });
    }
    async encryptConfig(configStr, passphrase) {
        return this.invoke('encryptConfig', { configStr, passphrase });
    }
    async decryptConfig(blobStr, passphrase) {
        return this.invoke('decryptConfig', { blobStr, passphrase });
    }
    async pushKeySync(blobStr) {
        return this.invoke('pushKeySync', { blobStr });
    }
    async pullKeySync(serverURL, token) {
        return this.invoke('pullKeySync', { serverURL, token });
    }
    async init(serverURL, userID, decKey, signKey, serverKey) {
        return this.invoke('init', { serverURL, userID, decKey, signKey, serverKey });
    }
    async listDirectory(path) {
        return this.invoke('listDirectory', { path });
    }
}

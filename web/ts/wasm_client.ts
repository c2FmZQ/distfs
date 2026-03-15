// This file defines the TypeScript interfaces for communicating with the WASM Web Worker.

export interface WasmRequest {
    type: string;
    id: string; // Unique ID for request/response matching
    [key: string]: any;
}

export interface WasmResponse {
    type: string;
    id: string;
    result?: any;
    error?: string;
}

export class WasmClient {
    private worker: Worker;
    private pendingRequests: Map<string, { resolve: (val: any) => void, reject: (err: any) => void }>;
    public onReady?: () => void;

    constructor(workerUrl: string) {
        this.worker = new Worker(workerUrl);
        this.pendingRequests = new Map();

        this.worker.onmessage = (event: MessageEvent<WasmResponse>) => {
            if (event.data.type === 'ready') {
                console.log("WASM Worker is ready.");
                if (this.onReady) this.onReady();
                return;
            }

            const { id, type, result, error } = event.data;
            const promise = this.pendingRequests.get(id);
            
            if (promise) {
                this.pendingRequests.delete(id);
                if (type === 'error' || error) {
                    promise.reject(new Error(error || "Unknown WASM error"));
                } else {
                    promise.resolve(result);
                }
            } else if (type === 'start-download') {
               // Ignore here, this is handled by Service Worker
            }
        };
    }

    private invoke(type: string, payload: any = {}): Promise<any> {
        return new Promise((resolve, reject) => {
            const id = Math.random().toString(36).substring(7);
            this.pendingRequests.set(id, { resolve, reject });
            this.worker.postMessage({ type, id, ...payload });
        });
    }

    async generateKeys(): Promise<{decKey: string, encKey: string, signKey: string, signPubKey: string}> {
        return this.invoke('generateKeys');
    }

    async fetchServerKey(serverURL: string): Promise<string> {
        return this.invoke('fetchServerKey', { serverURL });
    }

    async registerUser(serverURL: string, jwt: string, signKeyPubHex: string, encKeyHex: string): Promise<string> {
        return this.invoke('registerUser', { serverURL, jwt, signKeyPubHex, encKeyHex });
    }

    async encryptConfig(configStr: string, passphrase: string): Promise<string> {
        return this.invoke('encryptConfig', { configStr, passphrase });
    }

    async decryptConfig(blobStr: string, passphrase: string): Promise<string> {
        return this.invoke('decryptConfig', { blobStr, passphrase });
    }

    async pushKeySync(blobStr: string): Promise<boolean> {
        return this.invoke('pushKeySync', { blobStr });
    }

    async pullKeySync(serverURL: string, token: string): Promise<string> {
        return this.invoke('pullKeySync', { serverURL, token });
    }

    async init(serverURL: string, userID: string, decKey: string, signKey: string, serverKey: string): Promise<boolean> {
        return this.invoke('init', { serverURL, userID, decKey, signKey, serverKey });
    }

    async listDirectory(path: string): Promise<any[]> {
        return this.invoke('listDirectory', { path });
    }
}

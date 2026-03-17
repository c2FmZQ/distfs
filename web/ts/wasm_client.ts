export class WasmClient {
    private worker: Worker;
    private ready: boolean = false;
    public onReady?: () => void;

    constructor(workerScript: string) {
        this.worker = new Worker(workerScript);
        this.worker.onmessage = (e) => {
            if (e.data.type === 'ready') {
                this.ready = true;
                if (this.onReady) this.onReady();
            }
        };
    }

    async invoke(action: string, args: any): Promise<any> {
        return new Promise((resolve, reject) => {
            const id = Math.random().toString(36).substring(7);
            const handler = (e: MessageEvent) => {
                if (e.data.id === id) {
                    this.worker.removeEventListener('message', handler);
                    if (e.data.type === 'success') {
                        resolve(e.data.result);
                    } else {
                        reject(new Error(e.data.error));
                    }
                }
            };
            this.worker.addEventListener('message', handler);
            this.worker.postMessage({ type: 'invoke', action, args, id });
        });
    }

    async init(serverURL: string, userID: string, decKey: string, signKey: string, serverKey: string): Promise<void> {
        return this.invoke('init', { serverURL, userID, decKey, signKey, serverKey });
    }

    async listDirectory(path: string, offset?: number, limit?: number): Promise<{entries: any[], total: number}> {
        return this.invoke('listDirectory', { path, offset, limit });
    }

    async statFile(path: string): Promise<any> {
        return this.invoke('statFile', { path });
    }

    async readFile(path: string): Promise<string> {
        return this.invoke('readFile', { path });
    }

    async writeFile(path: string, content: string): Promise<void> {
        return this.invoke('writeFile', { path, content });
    }

    async mkdir(path: string): Promise<void> {
        return this.invoke('mkdir', { path });
    }

    async mv(oldPath: string, newPath: string): Promise<void> {
        return this.invoke('mv', { oldPath, newPath });
    }

    async rm(path: string): Promise<void> {
        return this.invoke('rm', { path });
    }

    async setACL(path: string, aclJSON: string): Promise<void> {
        return this.invoke('setACL', { path, aclJSON });
    }

    async lookupUser(email: string): Promise<string> {
        return this.invoke('lookupUser', { email });
    }

    async getQuota(): Promise<any> {
        return this.invoke('getQuota', {});
    }

    async generateKeys(): Promise<any> {
        return this.invoke('generateKeys', {});
    }

    async registerUser(serverURL: string, jwt: string, signPubKey: string, encKey: string): Promise<string> {
        return this.invoke('registerUser', { serverURL, jwt, signPubKey, encKey });
    }

    async fetchServerKey(serverURL: string): Promise<string> {
        return this.invoke('fetchServerKey', { serverURL });
    }

    async encryptConfig(config: string, passphrase: string): Promise<string> {
        return this.invoke('encryptConfig', { config, passphrase });
    }

    async decryptConfig(blob: string, passphrase: string): Promise<string> {
        return this.invoke('decryptConfig', { blob, passphrase });
    }

    async pushKeySync(blob: string): Promise<void> {
        return this.invoke('pushKeySync', { blob });
    }

    async pullKeySync(serverURL: string, token: string): Promise<string> {
        return this.invoke('pullKeySync', { serverURL, token });
    }

    postMessage(message: any, transfer?: Transferable[]): void {
        this.worker.postMessage(message, transfer || []);
    }

    async startDeviceAuth(authEndpoint: string, tokenEndpoint: string): Promise<any> {
        return this.invoke('startDeviceAuth', { authEndpoint, tokenEndpoint });
    }

    async pollForToken(authEndpoint: string, tokenEndpoint: string, deviceCode: string, userCode: string, verificationURI: string, interval: number): Promise<string> {
        return this.invoke('pollForToken', { authEndpoint, tokenEndpoint, deviceCode, userCode, verificationURI, interval });
    }
}

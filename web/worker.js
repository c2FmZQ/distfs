importScripts('wasm_exec.js');

const go = new Go();

// Load the compiled Go WebAssembly module
WebAssembly.instantiateStreaming(fetch('distfs.wasm'), go.importObject).then((result) => {
    go.run(result.instance);
    postMessage({ type: 'ready' });
}).catch(err => {
    console.error("WASM Load Failed:", err);
});

onmessage = async (event) => {
    const { type, id, action, args } = event.data;

    // Handle generic 'invoke' for new actions without updating switch every time
    if (type === 'invoke') {
        const timeout = setTimeout(() => {
            postMessage({ type: 'error', id, error: `Action ${action} timed out after 30s` });
        }, 30000);

        try {
            const fn = self.DistFS[action];
            if (!fn) throw new Error(`WASM action not found: ${action}`);
            
            // Map args object to positional arguments for Go
            let result;
            switch(action) {
                case 'init': result = await fn(args.serverURL, args.userID, args.decKey, args.signKey, args.serverKey); break;
                case 'listDirectory': result = await fn(args.path); break;
                case 'statFile': result = await fn(args.path); break;
                case 'readFile': result = await fn(args.path); break;
                case 'writeFile': result = await fn(args.path, args.content); break;
                case 'mkdir': result = await fn(args.path); break;
                case 'mv': result = await fn(args.oldPath, args.newPath); break;
                case 'rm': result = await fn(args.path); break;
                case 'getQuota': result = await fn(); break;
                case 'generateKeys': result = await fn(); break;
                case 'fetchServerKey': result = await fn(args.serverURL); break;
                case 'registerUser': result = await fn(args.serverURL, args.jwt, args.signPubKey, args.encKey); break;
                case 'encryptConfig': result = await fn(args.config, args.passphrase); break;
                case 'decryptConfig': result = await fn(args.blob, args.passphrase); break;
                case 'pushKeySync': result = await fn(args.blob); break;
                case 'pullKeySync': result = await fn(args.serverURL, args.token); break;
                case 'startDeviceAuth': result = await fn(args.authEndpoint, args.tokenEndpoint); break;
                case 'pollForToken': result = await fn(args.authEndpoint, args.tokenEndpoint, args.deviceCode, args.userCode, args.verificationURI, args.interval); break;
                default: throw new Error(`Action mapping missing in worker for: ${action}`);
            }
            clearTimeout(timeout);
            postMessage({ type: 'success', id, result });
        } catch (e) {
            clearTimeout(timeout);
            postMessage({ type: 'error', id, error: e.toString() });
        }
        return;
    }

    // Streaming actions (legacy / specialized)
    try {
        if (type === 'media-stream') {
            const mediaPort = event.ports[0];
            try {
                const path = event.data.id;
                const meta = await self.DistFS.statFile(path); 
                mediaPort.postMessage({ 
                    type: 'media-metadata', 
                    size: meta.size,
                    mimeType: meta.mimeType || 'application/octet-stream'
                });

                mediaPort.onmessage = async (msg) => {
                    if (msg.data.type === 'stream-range') {
                        let offset = msg.data.start;
                        const end = msg.data.end;
                        const chunkSize = 1024 * 1024; // 1MB chunks

                        while (offset <= end) {
                            const length = Math.min(chunkSize, end - offset + 1);
                            const res = await self.DistFS.readFileChunk(path, offset, length);
                            const chunk = res.chunk;

                            if (res.detectedMimeType) {
                                mediaPort.postMessage({ type: 'mime-update', mimeType: res.detectedMimeType });
                            }

                            mediaPort.postMessage({ type: 'chunk', data: chunk }, [chunk.buffer]);
                            offset += length;
                        }
                        mediaPort.postMessage({ type: 'done' });
                    }                };
            } catch(err) {
                 mediaPort.postMessage({ type: 'error', error: err.toString() });
            }
        } else if (type === 'download-stream') {
            const port = event.ports[0];
            try {
                const path = event.data.id;
                const meta = await self.DistFS.statFile(path);
                let offset = 0;
                const size = meta.size;
                const chunkSize = 1024 * 1024;

                port.onmessage = async (msg) => {
                    if (msg.data.type === 'pull') {
                        if (offset < size) {
                            const length = Math.min(chunkSize, size - offset);
                            const chunk = await self.DistFS.readFileChunk(path, offset, length);
                            port.postMessage({ type: 'chunk', data: chunk }, [chunk.buffer]);
                            offset += length;
                        } else {
                            port.postMessage({ type: 'done' });
                        }
                    }
                };
                port.postMessage({ type: 'pull' });
            } catch(err) {
                port.postMessage({ type: 'error', error: err.toString() });
            }
        }
    } catch (e) {
        console.error("Worker generic error:", e);
    }
};

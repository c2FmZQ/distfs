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
    const { type, id } = event.data;

    if (!id && type !== 'download-stream') {
        // Ignore internal or legacy messages without an ID
        return;
    }

    try {
        let result;
        switch (type) {
            case 'init':
                result = await self.DistFS.init(
                    event.data.serverURL,
                    event.data.userID,
                    event.data.decKey,
                    event.data.signKey,
                    event.data.serverKey
                );
                break;
            case 'listDirectory':
                result = await self.DistFS.listDirectory(event.data.path);
                break;
            case 'generateKeys':
                result = await self.DistFS.generateKeys();
                break;
            case 'fetchServerKey':
                result = await self.DistFS.fetchServerKey(event.data.serverURL);
                break;
            case 'registerUser':
                result = await self.DistFS.registerUser(
                    event.data.serverURL,
                    event.data.jwt,
                    event.data.signKeyPubHex,
                    event.data.encKeyHex
                );
                break;
            case 'encryptConfig':
                result = await self.DistFS.encryptConfig(event.data.configStr, event.data.passphrase);
                break;
            case 'decryptConfig':
                result = await self.DistFS.decryptConfig(event.data.blobStr, event.data.passphrase);
                break;
            case 'pushKeySync':
                result = await self.DistFS.pushKeySync(event.data.blobStr);
                break;
            case 'pullKeySync':
                result = await self.DistFS.pullKeySync(event.data.serverURL, event.data.token);
                break;
            case 'startDeviceAuth':
                result = await self.DistFS.startDeviceAuth(event.data.authEndpoint, event.data.tokenEndpoint);
                break;
            case 'pollForToken':
                result = await self.DistFS.pollForToken(
                    event.data.authEndpoint,
                    event.data.tokenEndpoint,
                    event.data.deviceCode,
                    event.data.userCode,
                    event.data.verificationURI,
                    event.data.interval
                );
                break;
            case 'media-stream':
                const mediaPort = event.ports[0];
                try {
                    const id = event.data.id;
                    const meta = await self.DistFS.statFile(id); 
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
                                const chunk = await self.DistFS.readFileChunk(id, offset, length);
                                mediaPort.postMessage({ type: 'chunk', data: chunk }, [chunk.buffer]);
                                offset += length;
                            }
                            mediaPort.postMessage({ type: 'done' });
                        }
                    };
                } catch(err) {
                     mediaPort.postMessage({ type: 'error', error: err.toString() });
                }
                return;
            case 'download-stream':
                const port = event.ports[0];
                try {
                    const id = event.data.id;
                    const meta = await self.DistFS.statFile(id);
                    let offset = 0;
                    const size = meta.size;
                    const chunkSize = 1024 * 1024;

                    port.onmessage = async (msg) => {
                        if (msg.data.type === 'pull') {
                            if (offset < size) {
                                const length = Math.min(chunkSize, size - offset);
                                const chunk = await self.DistFS.readFileChunk(id, offset, length);
                                port.postMessage({ type: 'chunk', data: chunk }, [chunk.buffer]);
                                offset += length;
                            } else {
                                port.postMessage({ type: 'done' });
                            }
                        }
                    };
                    // Initial pull trigger
                    port.postMessage({ type: 'pull' });
                } catch(err) {
                    port.postMessage({ type: 'error', error: err.toString() });
                }
                return;
            default:
                throw new Error(`Unknown action type: ${type}`);
        }
        postMessage({ type: 'success', id, result });
    } catch (e) {
        postMessage({ type: 'error', id, error: e.toString() });
    }
};

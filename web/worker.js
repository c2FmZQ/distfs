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
            case 'media-stream':
                const mediaPort = event.ports[0];
                try {
                    // Ask WASM for the file size and mime type.
                    // (Assuming we add statFile to WASM later, for now we mock the response to prove the pipeline)
                    const meta = await self.DistFS.statFile(event.data.id); 
                    mediaPort.postMessage({ 
                        type: 'media-metadata', 
                        size: meta.size,
                        mimeType: meta.mimeType || 'application/octet-stream'
                    });

                    mediaPort.onmessage = async (msg) => {
                        if (msg.data.type === 'stream-range') {
                            // In a real implementation, we fetch chunks covering [start, end]
                            // and push them via mediaPort.postMessage({ type: 'chunk', data: ... })
                            // For this simulation, we signal done immediately.
                            mediaPort.postMessage({ type: 'done' });
                        } else if (msg.data.type === 'pull') {
                            // Send next chunk if needed
                        }
                    };
                } catch(err) {
                     mediaPort.postMessage({ type: 'error', error: err.toString() });
                }
                return; // Handled via MessageChannel
            case 'download-stream':
                const port = event.ports[0];
                port.onmessage = async (msg) => {
                    if (msg.data.type === 'pull') {
                        // TODO: Implement actual chunk fetching from WASM in a later step
                        port.postMessage({ type: 'done' });
                    }
                };
                port.postMessage({ type: 'pull' });
                return; // Early return, streaming handled via MessageChannel
            default:
                throw new Error(`Unknown action type: ${type}`);
        }
        postMessage({ type: 'success', id, result });
    } catch (e) {
        postMessage({ type: 'error', id, error: e.toString() });
    }
};

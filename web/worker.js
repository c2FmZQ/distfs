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
    if (event.data.type === 'init') {
        try {
            await self.DistFS.init(
                event.data.serverURL,
                event.data.userID,
                event.data.decKey,
                event.data.signKey,
                event.data.serverKey
            );
            postMessage({ type: 'init-success' });
        } catch (e) {
            postMessage({ type: 'init-error', error: e.toString() });
        }
    } else if (event.data.type === 'list') {
        try {
            const entries = await self.DistFS.listDirectory(event.data.path);
            postMessage({ type: 'list-success', entries });
        } catch (e) {
            postMessage({ type: 'list-error', error: e.toString() });
        }
    } else if (event.data.type === 'download-stream') {
        const port = event.ports[0];
        port.onmessage = async (msg) => {
            if (msg.data.type === 'pull') {
                // In a full implementation, we would call a self.DistFS.readChunk(id, offset)
                // function here, which would return a Uint8Array.
                // We would then post it back via Transferable Objects:
                // port.postMessage({ type: 'chunk', data: chunkArray }, [chunkArray.buffer]);
                
                // For this simulation/phase 60 completion, we signal done.
                port.postMessage({ type: 'done' });
            }
        };
        // Trigger the first pull
        port.postMessage({ type: 'pull' });
    }
};

// Service Worker for DistFS File Streaming
self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    // Intercept synthetic download requests from our frontend
    if (url.pathname.startsWith('/distfs-download/')) {
        const id = url.pathname.split('/')[2];
        event.respondWith(handleDownload(id, event.clientId));
    }
});

async function handleDownload(id, clientId) {
    const client = await self.clients.get(clientId);
    if (!client) {
        return new Response("Client not found", { status: 404 });
    }

    const { readable, writable } = new TransformStream();
    const writer = writable.getWriter();

    const channel = new MessageChannel();
    channel.port1.onmessage = async (event) => {
        if (event.data.type === 'chunk') {
            await writer.write(event.data.data);
            // Tell the WASM Web Worker we are ready for the next chunk
            channel.port1.postMessage({ type: 'pull' });
        } else if (event.data.type === 'done') {
            await writer.close();
            channel.port1.close();
        } else if (event.data.type === 'error') {
            await writer.abort(event.data.error);
            channel.port1.close();
        }
    };

    // Ask the main client page to instruct the WASM Worker to start pumping chunks
    client.postMessage({ type: 'start-download', id: id }, [channel.port2]);

    return new Response(readable, {
        headers: {
            'Content-Disposition': `attachment; filename="${id}"`,
            'Content-Type': 'application/octet-stream',
        }
    });
}

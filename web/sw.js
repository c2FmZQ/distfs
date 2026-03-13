// Service Worker for DistFS File Streaming
const CACHE_NAME = 'distfs-encrypted-chunks-v1';

self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    
    // Transparently cache encrypted data chunks fetched by the WASM module
    if (url.pathname.startsWith('/v1/data/')) {
        event.respondWith(
            caches.match(event.request).then((cachedResponse) => {
                if (cachedResponse) {
                    return cachedResponse;
                }
                return fetch(event.request).then((response) => {
                    // Only cache successful GET requests for chunks
                    if (event.request.method === 'GET' && response.status === 200) {
                        const responseToCache = response.clone();
                        caches.open(CACHE_NAME).then((cache) => {
                            cache.put(event.request, responseToCache);
                        });
                    }
                    return response;
                });
            })
        );
        return;
    }

    // Intercept synthetic download requests from our frontend
    if (url.pathname.startsWith('/distfs-download/')) {
        const id = url.pathname.split('/')[2];
        event.respondWith(handleDownload(id, event.clientId));
    }
    
    // Intercept media streaming requests
    if (url.pathname.startsWith('/distfs-media/')) {
        const id = url.pathname.split('/')[2];
        event.respondWith(handleMediaStream(event.request, id, event.clientId));
    }
});

async function handleMediaStream(request, id, clientId) {
    const client = await self.clients.get(clientId);
    if (!client) {
        return new Response("Client not found", { status: 404 });
    }

    const rangeHeader = request.headers.get('range');
    
    return new Promise((resolve) => {
        const channel = new MessageChannel();
        
        channel.port1.onmessage = (event) => {
            if (event.data.type === 'media-metadata') {
                // The WASM worker tells us the total file size and mime type
                const fileSize = event.data.size;
                const mimeType = event.data.mimeType || 'application/octet-stream';
                
                if (rangeHeader) {
                    const parts = rangeHeader.replace(/bytes=/, "").split("-");
                    const start = parseInt(parts[0], 10);
                    const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
                    const chunksize = (end - start) + 1;

                    const { readable, writable } = new TransformStream();
                    const writer = writable.getWriter();
                    
                    channel.port1.onmessage = async (chunkEvent) => {
                        if (chunkEvent.data.type === 'chunk') {
                            await writer.write(chunkEvent.data.data);
                            channel.port1.postMessage({ type: 'pull' });
                        } else if (chunkEvent.data.type === 'done') {
                            await writer.close();
                            channel.port1.close();
                        }
                    };

                    resolve(new Response(readable, {
                        status: 206,
                        headers: {
                            'Content-Range': `bytes ${start}-${end}/${fileSize}`,
                            'Accept-Ranges': 'bytes',
                            'Content-Length': chunksize.toString(),
                            'Content-Type': mimeType,
                        }
                    }));
                    
                    // Tell WASM to start sending chunks for this specific range
                    channel.port1.postMessage({ type: 'stream-range', start, end });
                    
                } else {
                    // Full file request
                    const { readable, writable } = new TransformStream();
                    const writer = writable.getWriter();
                    
                    channel.port1.onmessage = async (chunkEvent) => {
                        if (chunkEvent.data.type === 'chunk') {
                            await writer.write(chunkEvent.data.data);
                            channel.port1.postMessage({ type: 'pull' });
                        } else if (chunkEvent.data.type === 'done') {
                            await writer.close();
                            channel.port1.close();
                        }
                    };

                    resolve(new Response(readable, {
                        status: 200,
                        headers: {
                            'Content-Length': fileSize.toString(),
                            'Content-Type': mimeType,
                            'Accept-Ranges': 'bytes'
                        }
                    }));
                    
                    channel.port1.postMessage({ type: 'stream-range', start: 0, end: fileSize - 1 });
                }
            } else if (event.data.type === 'error') {
                resolve(new Response(event.data.error, { status: 500 }));
                channel.port1.close();
            }
        };

        client.postMessage({ type: 'request-media-meta', id: id }, [channel.port2]);
    });
}

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

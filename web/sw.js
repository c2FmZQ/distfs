// Service Worker for DistFS File Streaming
console.log('SW: Script loaded');
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
        console.log(`SW: Intercepting download request for ${url.pathname}`);
        const id = url.pathname.substring('/distfs-download'.length);
        event.respondWith(handleDownload(id, event.clientId));
    }
    
    // Intercept media streaming requests
    if (url.pathname.startsWith('/distfs-media/')) {
        console.log(`SW: Intercepting media request for ${url.pathname}, clientId=${event.clientId}`);
        const id = url.pathname.substring('/distfs-media'.length);
        event.respondWith(handleMediaStream(event.request, id, event.clientId));
    }
});

async function handleMediaStream(request, id, clientId) {
    if (!clientId) {
        const allClients = await self.clients.matchAll();
        if (allClients.length > 0) {
            clientId = allClients[0].id;
        }
    }

    const client = await self.clients.get(clientId);
    if (!client) {
        console.error(`SW: Client not found for id ${clientId}`);
        return new Response("Client not found", { status: 404 });
    }

    console.log(`SW: Found client ${clientId}, requesting metadata for ${id}`);
    const rangeHeader = request.headers.get('range');
    
    return new Promise((resolve) => {
        const channel = new MessageChannel();
        
        channel.port1.onmessage = (event) => {
            if (event.data.type === 'media-metadata') {
                console.log(`SW: Received metadata for ${id}: size=${event.data.size}`);
                const fileSize = event.data.size;
                let mimeType = event.data.mimeType || 'application/octet-stream';
                
                const { readable, writable } = new TransformStream();
                const writer = writable.getWriter();
                let responseSent = false;

                const sendResponse = () => {
                    if (responseSent) return;
                    responseSent = true;

                    if (rangeHeader) {
                        const parts = rangeHeader.replace(/bytes=/, "").split("-");
                        const start = parseInt(parts[0], 10);
                        const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
                        const chunksize = (end - start) + 1;

                        resolve(new Response(readable, {
                            status: 206,
                            headers: {
                                'Content-Range': `bytes ${start}-${end}/${fileSize}`,
                                'Accept-Ranges': 'bytes',
                                'Content-Length': chunksize.toString(),
                                'Content-Type': mimeType,
                            }
                        }));
                    } else {
                        resolve(new Response(readable, {
                            status: 200,
                            headers: {
                                'Content-Length': fileSize.toString(),
                                'Content-Type': mimeType,
                                'Accept-Ranges': 'bytes'
                            }
                        }));
                    }
                };

                // Fallback timeout for sniffing
                const sniffTimeout = setTimeout(sendResponse, 2000);

                channel.port1.onmessage = async (chunkEvent) => {
                    if (chunkEvent.data.type === 'chunk') {
                        await writer.write(chunkEvent.data.data);
                        sendResponse(); // Ensure response is sent on first chunk
                        channel.port1.postMessage({ type: 'pull' });
                    } else if (chunkEvent.data.type === 'mime-update') {
                        console.log(`SW: Sniffed MIME update for ${id}: ${chunkEvent.data.mimeType}`);
                        mimeType = chunkEvent.data.mimeType;
                        clearTimeout(sniffTimeout);
                        sendResponse();
                    } else if (chunkEvent.data.type === 'done') {
                        await writer.close();
                        channel.port1.close();
                    }
                };

                const start = rangeHeader ? parseInt(rangeHeader.replace(/bytes=/, "").split("-")[0], 10) : 0;
                const end = rangeHeader && rangeHeader.split("-")[1] ? parseInt(rangeHeader.split("-")[1], 10) : fileSize - 1;
                channel.port1.postMessage({ type: 'stream-range', start, end });

            } else if (event.data.type === 'error') {
                console.error(`SW: Error from client: ${event.data.error}`);
                resolve(new Response(event.data.error, { status: 500 }));
                channel.port1.close();
            }
        };

        client.postMessage({ type: 'request-media-meta', id: id }, [channel.port2]);
    });
}

async function handleDownload(id, clientId) {
    if (!clientId) {
        const allClients = await self.clients.matchAll();
        if (allClients.length > 0) {
            clientId = allClients[0].id;
        }
    }

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
            channel.port1.postMessage({ type: 'pull' });
        } else if (event.data.type === 'done') {
            await writer.close();
            channel.port1.close();
        } else if (event.data.type === 'error') {
            await writer.abort(event.data.error);
            channel.port1.close();
        }
    };

    client.postMessage({ type: 'start-download', id: id }, [channel.port2]);

    return new Response(readable, {
        headers: {
            'Content-Disposition': `attachment; filename="${id.split('/').pop()}"`,
            'Content-Type': 'application/octet-stream',
        }
    });
}

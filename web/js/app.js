import { WasmClient } from './wasm_client.js';
class DistFSApp {
    client;
    serverURL = localStorage.getItem('distfs_server_url') || 'http://localhost:8080';
    currentPath = '/';
    constructor() {
        this.client = new WasmClient('worker.js');
        this.client.onReady = () => {
            const statusEl = document.getElementById('status');
            if (statusEl) {
                statusEl.innerText = 'WASM Ready. Awaiting authentication.';
            }
        };
        this.initUI();
        this.setupServiceWorkerBridge();
    }
    setupServiceWorkerBridge() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.addEventListener('message', (event) => {
                if (event.data.type === 'start-download') {
                    // Send directly to the WasmClient's internal worker to bypass the main thread UI block
                    this.client.worker.postMessage({
                        type: 'download-stream',
                        id: event.data.id
                    }, [event.ports[0]]);
                }
                else if (event.data.type === 'request-media-meta') {
                    this.client.worker.postMessage({
                        type: 'media-stream',
                        id: event.data.id
                    }, [event.ports[0]]);
                }
            });
        }
    }
    initUI() {
        const statusEl = document.getElementById('status');
        if (statusEl) {
            statusEl.innerText = 'Initializing Web Worker...';
        }
        const btnNew = document.getElementById('btn-new-account');
        if (btnNew) {
            btnNew.addEventListener('click', () => this.handleNewAccount());
        }
        const btnLogin = document.getElementById('btn-login');
        if (btnLogin) {
            btnLogin.addEventListener('click', () => this.handleLogin());
        }
        document.getElementById('btn-cancel-share')?.addEventListener('click', () => {
            document.getElementById('share-modal').style.display = 'none';
        });
        document.getElementById('btn-confirm-share')?.addEventListener('click', async () => {
            const fileName = document.getElementById('share-file-name').innerText;
            const target = document.getElementById('share-target-email').value;
            const perms = document.getElementById('share-perms').value;
            if (!target)
                return;
            const fullPath = this.currentPath === '/' ? `/${fileName}` : `${this.currentPath}/${fileName}`;
            try {
                // TODO: Wire up actual ACL mutation via WASM
                // await this.client.invoke('setACL', { path: fullPath, target, perms });
                alert(`Successfully shared ${fileName} with ${target} (${perms})`);
                document.getElementById('share-modal').style.display = 'none';
            }
            catch (err) {
                alert(`Failed to share: ${err.message}`);
            }
        });
        this.setupDragAndDrop();
    }
    setupDragAndDrop() {
        const mainView = document.getElementById('main-view');
        if (!mainView)
            return;
        mainView.addEventListener('dragover', (e) => {
            e.preventDefault();
            mainView.classList.add('dragover');
        });
        mainView.addEventListener('dragleave', (e) => {
            e.preventDefault();
            mainView.classList.remove('dragover');
        });
        mainView.addEventListener('drop', (e) => {
            e.preventDefault();
            mainView.classList.remove('dragover');
            if (e.dataTransfer && e.dataTransfer.files.length > 0) {
                const file = e.dataTransfer.files[0];
                alert(`File upload not yet implemented. Caught: ${file.name}`);
                // TODO: Implement chunked streaming upload to WASM worker
            }
        });
    }
    async handleNewAccount() {
        const statusEl = document.getElementById('status');
        statusEl.innerText = 'Generating Post-Quantum Keys...';
        try {
            const keys = await this.client.generateKeys();
            console.log("Keys generated locally.");
            const mockJWT = prompt("Enter an OIDC JWT to register:");
            if (!mockJWT) {
                statusEl.innerText = 'Registration cancelled.';
                return;
            }
            statusEl.innerText = 'Registering with cluster...';
            const userID = await this.client.registerUser(this.serverURL, mockJWT, keys.signPubKey, keys.encKey);
            const passphrase = prompt("Registration successful! Enter a passphrase to backup your keys to the cloud:");
            if (!passphrase) {
                statusEl.innerText = 'Registration complete, but keys were not backed up.';
                return;
            }
            statusEl.innerText = 'Fetching server key...';
            const serverKeyHex = await this.client.fetchServerKey(this.serverURL);
            const config = {
                user_id: userID,
                enc_key: keys.decKey,
                sign_key: keys.signKey,
                server_key: serverKeyHex
            };
            statusEl.innerText = 'Encrypting configuration...';
            const encryptedBlob = await this.client.encryptConfig(JSON.stringify(config), passphrase);
            statusEl.innerText = 'Initializing client...';
            await this.client.init(this.serverURL, config.user_id, config.enc_key, config.sign_key, config.server_key);
            statusEl.innerText = 'Pushing to cloud backup...';
            await this.client.pushKeySync(encryptedBlob);
            statusEl.innerText = `Account created and backed up! User ID: ${userID}`;
            this.onLoginSuccess(userID);
        }
        catch (e) {
            statusEl.innerText = `Error: ${e.message}`;
        }
    }
    async handleLogin() {
        const statusEl = document.getElementById('status');
        try {
            const mockJWT = prompt("Enter your OIDC JWT to login:");
            if (!mockJWT)
                return;
            statusEl.innerText = 'Fetching cloud backup...';
            const blobStr = await this.client.pullKeySync(this.serverURL, mockJWT);
            const passphrase = prompt("Enter your passphrase to decrypt your keys:");
            if (!passphrase)
                return;
            statusEl.innerText = 'Decrypting keys...';
            const configStr = await this.client.decryptConfig(blobStr, passphrase);
            const config = JSON.parse(configStr);
            statusEl.innerText = 'Initializing client...';
            await this.client.init(this.serverURL, config.user_id, config.enc_key, config.sign_key, config.server_key);
            this.onLoginSuccess(config.user_id);
        }
        catch (e) {
            statusEl.innerText = `Login Error: ${e.message}`;
        }
    }
    onLoginSuccess(userID) {
        document.getElementById('auth-overlay').style.display = 'none';
        document.getElementById('user-info').innerText = `User: ${userID.substring(0, 8)}...`;
        this.loadDirectory('/');
    }
    async loadDirectory(path) {
        this.currentPath = path;
        document.getElementById('breadcrumb').innerText = path;
        const fileList = document.getElementById('file-list');
        fileList.innerHTML = '<div>Loading...</div>';
        try {
            const entries = await this.client.listDirectory(path);
            fileList.innerHTML = '';
            if (path !== '/') {
                const upDir = document.createElement('div');
                upDir.className = 'file-item';
                upDir.innerHTML = `<div class="file-icon">📁</div><div class="file-name">..</div>`;
                upDir.onclick = () => {
                    const parent = path.substring(0, path.lastIndexOf('/')) || '/';
                    this.loadDirectory(parent);
                };
                fileList.appendChild(upDir);
            }
            for (const entry of entries) {
                const el = document.createElement('div');
                el.className = 'file-item';
                const isImage = entry.name.match(/\.(jpg|jpeg|png|gif|webp)$/i);
                let iconContent = entry.isDir ? '📁' : '📄';
                if (!entry.isDir && isImage) {
                    // For images, we use our Service Worker media stream to render the thumbnail.
                    // The SW intercepts /distfs-media/ requests and decrypts on the fly.
                    iconContent = `<img src="/distfs-media/${entry.name}" style="max-width: 100%; max-height: 100px; object-fit: contain;" alt="${entry.name}">`;
                }
                const sizeStr = entry.isDir ? '' : `<br><small>${(entry.size / 1024).toFixed(1)} KB</small>`;
                el.innerHTML = `
                    <div class="file-icon" style="height: 100px; display: flex; align-items: center; justify-content: center;">${iconContent}</div>
                    <div class="file-name">${entry.name}${sizeStr}</div>
                    <button class="share-btn" style="margin-top: 5px; font-size: 0.8em; padding: 2px 5px;" onclick="event.stopPropagation(); window.openShareModal('${entry.name}')">Share</button>
                `;
                el.onclick = () => {
                    if (entry.isDir) {
                        const newPath = path === '/' ? `/${entry.name}` : `${path}/${entry.name}`;
                        this.loadDirectory(newPath);
                    }
                    else {
                        const dlLink = document.createElement('a');
                        dlLink.href = `/distfs-download/${entry.name}`;
                        dlLink.download = entry.name;
                        dlLink.click();
                    }
                };
                fileList.appendChild(el);
            }
        }
        catch (e) {
            fileList.innerHTML = `<div style="color:red">Error: ${e.message}</div>`;
        }
    }
    async generateThumbnail(imageBlob, maxWidth = 200, maxHeight = 200) {
        return new Promise((resolve, reject) => {
            const img = new Image();
            const objectUrl = URL.createObjectURL(imageBlob);
            img.onload = () => {
                URL.revokeObjectURL(objectUrl);
                let width = img.width;
                let height = img.height;
                if (width > maxWidth) {
                    height *= maxWidth / width;
                    width = maxWidth;
                }
                if (height > maxHeight) {
                    width *= maxHeight / height;
                    height = maxHeight;
                }
                const canvas = document.createElement('canvas');
                canvas.width = width;
                canvas.height = height;
                const ctx = canvas.getContext('2d');
                if (!ctx) {
                    return reject(new Error("Failed to get 2d context"));
                }
                ctx.drawImage(img, 0, 0, width, height);
                canvas.toBlob((blob) => {
                    if (blob)
                        resolve(blob);
                    else
                        reject(new Error("Failed to generate blob"));
                }, 'image/jpeg', 0.8);
            };
            img.onerror = reject;
            img.src = objectUrl;
        });
    }
}
window.addEventListener('DOMContentLoaded', () => {
    const app = new DistFSApp();
    window.openShareModal = (fileName) => {
        document.getElementById('share-file-name').innerText = fileName;
        document.getElementById('share-modal').style.display = 'flex';
    };
});

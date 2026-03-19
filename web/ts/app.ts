import { WasmClient } from './wasm_client.js';

interface FileEntry {
    name: string;
    isDir: boolean;
    size: number;
    modTime: number;
    owner: string;
    group: string;
    mode: number;
    mimeType: string;
    lockbox: Record<string, { kem: string, dem: string }>;
    accessACL?: {
        Users: Record<string, number>;
        Groups: Record<string, number>;
    };
}

interface UserQuota {
    used_bytes: number;
    total_bytes: number;
    used_inodes: number;
    total_inodes: number;
}

interface WebMetadata {
    starred: string[];
    recent: string[];
}

class DistFSApp {
    private client: WasmClient;
    private serverURL = localStorage.getItem('distfs_server_url') || window.location.origin;
    private currentPath = '/';
    private viewMode: 'grid' | 'list' = 'grid';
    private selectedItems: Set<FileEntry> = new Set();
    private currentEntries: FileEntry[] = [];
    private userID: string = '';
    private homeDir: string | null = null;
    private meta: WebMetadata = { starred: [], recent: [] };
    private treeData: Map<string, string[]> = new Map();
    private isRefreshingTree = false;

    constructor() {
        this.client = new WasmClient('worker.js');
        this.client.onReady = () => {
            const statusEl = document.getElementById('status');
            if (statusEl) statusEl.innerText = 'WASM Ready. Awaiting authentication.';
            const btnLogin = document.getElementById('btn-login') as HTMLButtonElement;
            if (btnLogin) btnLogin.disabled = false;
            const btnNew = document.getElementById('btn-new-account') as HTMLButtonElement;
            if (btnNew) btnNew.disabled = false;
        };
        this.initUI();
        this.setupServiceWorkerBridge();
    }

    private setupServiceWorkerBridge() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.addEventListener('message', (event) => {
                if (event.data.type === 'start-download') {
                    this.client.postMessage({ type: 'download-stream', id: event.data.id }, [event.ports[0]]);
                } else if (event.data.type === 'request-media-meta') {
                    const mediaPort = event.ports[0];
                    const originalOnMessage = mediaPort.onmessage;
                    mediaPort.onmessage = (msg) => {
                        if (msg.data.type === 'mime-update') {
                            const path = event.data.id;
                            const entry = this.currentEntries.find(e => {
                                const fullPath = this.currentPath === '/' ? `/${e.name}` : `${this.currentPath}/${e.name}`;
                                return fullPath === path;
                            });
                            if (entry && entry.mimeType !== msg.data.mimeType) {
                                let newMime = msg.data.mimeType;
                                if (newMime === 'text/plain; charset=utf-8' && path.endsWith('.md')) {
                                    newMime = 'text/markdown';
                                }
                                entry.mimeType = newMime;
                                console.log(`UI: MIME corrected for ${path}: ${entry.mimeType}`);
                                this.renderFileList();
                                if (this.selectedItems.has(entry)) this.renderDetailsPane(entry);
                                if (!document.getElementById('preview-overlay')!.classList.contains('hidden') && 
                                    document.getElementById('preview-title')!.innerText === entry.name) {
                                    this.openPreview(entry);
                                }
                            }
                        }
                        if (originalOnMessage) originalOnMessage.call(mediaPort, msg);
                    };
                    this.client.postMessage({ type: 'media-stream', id: event.data.id }, [mediaPort]);
                }
            });
        }
    }

    private initUI() {
        document.getElementById('btn-new-account')?.addEventListener('click', () => this.handleNewAccount());
        document.getElementById('btn-login')?.addEventListener('click', () => this.handleLogin());
        document.getElementById('btn-list-view')?.addEventListener('click', () => this.setViewMode('list'));
        document.getElementById('btn-grid-view')?.addEventListener('click', () => this.setViewMode('grid'));
        document.getElementById('btn-info-toggle')?.addEventListener('click', () => this.toggleDetailsPane());
        document.getElementById('btn-close-details')?.addEventListener('click', () => this.toggleDetailsPane(false));
        document.getElementById('nav-my-drive')?.addEventListener('click', () => this.loadDirectory('/'));
        document.getElementById('nav-recent')?.addEventListener('click', () => this.showRecent());
        document.getElementById('nav-starred')?.addEventListener('click', () => this.showStarred());
        document.getElementById('tree-root-node')?.addEventListener('click', () => this.loadDirectory('/'));
        document.getElementById('btn-cancel-device-flow')?.addEventListener('click', () => window.location.reload());
        document.getElementById('btn-close-preview')?.addEventListener('click', () => this.closePreview());
        document.getElementById('btn-preview-download')?.addEventListener('click', () => this.downloadSelected());
        document.getElementById('btn-cancel-share')?.addEventListener('click', () => {
            (document.getElementById('btn-confirm-share') as HTMLButtonElement).innerText = 'Share';
            document.getElementById('share-modal')!.style.display = 'none';
        });
        document.getElementById('btn-confirm-share')?.addEventListener('click', () => {
            this.handleShareSubmit();
        });

        this.setupDragAndDrop();
        this.setupGlobalClickHandlers();
    }

    private setViewMode(mode: 'grid' | 'list') {
        this.viewMode = mode;
        document.getElementById('btn-list-view')?.classList.toggle('active', mode === 'list');
        document.getElementById('btn-grid-view')?.classList.toggle('active', mode === 'grid');
        this.renderFileList();
    }

    private toggleDetailsPane(show?: boolean) {
        const pane = document.getElementById('details-pane')!;
        const isCollapsed = pane.classList.contains('collapsed');
        const shouldShow = show !== undefined ? show : isCollapsed;
        pane.classList.toggle('collapsed', !shouldShow);
        document.getElementById('btn-info-toggle')?.classList.toggle('active', shouldShow);
    }

    private setupGlobalClickHandlers() {
        document.getElementById('file-browser-container')?.addEventListener('click', (e) => {
            if (e.target === e.currentTarget || e.target === document.getElementById('file-list')) {
                this.clearSelection();
            }
        });
        window.addEventListener('click', () => {
            document.getElementById('context-menu')!.style.display = 'none';
        });
        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                if (!document.getElementById('preview-overlay')!.classList.contains('hidden')) this.closePreview();
                else this.clearSelection();
            }
        });
    }

    private async updateQuota() {
        try {
            const quota: UserQuota = await this.client.getQuota();
            document.getElementById('quota-bar-fill')!.style.width = `${quota.total_bytes > 0 ? (quota.used_bytes / quota.total_bytes) * 100 : 0}%`;
            document.getElementById('quota-used')!.innerText = this.formatSize(quota.used_bytes);
            document.getElementById('quota-total')!.innerText = quota.total_bytes > 0 ? this.formatSize(quota.total_bytes) : "Unlimited";
        } catch (e) { console.error("Quota fetch failed", e); }
    }

    private async performDeviceFlow(): Promise<string> {
        const authRes = await fetch(`${this.serverURL}/v1/auth/config`);
        const config = await authRes.json();
        const authInfo = await this.client.startDeviceAuth(config.device_authorization_endpoint, config.token_endpoint);
        const modal = document.getElementById('device-flow-modal')!;
        const code = document.getElementById('device-flow-code')!;
        const link = document.getElementById('device-flow-link')! as HTMLAnchorElement;
        
        link.href = authInfo.verificationURIComplete || authInfo.verificationURI;
        link.innerText = authInfo.verificationURI;
        code.innerText = authInfo.userCode;
        modal.style.display = 'flex';
        
        try {
            return await this.client.pollForToken(config.device_authorization_endpoint, config.token_endpoint, authInfo.deviceCode, authInfo.userCode, authInfo.verificationURI, authInfo.interval);
        } finally { modal.style.display = 'none'; }
    }

    private async handleLogin() {
        const statusEl = document.getElementById('status')!;
        try {
             statusEl.innerText = 'Authorizing...';
             const jwt = await this.performDeviceFlow();
             statusEl.innerText = 'Fetching keys...';
             const blobStr = await this.client.pullKeySync(this.serverURL, jwt);
             const passphrase = prompt("Enter backup passphrase:");
             if (!passphrase) return;
             const config = JSON.parse(await this.client.decryptConfig(blobStr, passphrase));
             const serverKeyHex = await this.client.fetchServerKey(this.serverURL);
             await this.client.init(this.serverURL, config.user_id, config.enc_key, config.sign_key, serverKeyHex);
             this.userID = config.user_id;
             await this.onLoginSuccess();
        } catch (e: any) { 
            console.error("Login failed:", e);
            statusEl.innerText = `Error: ${e.message}`; 
        }
    }

    private async handleNewAccount() {
        const statusEl = document.getElementById('status')!;
        try {
            statusEl.innerText = 'Generating Keys...';
            const keys = await this.client.generateKeys();
            const jwt = await this.performDeviceFlow();
            statusEl.innerText = 'Registering...';
            const userID = await this.client.registerUser(this.serverURL, jwt, keys.signPubKey, keys.encKey);
            const passphrase = prompt("Enter backup passphrase:");
            if (!passphrase) return;
            const serverKeyHex = await this.client.fetchServerKey(this.serverURL);
            const config = { user_id: userID, enc_key: keys.decKey, sign_key: keys.signKey, server_key: serverKeyHex };
            await this.client.init(this.serverURL, userID, keys.decKey, keys.signKey, serverKeyHex);
            await this.client.pushKeySync(await this.client.encryptConfig(JSON.stringify(config), passphrase));
            this.userID = userID;
            await this.onLoginSuccess();
        } catch (e: any) { 
            console.error("Login failed:", e);
            statusEl.innerText = `Error: ${e.message}`; 
        }
    }

    private async onLoginSuccess() {
        document.getElementById('auth-overlay')!.style.display = 'none';
        document.getElementById('user-info')!.innerText = `User: ${this.userID.substring(0,8)}...`;
        await this.discoverHome();
        await this.loadMetadata();
        await this.loadDirectory('/');
        await this.updateQuota();
        await this.refreshFolderTree();
    }

    private async discoverHome() {
        try {
            const res = await this.client.listDirectory('/users');
            const users = res.entries;
            for (const u of users) {
                try {
                    const info = await this.client.statFile(`/users/${u.name}`);
                    if (info.owner === this.userID) { this.homeDir = `/users/${u.name}`; break; }
                } catch (e) {}
            }
        } catch (e) { console.warn("Home discovery failed"); }
    }

    private async loadMetadata() {
        if (!this.homeDir) return;
        try { this.meta = JSON.parse(await this.client.readFile(`${this.homeDir}/.distfs_web_meta.json`)); } catch (e) {}
    }

    private async saveMetadata() {
        if (!this.homeDir) return;
        try { await this.client.writeFile(`${this.homeDir}/.distfs_web_meta.json`, JSON.stringify(this.meta)); } catch (e) {}
    }

    private async loadDirectory(path: string, offset: number = 0) {
        if (offset === 0) {
            this.currentPath = path;
            this.renderBreadcrumbs();
            const fileList = document.getElementById('file-list')!;
            fileList.innerHTML = '';
            const loading = document.createElement('div');
            loading.style.padding = '24px';
            loading.style.color = 'var(--text-muted)';
            loading.textContent = 'Syncing metadata...';
            fileList.appendChild(loading);
            this.currentEntries = [];
        }
        const fileList = document.getElementById('file-list')!;
        try {
            const limit = 1000;
            const res = await this.client.listDirectory(path, offset, limit);
            const rawEntries = res.entries;
            console.log(`UI: listDirectory(${path}, ${offset}) returned ${rawEntries.length} entries (total: ${res.total})`);
            const folderNames: string[] = [];
            const newEntries: FileEntry[] = [];

            // SEC: Process in smaller batches to avoid overwhelming the WASM worker and browser thread
            const batchSize = 50;
            for (let i = 0; i < rawEntries.length; i += batchSize) {
                const batch = rawEntries.slice(i, i + batchSize);
                const batchResults = await Promise.all(batch.map(async (e: any) => {
                    const fullPath = path === '/' ? `/${e.name}` : `${path}/${e.name}`;
                    try {
                        const info = await this.client.statFile(fullPath);
                        if (info.isDir) folderNames.push(info.name);
                        return info as FileEntry;
                    } catch (err) {
                        console.error(`UI: statFile error for ${fullPath}:`, err);
                        return { name: e.name, isDir: e.isDir, size: e.size, modTime: 0, owner: '?', group: '?', mode: 0, mimeType: 'application/octet-stream', lockbox: {} } as FileEntry;
                    }
                }));
                newEntries.push(...batchResults);
            }
            
            if (offset === 0) fileList.innerHTML = ''; // Clear "Syncing..."
            this.currentEntries.push(...newEntries);
            
            const existingFolders = this.treeData.get(path) || [];
            this.treeData.set(path, Array.from(new Set([...existingFolders, ...folderNames])));
            
            this.renderFileList();
            
            if (offset + limit < res.total) {
                this.renderLoadMore(path, offset + limit);
            } else {
                this.clearSelection();
                this.updateSidebarActive();
                if (offset === 0) await this.refreshFolderTree();
            }
        } catch (e: any) {
            console.error(`UI: loadDirectory error for ${path}:`, e);
            fileList.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.style.padding = '24px';
            errDiv.style.color = '#d93025';
            errDiv.textContent = `Error: ${e.message}`;
            fileList.appendChild(errDiv);
        }
    }

    private renderLoadMore(path: string, nextOffset: number) {
        const container = document.getElementById('file-list')!;
        const btn = document.createElement('button');
        btn.className = 'secondary-btn';
        btn.style.margin = '24px auto';
        btn.style.display = 'block';
        btn.innerText = `Load More (Total: ${this.currentEntries.length}+)`;
        btn.onclick = () => {
            btn.innerText = 'Loading...';
            btn.disabled = true;
            this.loadDirectory(path, nextOffset);
        };
        container.appendChild(btn);
    }

    private async refreshFolderTree() {
        if (this.isRefreshingTree) return;
        this.isRefreshingTree = true;
        const container = document.getElementById('tree-children')!;
        if (!container) return;
        try {
            const res = await this.client.listDirectory('/users');
            const usersRes = res.entries;
            console.log(`UI: Found ${usersRes.length} users for tree`);
            container.innerHTML = '';
            for (const u of usersRes) {
                console.log(`UI: Adding tree node for ${u.name}`);
                const fullPath = `/users/${u.name}`;
                const node = document.createElement('div');
                node.className = 'tree-node';
                node.textContent = `📁 ${u.name}`;
                if (this.currentPath === fullPath || this.currentPath.startsWith(fullPath + '/')) node.classList.add('selected');
                node.onclick = (e) => { e.stopPropagation(); this.loadDirectory(fullPath); };
                container.appendChild(node);
            }
        } finally { this.isRefreshingTree = false; }
    }

    private showRecent() {
        this.currentPath = 'Recent';
        this.renderBreadcrumbs();
        this.currentEntries = []; 
        this.renderFileList();
        this.updateSidebarActive('nav-recent');
    }

    private showStarred() {
        this.currentPath = 'Starred';
        this.renderBreadcrumbs();
        this.currentEntries = [];
        this.renderFileList();
        this.updateSidebarActive('nav-starred');
    }

    private updateSidebarActive(id: string = 'nav-my-drive') {
        document.querySelectorAll('.sidebar-nav li').forEach(el => el.classList.remove('active'));
        document.getElementById(id)?.classList.add('active');
    }

    private renderBreadcrumbs() {
        const container = document.getElementById('breadcrumb')!;
        container.innerHTML = '';
        if (this.currentPath === 'Recent' || this.currentPath === 'Starred') {
            const span = document.createElement('span'); span.innerText = this.currentPath;
            container.appendChild(span); return;
        }
        const parts = this.currentPath.split('/').filter(p => p !== '');
        const rootSpan = document.createElement('span'); rootSpan.innerText = 'My Files';
        rootSpan.onclick = () => this.loadDirectory('/');
        container.appendChild(rootSpan);
        let currentBuildPath = '';
        for (const part of parts) {
            const sep = document.createElement('span'); sep.className = 'separator'; sep.innerText = '›';
            container.appendChild(sep);
            currentBuildPath += '/' + part;
            const span = document.createElement('span'); span.innerText = part;
            const targetPath = currentBuildPath;
            span.onclick = () => this.loadDirectory(targetPath);
            container.appendChild(span);
        }
    }

    private renderFileList() {
        const container = document.getElementById('file-list')!;
        container.className = this.viewMode;
        container.innerHTML = '';
        if (this.viewMode === 'list') {
            const header = document.createElement('div'); header.className = 'file-header';
            
            const nameCell = document.createElement('div');
            nameCell.className = 'file-name-cell';
            nameCell.textContent = 'Name';
            
            const sizeCell = document.createElement('div');
            sizeCell.className = 'file-size-cell';
            sizeCell.textContent = 'Size';
            
            const dateCell = document.createElement('div');
            dateCell.className = 'file-date-cell';
            dateCell.textContent = 'Modified';
            
            header.appendChild(nameCell);
            header.appendChild(sizeCell);
            header.appendChild(dateCell);
            container.appendChild(header);
        }
        for (const entry of this.currentEntries) container.appendChild(this.createFileElement(entry));
    }

    private createFileElement(entry: FileEntry): HTMLElement {
        const el = document.createElement('div');
        el.className = 'file-item';
        if (this.selectedItems.has(entry)) el.classList.add('selected');
        const icon = entry.isDir ? '📁' : (entry.mimeType.startsWith('image/') ? '🖼️' : '📄');
        
        if (this.viewMode === 'grid') {
            const iconDiv = document.createElement('div');
            iconDiv.className = 'file-icon';
            if (!entry.isDir && entry.mimeType.startsWith('image/')) {
                const fullPath = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
                const img = document.createElement('img');
                img.src = `/distfs-media${fullPath}`;
                img.alt = entry.name;
                img.loading = 'lazy';
                iconDiv.appendChild(img);
            } else {
                iconDiv.textContent = icon;
            }
            
            const nameDiv = document.createElement('div');
            nameDiv.className = 'file-name';
            nameDiv.textContent = entry.name;
            
            const metaDiv = document.createElement('div');
            metaDiv.className = 'file-meta';
            metaDiv.textContent = entry.isDir ? '--' : this.formatSize(entry.size);
            
            el.appendChild(iconDiv);
            el.appendChild(nameDiv);
            el.appendChild(metaDiv);
        } else {
            const nameCell = document.createElement('div');
            nameCell.className = 'file-name-cell';
            
            const iconSpan = document.createElement('span');
            iconSpan.className = 'file-icon';
            iconSpan.textContent = icon;
            
            const nameSpan = document.createElement('span');
            nameSpan.className = 'file-name';
            nameSpan.textContent = entry.name;
            
            nameCell.appendChild(iconSpan);
            nameCell.appendChild(nameSpan);
            
            const sizeCell = document.createElement('div');
            sizeCell.className = 'file-size-cell';
            sizeCell.textContent = entry.isDir ? '--' : this.formatSize(entry.size);
            
            const dateCell = document.createElement('div');
            dateCell.className = 'file-date-cell';
            dateCell.textContent = this.formatDate(entry.modTime);
            
            el.appendChild(nameCell);
            el.appendChild(sizeCell);
            el.appendChild(dateCell);
        }
        el.onclick = (e) => {
            e.stopPropagation();
            if (!e.ctrlKey && !e.shiftKey) this.clearSelection();
            this.toggleSelection(entry);
        };
        el.ondblclick = () => {
            const fullPath = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
            if (entry.isDir) { this.clearSelection(); this.loadDirectory(fullPath); }
            else this.openPreview(entry);
        };
        el.oncontextmenu = (e) => { e.preventDefault(); if (!this.selectedItems.has(entry)) { this.clearSelection(); this.toggleSelection(entry); } this.showContextMenu(e.clientX, e.clientY, entry); };
        return el;
    }

    private toggleSelection(entry: FileEntry) {
        if (this.selectedItems.has(entry)) this.selectedItems.delete(entry); else this.selectedItems.add(entry);
        this.renderFileList();
        this.renderDetailsPane(this.selectedItems.size === 1 ? Array.from(this.selectedItems)[0] : null);
    }

    private clearSelection() {
        this.selectedItems.clear();
        this.renderFileList();
        this.renderDetailsPane(null);
    }

    private async openPreview(entry: FileEntry) {
        const fullPath = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
        const overlay = document.getElementById('preview-overlay')!;
        const body = document.getElementById('preview-body')!;
        document.getElementById('preview-title')!.innerText = entry.name;
        body.innerHTML = '';
        const loading = document.createElement('div');
        loading.style.color = 'white';
        loading.textContent = 'Loading...';
        body.appendChild(loading);
        overlay.classList.remove('hidden');
        try {
            if (entry.mimeType.startsWith('image/')) {
                const img = document.createElement('img');
                img.src = `/distfs-media${fullPath}`;
                img.style.maxWidth = '100%';
                img.style.maxHeight = '100%';
                img.style.objectFit = 'contain';
                body.innerHTML = '';
                body.appendChild(img);
            } else if (entry.mimeType.startsWith('video/') || entry.mimeType.startsWith('audio/')) {
                const tag = entry.mimeType.startsWith('video/') ? 'video' : 'audio';
                const media = document.createElement(tag);
                media.src = `/distfs-media${fullPath}`;
                media.controls = true;
                media.autoplay = true;
                media.style.maxWidth = '100%';
                media.style.maxHeight = '100%';
                body.innerHTML = '';
                body.appendChild(media);
            } else if (entry.mimeType === 'text/plain' || entry.mimeType === 'text/markdown' || entry.name.endsWith('.md') || entry.name.endsWith('.txt')) {
                const text = await this.client.readFile(fullPath);
                body.innerHTML = '';
                if (entry.mimeType === 'text/markdown' || entry.name.endsWith('.md')) {
                    const mdDiv = document.createElement('div');
                    mdDiv.id = 'markdown-preview';
                    mdDiv.style.background = 'white';
                    mdDiv.style.padding = '40px';
                    mdDiv.style.borderRadius = '4px';
                    mdDiv.style.width = '100%';
                    mdDiv.style.maxWidth = '800px';
                    mdDiv.style.color = 'black';
                    mdDiv.style.overflow = 'auto';
                    mdDiv.style.whiteSpace = 'pre-wrap';
                    mdDiv.textContent = text;
                    body.appendChild(mdDiv);
                } else {
                    const pre = document.createElement('pre');
                    pre.style.background = '#1e1e1e';
                    pre.style.color = '#d4d4d4';
                    pre.style.padding = '20px';
                    pre.style.borderRadius = '4px';
                    pre.style.width = '100%';
                    pre.style.maxWidth = '1000px';
                    pre.style.overflow = 'auto';
                    pre.textContent = text;
                    body.appendChild(pre);
                }
            } else {
                body.innerHTML = '';
                const fallback = document.createElement('div');
                fallback.style.color = 'white';
                fallback.style.textAlign = 'center';
                
                const icon = document.createElement('div');
                icon.style.fontSize = '4rem';
                icon.textContent = '📄';
                
                const text = document.createElement('div');
                text.textContent = 'No preview available.';
                
                const btn = document.createElement('button');
                btn.className = 'primary-btn';
                btn.id = 'btn-fallback-download';
                btn.textContent = 'Download';
                btn.onclick = () => this.downloadSelected();
                
                fallback.appendChild(icon);
                fallback.appendChild(text);
                fallback.appendChild(document.createElement('br'));
                fallback.appendChild(btn);
                body.appendChild(fallback);
            }
        } catch (e: any) {
            body.innerHTML = '';
            const errDiv = document.createElement('div');
            errDiv.style.color = '#f44336';
            errDiv.textContent = `Error: ${e.message}`;
            body.appendChild(errDiv);
        }
    }

    private closePreview() { document.getElementById('preview-overlay')!.classList.add('hidden'); document.getElementById('preview-body')!.innerHTML = ''; }

    private downloadSelected() {
        for (const entry of this.selectedItems) {
            const dl = document.createElement('a');
            const fullPath = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
            dl.href = `/distfs-download${fullPath}`;
            dl.download = entry.name;
            dl.click();
        }
    }

    private renderDetailsPane(entry: FileEntry | null) {
        const sel = document.getElementById('details-selection')!;
        const emp = document.getElementById('details-empty')!;
        if (!entry) { sel.classList.add('hidden'); emp.classList.remove('hidden'); return; }
        sel.classList.remove('hidden'); emp.classList.add('hidden');
        document.getElementById('details-name')!.innerText = entry.name;
        document.getElementById('details-type')!.innerText = entry.isDir ? 'Folder' : entry.mimeType;
        document.getElementById('details-size')!.innerText = entry.isDir ? '--' : this.formatSize(entry.size);
        document.getElementById('details-owner')!.innerText = entry.owner.substring(0,12) + '...';
        document.getElementById('details-date')!.innerText = this.formatDate(entry.modTime);
        const accessList = document.getElementById('access-list')!;
        accessList.innerHTML = '';
        for (const rid of Object.keys(entry.lockbox)) {
            const item = document.createElement('div');
            item.className = 'access-item';
            
            const avatar = document.createElement('div');
            avatar.className = 'access-avatar';
            avatar.textContent = rid === 'world' ? 'W' : (rid === entry.owner ? 'O' : 'U');
            
            const info = document.createElement('div');
            info.style.flex = '1';
            
            const name = document.createElement('div');
            name.style.fontWeight = '500';
            name.textContent = rid === 'world' ? 'Public' : rid.substring(0,8)+'...';
            
            const role = document.createElement('div');
            role.style.fontSize = '0.75rem';
            role.style.color = 'var(--text-muted)';
            role.textContent = rid === entry.owner ? 'Owner' : 'Authorized';
            
            info.appendChild(name);
            info.appendChild(role);
            item.appendChild(avatar);
            item.appendChild(info);
            accessList.appendChild(item);
        }
    }

    private showContextMenu(x: number, y: number, entry: FileEntry) {
        const menu = document.getElementById('context-menu')!;
        menu.style.left = `${x}px`; menu.style.top = `${y}px`; menu.style.display = 'block';
        menu.querySelectorAll('.menu-item').forEach(item => { (item as HTMLElement).onclick = () => this.handleAction((item as HTMLElement).dataset.action!, entry); });
    }

    private async handleAction(action: string, entry: FileEntry) {
        const fullPath = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
        switch (action) {
            case 'download': this.downloadSelected(); break;
            case 'delete':
                if (confirm(`Delete ${this.selectedItems.size} items?`)) {
                    for (const it of this.selectedItems) await this.client.rm(this.currentPath === '/' ? `/${it.name}` : `${this.currentPath}/${it.name}`);
                    await this.loadDirectory(this.currentPath);
                }
                break;
            case 'rename':
                const newName = prompt("New name:", entry.name);
                if (newName && newName !== entry.name) {
                    await this.client.mv(fullPath, (this.currentPath === '/' ? '/' : this.currentPath + '/') + newName);
                    await this.loadDirectory(this.currentPath);
                }
                break;
            case 'star': if (!this.meta.starred.includes(fullPath)) { this.meta.starred.push(fullPath); await this.saveMetadata(); } break;
            case 'share': 
                document.getElementById('share-file-name')!.innerText = entry.name; 
                (document.getElementById('btn-confirm-share') as HTMLButtonElement).innerText = 'Share';
                document.getElementById('share-modal')!.style.display = 'flex'; 
                break;
        }
    }

    private setupDragAndDrop() {
        const main = document.getElementById('main-view')!;
        window.addEventListener('dragover', (e) => { e.preventDefault(); main.classList.add('dragover'); });
        window.addEventListener('dragleave', (e) => { if (e.target === document.getElementById('drop-zone')) main.classList.remove('dragover'); });
        window.addEventListener('drop', (e) => {
            e.preventDefault(); main.classList.remove('dragover');
            if (e.dataTransfer && e.dataTransfer.files.length > 0) {
                for (const file of e.dataTransfer.files) this.startUpload(file);
            }
        });
    }

    private startUpload(file: File) {
        const id = `upload-${Date.now()}-${file.name}`;
        this.addJob(id, `Uploading ${file.name}`);
        let p = 0; const iv = setInterval(() => {
            p += 10; this.updateJobProgress(id, p);
            if (p >= 100) { clearInterval(iv); setTimeout(() => this.removeJob(id), 2000); this.loadDirectory(this.currentPath); }
        }, 300);
    }

    private addJob(id: string, name: string) {
        const mgr = document.getElementById('job-manager')!; mgr.style.display = 'block';
        const item = document.createElement('div'); item.id = `job-${id}`; item.className = 'job-item';
        
        const info = document.createElement('div');
        info.className = 'job-info';
        
        const nameSpan = document.createElement('span');
        nameSpan.textContent = name;
        
        const percentSpan = document.createElement('span');
        percentSpan.id = `job-percent-${id}`;
        percentSpan.textContent = '0%';
        
        info.appendChild(nameSpan);
        info.appendChild(percentSpan);
        
        const progressBg = document.createElement('div');
        progressBg.className = 'job-progress-bg';
        
        const progressFill = document.createElement('div');
        progressFill.className = 'job-progress-fill';
        progressFill.id = `job-fill-${id}`;
        
        progressBg.appendChild(progressFill);
        item.appendChild(info);
        item.appendChild(progressBg);
        
        document.getElementById('job-list')!.appendChild(item); this.updateJobCount();
    }

    private updateJobProgress(id: string, p: number) {
        const fill = document.getElementById(`job-fill-${id}`); if (fill) fill.style.width = `${p}%`;
        const txt = document.getElementById(`job-percent-${id}`); if (txt) txt.innerText = `${p}%`;
    }

    private removeJob(id: string) { const it = document.getElementById(`job-${id}`); if (it) it.remove(); this.updateJobCount(); }

    private updateJobCount() {
        const count = document.getElementById('job-list')!.children.length;
        document.getElementById('job-count')!.innerText = count.toString();
        if (count === 0) document.getElementById('job-manager')!.style.display = 'none';
    }

    private formatSize(b: number): string {
        if (b === 0) return '0 B'; const k = 1024; const s = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(b) / Math.log(k));
        return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + s[i];
    }

    private formatDate(ts: number): string {
        return ts ? new Date(ts * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '-';
    }

    private async handleShareSubmit() {
        console.log("UI: handleShareSubmit HELLO");
        if (!this.selectedItems.size) {
            console.warn("UI: No items selected for sharing");
            return;
        }
        const entry = Array.from(this.selectedItems)[0];
        const identifier = (document.getElementById('share-target-identifier') as HTMLInputElement).value;
        const perms = (document.getElementById('share-perms') as HTMLSelectElement).value;
        const path = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
        console.log(`UI: Sharing ${path} with ${identifier} (perms: ${perms})`);
        
        const btn = document.getElementById('btn-confirm-share') as HTMLButtonElement;
        btn.innerText = 'Sharing...'; btn.disabled = true;
        try {
            // 1. Resolve identifier to UserID securely via Registry
            console.log(`UI: Resolving identifier ${identifier}...`);
            const targetID = await this.client.lookupUser(identifier);
            console.log(`UI: Resolved to ${targetID}`);
            if (!targetID) throw new Error("User not found in registry");

            const acl = entry.accessACL || { Users: {}, Groups: {} };
            if (!acl.Users) acl.Users = {};
            acl.Users[targetID] = perms === 'rw-' ? 6 : 4;

            // Map UI structure to expected WASM JSON structure
            const wasmAcl = {
                users: acl.Users,
                groups: acl.Groups
            };
            console.log(`UI: Setting ACL for ${path}...`);
            await this.client.setACL(path, JSON.stringify(wasmAcl));
            console.log(`UI: ACL set successfully`);
            
            document.getElementById('share-modal')!.style.display = 'none';
            console.log(`UI: Shared with ${identifier}`);
            await this.loadDirectory(this.currentPath);
        } catch (e: any) { 
            console.error("UI: Share error:", e);
            const btn = document.getElementById('btn-confirm-share') as HTMLButtonElement;
            btn.innerText = 'Error';
        } finally { 
            const btn = document.getElementById('btn-confirm-share') as HTMLButtonElement;
            btn.disabled = false; 
        }
    }
}

window.addEventListener('error', (e) => {
    console.error("GLOBAL ERROR:", e.error);
});
window.addEventListener('unhandledrejection', (e) => {
    console.error("GLOBAL REJECTION:", e.reason);
});

window.addEventListener('DOMContentLoaded', () => { 
    console.log("UI: DOMContentLoaded - Initializing DistFSApp");
    try {
        new DistFSApp(); 
        console.log("UI: DistFSApp initialized successfully");
    } catch (e) {
        console.error("UI: FAILED TO INITIALIZE DistFSApp:", e);
    }
});

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
    private treeData: Map<string, string[]> = new Map(); // path -> child folder names

    constructor() {
        this.client = new WasmClient('worker.js');
        this.client.onReady = () => {
            const statusEl = document.getElementById('status');
            if (statusEl) statusEl.innerText = 'WASM Ready. Awaiting authentication.';
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
                                // Refine text/plain if extension is .md
                                if (newMime === 'text/plain; charset=utf-8' && path.endsWith('.md')) {
                                    newMime = 'text/markdown';
                                }
                                entry.mimeType = newMime;
                                console.log(`UI: MIME type corrected via sniffing for ${path}: ${entry.mimeType}`);
                                this.renderFileList();
                                if (this.selectedItems.has(entry)) this.renderDetailsPane(entry);
                                // If the preview overlay is open for THIS file, re-render it
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
            document.getElementById('share-modal')!.style.display = 'none';
        });
        document.getElementById('btn-confirm-share')?.addEventListener('click', () => this.handleShareSubmit());

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
            const used = quota.used_bytes;
            const total = quota.total_bytes;
            const percent = total > 0 ? (used / total) * 100 : 0;
            document.getElementById('quota-bar-fill')!.style.width = `${percent}%`;
            document.getElementById('quota-used')!.innerText = this.formatSize(used);
            document.getElementById('quota-total')!.innerText = total > 0 ? this.formatSize(total) : "Unlimited";
        } catch (e) {
            console.error("Failed to fetch quota", e);
        }
    }

    private async performDeviceFlow(): Promise<string> {
        const authRes = await fetch(`${this.serverURL}/v1/auth/config`);
        const config = await authRes.json();
        const authInfo = await this.client.startDeviceAuth(config.device_authorization_endpoint, config.token_endpoint);
        const modal = document.getElementById('device-flow-modal')!;
        const link = document.getElementById('device-flow-link')! as HTMLAnchorElement;
        const code = document.getElementById('device-flow-code')!;
        link.href = authInfo.verificationURIComplete || authInfo.verificationURI;
        link.innerText = authInfo.verificationURI;
        code.innerText = authInfo.userCode;
        modal.style.display = 'flex';
        try {
            return await this.client.pollForToken(config.device_authorization_endpoint, config.token_endpoint, authInfo.deviceCode, authInfo.userCode, authInfo.verificationURI, authInfo.interval);
        } finally {
            modal.style.display = 'none';
        }
    }

    private async handleLogin() {
        const statusEl = document.getElementById('status')!;
        try {
             statusEl.innerText = 'Authorizing...';
             const jwt = await this.performDeviceFlow();
             statusEl.innerText = 'Fetching backup...';
             const blobStr = await this.client.pullKeySync(this.serverURL, jwt);
             const passphrase = prompt("Enter your backup passphrase:");
             if (!passphrase) return;
             const configStr = await this.client.decryptConfig(blobStr, passphrase);
             const config = JSON.parse(configStr);
             const serverKeyHex = await this.client.fetchServerKey(this.serverURL);
             await this.client.init(this.serverURL, config.user_id, config.enc_key, config.sign_key, serverKeyHex);
             this.userID = config.user_id;
             await this.onLoginSuccess();
        } catch (e: any) { statusEl.innerText = `Login Error: ${e.message}`; }
    }

    private async handleNewAccount() {
        const statusEl = document.getElementById('status')!;
        try {
            statusEl.innerText = 'Generating Keys...';
            const keys = await this.client.generateKeys();
            const jwt = await this.performDeviceFlow();
            statusEl.innerText = 'Registering...';
            const userID = await this.client.registerUser(this.serverURL, jwt, keys.signPubKey, keys.encKey);
            const passphrase = prompt("Registration successful! Enter a backup passphrase:");
            if (!passphrase) return;
            const serverKeyHex = await this.client.fetchServerKey(this.serverURL);
            const config = { user_id: userID, enc_key: keys.decKey, sign_key: keys.signKey, server_key: serverKeyHex };
            const encryptedBlob = await this.client.encryptConfig(JSON.stringify(config), passphrase);
            await this.client.init(this.serverURL, config.user_id, config.enc_key, config.sign_key, serverKeyHex);
            await this.client.pushKeySync(encryptedBlob);
            this.userID = userID;
            await this.onLoginSuccess();
        } catch (e: any) { statusEl.innerText = `Error: ${e.message}`; }
    }

    private async onLoginSuccess() {
        document.getElementById('auth-overlay')!.style.display = 'none';
        document.getElementById('user-info')!.innerText = `User: ${this.userID.substring(0,8)}...`;
        await this.discoverHome();
        await this.loadMetadata();
        await this.loadDirectory('/');
        await this.updateQuota();
        this.refreshFolderTree('/');
    }

    private async discoverHome() {
        try {
            const users = await this.client.listDirectory('/users');
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
        try {
            const content = await this.client.readFile(`${this.homeDir}/.distfs_web_meta.json`);
            this.meta = JSON.parse(content);
        } catch (e) {}
    }

    private async saveMetadata() {
        if (!this.homeDir) return;
        try { await this.client.writeFile(`${this.homeDir}/.distfs_web_meta.json`, JSON.stringify(this.meta)); } catch (e) {}
    }

    private async loadDirectory(path: string) {
        this.currentPath = path;
        this.renderBreadcrumbs();
        const fileList = document.getElementById('file-list')!;
        fileList.innerHTML = '<div style="padding: 24px; color: var(--text-muted);">Syncing metadata...</div>';
        try {
            const rawEntries = await this.client.listDirectory(path);
            const folderNames: string[] = [];
            
            this.currentEntries = await Promise.all(rawEntries.map(async (e) => {
                const fullPath = path === '/' ? `/${e.name}` : `${path}/${e.name}`;
                try {
                    const info = await this.client.statFile(fullPath);
                    if (info.isDir) folderNames.push(info.name);
                    return info as FileEntry;
                } catch (err) {
                    return { ...e, owner: '?', lockbox: {}, mimeType: 'application/octet-stream', mode: 0, group: '?' } as FileEntry;
                }
            }));

            this.treeData.set(path, folderNames);
            this.renderFileList();
            this.clearSelection();
            this.updateSidebarActive();
            this.refreshFolderTree(path);
        } catch (e: any) { fileList.innerHTML = `<div style="padding: 24px; color: #d93025;">Error: ${e.message}</div>`; }
    }

    private async refreshFolderTree(parentPath: string) {
        const container = document.getElementById('tree-children')!;
        if (parentPath === '/') container.innerHTML = '';
        const folders = this.treeData.get(parentPath) || [];
        for (const name of folders) {
            const fullPath = parentPath === '/' ? `/${name}` : `${parentPath}/${name}`;
            const node = document.createElement('div');
            node.className = 'tree-node';
            node.innerText = `📁 ${name}`;
            node.onclick = () => this.loadDirectory(fullPath);
            container.appendChild(node);
        }
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
            header.innerHTML = `<div class="file-name-cell">Name</div><div class="file-size-cell">Size</div><div class="file-date-cell">Modified</div>`;
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
            const iconDiv = document.createElement('div'); iconDiv.className = 'file-icon';
            if (!entry.isDir && entry.mimeType.startsWith('image/')) {
                const fullPath = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
                const img = document.createElement('img'); img.src = `/distfs-media${fullPath}`; img.alt = entry.name; img.loading = 'lazy';
                iconDiv.appendChild(img);
            } else iconDiv.innerText = icon;
            const nameDiv = document.createElement('div'); nameDiv.className = 'file-name'; nameDiv.innerText = entry.name;
            const metaDiv = document.createElement('div'); metaDiv.className = 'file-meta'; metaDiv.innerText = entry.isDir ? '--' : this.formatSize(entry.size);
            el.appendChild(iconDiv); el.appendChild(nameDiv); el.appendChild(metaDiv);
        } else {
            el.innerHTML = `<div class="file-name-cell"><span class="file-icon">${icon}</span><span class="file-name">${entry.name}</span></div>
                <div class="file-size-cell">${entry.isDir ? '--' : this.formatSize(entry.size)}</div>
                <div class="file-date-cell">${this.formatDate(entry.modTime)}</div>`;
        }
        el.onclick = (e) => {
            e.stopPropagation();
            if (!e.ctrlKey && !e.shiftKey) this.clearSelection();
            this.toggleSelection(entry);
        };
        el.ondblclick = () => {
            const fullPath = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
            if (entry.isDir) {
                this.clearSelection();
                this.loadDirectory(fullPath);
            } else this.openPreview(entry);
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
        const title = document.getElementById('preview-title')!;
        const body = document.getElementById('preview-body')!;
        title.innerText = entry.name;
        body.innerHTML = '<div style="color: white">Loading preview...</div>';
        overlay.classList.remove('hidden');
        try {
            if (entry.mimeType.startsWith('image/')) {
                body.innerHTML = `<img src="/distfs-media${fullPath}" style="max-width:100%; max-height:100%; object-fit:contain;">`;
            } else if (entry.mimeType.startsWith('video/') || entry.mimeType.startsWith('audio/')) {
                const tag = entry.mimeType.startsWith('video/') ? 'video' : 'audio';
                body.innerHTML = `<${tag} src="/distfs-media${fullPath}" controls autoplay style="max-width:100%; max-height:100%;"></${tag}>`;
            } else if (entry.mimeType === 'text/plain' || entry.mimeType === 'text/markdown' || entry.name.endsWith('.md')) {
                const text = await this.client.readFile(fullPath);
                if (entry.mimeType === 'text/markdown' || entry.name.endsWith('.md')) {
                    body.innerHTML = `<div id="markdown-preview" style="background: white; padding: 40px; border-radius: 4px; width: 100%; max-width: 800px; color: black; overflow: auto;">${text.replace(/\n/g, '<br>')}</div>`;
                } else {
                    body.innerHTML = `<pre style="background: #1e1e1e; color: #d4d4d4; padding: 20px; border-radius: 4px; width: 100%; max-width: 1000px; overflow: auto;">${text}</pre>`;
                }
            } else {
                body.innerHTML = `<div style="color: white; text-align: center;"><div style="font-size: 4rem; margin-bottom: 20px;">📄</div><div>Preview not available for this file type.</div><br><button class="primary-btn" id="btn-fallback-download">Download Instead</button></div>`;
                document.getElementById('btn-fallback-download')?.addEventListener('click', () => this.downloadSelected());
            }
        } catch (e: any) { body.innerHTML = `<div style="color: #f44336">Failed to load preview: ${e.message}</div>`; }
    }

    private closePreview() { document.getElementById('preview-overlay')!.classList.add('hidden'); document.getElementById('preview-body')!.innerHTML = ''; }

    private downloadSelected() {
        for (const entry of this.selectedItems) {
            const fullPath = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
            const dlLink = document.createElement('a'); dlLink.href = `/distfs-download${fullPath}`; dlLink.download = entry.name; dlLink.click();
        }
    }

    private renderDetailsPane(entry: FileEntry | null) {
        const selectionDiv = document.getElementById('details-selection')!;
        const emptyDiv = document.getElementById('details-empty')!;
        if (!entry) { selectionDiv.classList.add('hidden'); emptyDiv.classList.remove('hidden'); return; }
        emptyDiv.classList.add('hidden'); selectionDiv.classList.remove('hidden');
        document.getElementById('details-name')!.innerText = entry.name;
        document.getElementById('details-type')!.innerText = entry.isDir ? 'Folder' : (entry.mimeType || 'File');
        document.getElementById('details-size')!.innerText = entry.isDir ? '--' : this.formatSize(entry.size);
        document.getElementById('details-location')!.innerText = this.currentPath;
        document.getElementById('details-owner')!.innerText = entry.owner.substring(0,12) + '...';
        document.getElementById('details-date')!.innerText = this.formatDate(entry.modTime);
        const previewBox = document.getElementById('details-preview-box')!;
        previewBox.innerHTML = '';
        if (!entry.isDir && entry.mimeType.startsWith('image/')) {
            const fullPath = this.currentPath === '/' ? `/${entry.name}` : `${this.currentPath}/${entry.name}`;
            const img = document.createElement('img'); img.src = `/distfs-media${fullPath}`; previewBox.appendChild(img);
        } else previewBox.innerText = entry.isDir ? '📁' : '📄';
        const accessList = document.getElementById('access-list')!;
        accessList.innerHTML = '';
        for (const rid of Object.keys(entry.lockbox)) {
            const isOwner = rid === entry.owner;
            const item = document.createElement('div'); item.className = 'access-item';
            item.innerHTML = `<div class="access-avatar">${rid === 'world' ? 'W' : (isOwner ? 'O' : 'U')}</div>
                <div style="flex:1"><div style="font-weight:500">${rid === 'world' ? 'Public' : rid.substring(0,8)+'...'}</div>
                <div style="font-size:0.75rem; color:var(--text-muted)">${isOwner ? 'Owner' : 'Authorized'}</div></div>`;
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
                    for (const it of this.selectedItems) {
                        const p = this.currentPath === '/' ? `/${it.name}` : `${this.currentPath}/${it.name}`;
                        try { await this.client.rm(p); } catch (e: any) { alert(`Failed: ${e.message}`); }
                    }
                    await this.loadDirectory(this.currentPath);
                }
                break;
            case 'rename':
                const newName = prompt("Enter new name:", entry.name);
                if (newName && newName !== entry.name) {
                    try { await this.client.mv(fullPath, this.currentPath === '/' ? `/${newName}` : `${this.currentPath}/${newName}`); await this.loadDirectory(this.currentPath); }
                    catch (e: any) { alert(`Rename failed: ${e.message}`); }
                }
                break;
            case 'star':
                if (!this.meta.starred.includes(fullPath)) { this.meta.starred.push(fullPath); await this.saveMetadata(); }
                break;
            case 'share':
                document.getElementById('share-file-name')!.innerText = entry.name;
                document.getElementById('share-modal')!.style.display = 'flex';
                break;
        }
    }

    private setupDragAndDrop() {
        const mainView = document.getElementById('main-view')!;
        window.addEventListener('dragover', (e) => { e.preventDefault(); mainView.classList.add('dragover'); });
        window.addEventListener('dragleave', (e) => { if (e.target === document.getElementById('drop-zone')) mainView.classList.remove('dragover'); });
        window.addEventListener('drop', (e) => {
            e.preventDefault(); mainView.classList.remove('dragover');
            if (e.dataTransfer && e.dataTransfer.files.length > 0) {
                for (const file of e.dataTransfer.files) this.startUpload(file);
            }
        });
    }

    private startUpload(file: File) {
        const jobID = `upload-${Date.now()}-${file.name}`;
        this.addJob(jobID, `Uploading ${file.name}`);
        let progress = 0;
        const interval = setInterval(() => {
            progress += 10; this.updateJobProgress(jobID, progress);
            if (progress >= 100) { clearInterval(interval); setTimeout(() => this.removeJob(jobID), 2000); this.loadDirectory(this.currentPath); }
        }, 300);
    }

    private addJob(id: string, name: string) {
        const mgr = document.getElementById('job-manager')!; mgr.style.display = 'block';
        const list = document.getElementById('job-list')!;
        const item = document.createElement('div'); item.id = `job-${id}`; item.className = 'job-item';
        item.innerHTML = `<div class="job-info"><span>${name}</span><span id="job-percent-${id}">0%</span></div>
            <div class="job-progress-bg"><div class="job-progress-fill" id="job-fill-${id}"></div></div>`;
        list.appendChild(item); this.updateJobCount();
    }

    private updateJobProgress(id: string, percent: number) {
        const fill = document.getElementById(`job-fill-${id}`); const text = document.getElementById(`job-percent-${id}`);
        if (fill) fill.style.width = `${percent}%`; if (text) text.innerText = `${percent}%`;
    }

    private removeJob(id: string) { const item = document.getElementById(`job-${id}`); if (item) item.remove(); this.updateJobCount(); }

    private updateJobCount() {
        const list = document.getElementById('job-list')!; const count = list.children.length;
        document.getElementById('job-count')!.innerText = count.toString();
        if (count === 0) document.getElementById('job-manager')!.style.display = 'none';
    }

    private formatSize(bytes: number): string {
        if (bytes === 0) return '0 B'; const k = 1024; const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    private formatDate(timestamp: number): string {
        if (!timestamp) return '-';
        return new Date(timestamp * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    private handleShareSubmit() {
        document.getElementById('share-modal')!.style.display = 'none';
        alert("Shared successfully (Simulated)");
    }
}

window.addEventListener('DOMContentLoaded', () => { new DistFSApp(); });

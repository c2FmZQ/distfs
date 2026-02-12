let secret = sessionStorage.getItem('raft_secret');

if (!secret) {
    secret = prompt("Enter Cluster Secret:");
    if (secret) sessionStorage.setItem('raft_secret', secret);
}

const headers = { 'X-Raft-Secret': secret };

function showTab(id) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('nav button').forEach(el => el.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    document.querySelector(`button[onclick="showTab('${id}')"]`).classList.add('active');
    
    if (id === 'overview') fetchStatus();
    if (id === 'users') fetchUsers();
    if (id === 'nodes') fetchNodes();
}

async function fetchStatus() {
    try {
        const res = await fetch('/v1/cluster/status', { headers });
        if (res.status === 401) return handleAuthFail();
        const data = await res.json();
        document.getElementById('raft-state').innerText = data.state;
        document.getElementById('raft-leader').innerText = data.leader;
        
        let commit = '-';
        if (data.stats && data.stats.commit_index) commit = data.stats.commit_index;
        // Raft stats format varies, handling flat map
        if (data.stats && data.stats['commit_index']) commit = data.stats['commit_index'];
        
        document.getElementById('raft-commit').innerText = commit;
        document.getElementById('connection-status').innerText = "Connected";
        document.getElementById('connection-status').style.color = "#4caf50";
    } catch (e) {
        console.error(e);
        document.getElementById('connection-status').innerText = "Error";
        document.getElementById('connection-status').style.color = "red";
    }
}

async function fetchUsers() {
    try {
        const res = await fetch('/api/cluster/users', { headers });
        const data = await res.json();
        const tbody = document.getElementById('users-table');
        tbody.innerHTML = '';
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4">No users found</td></tr>';
            return;
        }
        data.forEach(u => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${u.id}</td>
                <td>${u.usage ? u.usage.inodes : 0}</td>
                <td>${formatBytes(u.usage ? u.usage.bytes : 0)}</td>
                <td>${u.quota && u.quota.max_bytes ? formatBytes(u.quota.max_bytes) : 'Unlim'}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) { console.error(e); }
}

async function fetchNodes() {
    try {
        const res = await fetch('/api/cluster/nodes', { headers });
        const data = await res.json();
        const tbody = document.getElementById('nodes-table');
        tbody.innerHTML = '';
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4">No nodes found</td></tr>';
            return;
        }
        data.forEach(n => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${n.id}</td>
                <td>${n.address}</td>
                <td>${n.status}</td>
                <td>${new Date(n.last_heartbeat * 1000).toLocaleString()}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) { console.error(e); }
}

async function performLookup() {
    const email = document.getElementById('lookup-email').value;
    try {
        const res = await fetch('/api/cluster/lookup', {
            method: 'POST',
            headers: { ...headers, 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        document.getElementById('lookup-result').innerText = data.id || "Error";
    } catch (e) {
        document.getElementById('lookup-result').innerText = "Request failed";
    }
}

function handleAuthFail() {
    sessionStorage.removeItem('raft_secret');
    location.reload();
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Init
fetchStatus();

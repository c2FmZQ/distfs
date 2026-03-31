import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';

const captureScreenshot = async (page: any, name: string) => {
  if (process.env.CAPTURE_SCREENSHOTS === 'true') {
    console.log(`Capturing screenshot: ${name}.png`);
    await page.screenshot({ path: `docs/assets/${name}.png`, fullPage: true });
  }
};

const runCLI = (cmd: string, password?: string) => {
  console.log(`RUNNING CLI: ${cmd}`);
  const env = { ...process.env };
  if (password) env.DISTFS_PASSWORD = password;
  try {
    const out = execSync(cmd, { env }).toString();
    console.log(`CLI OUTPUT: ${out.trim()}`);
    return out;
  } catch (err: any) {
    console.error(`CLI ERROR: ${err.message}`);
    console.error(`CLI STDERR: ${err.stderr?.toString()}`);
    throw err;
  }
};

const authorizeDeviceCode = async (request: any, userCode: string, email: string) => {
  console.log(`Authorizing user code ${userCode} for ${email}...`);
  for (let i = 0; i < 5; i++) {
    const res = await request.get(`http://test-auth:8080/authorize_code?user_code=${userCode}&email=${email}`);
    if (res.ok()) return;
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`Failed to authorize user code ${userCode}`);
};

test.describe('DistFS Web Client Phase 64 E2E', () => {

  let USERS_GID = '';

  test.beforeAll(async () => {
    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    
    // Helper to get group ID by name
    const getGroupID = (name: string) => {
        try {
            // Use ls on the registry to get the group ID instead of recreating it
            const out = runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} ls -l /registry/${name}.group`, 'testpassword');
            const match = out.match(/->\s+([a-f0-9]+)\.group-id/);
            if (match) return match[1];
            return '';
        } catch (e: any) {
            return '';
        }
    };

    try {
        runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} group-create world "World Group"`, 'testpassword');
    } catch(e) {}

    USERS_GID = getGroupID('users');

    try {
        runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} mkdir /users`, 'testpassword');
        runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} chmod 0755 /users`, 'testpassword');
    } catch (e) {}
  });
  test('Workspace Layout and Navigation', async ({ page, request }) => {
    const email = 'web-workspace@distfs.local';
    const authRes = await request.get(`http://test-auth:8080/mint?email=${email}`);
    const jwt = await authRes.text();
    
    const confFile = `/tmp/ws-${Date.now()}.json`;
    const initOut = runCLI(`/bin/distfs -allow-insecure -config ${confFile} init --new -server http://storage-node-1:8080 -jwt ${jwt}`, 'test-passphrase-123');
    const userID = initOut.match(/User ID:\s+([a-f0-9]+)/)?.[1] || '';

    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock --quota 100000000,100 ws-user ${userID}`, 'testpassword');
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} group-add "${USERS_GID || 'users'}" ws-user`, 'testpassword');
    try {
        runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} mkdir --owner ws-user /users/ws-user`, 'testpassword');
    } catch(e) {}

    await new Promise(r => setTimeout(r, 2000));
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} mkdir /users/ws-user/Documents`, 'test-passphrase-123');
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} mkdir /users/ws-user/Photos`, 'test-passphrase-123');
    runCLI(`echo "Phase 64 Content" > /tmp/test.txt`);
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} put /tmp/test.txt /users/ws-user/Documents/notes.txt`, 'test-passphrase-123');

    page.on('console', msg => console.log(`BROWSER: ${msg.text()}`));
    page.on('dialog', async d => {
        if (d.type() === 'prompt') await d.accept('test-passphrase-123');
        else await d.accept();
    });

    await page.goto('/');
    await expect(page.locator('#status')).toContainText('WASM Ready', { timeout: 30000 });
    await page.click('#btn-login');
    const codeLoc = page.locator('#device-flow-code');
    await expect(codeLoc).not.toBeEmpty({ timeout: 30000 });
    const userCode = await codeLoc.textContent();
    await authorizeDeviceCode(request, userCode!, email);

    await expect(page.locator('#auth-overlay')).toBeHidden({ timeout: 30000 });
    
    // 1. Verify Layout
    await expect(page.locator('#sidebar')).toBeVisible();
    await expect(page.locator('#details-pane')).toBeVisible();
    await expect(page.locator('#quota-info')).toBeVisible();
    await captureScreenshot(page, 'ws-layout-overview');

    // 2. Folder Tree Navigation
    await page.locator('.tree-node', { hasText: 'ws-user' }).first().click();
    await expect(page.locator('#breadcrumb')).toContainText('ws-user');
    
    // 3. View Toggling
    await page.click('#btn-list-view');
    await expect(page.locator('#file-list')).toHaveClass(/list/);
    await captureScreenshot(page, 'ws-list-view');

    await page.click('#btn-grid-view');
    await expect(page.locator('#file-list')).toHaveClass(/grid/);
    
    // 4. Details Pane
    await page.click('#file-list >> text=Documents');
    // Ensure the hidden class is removed
    await expect(page.locator('#details-selection')).not.toHaveClass(/hidden/, { timeout: 10000 });
    await expect(page.locator('#details-name')).toHaveText('Documents');
    await expect(page.locator('#details-type')).toHaveText('Folder');
    await captureScreenshot(page, 'ws-details-pane');

    // 5. Context Menu
    await page.click('#file-list >> text=Photos', { button: 'right' });
    await expect(page.locator('#context-menu')).toBeVisible();
    await captureScreenshot(page, 'ws-context-menu');
  });

  test('Multi-select and Batch Actions', async ({ page, request }) => {
    const email = 'web-batch@distfs.local';
    const authRes = await request.get(`http://test-auth:8080/mint?email=${email}`);
    const jwt = await authRes.text();
    
    const confFile = `/tmp/batch-${Date.now()}.json`;
    const initOut = runCLI(`/bin/distfs -allow-insecure -config ${confFile} init --new -server http://storage-node-1:8080 -jwt ${jwt}`, 'test-passphrase-123');
    const userID = initOut.match(/User ID:\s+([a-f0-9]+)/)?.[1] || '';

    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock batch-user ${userID}`, 'testpassword');
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} group-add "${USERS_GID || 'users'}" batch-user`, 'testpassword');
    try {
        runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} mkdir --owner batch-user /users/batch-user`, 'testpassword');
    } catch(e) {}

    await new Promise(r => setTimeout(r, 2000));
    for (let i = 1; i <= 3; i++) {
        runCLI(`echo "File ${i}" > /tmp/f${i}.txt`);
        runCLI(`/bin/distfs -allow-insecure -config ${confFile} put /tmp/f${i}.txt /users/batch-user/file${i}.txt`, 'test-passphrase-123');
    }

    page.on('console', msg => console.log(`BROWSER: ${msg.text()}`));
    page.on('dialog', async d => {
        if (d.type() === 'prompt') await d.accept('test-passphrase-123');
        else await d.accept();
    });

    await page.goto('/');
    await expect(page.locator('#status')).toContainText('WASM Ready', { timeout: 30000 });
    await page.click('#btn-login');
    const codeLoc = page.locator('#device-flow-code');
    await expect(codeLoc).not.toBeEmpty({ timeout: 30000 });
    const userCode = await codeLoc.textContent();
    await authorizeDeviceCode(request, userCode!, email);
    await expect(page.locator('#auth-overlay')).toBeHidden({ timeout: 30000 });

    await page.locator('.tree-node', { hasText: 'batch-user' }).first().click();
    
    // Multi-select using Ctrl
    await page.click('#file-list >> text=file1.txt');
    await page.click('#file-list >> text=file2.txt', { modifiers: ['Control'] });
    await page.click('#file-list >> text=file3.txt', { modifiers: ['Control'] });

    await expect(page.locator('.file-item.selected')).toHaveCount(3);
    await captureScreenshot(page, 'ws-multi-select');

    // Delete batch
    await page.click('#file-list >> text=file1.txt', { button: 'right' });
    await page.click('#context-menu >> [data-action="delete"]');

    await expect(page.locator('#file-list >> text=file1.txt')).toBeHidden({ timeout: 15000 });
    await expect(page.locator('#file-list >> text=file2.txt')).toBeHidden();
    await expect(page.locator('#file-list >> text=file3.txt')).toBeHidden();
  });

  test('Content Preview Overlay', async ({ page, request }) => {
    const email = 'web-preview@distfs.local';
    const authRes = await request.get(`http://test-auth:8080/mint?email=${email}`);
    const jwt = await authRes.text();
    
    const confFile = `/tmp/preview-${Date.now()}.json`;
    const initOut = runCLI(`/bin/distfs -allow-insecure -config ${confFile} init --new -server http://storage-node-1:8080 -jwt ${jwt}`, 'test-passphrase-123');
    const userID = initOut.match(/User ID:\s+([a-f0-9]+)/)?.[1] || '';

    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock preview-user ${userID}`, 'testpassword');
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} group-add "${USERS_GID || 'users'}" preview-user`, 'testpassword');
    try {
        runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} mkdir --owner preview-user /users/preview-user`, 'testpassword');
    } catch(e) {}

    await new Promise(r => setTimeout(r, 2000));
    const mdContent = "# DistFS Preview\n\n- E2EE\n- PQC\n- WASM";
    runCLI(`echo "${mdContent}" > /tmp/test.md`);
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} put /tmp/test.md /users/preview-user/readme.md`, 'test-passphrase-123');

    page.on('console', msg => console.log(`BROWSER: ${msg.text()}`));
    page.on('dialog', async d => {
        if (d.type() === 'prompt') await d.accept('test-passphrase-123');
        else await d.accept();
    });

    await page.goto('/');
    await expect(page.locator('#status')).toContainText('WASM Ready', { timeout: 30000 });
    await page.click('#btn-login');
    const codeLoc = page.locator('#device-flow-code');
    await expect(codeLoc).not.toBeEmpty({ timeout: 30000 });
    const userCode = await codeLoc.textContent();
    await authorizeDeviceCode(request, userCode!, email);
    await expect(page.locator('#auth-overlay')).toBeHidden({ timeout: 30000 });

    await page.locator('.tree-node', { hasText: 'preview-user' }).first().click();
    await expect(page.locator('#file-list')).not.toContainText('Syncing metadata');
    await page.dblclick('#file-list >> text=readme.md');

    await expect(page.locator('#preview-overlay')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#preview-title')).toHaveText('readme.md');
    await expect(page.locator('#markdown-preview')).toContainText('DistFS Preview');
    await captureScreenshot(page, 'ws-content-preview');

    await page.click('#btn-close-preview');
    await expect(page.locator('#preview-overlay')).toBeHidden();
  });

  test('Cryptographic Sharing (ACL Updates)', async ({ page, request, browser }) => {
    test.setTimeout(60000);
    const aliceEmail = 'alice-web@distfs.local';
    const bobEmail = 'bob-web@distfs.local';
    const aliceAlias = `alice-${Date.now()}`;
    const bobAlias = `bob-${Date.now()}`;
    
    // 1. Setup Alice
    const aliceAuth = await request.get(`http://test-auth:8080/mint?email=${aliceEmail}`);
    const aliceJwt = await aliceAuth.text();
    const aliceConf = `/tmp/alice-${Date.now()}.json`;
    const aliceInitOut = runCLI(`/bin/distfs -allow-insecure -config ${aliceConf} init --new -server http://storage-node-1:8080 -jwt ${aliceJwt}`, 'test-passphrase-123');
    const aliceID = aliceInitOut.match(/User ID:\s+([a-f0-9]+)/)?.[1] || '';

    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock ${aliceAlias} ${aliceID}`, 'testpassword');
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} group-add "${USERS_GID || 'users'}" ${aliceAlias}`, 'testpassword');
    try {
        runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} mkdir --owner ${aliceAlias} /users/${aliceAlias}`, 'testpassword');
    } catch (e) {}
    runCLI(`/bin/distfs -allow-insecure -config ${aliceConf} chmod 0755 /users/${aliceAlias}`, 'test-passphrase-123');

    // 2. Setup Bob
    const bobAuth = await request.get(`http://test-auth:8080/mint?email=${bobEmail}`);
    const bobJwt = await bobAuth.text();
    const bobConf = `/tmp/bob-${Date.now()}.json`;
    const bobInitOut = runCLI(`/bin/distfs -allow-insecure -config ${bobConf} init --new -server http://storage-node-1:8080 -jwt ${bobJwt}`, 'test-passphrase-456');
    const bobID = bobInitOut.match(/User ID:\s+([a-f0-9]+)/)?.[1] || '';
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock ${bobAlias} ${bobID}`, 'testpassword');
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} group-add "${USERS_GID || 'users'}" ${bobAlias}`, 'testpassword');

    // 3. Alice creates a file
    await new Promise(r => setTimeout(r, 2000));
    runCLI(`echo "Alice Secret Data" > /tmp/secret.txt`);
    runCLI(`/bin/distfs -allow-insecure -config ${aliceConf} put /tmp/secret.txt /users/${aliceAlias}/secret.txt`, 'test-passphrase-123');

    // 4. Alice logs in and shares with Bob via UI
    page.on('console', msg => console.log(`BROWSER: ${msg.text()}`));
    page.on('dialog', async d => {
        if (d.type() === 'prompt') await d.accept('test-passphrase-123');
        else await d.accept();
    });

    await page.goto('/');
    await expect(page.locator('#status')).toContainText('WASM Ready', { timeout: 30000 });
    await page.click('#btn-login');
    const aliceCodeLoc = page.locator('#device-flow-code');
    await expect(aliceCodeLoc).not.toBeEmpty({ timeout: 30000 });
    const aliceCode = await aliceCodeLoc.textContent();
    await authorizeDeviceCode(request, aliceCode!, aliceEmail);
    await expect(page.locator('#auth-overlay')).toBeHidden({ timeout: 30000 });

    await page.locator('.tree-node', { hasText: aliceAlias }).first().click();
    await page.click('#file-list >> text=secret.txt', { button: 'right' });
    await page.click('#context-menu >> [data-action="share"]');
    
    await page.fill('#share-target-identifier', bobID);
    await page.selectOption('#share-perms', 'r--');
    
    // Capture state for debugging/docs
    await captureScreenshot(page, 'ws-share-modal-active');
    
    // The global dialog handler will accept the "Shared successfully" alert
    await expect(page.locator('#btn-confirm-share')).toBeVisible();
    await page.click('#btn-confirm-share');

    // Wait for the modal to close to ensure the share completed
    await expect(page.locator('#share-modal')).toBeHidden({ timeout: 10000 });

    // 5. Verify Bob's access via Bob's browser context
    const bobContext = await browser.newContext();
    const bobPage = await bobContext.newPage();
    
    bobPage.on('console', msg => console.log(`BOB_BROWSER: ${msg.text()}`));
    bobPage.on('pageerror', err => console.log(`BOB_PAGEERROR: ${err.message}`));
    bobPage.on('dialog', async d => {
        if (d.type() === 'prompt') await d.accept('test-passphrase-456');
        else await d.accept();
    });

    await bobPage.goto('/');
    await expect(bobPage.locator('#status')).toContainText('WASM Ready', { timeout: 30000 });
    await bobPage.click('#btn-login');
    const bobCodeLoc = bobPage.locator('#device-flow-code');
    await expect(bobCodeLoc).not.toBeEmpty({ timeout: 30000 });
    const bobCode = await bobCodeLoc.textContent();
    await authorizeDeviceCode(request, bobCode!, bobEmail);
    await expect(bobPage.locator('#auth-overlay')).toBeHidden({ timeout: 30000 });

    // Bob navigates to Alice's folder
    // Since /users/alice-user is 0755, Bob can see it
    await bobPage.locator('.tree-node', { hasText: aliceAlias }).first().click();
    await expect(bobPage.locator('#file-list >> text=secret.txt')).toBeVisible({ timeout: 15000 });
    
    // Bob attempts to preview (this requires successful Lockbox decryption)
    await bobPage.dblclick('#file-list >> text=secret.txt');
    await expect(bobPage.locator('#preview-overlay')).toBeVisible({ timeout: 15000 });
    await expect(bobPage.locator('#preview-body')).toContainText('Alice Secret Data');
    await captureScreenshot(bobPage, 'ws-bob-access-verified');
  });

});
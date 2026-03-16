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

  test('Workspace Layout and Navigation', async ({ page, request }) => {
    const email = 'workspace@distfs.local';
    const authRes = await request.get(`http://test-auth:8080/mint?email=${email}`);
    const jwt = await authRes.text();
    
    const confFile = `/tmp/ws-${Date.now()}.json`;
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} init --new -server http://storage-node-1:8080 -jwt ${jwt}`, 'test-passphrase-123');
    
    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock --quota 100000000,100 ws-user ${email}`, 'testpassword');
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} mkdir --owner ws-user /ws-user`, 'testpassword');

    await new Promise(r => setTimeout(r, 2000));
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} mkdir /ws-user/Documents`, 'test-passphrase-123');
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} mkdir /ws-user/Photos`, 'test-passphrase-123');
    runCLI(`echo "Phase 64 Content" > /tmp/test.txt`);
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} put /tmp/test.txt /ws-user/Documents/notes.txt`, 'test-passphrase-123');

    page.on('dialog', async d => {
        if (d.type() === 'prompt') await d.accept('test-passphrase-123');
        else await d.accept();
    });

    await page.goto('/');
    await page.click('#btn-login');
    const codeLoc = page.locator('#device-flow-code');
    await expect(codeLoc).not.toBeEmpty({ timeout: 15000 });
    const userCode = await codeLoc.textContent();
    await authorizeDeviceCode(request, userCode!, email);

    await expect(page.locator('#auth-overlay')).toBeHidden({ timeout: 30000 });
    
    // 1. Verify Layout
    await expect(page.locator('#sidebar')).toBeVisible();
    await expect(page.locator('#details-pane')).toBeVisible();
    await expect(page.locator('#quota-info')).toBeVisible();
    await captureScreenshot(page, 'ws-layout-overview');

    // 2. Folder Tree Navigation
    await page.click('#tree-children >> text=ws-user');
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
    const email = 'batch@distfs.local';
    const authRes = await request.get(`http://test-auth:8080/mint?email=${email}`);
    const jwt = await authRes.text();
    
    const confFile = `/tmp/batch-${Date.now()}.json`;
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} init --new -server http://storage-node-1:8080 -jwt ${jwt}`, 'test-passphrase-123');
    
    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock batch-user ${email}`, 'testpassword');
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} mkdir --owner batch-user /batch-user`, 'testpassword');

    await new Promise(r => setTimeout(r, 2000));
    for (let i = 1; i <= 3; i++) {
        runCLI(`echo "File ${i}" > /tmp/f${i}.txt`);
        runCLI(`/bin/distfs -allow-insecure -config ${confFile} put /tmp/f${i}.txt /batch-user/file${i}.txt`, 'test-passphrase-123');
    }

    page.on('dialog', async d => {
        if (d.type() === 'prompt') await d.accept('test-passphrase-123');
        else await d.accept();
    });

    await page.goto('/');
    await page.click('#btn-login');
    const codeLoc = page.locator('#device-flow-code');
    await expect(codeLoc).not.toBeEmpty({ timeout: 15000 });
    const userCode = await codeLoc.textContent();
    await authorizeDeviceCode(request, userCode!, email);
    await expect(page.locator('#auth-overlay')).toBeHidden({ timeout: 30000 });

    await page.click('#tree-children >> text=batch-user');
    
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
    const email = 'preview@distfs.local';
    const authRes = await request.get(`http://test-auth:8080/mint?email=${email}`);
    const jwt = await authRes.text();
    
    const confFile = `/tmp/preview-${Date.now()}.json`;
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} init --new -server http://storage-node-1:8080 -jwt ${jwt}`, 'test-passphrase-123');
    
    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock preview-user ${email}`, 'testpassword');
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} mkdir --owner preview-user /preview-user`, 'testpassword');

    await new Promise(r => setTimeout(r, 2000));
    const mdContent = "# DistFS Preview\n\n- E2EE\n- PQC\n- WASM";
    runCLI(`echo "${mdContent}" > /tmp/test.md`);
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} put /tmp/test.md /preview-user/readme.md`, 'test-passphrase-123');

    page.on('dialog', async d => {
        if (d.type() === 'prompt') await d.accept('test-passphrase-123');
        else await d.accept();
    });

    await page.goto('/');
    await page.click('#btn-login');
    const codeLoc = page.locator('#device-flow-code');
    await expect(codeLoc).not.toBeEmpty({ timeout: 15000 });
    const userCode = await codeLoc.textContent();
    await authorizeDeviceCode(request, userCode!, email);
    await expect(page.locator('#auth-overlay')).toBeHidden({ timeout: 30000 });

    await page.click('#tree-children >> text=preview-user');
    await expect(page.locator('#file-list')).not.toContainText('Syncing metadata');
    await page.dblclick('#file-list >> text=readme.md');

    await expect(page.locator('#preview-overlay')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#preview-title')).toHaveText('readme.md');
    await expect(page.locator('#markdown-preview')).toContainText('DistFS Preview');
    await captureScreenshot(page, 'ws-content-preview');

    await page.click('#btn-close-preview');
    await expect(page.locator('#preview-overlay')).toBeHidden();
  });

});
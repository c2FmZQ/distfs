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

/**
 * Helper to authorize a device flow code via the test-auth server
 */
const authorizeDeviceCode = async (request: any, userCode: string, email: string) => {
  console.log(`Authorizing user code ${userCode} for ${email}...`);
  // Try a few times in case the test-auth server is slow to register the code
  for (let i = 0; i < 5; i++) {
    const res = await request.get(`http://test-auth:8080/authorize_code?user_code=${userCode}&email=${email}`);
    if (res.ok()) return;
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`Failed to authorize user code ${userCode}`);
};

test.describe('DistFS Web Client E2E', () => {

  test('New Account Registration and Directory Listing', async ({ page, request }) => {
    page.on('console', msg => console.log(`BROWSER CONSOLE [${msg.type()}]: ${msg.text()}`));
    
    page.on('dialog', async dialog => {
      if (dialog.type() === 'prompt') await dialog.accept('test-passphrase-123');
      else await dialog.accept();
    });

    await page.goto('/');
    await expect(page.locator('#status')).toContainText('WASM Ready', { timeout: 20000 });
    
    await captureScreenshot(page, 'login-screen');

    await page.click('#btn-new-account');

    // Wait for the Device Flow modal to appear
    const modal = page.locator('#device-flow-modal');
    await expect(modal).toBeVisible({ timeout: 15000 });
    
    const userCode = await page.locator('#device-flow-code').textContent();
    await authorizeDeviceCode(request, userCode!, 'newuser@distfs.local');

    // Registration should now continue automatically
    await expect(page.locator('#status')).toContainText('Account created and backed up!', { timeout: 30000 });
    
    await expect(page.locator('#auth-overlay')).toBeHidden();
    await expect(page.locator('#user-info')).toContainText('User:');
    
    await expect(page.locator('#file-list')).toContainText('account is locked pending administrator approval');
    await captureScreenshot(page, 'locked-dashboard');
  });

  test('Existing Account Login via KeySync', async ({ page, request }) => {
    page.on('console', msg => console.log(`BROWSER CONSOLE [${msg.type()}]: ${msg.text()}`));
    
    const email = 'keysync@distfs.local';
    // 1. Seed an account using the CLI
    const seedAuthRes = await request.get(`http://test-auth:8080/mint?email=${email}`);
    const seedJwt = await seedAuthRes.text();
    
    console.log("Seeding account for KeySync test...");
    const confFile = `/tmp/keysync-${Date.now()}.json`;
    const initOut = runCLI(`/bin/distfs -allow-insecure -config ${confFile} init --new -server http://storage-node-1:8080 -jwt ${seedJwt}`, 'test-passphrase-123');
    const match = initOut.match(/User ID:\s+([a-f0-9]+)/);
    if (!match) throw new Error(`Failed to extract User ID from output: ${initOut}`);
    const userID = match[1];
    
    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock keysync-user ${email}`, 'testpassword');

    // 2. Drive the UI Login Flow
    page.on('dialog', async dialog => {
      if (dialog.type() === 'prompt') await dialog.accept('test-passphrase-123');
      else await dialog.accept();
    });

    await page.goto('/');
    await expect(page.locator('#status')).toContainText('WASM Ready', { timeout: 20000 });
    
    await page.click('#btn-login');

    // Wait for the Device Flow modal
    const modal = page.locator('#device-flow-modal');
    await expect(modal).toBeVisible({ timeout: 15000 });
    
    const userCode = await page.locator('#device-flow-code').textContent();
    await authorizeDeviceCode(request, userCode!, email);

    await expect(page.locator('#status')).toContainText(`Logged in successfully as ${userID}`, { timeout: 30000 });
    await expect(page.locator('#auth-overlay')).toBeHidden();
    
    await captureScreenshot(page, 'dashboard-unlocked');
  });

  test('File Navigation, Sharing, and Media Rendering', async ({ page, request }) => {
    page.on('console', msg => console.log(`BROWSER CONSOLE [${msg.type()}]: ${msg.text()}`));
    
    const email = 'media@distfs.local';
    const authRes = await request.get(`http://test-auth:8080/mint?email=${email}`);
    const jwt = await authRes.text();
    
    console.log("Seeding account and data for Navigation test...");
    const confFile = `/tmp/media-${Date.now()}.json`;
    const initOut = runCLI(`/bin/distfs -allow-insecure -config ${confFile} init --new -server http://storage-node-1:8080 -jwt ${jwt}`, 'test-passphrase-123');
    const match = initOut.match(/User ID:\s+([a-f0-9]+)/);
    if (!match) throw new Error(`Failed to extract User ID from output: ${initOut}`);
    const userID = match[1];
    
    const adminConfig = process.env.DISTFS_CONFIG_DIR + '/config.json';
    // Admin creates and provision a directory for the user
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} registry-add --yes --unlock --quota 1000000,100 media-user ${email}`, 'testpassword');
    runCLI(`/bin/distfs -admin -allow-insecure -config ${adminConfig} mkdir --owner media-user /media-user`, 'testpassword');

    // Give some time for Raft consensus to propagate the new directory
    await new Promise(r => setTimeout(r, 3000));

    runCLI(`/bin/distfs -allow-insecure -config ${confFile} mkdir /media-user/Photos`, 'test-passphrase-123');
    runCLI(`echo "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=" | base64 -d > /tmp/img.png`);
    runCLI(`/bin/distfs -allow-insecure -config ${confFile} put /tmp/img.png /media-user/Photos/test-image.png`, 'test-passphrase-123');

    page.on('dialog', async dialog => {
      if (dialog.type() === 'prompt') await dialog.accept('test-passphrase-123');
      else await dialog.accept(); // For the success alert
    });

    await page.goto('/');
    await expect(page.locator('#status')).toContainText('WASM Ready', { timeout: 20000 });
    
    await page.click('#btn-login');
    const modal = page.locator('#device-flow-modal');
    await expect(modal).toBeVisible({ timeout: 15000 });
    
    const userCode = await page.locator('#device-flow-code').textContent();
    await authorizeDeviceCode(request, userCode!, email);

    await expect(page.locator('#auth-overlay')).toBeHidden({ timeout: 30000 });
    
    await expect(page.locator('#file-list')).toContainText('media-user');
    await page.getByText('media-user', { exact: true }).click();
    await expect(page.locator('#breadcrumb')).toHaveText('/media-user');
    
    await expect(page.locator('#file-list')).toContainText('Photos');
    await page.getByText('Photos', { exact: true }).click();
    await expect(page.locator('#breadcrumb')).toHaveText('/media-user/Photos');
    
    await expect(page.locator('#file-list')).toContainText('test-image.png');

    await captureScreenshot(page, 'populated-tree');

    const imageLoc = page.locator('img[alt="test-image.png"]');
    await expect(imageLoc).toBeVisible();
    expect(await imageLoc.getAttribute('src')).toBe('/distfs-media/media-user/Photos/test-image.png');
    await captureScreenshot(page, 'image-thumbnail');

    await page.locator('.share-btn').first().click();
    await expect(page.locator('#share-modal')).toBeVisible();
    await page.locator('#share-target-email').fill('alice@example.com');
    await page.locator('#share-perms').selectOption('rw-');
    
    await page.click('#btn-confirm-share');
    await expect(page.locator('#share-modal')).toBeHidden();
  });

});
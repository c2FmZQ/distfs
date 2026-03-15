import { test, expect } from '@playwright/test';

test.describe('DistFS Web Client E2E', () => {

  test('New Account Registration and Directory Listing', async ({ page, request }) => {
    page.on('console', msg => console.log(`BROWSER CONSOLE: ${msg.type()}: ${msg.text()}`));
    // 1. Fetch a valid JWT from the test auth server
    const authRes = await request.get('http://test-auth:8080/mint?email=playwright@distfs.local');
    expect(authRes.ok()).toBeTruthy();
    const jwt = await authRes.text();

    // 2. Set up dialog handlers to mock prompt()
    // The flow calls prompt() twice: once for JWT, once for Passphrase
    let promptCount = 0;
    page.on('dialog', async dialog => {
      expect(dialog.type()).toBe('prompt');
      promptCount++;
      if (promptCount === 1) {
        // First prompt is for the OIDC JWT
        await dialog.accept(jwt);
      } else if (promptCount === 2) {
        // Second prompt is for the Passphrase
        await dialog.accept('test-passphrase-123');
      } else {
        await dialog.dismiss();
      }
    });

    // 3. Navigate to the app and inject the correct server URL
    await page.addInitScript(() => {
      localStorage.setItem('distfs_server_url', 'http://storage-node-1:8080');
    });
    
    await page.goto('/');

    // 4. Wait for WASM to be ready
    await expect(page.locator('#status')).toContainText('WASM Ready');

    // 5. Click "Create New Account"
    await page.click('#btn-new-account');

    // 6. Assert that registration succeeds and the UI transitions
    await expect(page.locator('#status')).toContainText('Account created and backed up!', { timeout: 15000 });
    
    // Auth overlay should disappear, revealing the main UI
    await expect(page.locator('#auth-overlay')).toBeHidden();

    // The user info should reflect a logged-in state
    await expect(page.locator('#user-info')).toContainText('User:');

    // 7. Verify the empty root directory attempts to load but hits the "locked" security constraint
    await expect(page.locator('#breadcrumb')).toHaveText('/');
    
    // DistFS creates new users in a locked state by default requiring out-of-band verification.
    // The UI should successfully make the cryptographically sealed request, but the server
    // should correctly reject it with a 403.
    await expect(page.locator('#file-list')).toContainText('account is locked pending administrator approval');
  });

});
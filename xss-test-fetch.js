/**
 * XSS Vulnerability Test Script using Node.js/fetch
 * 
 * Tests multiple endpoints for XSS vulnerabilities by checking if payloads
 * are properly encoded or reflected without encoding in responses.
 * 
 * Target: http://host.docker.internal:8080
 */

import { writeFileSync } from 'fs';

const BASE_URL = 'http://host.docker.internal:8080';

// Test payloads
const PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>'
];

// Test endpoints
const ENDPOINTS = [
  {
    name: 'GET /search?q=XSS_PAYLOAD',
    method: 'GET',
    path: (payload) => `/search?q=${encodeURIComponent(payload)}`,
    checkInResponse: true
  },
  {
    name: 'GET /comment?filter=XSS_PAYLOAD',
    method: 'GET',
    path: (payload) => `/comment?filter=${encodeURIComponent(payload)}`,
    checkInResponse: true
  },
  {
    name: 'GET /profile?name=XSS_PAYLOAD&bio=XSS_PAYLOAD',
    method: 'GET',
    path: (payload) => `/profile?name=${encodeURIComponent(payload)}&bio=${encodeURIComponent(payload)}`,
    checkInResponse: true
  },
  {
    name: 'POST /comment?content=XSS_PAYLOAD',
    method: 'POST',
    path: (payload) => `/comment?content=${encodeURIComponent(payload)}`,
    checkInResponse: true,
    body: (payload) => `content=${encodeURIComponent(payload)}`
  }
];

// Results storage
const results = [];

function encodeHTML(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

function checkXSSVulnerability(payload, responseText) {
  // Check if raw payload exists (not encoded)
  const rawPayloadExists = responseText.includes(payload);
  
  // Check if payload is HTML encoded
  const encodedPayload = encodeHTML(payload);
  const encodedPayloadExists = responseText.includes(encodedPayload);
  
  // Check for potentially dangerous patterns
  const dangerousPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /onerror\s*=/gi,
    /onload\s*=/gi,
    /javascript\s*:/gi,
    /<img[^>]*>/gi,
    /<svg[^>]*>/gi
  ];
  
  let dangerousFound = [];
  for (const pattern of dangerousPatterns) {
    if (pattern.test(responseText)) {
      dangerousFound.push(pattern.toString());
    }
  }
  
  return {
    rawPayloadReflected: rawPayloadExists,
    encodedPayloadFound: encodedPayloadExists,
    dangerousPatterns: dangerousFound,
    isVulnerable: rawPayloadExists && dangerousFound.length > 0
  };
}

async function makeRequest(endpoint, payload) {
  const url = `${BASE_URL}${endpoint.path(payload)}`;
  const options = {
    method: endpoint.method,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  };
  
  if (endpoint.method === 'POST' && endpoint.body) {
    options.body = endpoint.body(payload);
  }
  
  try {
    const response = await fetch(url, options);
    const text = await response.text();
    const status = response.status;
    
    return {
      success: true,
      status,
      text: text.substring(0, 2000), // Limit text length for output
      fullText: text
    };
  } catch (error) {
    return {
      success: false,
      error: error.message
    };
  }
}

async function runTests() {
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║        XSS Vulnerability Test - Node.js/fetch                 ║');
  console.log('╚════════════════════════════════════════════════════════════════╝');
  console.log(`\n📡 Target: ${BASE_URL}\n`);
  
  // Login first to get authenticated session
  console.log('🔐 Step 1: Authenticating...\n');
  
  let sessionCookie = '';
  try {
    const loginResponse = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: 'username=admin&password=password123',
      redirect: 'manual'
    });
    
    const cookies = loginResponse.headers.get('set-cookie');
    if (cookies) {
      sessionCookie = cookies.split(';')[0];
      console.log('✅ Authentication successful\n');
    } else {
      console.log('⚠️  No session cookie found, continuing without authentication\n');
    }
  } catch (error) {
    console.log(`⚠️  Login error: ${error.message}, continuing...\n`);
  }

  console.log('════════════════════════════════════════════════════════════════');
  console.log('📋 Starting XSS Vulnerability Tests');
  console.log('════════════════════════════════════════════════════════════════\n');
  
  for (const endpoint of ENDPOINTS) {
    console.log(`\n▶ Testing: ${endpoint.name}`);
    console.log('-'.repeat(60));
    
    for (const payload of PAYLOADS) {
      console.log(`\n  Payload: ${payload}`);
      
      const options = {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      };
      
      if (sessionCookie) {
        options.headers['Cookie'] = sessionCookie;
      }
      
      if (endpoint.method === 'POST' && endpoint.body) {
        options.body = endpoint.body(payload);
      }
      
      const url = `${BASE_URL}${endpoint.path(payload)}`;
      
      try {
        const response = await fetch(url, options);
        const text = await response.text();
        const status = response.status;
        
        console.log(`  Status: ${status}`);
        
        // Check for vulnerability
        const vulnerability = checkXSSVulnerability(payload, text);
        
        const result = {
          endpoint: endpoint.name,
          payload,
          status,
          url,
          vulnerability,
          responseSnippet: text.substring(0, 500)
        };
        
        results.push(result);
        
        // Output vulnerability status
        if (vulnerability.isVulnerable) {
          console.log('  ⚠️  VULNERABLE: Raw payload reflected without encoding!');
          console.log(`     Dangerous patterns found: ${vulnerability.dangerousPatterns.join(', ')}`);
        } else if (vulnerability.rawPayloadReflected) {
          console.log('  ⚠️  WARNING: Raw payload reflected (may or may not be exploitable)');
        } else {
          console.log('  ✅ SAFE: Payload not directly reflected or properly encoded');
        }
        
      } catch (error) {
        console.log(`  ❌ Error: ${error.message}`);
        results.push({
          endpoint: endpoint.name,
          payload,
          error: error.message
        });
      }
    }
  }
  
  // Summary
  console.log('\n\n' + '='.repeat(70));
  console.log('📊 TEST RESULTS SUMMARY');
  console.log('='.repeat(70));
  
  let vulnerableCount = 0;
  let warningCount = 0;
  let safeCount = 0;
  let errorCount = 0;
  
  for (const result of results) {
    if (result.error) {
      errorCount++;
      continue;
    }
    
    if (result.vulnerability?.isVulnerable) {
      vulnerableCount++;
    } else if (result.vulnerability?.rawPayloadReflected) {
      warningCount++;
    } else {
      safeCount++;
    }
  }
  
  console.log(`
  Total Tests:     ${results.length}
  Vulnerable:      ${vulnerableCount} ⚠️
  Warning:         ${warningCount} ⚡
  Safe:            ${safeCount} ✅
  Errors:          ${errorCount} ❌
  `);
  
  // Detailed results
  console.log('='.repeat(70));
  console.log('📝 DETAILED RESULTS');
  console.log('='.repeat(70));
  
  for (const result of results) {
    if (result.error) {
      console.log(`\n❌ ${result.endpoint} | ${result.payload}`);
      console.log(`   Error: ${result.error}`);
      continue;
    }
    
    const status = result.vulnerability?.isVulnerable ? '⚠️ VULNERABLE' : 
                   result.vulnerability?.rawPayloadReflected ? '⚡ WARNING' : '✅ SAFE';
    
    console.log(`\n${status} | ${result.endpoint}`);
    console.log(`   Payload: ${result.payload}`);
    console.log(`   Status Code: ${result.status}`);
    
    if (result.vulnerability?.isVulnerable) {
      console.log(`   Patterns: ${result.vulnerability.dangerousPatterns.join(', ')}`);
    }
  }
  
  console.log('\n' + '='.repeat(70));
  console.log('🧪 Test completed at: ' + new Date().toISOString());
  console.log('='.repeat(70) + '\n');
  
  return results;
}

// Run the tests
runTests()
  .then(results => {
    // Save results to file
    const report = {
      timestamp: new Date().toISOString(),
      target: BASE_URL,
      results: results
    };
    
    writeFileSync(
      'xss-test-report.json',
      JSON.stringify(report, null, 2)
    );
    
    console.log('📄 Report saved to: xss-test-report.json');
    
    process.exit(0);
  })
  .catch(err => {
    console.error('❌ Fatal error:', err);
    process.exit(1);
  });

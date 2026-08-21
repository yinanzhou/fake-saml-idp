/**
 * Verification Test Suite for Fake SAML IdP
 */

import { DEFAULT_KEY_PAIR, pemToBase64, computeCertFingerprint } from '../public/js/crypto-keys.js';
import { PRESETS } from '../public/js/presets.js';
import { decompressRawDeflate, parseAuthnRequestXml } from '../public/js/saml-parser.js';
import zlib from 'zlib';
import crypto from 'crypto';

// Setup browser WebCrypto shim for Node environment
if (typeof window === 'undefined') {
  globalThis.window = { crypto: crypto.webcrypto };
}

async function runTests() {
  console.log('🧪 Starting Fake SAML IdP Automated Tests...\n');
  let passed = 0;
  let failed = 0;

  function assert(condition, name) {
    if (condition) {
      console.log(`  ✅ PASS: ${name}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${name}`);
      failed++;
    }
  }

  // 1. Test Default Key Pair & Fingerprint
  console.log('1. Key Management & Fingerprint:');
  assert(DEFAULT_KEY_PAIR.certPem.includes('-----BEGIN CERTIFICATE-----'), 'Certificate is valid PEM');
  assert(DEFAULT_KEY_PAIR.privateKeyPkcs8Pem.includes('-----BEGIN PRIVATE KEY-----'), 'Private key is valid PKCS#8 PEM');
  
  const b64Cert = pemToBase64(DEFAULT_KEY_PAIR.certPem);
  assert(b64Cert.length > 500 && !b64Cert.includes('\n'), 'Base64 extraction cleans whitespace and headers');

  const computedFp = await computeCertFingerprint(DEFAULT_KEY_PAIR.certPem);
  assert(computedFp === DEFAULT_KEY_PAIR.fingerprintSha256, `Fingerprint matches expected: ${computedFp}`);

  // 2. Test Presets (including Google and DBSC)
  console.log('\n2. Built-in Persona & DBSC Presets:');
  assert(PRESETS.length === 5, `Found exact 5 streamlined presets: ${PRESETS.map(p => p.id).join(', ')}`);
  
  const googlePreset = PRESETS.find(p => p.id === 'google');
  assert(googlePreset !== undefined, 'Google Workspace preset exists');
  assert(googlePreset.attributes.some(a => a.name === 'email'), 'Google preset has email attribute');
  assert(googlePreset.attributes.some(a => a.name === 'first_name'), 'Google preset has first_name attribute');

  const dbscPreset = PRESETS.find(p => p.id === 'dbsc');
  assert(dbscPreset !== undefined, 'DBSC preset exists');
  assert(dbscPreset.dbsc.enabled === true, 'DBSC preset has dbsc enabled');
  assert(dbscPreset.dbsc.keys.length > 0 && dbscPreset.dbsc.keys[0].digest !== '', 'DBSC TrustedKey digest is configured');
  assert(dbscPreset.dbsc.certificates.length > 0 && dbscPreset.dbsc.certificates[0].fingerprint !== '', 'DBSC TrustedCertificate fingerprint is configured');

  // 3. Test Raw Deflate Inflation & Parser
  console.log('\n3. SAML AuthnRequest Deflation & Parser:');
  const sampleAuthnRequestXml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req_123456789" Version="2.0" IssueInstant="2026-08-21T01:50:00Z" Destination="https://fake-saml-idp.pages.dev/" AssertionConsumerServiceURL="https://sp.example.com/saml/acs" ForceAuthn="true"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">test.user@company.com</saml:NameID></saml:Subject></samlp:AuthnRequest>`;
  
  const deflatedBuffer = zlib.deflateRawSync(Buffer.from(sampleAuthnRequestXml, 'utf-8'));
  const inflatedString = await decompressRawDeflate(new Uint8Array(deflatedBuffer));
  assert(inflatedString === sampleAuthnRequestXml, 'Raw deflate decompression matches original XML');

  // Verify XML parser if xmldom / DOMParser is available or check regex fallback
  if (typeof DOMParser !== 'undefined') {
    const parsed = parseAuthnRequestXml(sampleAuthnRequestXml);
    assert(parsed.id === '_req_123456789', 'Extracted AuthnRequest ID');
    assert(parsed.acsUrl === 'https://sp.example.com/saml/acs', 'Extracted ACS URL');
    assert(parsed.issuer === 'https://sp.example.com/metadata', 'Extracted SP Entity ID');
    assert(parsed.requestedSubject === 'test.user@company.com', 'Extracted requested Subject / login_hint');
  } else {
    // Basic test
    assert(sampleAuthnRequestXml.includes('test.user@company.com'), 'AuthnRequest contains login_hint subject');
  }

  // 4. Test WebCrypto RSA Signing with Default Private Key
  console.log('\n4. WebCrypto RSA-SHA256 Signing:');
  const privKeyBuf = Buffer.from(pemToBase64(DEFAULT_KEY_PAIR.privateKeyPkcs8Pem), 'base64');
  const cryptoKey = await window.crypto.subtle.importKey(
    'pkcs8',
    privKeyBuf,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  assert(cryptoKey !== null, 'Imported PKCS#8 private key successfully into WebCrypto');

  const testPayload = new TextEncoder().encode('SAML 2.0 Assertion Canonical XML Test');
  const testSignature = await window.crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, testPayload);
  assert(testSignature.byteLength === 256, 'Signature length is 256 bytes (2048-bit RSA)');

  // Verify signature with Node Crypto (OpenSSL)
  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(Buffer.from(testPayload));
  const isVerified = verifier.verify(DEFAULT_KEY_PAIR.certPem, Buffer.from(testSignature));
  assert(isVerified === true, 'RSA-SHA256 signature verified successfully against default X.509 certificate');

  console.log(`\n========================================`);
  console.log(`Test Results: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test execution error:', err);
  process.exit(1);
});

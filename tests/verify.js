/**
 * Verification Test Suite for Fake SAML IdP
 * Tests W3C c14n-exc canonicalization, schema compliance, Base64URL encoding,
 * and cryptographically verifies Assertion & Response XMLDSig signatures.
 */

import { DEFAULT_KEY_PAIR, pemToBase64, computeCertFingerprint, importPrivateKey } from '../public/js/crypto-keys.js';
import { PRESETS, detectSmartPreset } from '../public/js/presets.js';
import { decompressRawDeflate, parseAuthnRequestXml, parseLogoutRequestXml, parseCurrentUrlParams } from '../public/js/saml-parser.js';
import { buildSamlResponse, buildSamlLogoutResponse, toBase64Url } from '../public/js/saml-builder.js';
import { canonicalize, computeXmlDigest } from '../public/js/xml-signer.js';
import zlib from 'zlib';
import crypto from 'crypto';

// Setup browser WebCrypto & DOM shims for Node environment
if (typeof window === 'undefined') {
  globalThis.window = { crypto: crypto.webcrypto };
}

class MiniNode {
  constructor(nodeType, nodeName, nodeValue = null) {
    this.nodeType = nodeType;
    this.nodeName = nodeName;
    this.nodeValue = nodeValue;
    this.tagName = nodeName;
    this.localName = nodeName.includes(':') ? nodeName.split(':')[1] : nodeName;
    this.attributes = [];
    this.childNodes = [];
    this.parentNode = null;
  }

  get nextSibling() {
    if (!this.parentNode) return null;
    const idx = this.parentNode.childNodes.indexOf(this);
    if (idx >= 0 && idx < this.parentNode.childNodes.length - 1) {
      return this.parentNode.childNodes[idx + 1];
    }
    return null;
  }

  get textContent() {
    if (this.nodeType === 3 || this.nodeType === 4) return this.nodeValue || '';
    return this.childNodes.map(c => c.textContent).join('');
  }

  set textContent(val) {
    this.childNodes = [];
    if (val !== undefined && val !== null) {
      const txt = new MiniNode(3, '#text', String(val));
      this.appendChild(txt);
    }
  }

  getAttribute(name) {
    const attr = this.attributes.find(a => a.name === name);
    return attr ? attr.value : null;
  }

  setAttribute(name, value) {
    const attr = this.attributes.find(a => a.name === name);
    if (attr) {
      attr.value = String(value);
    } else {
      this.attributes.push({ name, value: String(value) });
    }
  }

  removeAttribute(name) {
    const idx = this.attributes.findIndex(a => a.name === name);
    if (idx >= 0) this.attributes.splice(idx, 1);
  }

  appendChild(child) {
    if (child.parentNode) {
      child.parentNode.removeChild(child);
    }
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }

  removeChild(child) {
    const idx = this.childNodes.indexOf(child);
    if (idx >= 0) {
      this.childNodes.splice(idx, 1);
      child.parentNode = null;
      return child;
    }
    return null;
  }

  insertBefore(newNode, refNode) {
    if (!refNode) return this.appendChild(newNode);
    const idx = this.childNodes.indexOf(refNode);
    if (idx >= 0) {
      if (newNode.parentNode) {
        newNode.parentNode.removeChild(newNode);
      }
      newNode.parentNode = this;
      this.childNodes.splice(idx, 0, newNode);
      return newNode;
    }
    return this.appendChild(newNode);
  }

  getElementsByTagName(name) {
    const results = [];
    const traverse = (node) => {
      for (const child of node.childNodes) {
        if (child.nodeType === 1) {
          if (name === '*' || child.tagName === name || child.localName === name) {
            results.push(child);
          }
          traverse(child);
        }
      }
    };
    traverse(this);
    return results;
  }

  getElementsByTagNameNS(ns, localName) {
    const results = [];
    const traverse = (node) => {
      for (const child of node.childNodes) {
        if (child.nodeType === 1) {
          if (localName === '*' || child.localName === localName || child.tagName === localName || child.tagName.endsWith(':' + localName)) {
            results.push(child);
          }
          traverse(child);
        }
      }
    };
    traverse(this);
    return results;
  }

  querySelector(selector) {
    const all = this.getElementsByTagName('*');
    for (const el of all) {
      if (el.tagName === selector || el.localName === selector) {
        return el;
      }
    }
    return null;
  }

  cloneNode(deep = true) {
    const clone = new MiniNode(this.nodeType, this.nodeName, this.nodeValue);
    clone.attributes = this.attributes.map(a => ({ name: a.name, value: a.value }));
    if (deep) {
      for (const child of this.childNodes) {
        clone.appendChild(child.cloneNode(true));
      }
    }
    return clone;
  }
}

function parseXmlString(xmlString) {
  const doc = new MiniNode(9, '#document');
  doc.documentElement = null;
  doc.importNode = (node, deep = true) => node.cloneNode(deep);

  let xml = xmlString.replace(/<\?xml[^>]*\?>/i, '').trim();
  const tagRegex = /<!--[\s\S]*?-->|<!\[CDATA\[([\s\S]*?)\]\]>|<(\/)?([a-zA-Z0-9_:-]+)((?:\s+[^=>\/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/)?>|([^<]+)/g;
  let match;
  let current = doc;

  while ((match = tagRegex.exec(xml)) !== null) {
    const [full, cdataContent, isClosing, tagName, attrString, isSelfClosing, textContent] = match;

    if (full.startsWith('<!--')) {
      continue;
    } else if (cdataContent !== undefined) {
      const cdataNode = new MiniNode(4, '#cdata-section', cdataContent);
      current.appendChild(cdataNode);
    } else if (textContent !== undefined) {
      if (textContent.trim()) {
        const textNode = new MiniNode(3, '#text', textContent);
        current.appendChild(textNode);
      }
    } else if (isClosing) {
      if (current.parentNode) {
        current = current.parentNode;
      }
    } else if (tagName) {
      const elem = new MiniNode(1, tagName);
      if (attrString) {
        const attrRegex = /([a-zA-Z0-9_:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
        let attrMatch;
        while ((attrMatch = attrRegex.exec(attrString)) !== null) {
          elem.attributes.push({ name: attrMatch[1], value: attrMatch[2] !== undefined ? attrMatch[2] : attrMatch[3] });
        }
      }

      current.appendChild(elem);
      if (!doc.documentElement) {
        doc.documentElement = elem;
      }

      if (!isSelfClosing) {
        current = elem;
      }
    }
  }

  return doc;
}

function serializeNode(node) {
  if (node.nodeType === 3 || node.nodeType === 4) {
    return node.nodeValue || '';
  }
  if (node.nodeType === 9) {
    return node.documentElement ? serializeNode(node.documentElement) : '';
  }
  if (node.nodeType === 1) {
    let s = '<' + node.tagName;
    for (const a of node.attributes) {
      s += ' ' + a.name + '="' + a.value + '"';
    }
    if (node.childNodes.length === 0) {
      return s + '/>';
    }
    s += '>';
    for (const c of node.childNodes) {
      s += serializeNode(c);
    }
    s += '</' + node.tagName + '>';
    return s;
  }
  return '';
}

if (typeof globalThis.DOMParser === 'undefined') {
  globalThis.DOMParser = class {
    parseFromString(xml) {
      return parseXmlString(xml);
    }
  };
}

if (typeof globalThis.XMLSerializer === 'undefined') {
  globalThis.XMLSerializer = class {
    serializeToString(node) {
      return serializeNode(node);
    }
  };
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

  // 2. Test Presets & DBSC Base64URL Normalization
  console.log('\n2. Built-in Persona & DBSC Presets:');
  assert(PRESETS.length === 5, `Found exact 5 streamlined presets: ${PRESETS.map(p => p.id).join(', ')}`);
  
  const googlePreset = PRESETS.find(p => p.id === 'google');
  assert(googlePreset !== undefined, 'Google Workspace preset exists');
  assert(googlePreset.defaultSpEntityId === 'google.com', 'Google preset has defaultSpEntityId = google.com');
  assert(googlePreset.defaultAcsUrl === 'https://www.google.com/a/company.com/acs', 'Google preset has target ACS URL');
  assert(googlePreset.attributes.some(a => a.name === 'email'), 'Google preset has email attribute');
  assert(googlePreset.attributes.some(a => a.name === 'first_name'), 'Google preset has first_name attribute');

  const dbscPreset = PRESETS.find(p => p.id === 'dbsc');
  assert(dbscPreset !== undefined, 'DBSC preset exists');
  assert(dbscPreset.dbsc.enabled === true, 'DBSC preset has dbsc enabled');
  
  const dbscKeyDigest = dbscPreset.dbsc.keys[0].digest;
  assert(!dbscKeyDigest.includes('=') && !dbscKeyDigest.includes('+') && !dbscKeyDigest.includes('/'), 'DBSC TrustedKey digest is unpadded Base64URL');
  
  const dbscCertFp = dbscPreset.dbsc.certificates[0].fingerprint;
  assert(!dbscCertFp.includes('=') && !dbscCertFp.includes('+') && !dbscCertFp.includes('/'), 'DBSC TrustedCertificate fingerprint is unpadded Base64URL');

  // Smart Preset Detection Tests
  assert(detectSmartPreset('https://signin.aws.amazon.com/saml', '') === 'aws_iam', 'Smart detects AWS IAM from SP Entity ID');
  assert(detectSmartPreset('https://sts.windows.net/tenant-id/', '') === 'azure_ad', 'Smart detects Azure AD from SP Entity ID');
  assert(detectSmartPreset('google.com', 'https://www.google.com/a/company.com/acs') === 'google', 'Smart detects Google Workspace from ACS URL');
  assert(detectSmartPreset('', '', '?dbsc=true') === 'dbsc', 'Smart detects DBSC from URL query parameter');
  assert(detectSmartPreset('https://custom-app.example.com/saml', 'https://custom-app.example.com/acs') === 'default', 'Smart defaults to standard user for generic SP');

  // 3. Test Base64URL Helper
  console.log('\n3. Base64URL Normalization Helper:');
  const b64Input = 'nZgxCylNy7jXvn4+j0DykE+TDK4W41LTffxei29e/G0=';
  const expectedB64Url = 'nZgxCylNy7jXvn4-j0DykE-TDK4W41LTffxei29e_G0';
  assert(toBase64Url(b64Input) === expectedB64Url, 'Converts standard Base64 with padding to Base64URL');

  const hexFingerprint = 'f3e9619a9d701a52701469e4f83d32847b2374e2593f66d48b788647097c234b';
  const expectedHexB64Url = Buffer.from(hexFingerprint, 'hex').toString('base64url');
  assert(toBase64Url(hexFingerprint) === expectedHexB64Url, 'Converts 32-byte Hex fingerprint to Base64URL');

  // 4. Test Raw Deflate Inflation & Parser
  console.log('\n4. SAML AuthnRequest Deflation & Parser:');
  const sampleAuthnRequestXml = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req_123456789" Version="2.0" IssueInstant="2026-08-21T01:50:00Z" Destination="https://fake-saml-idp.pages.dev/" AssertionConsumerServiceURL="https://sp.example.com/saml/acs" ForceAuthn="true"><saml:Issuer>https://sp.example.com/metadata</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">test.user@company.com</saml:NameID></saml:Subject></samlp:AuthnRequest>`;
  
  const deflatedBuffer = zlib.deflateRawSync(Buffer.from(sampleAuthnRequestXml, 'utf-8'));
  const inflatedString = await decompressRawDeflate(new Uint8Array(deflatedBuffer));
  assert(inflatedString === sampleAuthnRequestXml, 'Raw deflate decompression matches original XML');

  const parsed = parseAuthnRequestXml(sampleAuthnRequestXml);
  assert(parsed.id === '_req_123456789', 'Extracted AuthnRequest ID');
  assert(parsed.acsUrl === 'https://sp.example.com/saml/acs', 'Extracted ACS URL');
  assert(parsed.issuer === 'https://sp.example.com/metadata', 'Extracted SP Entity ID');
  assert(parsed.requestedSubject === 'test.user@company.com', 'Extracted requested Subject / login_hint');

  const urlHint1 = await parseCurrentUrlParams('?login_hint=alice@example.com');
  assert(urlHint1.loginHint === 'alice@example.com', 'Extracted snake_case login_hint parameter');
  assert(urlHint1.loginHintSource.includes('?login_hint='), 'loginHintSource references login_hint');

  const urlHint2 = await parseCurrentUrlParams('?LoginHint=bob@example.com');
  assert(urlHint2.loginHint === 'bob@example.com', 'Extracted PascalCase LoginHint parameter');
  assert(urlHint2.loginHintSource.includes('?LoginHint='), 'loginHintSource references LoginHint');

  // 5. Test W3C Exclusive XML Canonicalization (c14n-exc) Subtree Namespace Inheritance
  console.log('\n5. W3C Exclusive XML Canonicalization (c14n-exc):');
  const xmlWithParentNs = parseXmlString(
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp_1">' +
      '<saml:Assertion ID="_asrt_1">' +
        '<saml:Issuer>https://fake-saml-idp.pages.dev/saml/idp</saml:Issuer>' +
      '</saml:Assertion>' +
    '</samlp:Response>'
  );

  const assertionSubtree = xmlWithParentNs.getElementsByTagNameNS('*', 'Assertion')[0];
  const canonicalAssertion = canonicalize(assertionSubtree);
  
  assert(canonicalAssertion.startsWith('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_asrt_1">'),
    'Canonicalized child <saml:Assertion> correctly inherits visibly utilized xmlns:saml from parent');
  assert(!canonicalAssertion.includes('xmlns:samlp'),
    'Canonicalized child <saml:Assertion> omits unused parent xmlns:samlp per W3C c14n-exc');

  // 6. Test SAML Response Builder & Schema Compliance
  console.log('\n6. SAML Response Builder & Schema Ordering:');
  const privateKey = await importPrivateKey(DEFAULT_KEY_PAIR.privateKeyPkcs8Pem);
  
  const samlBuildResult = await buildSamlResponse({
    acsUrl: 'https://www.google.com/a/company.com/acs',
    spEntityId: 'google.com',
    idpEntityId: 'https://fake-saml-idp.pages.dev/saml/idp',
    nameId: 'user@company.com',
    attributes: [
      { name: 'email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['user@company.com'] }
    ],
    dbscEnabled: true,
    dbscKeys: [{ digest: 'nZgxCylNy7jXvn4+j0DykE+TDK4W41LTffxei29e/G0=', digestAlg: 'SHA-256' }],
    dbscCertificates: [{ fingerprint: 'f3e9619a9d701a52701469e4f83d32847b2374e2593f66d48b788647097c234b', fingerprintAlg: 'SHA-256' }],
    signAssertion: true,
    signResponse: true,
    privateKey,
    certPem: DEFAULT_KEY_PAIR.certPem
  });

  const rawXml = samlBuildResult.rawXmlString;

  // Schema element order: Subject -> Conditions -> Advice -> AuthnStatement -> AttributeStatement
  const idxSubject = rawXml.indexOf('<saml:Subject>');
  const idxConditions = rawXml.indexOf('<saml:Conditions');
  const idxAdvice = rawXml.indexOf('<saml:Advice>');
  const idxAuthnStatement = rawXml.indexOf('<saml:AuthnStatement');
  const idxAttributeStatement = rawXml.indexOf('<saml:AttributeStatement>');

  assert(idxSubject !== -1 && idxConditions > idxSubject, 'Conditions follows Subject');
  assert(idxAdvice !== -1 && idxAdvice > idxConditions, 'Advice follows Conditions');
  assert(idxAuthnStatement > idxAdvice, 'AuthnStatement follows Advice (SAML 2.0 Schema compliant)');
  assert(idxAttributeStatement > idxAuthnStatement, 'AttributeStatement follows AuthnStatement');

  // Verify SubjectConfirmationData 5-minute window
  const subjectConfirmDataMatch = rawXml.match(/<saml:SubjectConfirmationData[^>]*NotOnOrAfter="([^"]+)"/);
  assert(subjectConfirmDataMatch !== null, 'SubjectConfirmationData has NotOnOrAfter attribute');
  if (subjectConfirmDataMatch) {
    const scdNotOnOrAfter = new Date(subjectConfirmDataMatch[1]);
    const diffMinutes = (scdNotOnOrAfter.getTime() - Date.now()) / (60 * 1000);
    assert(diffMinutes > 4 && diffMinutes <= 6, `SubjectConfirmationData validity is ~5 minutes (actual: ${diffMinutes.toFixed(1)}m)`);
  }

  // Verify DBSC Base64URL in built XML
  assert(rawXml.includes('digest="nZgxCylNy7jXvn4-j0DykE-TDK4W41LTffxei29e_G0"'), 'DBSC TrustedKey digest normalized to Base64URL in Advice');
  assert(rawXml.includes('fingerprint="8-lhmp1wGlJwFGnk-D0yhHsjdOJZP2bUi3iGRwl8I0s"'), 'DBSC TrustedCertificate fingerprint normalized to Base64URL in Advice');

  // 7. Full Cryptographic Verification of XMLDSig Signatures
  console.log('\n7. XMLDSig Cryptographic Verification (Response & Assertion):');
  
  const doc = samlBuildResult.xmlDoc;
  const assertionElem = doc.getElementsByTagNameNS('*', 'Assertion')[0];
  const responseElem = doc.documentElement;

  // Verify Response Signature & Digest (Enveloped-signature: top-level response signature removed, assertion signature intact)
  const respSig = responseElem.childNodes.find(c => c.nodeType === 1 && (c.localName === 'Signature' || c.tagName === 'ds:Signature'));
  assert(respSig !== undefined, 'Response contains top-level <ds:Signature>');

  const respSignedInfo = respSig.getElementsByTagNameNS('*', 'SignedInfo')[0];
  const respDigestValue = respSignedInfo.getElementsByTagNameNS('*', 'DigestValue')[0].textContent.trim();
  const respSignatureValue = respSig.getElementsByTagNameNS('*', 'SignatureValue')[0].textContent.trim();

  // Remove top-level response signature and canonicalize to verify Response DigestValue
  responseElem.removeChild(respSig);
  const canonicalRespTarget = canonicalize(responseElem);
  const computedRespDigest = await computeXmlDigest(canonicalRespTarget);

  assert(computedRespDigest === respDigestValue, `Response DigestValue matches SHA-256 digest: ${respDigestValue}`);

  // Verify Response SignatureValue with Node Crypto
  const canonicalRespSignedInfo = canonicalize(respSignedInfo);
  const respVerifier = crypto.createVerify('RSA-SHA256');
  respVerifier.update(Buffer.from(canonicalRespSignedInfo, 'utf-8'));
  const isRespSigValid = respVerifier.verify(DEFAULT_KEY_PAIR.certPem, Buffer.from(respSignatureValue, 'base64'));
  assert(isRespSigValid === true, 'Response SignatureValue verified successfully with RSA-SHA256 against X.509 certificate');

  // Verify Assertion Signature & Digest (Enveloped-signature: assertion's own signature removed)
  const assertionSig = assertionElem.getElementsByTagNameNS('*', 'Signature')[0];
  assert(assertionSig !== undefined, 'Assertion contains <ds:Signature>');

  const asrtSignedInfo = assertionSig.getElementsByTagNameNS('*', 'SignedInfo')[0];
  const asrtDigestValue = asrtSignedInfo.getElementsByTagNameNS('*', 'DigestValue')[0].textContent.trim();
  const asrtSignatureValue = assertionSig.getElementsByTagNameNS('*', 'SignatureValue')[0].textContent.trim();

  // Remove assertion signature and canonicalize to check Assertion DigestValue
  assertionElem.removeChild(assertionSig);
  const canonicalAsrtTarget = canonicalize(assertionElem);
  const computedAsrtDigest = await computeXmlDigest(canonicalAsrtTarget);
  
  assert(computedAsrtDigest === asrtDigestValue, `Assertion DigestValue matches SHA-256 digest: ${asrtDigestValue}`);

  // Verify Assertion SignatureValue with Node Crypto
  const canonicalAsrtSignedInfo = canonicalize(asrtSignedInfo);
  const asrtVerifier = crypto.createVerify('RSA-SHA256');
  asrtVerifier.update(Buffer.from(canonicalAsrtSignedInfo, 'utf-8'));
  const isAsrtSigValid = asrtVerifier.verify(DEFAULT_KEY_PAIR.certPem, Buffer.from(asrtSignatureValue, 'base64'));
  assert(isAsrtSigValid === true, 'Assertion SignatureValue verified successfully with RSA-SHA256 against X.509 certificate');

  // 8. Test Static Endpoints (Logout & Change Password)
  console.log('\n8. Static Endpoints (Single Logout & Change Password):');
  const fs = await import('fs');
  const path = await import('path');

  const logoutExists = fs.existsSync(path.resolve('public/logout.html'));
  assert(logoutExists === true, 'public/logout.html exists');
  if (logoutExists) {
    const logoutContent = fs.readFileSync(path.resolve('public/logout.html'), 'utf-8');
    assert(logoutContent.includes('Single Logout') && logoutContent.includes('logged out'), 'logout.html contains SLO content');
  }

  const changePassExists = fs.existsSync(path.resolve('public/change-password.html'));
  assert(changePassExists === true, 'public/change-password.html exists');
  if (changePassExists) {
    const changePassContent = fs.readFileSync(path.resolve('public/change-password.html'), 'utf-8');
    assert(changePassContent.includes('Change Password'), 'change-password.html contains change password content');
  }

  // 9. Test SAML Single Logout (SLO) Protocol & XMLDSig Signatures
  console.log('\n9. SAML Single Logout (SLO) Protocol & XMLDSig:');
  const sampleLogoutRequestXml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_slo_req_998877" Version="2.0" IssueInstant="2026-08-21T06:00:00Z" Destination="https://fake-saml-idp.pages.dev/logout">
  <saml:Issuer>https://sp.example.com/metadata</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice.slo@company.com</saml:NameID>
  <samlp:SessionIndex>_sess_slo_112233</samlp:SessionIndex>
</samlp:LogoutRequest>`;

  const parsedLogoutReq = parseLogoutRequestXml(sampleLogoutRequestXml);
  assert(parsedLogoutReq.id === '_slo_req_998877', 'Extracted LogoutRequest ID');
  assert(parsedLogoutReq.issuer === 'https://sp.example.com/metadata', 'Extracted LogoutRequest Issuer');
  assert(parsedLogoutReq.nameId === 'alice.slo@company.com', 'Extracted LogoutRequest NameID');
  assert(parsedLogoutReq.sessionIndex === '_sess_slo_112233', 'Extracted LogoutRequest SessionIndex');
  assert(parsedLogoutReq.destination === 'https://fake-saml-idp.pages.dev/logout', 'Extracted LogoutRequest Destination');

  // Build LogoutResponse
  const sloResponseResult = await buildSamlLogoutResponse({
    destination: 'https://sp.example.com/saml/slo',
    inResponseTo: parsedLogoutReq.id,
    idpEntityId: 'https://fake-saml-idp.pages.dev/saml/idp',
    statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
    statusMessage: 'Session terminated',
    signResponse: true,
    privateKey,
    certPem: DEFAULT_KEY_PAIR.certPem
  });

  assert(sloResponseResult.inResponseTo === '_slo_req_998877', 'LogoutResponse inResponseTo matches LogoutRequest ID');
  assert(sloResponseResult.destination === 'https://sp.example.com/saml/slo', 'LogoutResponse destination matches');
  assert(sloResponseResult.rawXmlString.includes('urn:oasis:names:tc:SAML:2.0:status:Success'), 'LogoutResponse contains Success status code');
  assert(sloResponseResult.rawXmlString.includes('<samlp:StatusMessage>Session terminated</samlp:StatusMessage>'), 'LogoutResponse contains status message');

  // Cryptographically verify LogoutResponse Signature
  const sloDoc = parseXmlString(sloResponseResult.rawXmlString);
  const sloRoot = sloDoc.documentElement;
  const sloSig = sloRoot.getElementsByTagNameNS('*', 'Signature')[0];
  assert(sloSig !== undefined, 'LogoutResponse contains <ds:Signature>');

  const sloSignedInfo = sloSig.getElementsByTagNameNS('*', 'SignedInfo')[0];
  const sloDigestValue = sloSignedInfo.getElementsByTagNameNS('*', 'DigestValue')[0].textContent.trim();
  const sloSignatureValue = sloSig.getElementsByTagNameNS('*', 'SignatureValue')[0].textContent.trim();

  // Remove signature and canonicalize root
  sloRoot.removeChild(sloSig);
  const canonicalSloTarget = canonicalize(sloRoot);
  const computedSloDigest = await computeXmlDigest(canonicalSloTarget);
  assert(computedSloDigest === sloDigestValue, `LogoutResponse DigestValue matches SHA-256 digest: ${sloDigestValue}`);

  // Verify SignatureValue with Node Crypto
  const canonicalSloSignedInfo = canonicalize(sloSignedInfo);
  const sloVerifier = crypto.createVerify('RSA-SHA256');
  sloVerifier.update(Buffer.from(canonicalSloSignedInfo, 'utf-8'));
  const isSloSigValid = sloVerifier.verify(DEFAULT_KEY_PAIR.certPem, Buffer.from(sloSignatureValue, 'base64'));
  assert(isSloSigValid === true, 'LogoutResponse SignatureValue verified successfully with RSA-SHA256 against X.509 certificate');

  // Test PartialLogout and Requester status codes
  const partialResponse = await buildSamlLogoutResponse({
    statusCode: 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout',
    signResponse: false
  });
  assert(partialResponse.rawXmlString.includes('urn:oasis:names:tc:SAML:2.0:status:PartialLogout'), 'LogoutResponse supports PartialLogout status');

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


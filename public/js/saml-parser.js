/**
 * SAML 2.0 AuthnRequest Parser & Decompressor
 * Handles RFC 1951 raw deflate, Base64 decoding, XML parsing, and login_hint detection.
 */

/**
 * Decompresses raw-deflated binary bytes into string
 */
export async function decompressRawDeflate(bytes) {
  // 1. Try modern native DecompressionStream('deflate-raw')
  if (typeof DecompressionStream !== 'undefined') {
    try {
      const stream = new Response(
        new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'))
      );
      return await stream.text();
    } catch (e1) {
      try {
        const stream2 = new Response(
          new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'))
        );
        return await stream2.text();
      } catch (e2) {
        // Fall through
      }
    }
  }

  // 2. Try window.pako if available
  if (typeof window !== 'undefined' && window.pako && window.pako.inflateRaw) {
    try {
      return window.pako.inflateRaw(bytes, { to: 'string' });
    } catch (e3) {
      try {
        return window.pako.inflate(bytes, { to: 'string' });
      } catch (e4) {
        // Fall through
      }
    }
  }

  // 3. Try Node.js zlib if running in Node environment
  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    try {
      const zlibModule = await import('zlib');
      const buf = Buffer.from(bytes);
      try {
        return zlibModule.default.inflateRawSync(buf).toString('utf-8');
      } catch (z1) {
        return zlibModule.default.inflateSync(buf).toString('utf-8');
      }
    } catch (nodeErr) {
      // Fall through
    }
  }

  // 4. If raw text / uncompressed XML
  const text = new TextDecoder('utf-8').decode(bytes);
  if (text.includes('<') && text.includes('AuthnRequest')) {
    return text;
  }

  throw new Error('Failed to decompress SAMLRequest. Neither DecompressionStream nor pako could decompress payload.');
}

/**
 * Decodes and inflates a SAMLRequest query parameter
 */
export async function decodeSamlRequest(rawParam) {
  if (!rawParam) return null;

  let cleaned = rawParam.trim();
  // Handle URL decoding if needed
  try {
    if (cleaned.includes('%')) {
      cleaned = decodeURIComponent(cleaned);
    }
  } catch (e) {
    // Ignore decode error
  }

  // Decode Base64 to bytes
  let binaryString;
  try {
    binaryString = atob(cleaned);
  } catch (e) {
    // Maybe it was not base64 encoded (e.g. raw XML)
    if (cleaned.includes('<samlp:AuthnRequest') || cleaned.includes('<AuthnRequest')) {
      return cleaned;
    }
    throw new Error('SAMLRequest parameter is not a valid Base64 string.');
  }

  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  // Try raw inflate first
  try {
    const xml = await decompressRawDeflate(bytes);
    return xml;
  } catch (err) {
    // If inflate failed, maybe SP passed uncompressed Base64 XML (HTTP-POST style)
    const rawText = new TextDecoder('utf-8').decode(bytes);
    if (rawText.includes('<') && (rawText.includes('AuthnRequest') || rawText.includes('samlp:'))) {
      return rawText;
    }
    throw err;
  }
}

/**
 * Parses XML string and extracts all SAML AuthnRequest parameters
 */
export function parseAuthnRequestXml(xmlString) {
  if (!xmlString) return null;

  const parser = new DOMParser();
  const xmlDoc = parser.parseFromString(xmlString, 'application/xml');

  // Check for parser errors
  const parseError = xmlDoc.getElementsByTagName('parsererror')[0];
  if (parseError) {
    throw new Error('Invalid XML in SAMLRequest: ' + parseError.textContent);
  }

  const root = xmlDoc.documentElement;
  const isAuthnRequest = root.localName === 'AuthnRequest';

  // Extract Attributes
  const id = root.getAttribute('ID') || '';
  const version = root.getAttribute('Version') || '2.0';
  const issueInstant = root.getAttribute('IssueInstant') || '';
  const destination = root.getAttribute('Destination') || '';
  const acsUrl = root.getAttribute('AssertionConsumerServiceURL') || '';
  const protocolBinding = root.getAttribute('ProtocolBinding') || '';
  const forceAuthn = root.getAttribute('ForceAuthn') === 'true';
  const isPassive = root.getAttribute('IsPassive') === 'true';

  // Extract Issuer
  const issuerElem = xmlDoc.getElementsByTagNameNS('*', 'Issuer')[0];
  const issuer = issuerElem ? issuerElem.textContent.trim() : '';

  // Extract Subject / NameID if present
  const nameIdElem = xmlDoc.getElementsByTagNameNS('*', 'NameID')[0];
  const requestedSubject = nameIdElem ? nameIdElem.textContent.trim() : '';
  const requestedNameIdFormat = nameIdElem ? nameIdElem.getAttribute('Format') || '' : '';

  // Extract RequestedAuthnContext
  const authnContextElem = xmlDoc.getElementsByTagNameNS('*', 'AuthnContextClassRef')[0];
  const requestedAuthnContext = authnContextElem ? authnContextElem.textContent.trim() : '';

  return {
    rawXml: xmlString,
    isAuthnRequest,
    id,
    version,
    issueInstant,
    destination,
    acsUrl,
    protocolBinding,
    forceAuthn,
    isPassive,
    issuer,
    requestedSubject,
    requestedNameIdFormat,
    requestedAuthnContext
  };
}

/**
 * Parses current page URL query string for SSO parameters & login_hint
 */
export async function parseCurrentUrlParams(searchString = (typeof window !== 'undefined' && window.location ? window.location.search : '')) {
  const urlParams = new URLSearchParams(searchString);

  const samlRequestRaw = urlParams.get('SAMLRequest');
  const relayState = urlParams.get('RelayState') || '';
  const sigAlg = urlParams.get('SigAlg') || '';
  const signature = urlParams.get('Signature') || '';

  // Check login hint from URL params (supports snake_case login_hint, PascalCase LoginHint, camelCase loginHint, username, email, user)
  let matchedParam = null;
  for (const key of ['login_hint', 'LoginHint', 'loginHint', 'username', 'email', 'user']) {
    if (urlParams.get(key)) {
      matchedParam = key;
      break;
    }
  }
  const loginHint = matchedParam ? urlParams.get(matchedParam) : '';

  let parsedRequest = null;
  let parseError = null;

  if (samlRequestRaw) {
    try {
      const xml = await decodeSamlRequest(samlRequestRaw);
      parsedRequest = parseAuthnRequestXml(xml);
    } catch (err) {
      console.error('Failed to parse incoming SAMLRequest:', err);
      parseError = err.message;
    }
  }

  // Determine effective login_hint source
  let effectiveLoginHint = loginHint;
  let loginHintSource = loginHint ? `URL Parameter (?${matchedParam}=...)` : '';

  if (!effectiveLoginHint && parsedRequest && parsedRequest.requestedSubject) {
    effectiveLoginHint = parsedRequest.requestedSubject;
    loginHintSource = 'SAML AuthnRequest (<saml:Subject>)';
  }

  return {
    hasSamlRequest: !!samlRequestRaw,
    samlRequestRaw,
    relayState,
    sigAlg,
    signature,
    loginHint: effectiveLoginHint,
    loginHintSource,
    parsedRequest,
    parseError
  };
}

/**
 * XML-DSig Canonicalization & Digital Signing for SAML 2.0 assertions & responses
 * Pure Vanilla JavaScript implementation utilizing WebCrypto API.
 */

import { pemToBase64, arrayBufferToBase64 } from './crypto-keys.js';

function escapeAttr(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/"/g, '&quot;')
    .replace(/\t/g, '&#x9;')
    .replace(/\n/g, '&#xA;')
    .replace(/\r/g, '&#xD;');
}

function escapeText(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\r/g, '&#xD;');
}

/**
 * W3C Exclusive XML Canonicalization (c14n-exc)
 */
export function canonicalize(node, renderedNamespaces = {}, inclusiveNamespaces = []) {
  if (!node) return '';

  // Text node
  if (node.nodeType === 3) {
    return escapeText(node.nodeValue);
  }

  // CDATA section
  if (node.nodeType === 4) {
    return escapeText(node.nodeValue);
  }

  // Comment node - strip comments
  if (node.nodeType === 8) {
    return '';
  }

  // Element node
  if (node.nodeType === 1) {
    let result = '<' + node.tagName;

    const localNamespaces = {};
    const attrs = [];

    // Separate namespace declarations and regular attributes
    if (node.attributes) {
      for (let i = 0; i < node.attributes.length; i++) {
        const attr = node.attributes[i];
        if (attr.name === 'xmlns') {
          localNamespaces[''] = attr.value;
        } else if (attr.name.startsWith('xmlns:')) {
          const prefix = attr.name.substring(6);
          localNamespaces[prefix] = attr.value;
        } else {
          attrs.push(attr);
        }
      }
    }

    const currentRendered = { ...renderedNamespaces };
    const nsToRender = [];

    // Determine element prefix and namespace
    const elemPrefix = node.tagName.includes(':') ? node.tagName.split(':')[0] : '';
    
    // Check if element prefix namespace needs to be rendered
    if (elemPrefix === '') {
      if (localNamespaces[''] !== undefined && localNamespaces[''] !== renderedNamespaces['']) {
        nsToRender.push({ name: 'xmlns', value: localNamespaces[''], prefix: '' });
        currentRendered[''] = localNamespaces[''];
      }
    } else {
      const nsVal = localNamespaces[elemPrefix] || renderedNamespaces[elemPrefix];
      if (nsVal !== undefined && renderedNamespaces[elemPrefix] !== nsVal) {
        nsToRender.push({ name: 'xmlns:' + elemPrefix, value: nsVal, prefix: elemPrefix });
        currentRendered[elemPrefix] = nsVal;
      }
    }

    // Check attribute prefixes
    for (const attr of attrs) {
      if (attr.name.includes(':')) {
        const p = attr.name.split(':')[0];
        if (p !== 'xml') {
          const nsVal = localNamespaces[p] || renderedNamespaces[p];
          if (nsVal !== undefined && currentRendered[p] !== nsVal) {
            nsToRender.push({ name: 'xmlns:' + p, value: nsVal, prefix: p });
            currentRendered[p] = nsVal;
          }
        }
      }
    }

    // Check inclusive / declared local namespaces on this element
    for (const [p, uri] of Object.entries(localNamespaces)) {
      if (!nsToRender.some(n => n.prefix === p) && currentRendered[p] !== uri) {
        nsToRender.push({ name: p === '' ? 'xmlns' : 'xmlns:' + p, value: uri, prefix: p });
        currentRendered[p] = uri;
      }
    }

    // Sort namespaces: default xmlns first, then lexicographically by prefix
    nsToRender.sort((a, b) => {
      if (a.prefix === '' && b.prefix !== '') return -1;
      if (a.prefix !== '' && b.prefix === '') return 1;
      return a.prefix.localeCompare(b.prefix);
    });

    for (const ns of nsToRender) {
      result += ' ' + ns.name + '="' + escapeAttr(ns.value) + '"';
    }

    // Sort attributes: unprefixed first, then by namespace URI / prefix, then by local name
    attrs.sort((a, b) => {
      const aPrefix = a.name.includes(':') ? a.name.split(':')[0] : '';
      const bPrefix = b.name.includes(':') ? b.name.split(':')[0] : '';
      if (aPrefix === '' && bPrefix !== '') return -1;
      if (aPrefix !== '' && bPrefix === '') return 1;
      return a.name.localeCompare(b.name);
    });

    for (const attr of attrs) {
      result += ' ' + attr.name + '="' + escapeAttr(attr.value) + '"';
    }

    result += '>';

    // Recursively process child nodes
    for (let i = 0; i < node.childNodes.length; i++) {
      result += canonicalize(node.childNodes[i], currentRendered, inclusiveNamespaces);
    }

    result += '</' + node.tagName + '>';
    return result;
  }

  // Document node
  if (node.nodeType === 9) {
    return canonicalize(node.documentElement, renderedNamespaces, inclusiveNamespaces);
  }

  return '';
}

/**
 * Computes SHA-256 digest of canonicalized XML string
 */
export async function computeXmlDigest(canonicalXml) {
  const encoder = new TextEncoder();
  const data = encoder.encode(canonicalXml);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  return arrayBufferToBase64(hashBuffer);
}

/**
 * Signs a target XML element (Assertion or Response) and inserts standard <ds:Signature>
 */
export async function signXmlElement({
  xmlDoc,
  targetElement,
  targetId,
  privateKey,
  certPem,
  insertLocation = 'afterIssuer'
}) {
  const certB64 = pemToBase64(certPem);

  // 1. Remove any existing ds:Signature inside targetElement to prepare for clean canonicalization
  const existingSig = targetElement.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Signature')[0]
    || targetElement.querySelector('Signature');
  if (existingSig && existingSig.parentNode === targetElement) {
    targetElement.removeChild(existingSig);
  }

  // 2. Canonicalize target element to calculate DigestValue
  const canonicalTarget = canonicalize(targetElement);
  const digestValue = await computeXmlDigest(canonicalTarget);

  // 3. Construct SignedInfo XML
  const signedInfoXml = `<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#${targetId}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>${digestValue}</ds:DigestValue></ds:Reference></ds:SignedInfo>`;

  const signedInfoDoc = new DOMParser().parseFromString(signedInfoXml, 'application/xml');
  const signedInfoElem = signedInfoDoc.documentElement;
  const canonicalSignedInfo = canonicalize(signedInfoElem);

  // 4. Sign the canonical SignedInfo with RSA private key
  const encoder = new TextEncoder();
  const signatureBuffer = await window.crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    encoder.encode(canonicalSignedInfo)
  );
  const signatureValue = arrayBufferToBase64(signatureBuffer);

  // 5. Construct full <ds:Signature> XML element
  const signatureXml = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#${targetId}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>${digestValue}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>${signatureValue}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${certB64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>`;

  const parsedSig = new DOMParser().parseFromString(signatureXml, 'application/xml').documentElement;
  const importedSig = xmlDoc.importNode(parsedSig, true);

  // 6. Insert Signature in schema-compliant location
  if (insertLocation === 'afterIssuer') {
    const issuer = targetElement.getElementsByTagNameNS('*', 'Issuer')[0];
    if (issuer && issuer.nextSibling) {
      targetElement.insertBefore(importedSig, issuer.nextSibling);
    } else {
      targetElement.appendChild(importedSig);
    }
  } else {
    targetElement.appendChild(importedSig);
  }

  return importedSig;
}

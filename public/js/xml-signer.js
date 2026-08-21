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
 * Returns a map of all in-scope namespace prefix -> URI bindings for a given DOM element node.
 */
export function getInScopeNamespaces(node) {
  const inScope = {};
  const chain = [];
  let curr = node;
  while (curr && curr.nodeType === 1) { // ELEMENT_NODE
    chain.unshift(curr);
    curr = curr.parentNode;
  }
  for (const elem of chain) {
    if (elem.attributes) {
      for (let i = 0; i < elem.attributes.length; i++) {
        const attr = elem.attributes[i];
        if (attr.name === 'xmlns') {
          inScope[''] = attr.value;
        } else if (attr.name.startsWith('xmlns:')) {
          inScope[attr.name.substring(6)] = attr.value;
        }
      }
    }
  }
  return inScope;
}

/**
 * W3C Exclusive XML Canonicalization (c14n-exc)
 * Specification: http://www.w3.org/2001/10/xml-exc-c14n#
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

    const inScope = getInScopeNamespaces(node);
    const visiblyUtilized = new Set();
    const regularAttrs = [];

    // 1. Identify element tag prefix
    const elemPrefix = node.tagName.includes(':') ? node.tagName.split(':')[0] : '';
    visiblyUtilized.add(elemPrefix);

    // 2. Identify regular attributes and their prefixes
    if (node.attributes) {
      for (let i = 0; i < node.attributes.length; i++) {
        const attr = node.attributes[i];
        if (attr.name === 'xmlns' || attr.name.startsWith('xmlns:')) {
          continue;
        }
        regularAttrs.push(attr);
        if (attr.name.includes(':')) {
          const attrPrefix = attr.name.split(':')[0];
          if (attrPrefix !== 'xml') {
            visiblyUtilized.add(attrPrefix);
          }
        }
      }
    }

    // 3. Inclusive namespaces prefix list (if specified)
    if (Array.isArray(inclusiveNamespaces)) {
      for (const p of inclusiveNamespaces) {
        visiblyUtilized.add(p === '#default' ? '' : p);
      }
    }

    const currentRendered = { ...renderedNamespaces };
    const nsToRender = [];

    // 4. Render only visibly utilized namespaces that have not been rendered with same URI in ancestor scope
    for (const p of visiblyUtilized) {
      const uri = inScope[p] !== undefined
        ? inScope[p]
        : (node.lookupNamespaceURI ? (p === '' ? (node.lookupNamespaceURI(null) || '') : (node.lookupNamespaceURI(p) || '')) : '');

      if (p === '') {
        // Default namespace
        if (uri && currentRendered[''] !== uri) {
          nsToRender.push({ name: 'xmlns', prefix: '', value: uri });
          currentRendered[''] = uri;
        } else if (!uri && currentRendered['']) {
          nsToRender.push({ name: 'xmlns', prefix: '', value: '' });
          currentRendered[''] = '';
        }
      } else {
        // Prefixed namespace
        if (uri && currentRendered[p] !== uri) {
          nsToRender.push({ name: 'xmlns:' + p, prefix: p, value: uri });
          currentRendered[p] = uri;
        }
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

    // Sort regular attributes: unprefixed first, then by namespace URI, then by local name
    regularAttrs.sort((a, b) => {
      const aHasPrefix = a.name.includes(':');
      const bHasPrefix = b.name.includes(':');
      if (!aHasPrefix && bHasPrefix) return -1;
      if (aHasPrefix && !bHasPrefix) return 1;
      if (!aHasPrefix && !bHasPrefix) {
        return a.name.localeCompare(b.name);
      }
      const aPrefix = a.name.split(':')[0];
      const bPrefix = b.name.split(':')[0];
      const aLocal = a.name.split(':')[1];
      const bLocal = b.name.split(':')[1];
      const aNs = inScope[aPrefix] || '';
      const bNs = inScope[bPrefix] || '';
      if (aNs !== bNs) {
        return aNs.localeCompare(bNs);
      }
      return aLocal.localeCompare(bLocal);
    });

    for (const attr of regularAttrs) {
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
  const cryptoObj = (typeof window !== 'undefined' && window.crypto) ? window.crypto : globalThis.crypto;
  const hashBuffer = await cryptoObj.subtle.digest('SHA-256', data);
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

  // 1. Remove any existing ds:Signature directly inside targetElement to prepare for clean canonicalization
  const existingSigs = [];
  for (let i = 0; i < targetElement.childNodes.length; i++) {
    const child = targetElement.childNodes[i];
    if (child.nodeType === 1 && (child.localName === 'Signature' || child.tagName === 'ds:Signature' || child.tagName === 'Signature')) {
      existingSigs.push(child);
    }
  }
  for (const sig of existingSigs) {
    targetElement.removeChild(sig);
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
  const cryptoObj = (typeof window !== 'undefined' && window.crypto) ? window.crypto : globalThis.crypto;
  const signatureBuffer = await cryptoObj.subtle.sign(
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
    let issuer = null;
    for (let i = 0; i < targetElement.childNodes.length; i++) {
      const child = targetElement.childNodes[i];
      if (child.nodeType === 1 && (child.localName === 'Issuer' || child.tagName.endsWith(':Issuer') || child.tagName === 'Issuer')) {
        issuer = child;
        break;
      }
    }
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


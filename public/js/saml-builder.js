/**
 * SAML 2.0 XML Response and Assertion Builder
 * Constructs schema-compliant SAML 2.0 responses with arbitrary attributes,
 * session validity windows, W3C DBSC advice extensions, and XMLDSig signatures.
 */

import { signXmlElement } from './xml-signer.js';

export function generateId(prefix = '_idp_') {
  const chars = '0123456789abcdef';
  let rand = '';
  for (let i = 0; i < 32; i++) {
    rand += chars[Math.floor(Math.random() * chars.length)];
  }
  return `${prefix}${rand}`;
}

export function toIsoUtcString(date = new Date()) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Builds and signs a SAML 2.0 Response XML Document
 */
export async function buildSamlResponse({
  // Endpoints & IDs
  acsUrl = 'https://sp.example.com/saml/acs',
  spEntityId = 'https://sp.example.com/saml/metadata',
  idpEntityId = 'https://fake-saml-idp.pages.dev/saml/idp',
  inResponseTo = '',
  statusCode = 'urn:oasis:names:tc:SAML:2.0:status:Success',
  statusMessage = '',

  // User Subject / NameID
  nameId = 'user@example.com',
  nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',

  // Session & Timestamps
  authnInstant = new Date(),
  sessionIndex = generateId('_session_'),
  validityMinutes = 60,
  authnContextClassRef = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',

  // Attributes: Array of { name, nameFormat, values: string[] }
  attributes = [],

  // DBSC (Device Bound Session Credentials) & Advice
  dbscEnabled = false,
  dbscKeys = [], // Array of { digest, digestAlg }
  dbscCertificates = [], // Array of { fingerprint, fingerprintAlg }
  customAdviceXml = '', // Raw custom XML inside <saml:Advice>

  // Raw Custom XML statements to append to Assertion
  customStatementsXml = '',

  // Signing configuration
  signAssertion = true,
  signResponse = false,
  privateKey = null,
  certPem = ''
}) {
  const now = new Date();
  const issueInstant = toIsoUtcString(now);

  const notBeforeDate = new Date(now.getTime() - 2 * 60 * 1000); // 2 minutes in past to allow clock skew
  const notBefore = toIsoUtcString(notBeforeDate);

  const notOnOrAfterDate = new Date(now.getTime() + validityMinutes * 60 * 1000);
  const notOnOrAfter = toIsoUtcString(notOnOrAfterDate);

  const responseId = generateId('_resp_');
  const assertionId = generateId('_asrt_');

  // Build AttributeStatement XML
  let attributeStatementXml = '';
  if (attributes && attributes.length > 0) {
    attributeStatementXml += '<saml:AttributeStatement>';
    for (const attr of attributes) {
      if (!attr.name) continue;
      const formatAttr = attr.nameFormat ? ` NameFormat="${attr.nameFormat}"` : ' NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic"';
      const friendlyAttr = attr.friendlyName ? ` FriendlyName="${attr.friendlyName}"` : '';
      attributeStatementXml += `<saml:Attribute Name="${attr.name}"${formatAttr}${friendlyAttr}>`;
      
      const values = Array.isArray(attr.values) ? attr.values : [attr.values];
      for (const val of values) {
        if (val !== undefined && val !== null) {
          attributeStatementXml += `<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">${escapeXml(String(val))}</saml:AttributeValue>`;
        }
      }
      attributeStatementXml += '</saml:Attribute>';
    }
    attributeStatementXml += '</saml:AttributeStatement>';
  }

  // Build Advice XML (including W3C DBSC Device Bound Session Credentials)
  let adviceXml = '';
  const hasDbscKeys = dbscEnabled && dbscKeys && dbscKeys.length > 0;
  const hasDbscCerts = dbscEnabled && dbscCertificates && dbscCertificates.length > 0;
  const hasCustomAdvice = !!customAdviceXml.trim();

  if (hasDbscKeys || hasDbscCerts || hasCustomAdvice) {
    adviceXml += '<saml:Advice>';
    
    if (hasDbscKeys) {
      for (const key of dbscKeys) {
        if (key.digest) {
          const alg = key.digestAlg || 'SHA-256';
          adviceXml += `<dbsc:TrustedKey xmlns:dbsc="https://www.w3.org/ns/dbsc/saml" digest="${escapeXml(key.digest)}" digest_alg="${escapeXml(alg)}"/>`;
        }
      }
    }

    if (hasDbscCerts) {
      for (const cert of dbscCertificates) {
        if (cert.fingerprint) {
          const alg = cert.fingerprintAlg || 'SHA-256';
          adviceXml += `<dbsc:TrustedCertificate xmlns:dbsc="https://www.w3.org/ns/dbsc/saml" fingerprint="${escapeXml(cert.fingerprint)}" fingerprint_alg="${escapeXml(alg)}"/>`;
        }
      }
    }

    if (hasCustomAdvice) {
      adviceXml += customAdviceXml.trim();
    }

    adviceXml += '</saml:Advice>';
  }

  // Build SubjectConfirmationData attributes
  let subjectConfirmationDataAttrs = `NotOnOrAfter="${notOnOrAfter}"`;
  if (acsUrl) {
    subjectConfirmationDataAttrs += ` Recipient="${escapeXml(acsUrl)}"`;
  }
  if (inResponseTo) {
    subjectConfirmationDataAttrs += ` InResponseTo="${escapeXml(inResponseTo)}"`;
  }

  // Build InResponseTo attribute for Response if present
  const inResponseToAttr = inResponseTo ? ` InResponseTo="${escapeXml(inResponseTo)}"` : '';
  const destinationAttr = acsUrl ? ` Destination="${escapeXml(acsUrl)}"` : '';

  // Status XML
  let statusXml = `<samlp:Status><samlp:StatusCode Value="${statusCode}"/>`;
  if (statusMessage) {
    statusXml += `<samlp:StatusMessage>${escapeXml(statusMessage)}</samlp:StatusMessage>`;
  }
  statusXml += '</samlp:Status>';

  // Construct complete SAML Response XML template
  const rawXml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="${responseId}"
                Version="2.0"
                IssueInstant="${issueInstant}"${destinationAttr}${inResponseToAttr}>
  <saml:Issuer>${escapeXml(idpEntityId)}</saml:Issuer>
  ${statusXml}
  <saml:Assertion ID="${assertionId}"
                  Version="2.0"
                  IssueInstant="${issueInstant}">
    <saml:Issuer>${escapeXml(idpEntityId)}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="${nameIdFormat}">${escapeXml(nameId)}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData ${subjectConfirmationDataAttrs}/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}">
      <saml:AudienceRestriction>
        <saml:Audience>${escapeXml(spEntityId)}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="${toIsoUtcString(authnInstant)}"
                         SessionIndex="${sessionIndex}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>${authnContextClassRef}</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    ${adviceXml}
    ${attributeStatementXml}
    ${customStatementsXml}
  </saml:Assertion>
</samlp:Response>`;

  // Parse into DOM for signing and final validation
  const xmlDoc = new DOMParser().parseFromString(rawXml, 'application/xml');
  const parseError = xmlDoc.getElementsByTagName('parsererror')[0];
  if (parseError) {
    throw new Error('Failed to construct valid XML: ' + parseError.textContent);
  }

  // Digital Signing
  if (privateKey && certPem) {
    const assertionElem = xmlDoc.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Assertion')[0]
      || xmlDoc.querySelector('Assertion');

    const responseElem = xmlDoc.documentElement;

    if (signAssertion && assertionElem) {
      await signXmlElement({
        xmlDoc,
        targetElement: assertionElem,
        targetId: assertionId,
        privateKey,
        certPem,
        insertLocation: 'afterIssuer'
      });
    }

    if (signResponse && responseElem) {
      await signXmlElement({
        xmlDoc,
        targetElement: responseElem,
        targetId: responseId,
        privateKey,
        certPem,
        insertLocation: 'afterIssuer'
      });
    }
  }

  const finalXmlString = new XMLSerializer().serializeToString(xmlDoc);
  const base64Response = btoa(unescape(encodeURIComponent(finalXmlString)));

  return {
    xmlDoc,
    xmlString: formatXml(finalXmlString),
    rawXmlString: finalXmlString,
    base64Response,
    responseId,
    assertionId,
    inResponseTo,
    acsUrl
  };
}

function escapeXml(str) {
  if (typeof str !== 'string') return String(str || '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Basic XML pretty-printer for display in code viewers
 */
export function formatXml(xml, indent = '  ') {
  let formatted = '';
  let pad = 0;

  // Split by tags
  const tokens = xml.replace(/(>)(<)(\/*)/g, '$1\r\n$2$3').split('\r\n');

  for (let i = 0; i < tokens.length; i++) {
    let node = tokens[i].trim();
    if (!node) continue;

    if (node.match(/^<\/\w/)) {
      // Closing tag: decrease indent
      pad = Math.max(pad - 1, 0);
    }

    formatted += indent.repeat(pad) + node + '\n';

    if (node.match(/^<\w[^>]*[^\/]>.*$/) && !node.match(/<\/\w[^>]*>$/) && !node.startsWith('<?xml')) {
      // Opening tag: increase indent
      pad++;
    }
  }

  return formatted.trim();
}

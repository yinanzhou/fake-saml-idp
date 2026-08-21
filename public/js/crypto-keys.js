/**
 * Cryptographic Keys & WebCrypto Utilities for Fake SAML IdP
 */

export const DEFAULT_KEY_PAIR = {
  certPem: `-----BEGIN CERTIFICATE-----
MIIDjDCCAnQCCQDyOn/FzemXfjANBgkqhkiG9w0BAQsFADCBhzELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28x
FjAUBgNVBAoMDUZha2UgU0FNTCBJZFAxETAPBgNVBAsMCElkZW50aXR5MSAwHgYD
VQQDDBdmYWtlLXNhbWwtaWRwLnBhZ2VzLmRldjAeFw0yNjA4MjEwMTU2MDFaFw00
NjA4MTYwMTU2MDFaMIGHMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5p
YTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEWMBQGA1UECgwNRmFrZSBTQU1MIElk
UDERMA8GA1UECwwISWRlbnRpdHkxIDAeBgNVBAMMF2Zha2Utc2FtbC1pZHAucGFn
ZXMuZGV2MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnYfxudQ/x32l
9Cg6ojExwgPIHjDnAPxuB52S+7+nPxmVYkYsOdQvigGBL175ifCI5AuR7vHA89nD
jMrxa4a5zeucjsXk6VEnptISHZ+GI9VPcoihK7P2vcHReNuyWy6njB3lHtNyFXxo
+NwvSHuHj3Fl4Gr3fP8nmOqwBrCv3i/7y58pu+6OqCOshFMPzPL/oCBJ78ry6vbI
EmV9rQukv/pAroHbi04nDv/dCpGsjJEAsM4JMJfR9oeW162TVnNGinIHTw5iUPMf
muAuLh+hT+yFruAbar+y0VuCxhti0KZzZdSt7iDiCXSHF6M+xPPccst9YcuanQJ/
lSE5SS+kEQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBiyt/w6CABDp0XAj+r7gjh
+tRqTnvmFS5Kaffacg1EpkzV+GF9so1MuypaamO6SRh6H0XID8N2jdBd2Ld6Avqw
gHmKBDFxq229rzNDQ56pXuBrjTCKIukq5FtXrGgKVICd0Gexh22lYmzzKz7hU6Wd
JuTqcd4KpKSd/0HfJeorIAwFLmkC4nxFE1/23OGDZpOUUB9cuLM9VyuOnoEA8IDF
NAe/teJDNT085NCwq1NHEqyL4gUP92MxyfdMVXiUoYoPNtjIfhYmeL1kthsB17Gz
F287WszF5/vgixixz+FIoDGM1W8uXqP1tEJFke5Mrm4TxweGDwFVtTYUAYTfPVWH
-----END CERTIFICATE-----`,

  privateKeyPkcs8Pem: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCdh/G51D/HfaX0
KDqiMTHCA8geMOcA/G4HnZL7v6c/GZViRiw51C+KAYEvXvmJ8IjkC5Hu8cDz2cOM
yvFrhrnN65yOxeTpUSem0hIdn4Yj1U9yiKErs/a9wdF427JbLqeMHeUe03IVfGj4
3C9Ie4ePcWXgavd8/yeY6rAGsK/eL/vLnym77o6oI6yEUw/M8v+gIEnvyvLq9sgS
ZX2tC6S/+kCugduLTicO/90KkayMkQCwzgkwl9H2h5bXrZNWc0aKcgdPDmJQ8x+a
4C4uH6FP7IWu4Btqv7LRW4LGG2LQpnNl1K3uIOIJdIcXoz7E89xyy31hy5qdAn+V
ITlJL6QRAgMBAAECggEAFALB1Q4+L9QpMZOupw3CuVeLozIpFfn67CK7GhmlYCGa
1Un+sjXe+BPq2h6hakFQ0k8Z8ZVqIk/GRGs/MZ6CmcLVN1myE2VIuSs0O+kYvBKL
rgvnFUseC8rEFisqQ+TwSZ8+jKTleA8+smYd54IxnSoVe+V6nLk4yXb+d0sYfAu/
Vcb56DeajQDJPBTnLhKX/K8yZGEMpic/Y59oej5k6E/fBLHxDqRZTSSJ6Fhad2Ed
1EQWvqPMtRMRF7jlbzOnMPvwfAdypo9bRPE6ni3GzYG/ZM9XN3qKvMd5Xv2ZcvIF
qGaprDRkUPlJoSXKJMavR3ndLNJDgkzEZau/DduMBQKBgQDK7vjLCXstAF+e8Jq7
8iCAUOnKZSvE7/9mHL118O448bqpBoTtePp0f7uKV+3SGWIMfms1DoO54N2jU6il
cFm93MXJM9mrmcGzuNNIHEOWHA1dUXo/kvDGOzt58mXMrlUTZ277v37pvHz55EbW
Gc8DmGKaSLiQQvP/38kdXxhEqwKBgQDGuZWe1lI1YueQFlhQz6qsWckVrgCY3RxM
MSpRbKDQfh5m9dmivrvh/jCUWq9UQwpihMzy/AXoRWVfNhjht/CvUACEGJA84YGA
alKILNi5JqHIQGh4xQbqJbGieWUww0iXq5s7Fq0GMFHJVfFTZwFrpv10Z6jo0O44
SqpYUjHiMwKBgB1fhadt0eRrn2uUC/GUVFv+WjiveCxjSKZxFoNRwkl/w7LffLIa
xrXCH1Ug8Q1uGyEP01i0pyBqieowG8MGhhbTM9WxqZoLAVyQLhTL8oRxvwV426cE
D9HBlRRLn6yGt029tPS/fRE79SL+hbpLtgkhL3SBfiVza3nn3GZh81NNAoGAMlam
YOLXVjCkiaovWuEP0bK4riYyfoZb+azmlFOY9NdNqjUSmRgJjbiO47WI/iYxRj1v
kQloEasqf5C7gsnOTQpN5yg1uUZCQJ4uI9KAX346svglvpniI4PC2G45xL1i8RCG
NNSMpamtvftoMwE/qd5WC5uKfNcX0OiQ9+hyPGMCgYEAsEQnBc5xwig2iCffDi8r
7W1oaW1edNZ+waR7I79b3fAxDGz9j/T/uex8EoDaR3xcIzp9rOmsRZa5Jsc23JuD
G0XKqZOQe4Wh5UoC8ZiQ2onl+KYBFTqR4at4Psb8ds5m9KjFU9rQ9q60vDkTNi1R
j/r0HL9nTi/dTPRm7wKfBes=
-----END PRIVATE KEY-----`,

  fingerprintSha256: 'CD:69:12:BD:FF:45:F1:2C:22:B9:00:A9:56:DF:12:49:25:33:F5:64:12:F9:A6:0E:85:4D:67:7D:58:F0:7C:57'
};

/**
 * Extracts raw Base64 from a PEM string
 */
export function pemToBase64(pem) {
  if (!pem) return '';
  return pem
    .replace(/-----[^\n]+-----/g, '')
    .replace(/\s+/g, '');
}

/**
 * Converts PEM string to ArrayBuffer for WebCrypto
 */
export function pemToArrayBuffer(pem) {
  const b64 = pemToBase64(pem);
  const binaryString = atob(b64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Converts ArrayBuffer to Base64
 */
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Formats Base64 string into PEM with line breaks
 */
export function base64ToPem(b64, type = 'CERTIFICATE') {
  const formatted = b64.match(/.{1,64}/g)?.join('\n') || b64;
  return `-----BEGIN ${type}-----\n${formatted}\n-----END ${type}-----`;
}

/**
 * Imports PKCS#8 RSA Private Key for WebCrypto signing
 */
export async function importPrivateKey(pkcs8Pem) {
  try {
    const keyData = pemToArrayBuffer(pkcs8Pem);
    return await window.crypto.subtle.importKey(
      'pkcs8',
      keyData,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      },
      true,
      ['sign']
    );
  } catch (err) {
    console.error('Failed to import PKCS#8 private key:', err);
    throw new Error('Invalid PKCS#8 Private Key format. Please ensure it is an unencrypted PKCS#8 RSA key.');
  }
}

/**
 * Calculates SHA-256 fingerprint for an X.509 certificate
 */
export async function computeCertFingerprint(certPem) {
  try {
    const certBuffer = pemToArrayBuffer(certPem);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', certBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
  } catch (err) {
    console.error('Failed to compute cert fingerprint:', err);
    return '';
  }
}

/**
 * Simple ASN.1 DER encoder helpers to construct self-signed X.509 certificates in browser
 */
function asn1Length(len) {
  if (len < 128) return [len];
  const bytes = [];
  let temp = len;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

function asn1Sequence(items) {
  const content = items.flat();
  return [0x30, ...asn1Length(content.length), ...content];
}

function asn1Integer(numOrBytes) {
  if (typeof numOrBytes === 'number') {
    return [0x02, 0x01, numOrBytes];
  }
  let bytes = Array.from(numOrBytes);
  if (bytes[0] & 0x80) bytes.unshift(0); // Ensure positive
  return [0x02, ...asn1Length(bytes.length), ...bytes];
}

function asn1BitString(bytes) {
  const content = [0x00, ...bytes];
  return [0x03, ...asn1Length(content.length), ...content];
}

function asn1OctetString(bytes) {
  return [0x04, ...asn1Length(bytes.length), ...bytes];
}

function asn1ObjectIdentifier(oidStr) {
  const parts = oidStr.split('.').map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i];
    const subBytes = [];
    subBytes.push(val & 0x7f);
    while ((val >>= 7) > 0) {
      subBytes.unshift((val & 0x7f) | 0x80);
    }
    bytes.push(...subBytes);
  }
  return [0x06, ...asn1Length(bytes.length), ...bytes];
}

function asn1PrintableString(str) {
  const bytes = Array.from(new TextEncoder().encode(str));
  return [0x13, ...asn1Length(bytes.length), ...bytes];
}

function asn1Utf8String(str) {
  const bytes = Array.from(new TextEncoder().encode(str));
  return [0x0c, ...asn1Length(bytes.length), ...bytes];
}

function asn1UTCTime(date) {
  const pad = n => String(n).padStart(2, '0');
  const str = `${pad(date.getUTCFullYear() % 100)}${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
  const bytes = Array.from(new TextEncoder().encode(str));
  return [0x17, ...asn1Length(bytes.length), ...bytes];
}

/**
 * Generates a new 2048-bit RSA keypair & self-signed X.509 certificate in browser using WebCrypto
 */
export async function generateNewKeypair(commonName = 'fake-saml-idp.pages.dev', validityYears = 10) {
  // 1. Generate RSA keypair
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );

  // 2. Export PKCS#8 private key
  const pkcs8Buf = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const privateKeyPem = base64ToPem(arrayBufferToBase64(pkcs8Buf), 'PRIVATE KEY');

  // 3. Export SPKI public key
  const spkiBuf = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
  const spkiBytes = new Uint8Array(spkiBuf);

  // 4. Construct TBSCertificate (To-Be-Signed Certificate)
  const serialNumber = new Uint8Array(8);
  window.crypto.getRandomValues(serialNumber);

  const sha256WithRSAEncryption = asn1Sequence([
    asn1ObjectIdentifier('1.2.840.113549.1.1.11'), // sha256WithRSAEncryption
    [0x05, 0x00] // NULL
  ]);

  const issuerSubject = asn1Sequence([
    // CN
    asn1Sequence([
      asn1Sequence([
        asn1ObjectIdentifier('2.5.4.3'), // commonName
        asn1Utf8String(commonName)
      ])
    ]),
    // O
    asn1Sequence([
      asn1Sequence([
        asn1ObjectIdentifier('2.5.4.10'), // organizationName
        asn1Utf8String('Fake SAML IdP')
      ])
    ])
  ]);

  const notBefore = new Date();
  const notAfter = new Date();
  notAfter.setFullYear(notBefore.getFullYear() + validityYears);

  const validity = asn1Sequence([
    asn1UTCTime(notBefore),
    asn1UTCTime(notAfter)
  ]);

  const tbsCertificate = asn1Sequence([
    [0xa0, 0x03, 0x02, 0x01, 0x02], // v3 ([0] EXPLICIT INTEGER 2)
    asn1Integer(serialNumber),
    sha256WithRSAEncryption,
    issuerSubject,
    validity,
    issuerSubject,
    Array.from(spkiBytes) // SubjectPublicKeyInfo
  ]);

  // 5. Sign TBSCertificate with private key
  const tbsBuffer = new Uint8Array(tbsCertificate).buffer;
  const signatureBuffer = await window.crypto.subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, tbsBuffer);
  const signatureBytes = new Uint8Array(signatureBuffer);

  // 6. Complete X.509 Certificate DER
  const certDer = asn1Sequence([
    tbsCertificate,
    sha256WithRSAEncryption,
    asn1BitString(signatureBytes)
  ]);

  const certPem = base64ToPem(arrayBufferToBase64(new Uint8Array(certDer).buffer), 'CERTIFICATE');
  const fingerprint = await computeCertFingerprint(certPem);

  return {
    privateKeyPkcs8Pem: privateKeyPem,
    certPem: certPem,
    fingerprintSha256: fingerprint
  };
}

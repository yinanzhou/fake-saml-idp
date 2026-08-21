# AI Agent & Developer Architecture Guide

This document provides architectural context, design constraints, and developer conventions for AI agents and human contributors extending the **Fake SAML 2.0 Identity Provider (IdP)** codebase.

## 1. Core Architecture & Constraints

- **100% Client-Side / Zero Backend**:
  - The application runs entirely in the user's browser without Node.js, server runtimes, or database dependencies.
  - All cryptography (RSA key generation, X.509 cert formatting, SHA-256 digests, and XML digital signatures) is executed via the native browser **WebCrypto API** (`crypto.subtle`).
  - Served directly from static hosts (Cloudflare Pages, GitHub Pages, Nginx, or local python server).

- **No Build Step / Pure Vanilla ES6**:
  - Do **NOT** introduce bundlers (Webpack, Vite, Rollup), transpilers (Babel), or UI frameworks (React, Vue) unless explicitly instructed.
  - All client code consists of standard ES6 modules loaded with `<script type="module" src="js/app.js">`.

## 2. Directory & File Map

```
.
├── AGENTS.md               # 🤖 AI Agent entry point & architectural context
├── README.md               # 📖 User documentation & deployment guide
├── package.json            # 📦 Test scripts and project metadata
├── .github/
│   └── workflows/test.yml  # ⚙️ GitHub Actions CI test pipeline (Node 20/22/24)
├── tests/
│   └── verify.js           # 🧪 Automated verification test suite (Node test runner)
└── public/                 # 🌐 Web root / Served assets
    ├── index.html          # Main single-page application & SP configuration hub
    ├── 404.html            # 404 handler
    ├── _headers            # Security (HSTS, CSP) & CORS headers
    ├── idp-cert.pem        # Static default X.509 certificate for SP upload
    ├── idp-metadata.xml    # SAML 2.0 EntityDescriptor metadata
    ├── css/
    │   └── style.css       # Clean, functional stylesheet (light/dark theme variables)
    └── js/
        ├── app.js          # App lifecycle, DOM events, UI state manager
        ├── saml-parser.js  # RFC 1951 deflate decompressor, AuthnRequest XML parser
        ├── saml-builder.js # Schema-compliant SAML 2.0 Response/Assertion builder
        ├── xml-signer.js   # W3C Exclusive Canonicalization (c14n-exc) & XMLDSig signer
        ├── crypto-keys.js  # WebCrypto RSA key management, PEM & X.509 cert parser
        └── presets.js      # Built-in test personas (Default, Google, DBSC, Azure AD, AWS)
```

## 3. Key Subsystems & Extension Guidelines

### A. SAML 2.0 Response & DBSC XML Generation (`public/js/saml-builder.js`)
- **Assertion Envelope & Signature Location**:
  - The XML digital signature (`<ds:Signature>`) MUST directly follow the `<saml:Issuer>` element according to SAML 2.0 core specifications (`saml-core-2.0-os`).
- **W3C DBSC SAML Extension Schema**:
  - Namespace: `xmlns:dbsc="https://www.w3.org/ns/dbsc/saml"` ([W3C Schema](https://www.w3.org/ns/dbsc/saml/dbsc-saml.xsd)).
  - Supported elements:
    - `<dbsc:TrustedKey digest="..." digest_alg="SHA-256|SHA-384|SHA-512"/>`
    - `<dbsc:TrustedCertificate fingerprint="..." fingerprint_alg="SHA-256|SHA-384|SHA-512"/>`
  - Placed inside `<saml:Advice>` directly following `<saml:AuthnStatement>` / `<saml:AttributeStatement>`.

### B. Canonicalization & XMLDSig Signing (`public/js/xml-signer.js`)
- **Exclusive XML Canonicalization (`c14n-exc`)**:
  - Implements `http://www.w3.org/2001/10/xml-exc-c14n#`.
  - Sorts namespaces lexicographically (unprefixed `xmlns` first, followed by prefixed declarations).
  - Sorts attributes lexicographically (unprefixed first, then by prefix/name).
  - Supports signing both `<saml:Assertion>` (default standard) and the enclosing `<samlp:Response>`.

### C. SAML AuthnRequest Decompression (`public/js/saml-parser.js`)
- **RFC 1951 Deflate Decoding**:
  - Browser environments use the native `DecompressionStream('deflate-raw')` with fallback to `DecompressionStream('deflate')`.
  - Automated tests running in Node.js fallback gracefully to `zlib.inflateRawSync`.
- **`login_hint` Extraction**:
  - Extracts subject identity from query parameters (`?login_hint=...`, `?username=...`, `?email=...`) or from incoming `<saml:Subject><saml:NameID>` in the `AuthnRequest`.

### D. Presets & Smart SP Detection (`public/js/presets.js` & `public/js/app.js`)
- **Smart Preset Detection**:
  - `detectSmartPreset(spEntityId, acsUrl, searchString)` inspects incoming SP issuer domains/patterns to automatically select matching presets (AWS IAM, Microsoft Entra ID, Google Workspace, DBSC).
- **Request Context Preservation**:
  - `applyPreset` MUST preserve request parameters (`inResponseTo`, `relayState`, `acsUrl`, `spEntityId`) and active user identity (`loginHint`), automatically propagating the active user to matching email/name attributes in the selected preset.

### E. Adding New Presets
When adding new test personas:
1. Define the preset object in `public/js/presets.js`:
   ```javascript
   {
     id: 'my_preset',
     name: 'My Service Provider Profile',
     description: 'Description of assertions...',
     nameId: 'user@example.com',
     nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
     attributes: [
       { name: 'email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['user@example.com'] }
     ],
     dbsc: { enabled: false, keys: [], certificates: [] }
   }
   ```
2. Update `detectSmartPreset` in `public/js/presets.js` if the SP has distinctive Entity ID or ACS patterns.
3. Add `<option value="my_preset">...</option>` inside `#preset-selector` in `public/index.html`.
4. Add a corresponding test assertion in `tests/verify.js`.

## 4. Verification & Testing

Always verify changes by running the automated test suite before committing:

```bash
npm test
# runs node tests/verify.js
```

To run a local server for browser testing:
```bash
npm run serve
# or: python3 -m http.server -d public 8000
```

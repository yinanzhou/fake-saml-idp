# Fake SAML 2.0 Identity Provider (IdP)

A SAML 2.0 Identity Provider designed for testing SAML Service Providers (SPs), custom SAML assertions, dynamic attributes, and **W3C Device Bound Session Credentials (DBSC)**.

## Key Features

- **Sensible Out-of-the-Box Defaults**: Pre-populated with standard user identity (`user@example.com`, Jane Doe, roles, groups, timestamps) for instant testing.
- **`login_hint` Auto-Detection**: Extracts `login_hint` from URL query parameters (`?login_hint=...`) or incoming SAML AuthnRequest `<saml:Subject>` to auto-populate user identity.
- **W3C DBSC (Device Bound Session Credentials)**: Support for `<saml:Advice>` containing `<dbsc:TrustedKey>` and `<dbsc:TrustedCertificate>` conforming to the official W3C schema (`xmlns:dbsc="https://www.w3.org/ns/dbsc/saml"`).
- **XML-DSig Signing**: Computes W3C Exclusive Canonicalization (`c14n-exc`) and generates RSA-SHA256 digital signatures.
- **Relying Party Hub & Cheatsheets**: Copy cards for SSO URLs, EntityID, Certificate PEM, Base64 strings, SHA-256 fingerprints, and metadata downloads.

## Relying Party (Service Provider) Configuration

| Configuration Field | Value |
| :--- | :--- |
| **Single Sign-On (SSO) URL** | `https://fake-saml-idp.pages.dev/` |
| **IdP Entity ID / Issuer** | `https://fake-saml-idp.pages.dev/saml/idp` |
| **SAML Metadata XML URL** | `https://fake-saml-idp.pages.dev/idp-metadata.xml` |
| **Direct Certificate URL** | `https://fake-saml-idp.pages.dev/idp-cert.pem` |
| **Default NameID Format** | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` |
| **Supported Bindings** | `HTTP-Redirect` & `HTTP-POST` |

## File Structure

```
.
├── AGENTS.md           # Developer & AI Agent architectural context
├── README.md           # Documentation and quick start guide
├── package.json        # Project metadata & test scripts
├── tests/
│   └── verify.js       # Automated verification test suite
└── public/             # Served assets
    ├── index.html      # Main application & Relying Party hub
    ├── 404.html        # 404 handler
    ├── _headers        # Security & CORS headers
    ├── idp-cert.pem    # Default X.509 certificate for direct upload
    ├── idp-metadata.xml# SAML 2.0 EntityDescriptor metadata
    ├── css/
    │   └── style.css   # Stylesheet
    └── js/
        ├── app.js          # App controller & UI events
        ├── saml-parser.js  # SAML AuthnRequest parser & login_hint detector
        ├── saml-builder.js # SAML 2.0 XML DOM constructor & DBSC builder
        ├── xml-signer.js   # W3C Canonical XML (c14n) & signer
        ├── crypto-keys.js  # Keys & X.509 cert generator
        └── presets.js      # Built-in persona presets (Default, Google, DBSC, Azure AD, AWS IAM)
```

## Local Development & Testing

Run automated tests:
```bash
npm test
```

Run a local server:
```bash
npm run serve
# or
python3 -m http.server -d public 8000
```

## AI Agent & Developer Architecture Guide

For AI coding agents and human contributors looking to extend the codebase, inspect [**`AGENTS.md`**](file:///Users/yinanzhou/Desktop/Test%20SAML%20IDP/AGENTS.md). It contains architectural constraints, the ES6 module map, W3C DBSC schema extension guidelines, and XML-DSig canonicalization rules.

## Disclaimer & Limitation of Liability

This software and related documentation are provided for testing, demonstration, and educational purposes only.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS, CONTRIBUTORS, OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY CLAIM, DAMAGES, LOSS OF DATA, SECURITY BREACH, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT OF, OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

No copyright ownership or affiliation is claimed over third-party standards, specifications, or protocols referenced herein.

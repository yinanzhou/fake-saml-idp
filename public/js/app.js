/**
 * Fake SAML IdP - Main Application Controller
 * Orchestrates UI state, SAMLRequest parsing, attribute builder, DBSC config,
 * live XML preview, WebCrypto signing, and SP form dispatch.
 */

import { DEFAULT_KEY_PAIR, importPrivateKey, generateNewKeypair, computeCertFingerprint, pemToBase64 } from './crypto-keys.js';
import { parseCurrentUrlParams, parseAuthnRequestXml, decodeSamlRequest } from './saml-parser.js';
import { buildSamlResponse, formatXml } from './saml-builder.js';
import { PRESETS, detectSmartPreset } from './presets.js';

// Application State
const state = {
  domain: window.location.origin.includes('pages.dev') ? 'https://fake-saml-idp.pages.dev' : window.location.origin,
  idpEntityId: '',
  ssoUrl: '',
  metadataUrl: '',
  certUrl: '',

  // Request state
  hasIncomingRequest: false,
  samlRequestRaw: '',
  relayState: '',
  parsedRequest: null,
  loginHint: '',
  loginHintSource: '',

  // Asserted Identity State (Sensible Defaults)
  acsUrl: 'https://sp.example.com/saml/acs',
  spEntityId: 'https://sp.example.com/saml/metadata',
  inResponseTo: '',
  nameId: 'user@example.com',
  nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  validityMinutes: 60,
  authnContextClassRef: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
  statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
  statusMessage: '',

  // Attributes list: [ { id, name, nameFormat, values: [string] } ]
  attributes: [],

  // DBSC State
  dbsc: {
    enabled: false,
    keys: [], // [ { id, digest, digestAlg } ]
    certificates: [] // [ { id, fingerprint, fingerprintAlg } ]
  },
  customAdviceXml: '',

  // Key & Signing State
  activeKeyPair: {
    certPem: DEFAULT_KEY_PAIR.certPem,
    privateKeyPkcs8Pem: DEFAULT_KEY_PAIR.privateKeyPkcs8Pem,
    fingerprintSha256: DEFAULT_KEY_PAIR.fingerprintSha256
  },
  importedPrivateKey: null,
  signAssertion: true,
  signResponse: false,

  // Generated Response Output
  lastGenerated: null,

  // Auto submit timer
  autoSubmitCountdown: 0,
  autoSubmitTimer: null,
  autoSubmitPaused: false
};

/**
 * Initialize Application
 */
async function initApp() {
  // Set URLs based on domain
  state.idpEntityId = `${state.domain}/saml/idp`;
  state.ssoUrl = `${state.domain}/`;
  state.metadataUrl = `${state.domain}/idp-metadata.xml`;
  state.certUrl = `${state.domain}/idp-cert.pem`;

  // Initialize WebCrypto private key
  try {
    state.importedPrivateKey = await importPrivateKey(state.activeKeyPair.privateKeyPkcs8Pem);
  } catch (e) {
    console.error('Failed to import default private key:', e);
  }

  // Parse incoming URL parameters (SAMLRequest, login_hint, RelayState)
  const urlParams = await parseCurrentUrlParams();

  if (urlParams.hasSamlRequest && urlParams.parsedRequest) {
    state.hasIncomingRequest = true;
    state.samlRequestRaw = urlParams.samlRequestRaw;
    state.relayState = urlParams.relayState;
    state.parsedRequest = urlParams.parsedRequest;

    if (urlParams.parsedRequest.acsUrl) {
      state.acsUrl = urlParams.parsedRequest.acsUrl;
    }
    if (urlParams.parsedRequest.issuer) {
      state.spEntityId = urlParams.parsedRequest.issuer;
    }
    if (urlParams.parsedRequest.id) {
      state.inResponseTo = urlParams.parsedRequest.id;
    }

    // Check login_hint / SP requested subject
    if (urlParams.loginHint) {
      state.loginHint = urlParams.loginHint;
      state.loginHintSource = urlParams.loginHintSource;
      state.nameId = urlParams.loginHint;
    }

    // Smartly detect preset based on incoming SP Entity ID and ACS URL
    const detectedPreset = detectSmartPreset(state.spEntityId, state.acsUrl, window.location.search);
    applyPreset(detectedPreset, false, { preserveUser: true });

    // Show request alert banner and switch to SSO Editor tab
    showRequestBanner();
    switchTab('tab-editor');
  } else {
    // If login_hint was passed in query params without SAMLRequest (IdP-initiated hint)
    if (urlParams.loginHint) {
      state.loginHint = urlParams.loginHint;
      state.loginHintSource = urlParams.loginHintSource;
      state.nameId = urlParams.loginHint;
      state.relayState = urlParams.relayState;

      const detectedPreset = detectSmartPreset('', '', window.location.search);
      applyPreset(detectedPreset, false, { preserveUser: true });

      showRequestBanner();
      switchTab('tab-editor');
    } else {
      // Default to landing page / Relying Party quick setup
      applyPreset('default', false);
      switchTab('tab-landing');
    }
  }

  // Render UI elements
  renderLandingConfig();
  renderRequestInspector();
  renderIdentityForm();
  renderAttributesTable();
  renderDbscSection();
  renderKeyManager();
  renderMetadataView();

  // Attach event listeners
  attachEventListeners();

  // Generate initial SAML response preview
  await updateSamlResponsePreview();
}

/**
 * Switch Active Tab
 */
function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === tabId);
  });
}

/**
 * Show banner when SAMLRequest / login_hint detected
 */
function showRequestBanner() {
  const banner = document.getElementById('request-alert-banner');
  if (!banner) return;

  let text = '';
  if (state.hasIncomingRequest) {
    text = `<strong>Incoming SAML Request Detected:</strong> SP Issuer: <code>${state.spEntityId}</code> | ACS: <code>${state.acsUrl}</code>`;
  }
  if (state.loginHint) {
    text += ` | <strong>Login Hint Auto-filled:</strong> <code>${state.loginHint}</code> (${state.loginHintSource})`;
  }

  document.getElementById('banner-message').innerHTML = text;
  banner.style.display = 'flex';
}

/**
 * Render Relying Party Landing page configuration
 */
function renderLandingConfig() {
  document.getElementById('landing-sso-url').textContent = state.ssoUrl;
  document.getElementById('landing-entity-id').textContent = state.idpEntityId;
  document.getElementById('landing-metadata-url').textContent = state.metadataUrl;
  document.getElementById('landing-cert-url').textContent = state.certUrl;
  document.getElementById('landing-fingerprint').textContent = state.activeKeyPair.fingerprintSha256;
  document.getElementById('landing-cert-b64').value = pemToBase64(state.activeKeyPair.certPem);
}

/**
 * Render Request Inspector Tab
 */
function renderRequestInspector() {
  const container = document.getElementById('request-inspector-content');
  if (!container) return;

  if (!state.hasIncomingRequest) {
    container.innerHTML = `
      <div style="padding: 20px; text-align: center; color: var(--text-secondary);">
        <p style="margin-bottom: 8px;">No incoming SP-Initiated SAMLRequest parameter was found in current URL.</p>
        <p style="font-size: 12px;">To test SP-initiated SSO, point your Relying Party / Service Provider SSO URL to: <code>${state.ssoUrl}</code></p>
      </div>
    `;
    return;
  }

  const req = state.parsedRequest;
  container.innerHTML = `
    <div class="grid-2" style="margin-bottom: 16px;">
      <div class="card" style="margin-bottom: 0;">
        <div class="form-group">
          <label class="form-label">SP Issuer (Entity ID)</label>
          <div class="copy-box"><span class="copy-box-text">${req.issuer || 'N/A'}</span></div>
        </div>
        <div class="form-group">
          <label class="form-label">ACS URL (Destination)</label>
          <div class="copy-box"><span class="copy-box-text">${req.acsUrl || 'N/A'}</span></div>
        </div>
        <div class="form-group">
          <label class="form-label">Request ID (InResponseTo)</label>
          <div class="copy-box"><span class="copy-box-text">${req.id || 'N/A'}</span></div>
        </div>
      </div>
      <div class="card" style="margin-bottom: 0;">
        <div class="form-group">
          <label class="form-label">RelayState</label>
          <div class="copy-box"><span class="copy-box-text">${state.relayState || '(None)'}</span></div>
        </div>
        <div class="form-group">
          <label class="form-label">Requested Subject / login_hint</label>
          <div class="copy-box"><span class="copy-box-text">${req.requestedSubject || state.loginHint || '(None)'}</span></div>
        </div>
        <div class="form-group">
          <label class="form-label">ForceAuthn / IsPassive</label>
          <div>
            <span class="badge ${req.forceAuthn ? 'badge-warning' : 'badge-info'}">ForceAuthn: ${req.forceAuthn}</span>
            <span class="badge badge-info">IsPassive: ${req.isPassive}</span>
          </div>
        </div>
      </div>
    </div>
    <div class="code-viewer-container">
      <div class="code-viewer-header">
        <span>Decoded SAML AuthnRequest XML</span>
        <button class="btn btn-sm" id="btn-copy-req-xml">Copy Request XML</button>
      </div>
      <pre class="code-viewer-content">${escapeHtml(formatXml(req.rawXml))}</pre>
    </div>
  `;

  document.getElementById('btn-copy-req-xml')?.addEventListener('click', () => {
    copyToClipboard(req.rawXml, 'AuthnRequest XML copied to clipboard!');
  });
}

/**
 * Render Identity and SSO parameters form
 */
function renderIdentityForm() {
  const setVal = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.value = val;
  };

  setVal('input-name-id', state.nameId);
  setVal('select-name-id-format', state.nameIdFormat);
  setVal('input-acs-url', state.acsUrl);
  setVal('input-sp-entity-id', state.spEntityId);
  setVal('input-in-response-to', state.inResponseTo);
  setVal('input-relay-state', state.relayState);
  setVal('input-validity-mins', state.validityMinutes);
  setVal('input-authn-context', state.authnContextClassRef);
  setVal('select-status-code', state.statusCode);
}

/**
 * Render Dynamic Attributes Table
 */
function renderAttributesTable() {
  const tbody = document.getElementById('attributes-table-body');
  if (!tbody) return;

  tbody.innerHTML = '';

  state.attributes.forEach((attr, idx) => {
    const tr = document.createElement('tr');
    tr.className = 'attr-row';
    tr.innerHTML = `
      <td style="width: 28%;">
        <input type="text" class="form-input code-font attr-name-input" data-index="${idx}" value="${escapeHtml(attr.name)}" placeholder="Attribute Name">
      </td>
      <td style="width: 24%;">
        <select class="form-select attr-format-select" data-index="${idx}" style="font-size: 11px;">
          <option value="urn:oasis:names:tc:SAML:2.0:attrname-format:basic" ${attr.nameFormat.includes('basic') ? 'selected' : ''}>Basic</option>
          <option value="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" ${attr.nameFormat.includes('uri') ? 'selected' : ''}>URI / URN</option>
          <option value="urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified" ${attr.nameFormat.includes('unspecified') ? 'selected' : ''}>Unspecified</option>
        </select>
      </td>
      <td style="width: 40%;">
        <div class="attr-values-container" data-index="${idx}">
          ${attr.values.map((v, vIdx) => `
            <div style="display: flex; gap: 6px; margin-bottom: 4px;">
              <input type="text" class="form-input code-font attr-value-input" data-attr-index="${idx}" data-val-index="${vIdx}" value="${escapeHtml(v)}" placeholder="Value">
              ${attr.values.length > 1 ? `<button type="button" class="btn btn-sm btn-danger btn-remove-val" data-attr-index="${idx}" data-val-index="${vIdx}">&times;</button>` : ''}
            </div>
          `).join('')}
          <button type="button" class="btn btn-sm btn-add-val" data-index="${idx}" style="font-size: 11px; margin-top: 2px;">+ Add Value</button>
        </div>
      </td>
      <td style="width: 8%; text-align: center;">
        <button type="button" class="btn btn-sm btn-danger btn-remove-attr" data-index="${idx}" title="Remove Attribute">&times;</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

/**
 * Render DBSC Section
 */
function renderDbscSection() {
  const toggle = document.getElementById('dbsc-enabled-toggle');
  const details = document.getElementById('dbsc-details-container');
  if (toggle) toggle.checked = state.dbsc.enabled;
  if (details) details.style.display = state.dbsc.enabled ? 'block' : 'none';

  // Render DBSC Keys
  const keysContainer = document.getElementById('dbsc-keys-container');
  if (keysContainer) {
    keysContainer.innerHTML = state.dbsc.keys.map((k, idx) => {
      const alg = k.digestAlg || 'SHA-256';
      return `
      <div class="dbsc-item">
        <div style="flex: 2;">
          <label class="form-label" style="font-size: 10px;">dbsc:TrustedKey @digest</label>
          <input type="text" class="form-input code-font dbsc-key-digest" data-index="${idx}" value="${escapeHtml(k.digest)}" placeholder="e.g. nZgxCylNy7jXvn4+j0DykE+TDK4W41LTffxei29e/G0=">
        </div>
        <div style="flex: 1;">
          <label class="form-label" style="font-size: 10px;">@digest_alg</label>
          <select class="form-select code-font dbsc-key-alg" data-index="${idx}">
            <option value="SHA-256" ${alg === 'SHA-256' ? 'selected' : ''}>SHA-256</option>
            <option value="SHA-384" ${alg === 'SHA-384' ? 'selected' : ''}>SHA-384</option>
            <option value="SHA-512" ${alg === 'SHA-512' ? 'selected' : ''}>SHA-512</option>
          </select>
        </div>
        <div style="padding-top: 18px;">
          <button type="button" class="btn btn-sm btn-danger btn-remove-dbsc-key" data-index="${idx}">&times;</button>
        </div>
      </div>
    `;
    }).join('');
  }

  // Render DBSC Certs
  const certsContainer = document.getElementById('dbsc-certs-container');
  if (certsContainer) {
    certsContainer.innerHTML = state.dbsc.certificates.map((c, idx) => {
      const alg = c.fingerprintAlg || 'SHA-256';
      return `
      <div class="dbsc-item">
        <div style="flex: 2;">
          <label class="form-label" style="font-size: 10px;">dbsc:TrustedCertificate @fingerprint</label>
          <input type="text" class="form-input code-font dbsc-cert-fp" data-index="${idx}" value="${escapeHtml(c.fingerprint)}" placeholder="e.g. f3e9619a9d701a52701469e4f83d32847b2374e2593f66d48b788647097c234b">
        </div>
        <div style="flex: 1;">
          <label class="form-label" style="font-size: 10px;">@fingerprint_alg</label>
          <select class="form-select code-font dbsc-cert-alg" data-index="${idx}">
            <option value="SHA-256" ${alg === 'SHA-256' ? 'selected' : ''}>SHA-256</option>
            <option value="SHA-384" ${alg === 'SHA-384' ? 'selected' : ''}>SHA-384</option>
            <option value="SHA-512" ${alg === 'SHA-512' ? 'selected' : ''}>SHA-512</option>
          </select>
        </div>
        <div style="padding-top: 18px;">
          <button type="button" class="btn btn-sm btn-danger btn-remove-dbsc-cert" data-index="${idx}">&times;</button>
        </div>
      </div>
    `;
    }).join('');
  }
}

/**
 * Render Key Manager Tab
 */
function renderKeyManager() {
  const certPemEl = document.getElementById('key-cert-pem');
  const pkcs8PemEl = document.getElementById('key-pkcs8-pem');
  const fpEl = document.getElementById('key-fingerprint');
  const signAsrtCheckbox = document.getElementById('sign-assertion-toggle');
  const signRespCheckbox = document.getElementById('sign-response-toggle');

  if (certPemEl) certPemEl.value = state.activeKeyPair.certPem;
  if (pkcs8PemEl) pkcs8PemEl.value = state.activeKeyPair.privateKeyPkcs8Pem;
  if (fpEl) fpEl.textContent = state.activeKeyPair.fingerprintSha256;
  if (signAsrtCheckbox) signAsrtCheckbox.checked = state.signAssertion;
  if (signRespCheckbox) signRespCheckbox.checked = state.signResponse;
}

/**
 * Render Metadata Tab
 */
function renderMetadataView() {
  const metadataViewer = document.getElementById('metadata-xml-viewer');
  if (!metadataViewer) return;

  const certB64 = pemToBase64(state.activeKeyPair.certPem);
  const metadataXml = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                     entityID="${state.idpEntityId}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false"
                       protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo id="KeyInfo-1">
        <ds:X509Data>
          <ds:X509Certificate>${certB64}</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="${state.ssoUrl}"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="${state.ssoUrl}"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                            Location="${state.ssoUrl}"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                            Location="${state.ssoUrl}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;

  metadataViewer.textContent = formatXml(metadataXml);
}

/**
 * Re-computes and signs the SAML 2.0 Response XML
 */
async function updateSamlResponsePreview() {
  try {
    const result = await buildSamlResponse({
      acsUrl: state.acsUrl,
      spEntityId: state.spEntityId,
      idpEntityId: state.idpEntityId,
      inResponseTo: state.inResponseTo,
      statusCode: state.statusCode,
      statusMessage: state.statusMessage,

      nameId: state.nameId,
      nameIdFormat: state.nameIdFormat,
      validityMinutes: parseInt(state.validityMinutes, 10) || 60,
      authnContextClassRef: state.authnContextClassRef,

      attributes: state.attributes,

      dbscEnabled: state.dbsc.enabled,
      dbscKeys: state.dbsc.keys,
      dbscCertificates: state.dbsc.certificates,
      customAdviceXml: state.customAdviceXml,

      signAssertion: state.signAssertion,
      signResponse: state.signResponse,
      privateKey: state.importedPrivateKey,
      certPem: state.activeKeyPair.certPem
    });

    state.lastGenerated = result;

    const xmlPreviewEl = document.getElementById('response-xml-preview');
    const b64PreviewEl = document.getElementById('response-b64-preview');
    const postAcsTargetEl = document.getElementById('post-acs-target-label');

    if (xmlPreviewEl) xmlPreviewEl.textContent = result.xmlString;
    if (b64PreviewEl) b64PreviewEl.value = result.base64Response;
    if (postAcsTargetEl) postAcsTargetEl.textContent = state.acsUrl;
  } catch (err) {
    console.error('Failed to build SAML Response:', err);
    showToast('Failed to build SAML Response: ' + err.message, true);
  }
}

/**
 * Applies a built-in Persona preset without overwriting request parameters (InResponseTo, RelayState, ACS URL, SP Entity ID, requested login_hint)
 */
function applyPreset(presetId, autoUpdate = true, options = {}) {
  const preset = PRESETS.find(p => p.id === presetId);
  if (!preset) return;

  // Determine effective NameID:
  // If login_hint is active or preserveUser is requested, keep the active user identifier
  const preserveUser = options.preserveUser ?? (!!state.loginHint || (state.hasIncomingRequest && !!state.nameId && state.nameId !== 'user@example.com'));
  const effectiveNameId = (preserveUser && state.nameId) ? state.nameId : preset.nameId;

  state.nameId = effectiveNameId;
  state.nameIdFormat = preset.nameIdFormat;

  // Deep clone preset attributes
  state.attributes = JSON.parse(JSON.stringify(preset.attributes));

  // If a specific user identity is active, propagate it to relevant email/name attributes in the preset
  if (effectiveNameId) {
    for (const attr of state.attributes) {
      const lowerName = attr.name.toLowerCase();
      if (
        lowerName === 'email' ||
        lowerName === 'primary_email' ||
        lowerName.endsWith('/emailaddress') ||
        lowerName === 'user' ||
        lowerName === 'login' ||
        lowerName === 'rolesessionname' ||
        lowerName.endsWith('/rolesessionname')
      ) {
        attr.values = [effectiveNameId];
      }
    }
  }

  // Configure DBSC settings from preset
  if (preset.dbsc) {
    state.dbsc = JSON.parse(JSON.stringify(preset.dbsc));
  } else {
    state.dbsc = { enabled: false, keys: [], certificates: [] };
  }

  // Synchronize preset selector dropdown
  const presetSelect = document.getElementById('preset-selector');
  if (presetSelect && presetSelect.value !== presetId) {
    presetSelect.value = presetId;
  }

  if (autoUpdate) {
    renderIdentityForm();
    renderAttributesTable();
    renderDbscSection();
    updateSamlResponsePreview();
    showToast(`Applied preset: ${preset.name}`);
  }
}

/**
 * Dispatches SAML Response form POST directly to SP ACS endpoint
 */
function submitSamlResponse() {
  if (!state.lastGenerated) {
    showToast('SAML Response is not yet generated.', true);
    return;
  }

  if (!state.acsUrl) {
    showToast('Assertion Consumer Service (ACS) URL is required.', true);
    return;
  }

  const form = document.createElement('form');
  form.method = 'POST';
  form.action = state.acsUrl;
  form.style.display = 'none';

  const samlInput = document.createElement('input');
  samlInput.type = 'hidden';
  samlInput.name = 'SAMLResponse';
  samlInput.value = state.lastGenerated.base64Response;
  form.appendChild(samlInput);

  if (state.relayState) {
    const relayInput = document.createElement('input');
    relayInput.type = 'hidden';
    relayInput.name = 'RelayState';
    relayInput.value = state.relayState;
    form.appendChild(relayInput);
  }

  document.body.appendChild(form);
  form.submit();
}

/**
 * Downloads a text string as a local file
 */
function downloadFile(filename, content, mimeType = 'text/plain') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Copy string to clipboard with visual toast
 */
async function copyToClipboard(text, message = 'Copied to clipboard!') {
  try {
    await navigator.clipboard.writeText(text);
    showToast(message);
  } catch (e) {
    // Fallback
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showToast(message);
  }
}

/**
 * Show a toast notification
 */
function showToast(message, isError = false) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${isError ? 'toast-error' : 'toast-success'}`;
  toast.textContent = message;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 200);
  }, 2800);
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str || '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Event Listeners Registration
 */
function attachEventListeners() {
  // Navigation Tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      switchTab(btn.dataset.tab);
    });
  });

  // Preset Selector Dropdown
  const presetSelect = document.getElementById('preset-selector');
  if (presetSelect) {
    presetSelect.addEventListener('change', e => {
      applyPreset(e.target.value, true);
    });
  }

  // Identity Form Inputs
  const bindInput = (id, prop) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', e => {
        state[prop] = e.target.value;
        updateSamlResponsePreview();
      });
    }
  };

  bindInput('input-name-id', 'nameId');
  bindInput('select-name-id-format', 'nameIdFormat');
  bindInput('input-acs-url', 'acsUrl');
  bindInput('input-sp-entity-id', 'spEntityId');
  bindInput('input-in-response-to', 'inResponseTo');
  bindInput('input-relay-state', 'relayState');
  bindInput('input-validity-mins', 'validityMinutes');
  bindInput('input-authn-context', 'authnContextClassRef');
  bindInput('select-status-code', 'statusCode');

  // Attribute Table Events
  document.getElementById('btn-add-attribute')?.addEventListener('click', () => {
    state.attributes.push({
      name: 'newAttribute',
      nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
      values: ['value1']
    });
    renderAttributesTable();
    updateSamlResponsePreview();
  });

  const attrTableBody = document.getElementById('attributes-table-body');
  if (attrTableBody) {
    attrTableBody.addEventListener('input', e => {
      const idx = e.target.dataset.index || e.target.dataset.attrIndex;
      if (idx === undefined) return;

      if (e.target.classList.contains('attr-name-input')) {
        state.attributes[idx].name = e.target.value;
      } else if (e.target.classList.contains('attr-value-input')) {
        const valIdx = e.target.dataset.valIndex;
        state.attributes[idx].values[valIdx] = e.target.value;
      }
      updateSamlResponsePreview();
    });

    attrTableBody.addEventListener('change', e => {
      if (e.target.classList.contains('attr-format-select')) {
        const idx = e.target.dataset.index;
        state.attributes[idx].nameFormat = e.target.value;
        updateSamlResponsePreview();
      }
    });

    attrTableBody.addEventListener('click', e => {
      if (e.target.classList.contains('btn-remove-attr')) {
        const idx = parseInt(e.target.dataset.index, 10);
        state.attributes.splice(idx, 1);
        renderAttributesTable();
        updateSamlResponsePreview();
      } else if (e.target.classList.contains('btn-add-val')) {
        const idx = parseInt(e.target.dataset.index, 10);
        state.attributes[idx].values.push('');
        renderAttributesTable();
        updateSamlResponsePreview();
      } else if (e.target.classList.contains('btn-remove-val')) {
        const attrIdx = parseInt(e.target.dataset.attrIndex, 10);
        const valIdx = parseInt(e.target.dataset.valIndex, 10);
        state.attributes[attrIdx].values.splice(valIdx, 1);
        renderAttributesTable();
        updateSamlResponsePreview();
      }
    });
  }

  // DBSC Events
  const dbscToggle = document.getElementById('dbsc-enabled-toggle');
  if (dbscToggle) {
    dbscToggle.addEventListener('change', e => {
      state.dbsc.enabled = e.target.checked;
      renderDbscSection();
      updateSamlResponsePreview();
    });
  }

  document.getElementById('btn-add-dbsc-key')?.addEventListener('click', () => {
    state.dbsc.keys.push({ digest: '', digestAlg: 'SHA-256' });
    renderDbscSection();
    updateSamlResponsePreview();
  });

  document.getElementById('btn-add-dbsc-cert')?.addEventListener('click', () => {
    state.dbsc.certificates.push({ fingerprint: '', fingerprintAlg: 'SHA-256' });
    renderDbscSection();
    updateSamlResponsePreview();
  });

  document.getElementById('dbsc-keys-container')?.addEventListener('input', e => {
    const idx = parseInt(e.target.dataset.index, 10);
    if (e.target.classList.contains('dbsc-key-digest')) {
      state.dbsc.keys[idx].digest = e.target.value;
      updateSamlResponsePreview();
    }
  });

  document.getElementById('dbsc-keys-container')?.addEventListener('change', e => {
    const idx = parseInt(e.target.dataset.index, 10);
    if (e.target.classList.contains('dbsc-key-alg')) {
      state.dbsc.keys[idx].digestAlg = e.target.value;
      updateSamlResponsePreview();
    }
  });

  document.getElementById('dbsc-keys-container')?.addEventListener('click', e => {
    if (e.target.classList.contains('btn-remove-dbsc-key')) {
      const idx = parseInt(e.target.dataset.index, 10);
      state.dbsc.keys.splice(idx, 1);
      renderDbscSection();
      updateSamlResponsePreview();
    }
  });

  document.getElementById('dbsc-certs-container')?.addEventListener('input', e => {
    const idx = parseInt(e.target.dataset.index, 10);
    if (e.target.classList.contains('dbsc-cert-fp')) {
      state.dbsc.certificates[idx].fingerprint = e.target.value;
      updateSamlResponsePreview();
    }
  });

  document.getElementById('dbsc-certs-container')?.addEventListener('change', e => {
    const idx = parseInt(e.target.dataset.index, 10);
    if (e.target.classList.contains('dbsc-cert-alg')) {
      state.dbsc.certificates[idx].fingerprintAlg = e.target.value;
      updateSamlResponsePreview();
    }
  });

  document.getElementById('dbsc-certs-container')?.addEventListener('click', e => {
    if (e.target.classList.contains('btn-remove-dbsc-cert')) {
      const idx = parseInt(e.target.dataset.index, 10);
      state.dbsc.certificates.splice(idx, 1);
      renderDbscSection();
      updateSamlResponsePreview();
    }
  });

  // Custom Advice XML Input
  document.getElementById('input-custom-advice-xml')?.addEventListener('input', e => {
    state.customAdviceXml = e.target.value;
    updateSamlResponsePreview();
  });

  // Signing Toggle
  document.getElementById('sign-assertion-toggle')?.addEventListener('change', e => {
    state.signAssertion = e.target.checked;
    updateSamlResponsePreview();
  });
  document.getElementById('sign-response-toggle')?.addEventListener('change', e => {
    state.signResponse = e.target.checked;
    updateSamlResponsePreview();
  });

  // Key Manager: Generate Keypair
  document.getElementById('btn-generate-keypair')?.addEventListener('click', async () => {
    try {
      showToast('Generating 2048-bit RSA Keypair in browser...');
      const newKeys = await generateNewKeypair('fake-saml-idp.pages.dev', 10);
      state.activeKeyPair = newKeys;
      state.importedPrivateKey = await importPrivateKey(newKeys.privateKeyPkcs8Pem);
      renderKeyManager();
      renderLandingConfig();
      renderMetadataView();
      await updateSamlResponsePreview();
      showToast('New RSA Keypair and X.509 Certificate generated!');
    } catch (err) {
      showToast('Key generation failed: ' + err.message, true);
    }
  });

  // Key Manager: Import Custom Keys
  document.getElementById('btn-apply-custom-keys')?.addEventListener('click', async () => {
    const certPem = document.getElementById('key-cert-pem')?.value.trim();
    const pkcs8Pem = document.getElementById('key-pkcs8-pem')?.value.trim();

    if (!certPem || !pkcs8Pem) {
      showToast('Both Certificate and Private Key PEM are required.', true);
      return;
    }

    try {
      const importedKey = await importPrivateKey(pkcs8Pem);
      const fingerprint = await computeCertFingerprint(certPem);
      state.importedPrivateKey = importedKey;
      state.activeKeyPair.certPem = certPem;
      state.activeKeyPair.privateKeyPkcs8Pem = pkcs8Pem;
      state.activeKeyPair.fingerprintSha256 = fingerprint;

      renderKeyManager();
      renderLandingConfig();
      renderMetadataView();
      await updateSamlResponsePreview();
      showToast('Custom keys imported and active!');
    } catch (err) {
      showToast('Invalid key or cert: ' + err.message, true);
    }
  });

  // Download buttons
  document.getElementById('btn-download-cert')?.addEventListener('click', () => {
    downloadFile('idp-cert.pem', state.activeKeyPair.certPem, 'application/x-pem-file');
  });
  document.getElementById('btn-download-landing-cert')?.addEventListener('click', () => {
    downloadFile('idp-cert.pem', state.activeKeyPair.certPem, 'application/x-pem-file');
  });
  document.getElementById('btn-download-metadata')?.addEventListener('click', () => {
    const xml = document.getElementById('metadata-xml-viewer')?.textContent || '';
    downloadFile('idp-metadata.xml', xml, 'application/samlmetadata+xml');
  });

  // Submission Buttons
  document.getElementById('btn-submit-saml-response')?.addEventListener('click', () => {
    submitSamlResponse();
  });
  document.getElementById('btn-preview-submit-saml')?.addEventListener('click', () => {
    submitSamlResponse();
  });

  // Copy Buttons
  document.getElementById('btn-copy-sso-url')?.addEventListener('click', () => copyToClipboard(state.ssoUrl, 'SSO URL copied!'));
  document.getElementById('btn-copy-entity-id')?.addEventListener('click', () => copyToClipboard(state.idpEntityId, 'IdP Entity ID copied!'));
  document.getElementById('btn-copy-metadata-url')?.addEventListener('click', () => copyToClipboard(state.metadataUrl, 'Metadata URL copied!'));
  document.getElementById('btn-copy-cert-url')?.addEventListener('click', () => copyToClipboard(state.certUrl, 'Certificate URL copied!'));
  document.getElementById('btn-copy-cert-pem')?.addEventListener('click', () => copyToClipboard(state.activeKeyPair.certPem, 'Certificate PEM copied!'));
  document.getElementById('btn-copy-cert-b64')?.addEventListener('click', () => copyToClipboard(pemToBase64(state.activeKeyPair.certPem), 'Certificate Base64 copied!'));
  document.getElementById('btn-copy-response-xml')?.addEventListener('click', () => {
    if (state.lastGenerated) copyToClipboard(state.lastGenerated.xmlString, 'SAMLResponse XML copied!');
  });
  document.getElementById('btn-copy-response-b64')?.addEventListener('click', () => {
    if (state.lastGenerated) copyToClipboard(state.lastGenerated.base64Response, 'SAMLResponse Base64 copied!');
  });

  // Theme Toggle
  document.getElementById('btn-toggle-theme')?.addEventListener('click', () => {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    document.documentElement.setAttribute('data-theme', isLight ? 'dark' : 'light');
  });
}

// Initialize on DOM load
window.addEventListener('DOMContentLoaded', initApp);

/**
 * Built-in Persona and Attribute Presets for Fake SAML IdP
 */

export const PRESETS = [
  {
    id: 'default',
    name: 'Default User (Sensible Defaults)',
    description: 'Standard enterprise profile with email, full name, roles and groups.',
    nameId: 'user@example.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attributes: [
      { name: 'email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['user@example.com'] },
      { name: 'firstName', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['Jane'] },
      { name: 'lastName', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['Doe'] },
      { name: 'displayName', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['Jane Doe'] },
      { name: 'roles', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['admin', 'user'] },
      { name: 'groups', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['Engineering', 'Admins'] },
      { name: 'department', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['IT'] }
    ],
    dbsc: {
      enabled: false,
      keys: [],
      certificates: []
    }
  },
  {
    id: 'dbsc',
    name: 'W3C DBSC (Device Bound Session Credentials)',
    description: 'Includes <saml:Advice> with dbsc:TrustedKey and dbsc:TrustedCertificate.',
    nameId: 'device-bound-user@example.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attributes: [
      { name: 'email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['device-bound-user@example.com'] },
      { name: 'firstName', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['Alice'] },
      { name: 'lastName', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['Security'] },
      { name: 'roles', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['device-authenticated-user'] }
    ],
    dbsc: {
      enabled: true,
      keys: [
        {
          digest: 'nZgxCylNy7jXvn4+j0DykE+TDK4W41LTffxei29e/G0=',
          digestAlg: 'SHA-256'
        }
      ],
      certificates: [
        {
          fingerprint: 'f3e9619a9d701a52701469e4f83d32847b2374e2593f66d48b788647097c234b',
          fingerprintAlg: 'SHA-256'
        }
      ]
    }
  },
  {
    id: 'google',
    name: 'Google Workspace / Google SSO',
    description: 'Google Workspace SAML assertions with email, first_name, and last_name.',
    nameId: 'user@company.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    attributes: [
      { name: 'email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['user@company.com'] },
      { name: 'primary_email', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['user@company.com'] },
      { name: 'first_name', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['Jane'] },
      { name: 'last_name', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic', values: ['Doe'] }
    ],
    dbsc: { enabled: false, keys: [], certificates: [] }
  },
  {
    id: 'azure_ad',
    name: 'Microsoft Entra ID (Azure AD)',
    description: 'Full schema URN claims used by Microsoft Entra ID.',
    nameId: 'admin@tenant.onmicrosoft.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    attributes: [
      { name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', values: ['admin@tenant.onmicrosoft.com'] },
      { name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', values: ['admin@tenant.onmicrosoft.com'] },
      { name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', values: ['Jane'] },
      { name: 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', values: ['Admin'] },
      { name: 'http://schemas.microsoft.com/identity/claims/objectidentifier', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', values: ['a1b2c3d4-e5f6-7890-abcd-ef1234567890'] },
      { name: 'http://schemas.microsoft.com/ws/2008/06/identity/claims/groups', nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri', values: ['d3b07384-d113-4c92-9694-817865239a04', '8f89e248-26f6-455b-b9d9-761a5b82e212'] }
    ],
    dbsc: { enabled: false, keys: [], certificates: [] }
  },
  {
    id: 'aws_iam',
    name: 'AWS IAM Identity Center / SAML',
    description: 'AWS IAM SAML attributes for assume role (Role, RoleSessionName, SessionDuration).',
    nameId: 'aws-admin@example.com',
    nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    attributes: [
      {
        name: 'https://aws.amazon.com/SAML/Attributes/Role',
        nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        values: ['arn:aws:iam::123456789012:role/SAML-AdminRole,arn:aws:iam::123456789012:saml-provider/FakeSAMLIdP']
      },
      {
        name: 'https://aws.amazon.com/SAML/Attributes/RoleSessionName',
        nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        values: ['aws-admin@example.com']
      },
      {
        name: 'https://aws.amazon.com/SAML/Attributes/SessionDuration',
        nameFormat: 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic',
        values: ['43200']
      }
    ],
    dbsc: { enabled: false, keys: [], certificates: [] }
  }
];

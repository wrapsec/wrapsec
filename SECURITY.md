# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **security@wrapsec.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce or proof-of-concept code
- Affected component (API, dashboard, SDK, detection pipeline)
- Affected versions

You will receive an acknowledgement within **48 hours** and a resolution timeline within **5 business days**.

## Disclosure Policy

We follow responsible disclosure. Once a fix is released, we will publish a security advisory crediting the reporter (unless you prefer to remain anonymous). We ask that you allow reasonable time to address the issue before public disclosure.

## Scope

**In scope:**
- Authentication and session management
- API key handling and encryption
- Detection pipeline bypass
- Tenant data isolation
- Dashboard (Next.js BFF routes)
- Python SDK (`wrapsec-python`) and Node.js SDK (`wrapsec-node`)

**Out of scope:**
- Vulnerabilities in third-party dependencies (report directly to the dependency maintainer)
- Issues only reproducible with admin credentials on a self-hosted instance you fully control

## Security Contacts

- **Vulnerabilities:** security@wrapsec.com
- **General enquiries:** hello@wrapsec.com

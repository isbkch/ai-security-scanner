# Security Policy

## Supported Versions

We actively support the following versions of the AI Security Scanner with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting Security Vulnerabilities

We take the security of the AI Security Scanner seriously. If you discover a security vulnerability, please follow these guidelines:

### Responsible Disclosure

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them through one of the following methods:

1. **Email**: Send details to security@[your-domain].com
2. **GitHub Security Advisory**: Use the "Report a vulnerability" button in the Security tab of this repository
3. **Private Contact**: Reach out to the maintainers directly through private channels

### What to Include

When reporting a security vulnerability, please include as much of the following information as possible:

- **Type of issue** (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- **Full paths of source file(s)** related to the manifestation of the issue
- **The location of the affected source code** (tag/branch/commit or direct URL)
- **Any special configuration** required to reproduce the issue
- **Step-by-step instructions** to reproduce the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the issue**, including how an attacker might exploit the issue

This information will help us triage your report more quickly.

### Response Timeline

We will acknowledge receipt of your vulnerability report within **48 hours** and will send a more detailed response within **7 days** indicating the next steps in handling your report.

After the initial reply to your report, we will endeavor to keep you informed of the progress being made towards a fix and full announcement, and may ask for additional information or guidance surrounding the reported issue.

## Security Considerations for Users

### API Key Security

- **Never commit API keys** (OpenAI, Anthropic, GitHub tokens) to version control
- Use environment variables or secure configuration management
- Rotate API keys regularly
- Use principle of least privilege for GitHub tokens

### LLM Provider Security

- Be aware that code snippets are sent to LLM providers for analysis
- Consider using self-hosted LLM solutions for sensitive codebases
- Review your LLM provider's data retention and privacy policies
- Use the `--no-ai` flag to disable LLM analysis for sensitive scans

### Database Security

- Use strong passwords for database connections
- Enable SSL/TLS for database connections
- Regularly update PostgreSQL and apply security patches
- Implement proper access controls and network segmentation

### GitHub Integration Security

- Use personal access tokens with minimal required scopes
- Regularly review and rotate GitHub tokens
- Monitor token usage and revoke unused tokens
- Be cautious when scanning public repositories with sensitive configurations

### Container Security

- Regularly update the base Docker images
- Scan container images for vulnerabilities
- Use non-root users in containers when possible
- Implement proper secrets management in containerized environments

## Security Features of the Scanner

### Defensive Design

- **Input validation**: All user inputs are validated and sanitized
- **Sandboxed execution**: Code analysis runs in isolated environments
- **Rate limiting**: LLM API calls are rate-limited to prevent abuse
- **Error handling**: Graceful error handling prevents information disclosure

### Vulnerability Detection

The scanner is designed to detect various types of security vulnerabilities:

- SQL Injection
- Cross-Site Scripting (XSS)
- Weak cryptography
- Hardcoded secrets
- Insecure deserialization
- Command injection
- Path traversal
- And more...

### False Positive Reduction

- AI-powered analysis helps reduce false positives
- Confidence scoring provides additional context
- Customizable confidence thresholds allow tuning

## Secure Development Practices

### Code Review

All code changes undergo security-focused code review:

- Manual review by maintainers
- Automated security scanning with Bandit
- Dependency vulnerability scanning with Safety
- Static analysis with multiple tools

### Testing

Security testing is integrated into our development process:

- Unit tests for security-critical functions
- Integration tests with vulnerable code examples
- Fuzzing tests for input validation
- Regular security assessments

### Dependencies

We maintain security hygiene for dependencies:

- Regular dependency updates
- Automated vulnerability scanning
- Minimal dependency principle
- Security-focused dependency selection

### CI/CD Security

Our build and deployment pipeline includes security controls:

- Signed commits and tags
- Secure artifact storage
- Automated security scanning
- Environment isolation

## Incident Response

In case of a confirmed security vulnerability:

1. **Assessment**: We will assess the severity and impact
2. **Fix Development**: Develop and test a security fix
3. **Coordinated Disclosure**: Work with reporter on disclosure timeline
4. **Release**: Release patched version with security advisory
5. **Communication**: Notify users through appropriate channels

## Security Contact

For security-related questions or concerns:

- **Email**: security@[your-domain].com
- **PGP Key**: [Link to PGP key if available]
- **Response Time**: 48 hours for initial acknowledgment

## Acknowledgments

We appreciate the security research community's efforts in making the AI Security Scanner more secure. Security researchers who responsibly disclose vulnerabilities will be acknowledged in our security advisories (unless they prefer to remain anonymous).

### Hall of Fame

*This section will be updated as we receive and address security reports.*

## Legal

This security policy is subject to our terms of service and privacy policy. By reporting vulnerabilities, you agree to our responsible disclosure guidelines and legal protections for security researchers acting in good faith.
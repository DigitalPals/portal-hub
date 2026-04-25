# Security Policy

Portal Proxy is designed to run behind Tailscale and should not be exposed to
the public internet.

## Supported Versions

Only the latest `0.x` release receives security fixes while the project is
pre-1.0.

## Reporting Vulnerabilities

Do not open public issues for vulnerabilities. Report privately to the project
maintainer with:

- affected version
- deployment model
- reproduction steps
- expected impact

## Security Notes

- Session logs may contain secrets. Protect `/var/lib/portal-proxy`.
- Use a dedicated non-root user.
- Use forced-command SSH keys.
- Restrict access with Tailscale ACLs.
- Consider `PORTAL_PROXY_ALLOWED_TARGETS` in shared environments.
- Set a finite `PORTAL_PROXY_MAX_LOG_BYTES`.

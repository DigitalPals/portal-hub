# Security Policy

Portal Hub is designed to run behind Tailscale and should not be exposed to
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

- Session logs may contain secrets. Protect `/var/lib/portal-hub`.
- Synced hosts, settings, and snippets are readable by anyone who can read the
  Hub state directory.
- Vault private keys are stored as client-side encrypted blobs. Hub must never
  receive the vault passphrase, derived key, or decrypted private key material.
- Sync and vault operations are written to `/var/lib/portal-hub/sync/audit.log`
  without private key blobs or terminal previews.
- Web authentication stores users, OAuth tokens, profiles, and web audit events
  in `/var/lib/portal-hub/hub.db`. Protect this database like credential data.
- The owner bootstrap page is available only while the user table is empty.
- Use a dedicated non-root user.
- Use forced-command SSH keys.
- Restrict access with Tailscale ACLs.
- Consider `PORTAL_HUB_ALLOWED_TARGETS` in shared environments.
- Set a finite `PORTAL_HUB_MAX_LOG_BYTES`.
- The web interface uses passkeys for passwordless authentication. Passkeys
  require HTTPS, except for localhost development domains such as
  `portal-hub.localhost`. Prefer placing it behind HTTPS and Tailscale or
  another private network boundary.

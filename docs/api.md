# Portal Hub API

Portal Hub is executed over SSH forced commands. New clients should request
versioned JSON responses and reject unknown API versions.

## Version

```sh
portal-hub version --json
```

Response:

```json
{
  "version": "0.5.0-beta.4",
  "api_version": 1,
  "metadata_schema_version": 1,
  "min_portal_api_version": 1
}
```

## List Sessions

```sh
portal-hub list --active --include-preview --preview-bytes 524288 --format v1
```

Response:

```json
{
  "api_version": 1,
  "generated_at": "2026-04-25T00:00:00Z",
  "sessions": [
    {
      "schema_version": 1,
      "session_id": "00000000-0000-0000-0000-000000000001",
      "session_name": "portal-00000000-0000-0000-0000-000000000001",
      "target_host": "example.internal",
      "target_port": 22,
      "target_user": "john",
      "created_at": "2026-04-25T00:00:00Z",
      "updated_at": "2026-04-25T00:10:00Z",
      "ended_at": null,
      "active": true,
      "last_output_at": "2026-04-25T00:09:59Z",
      "preview_base64": "Li4u",
      "preview_truncated": false
    }
  ]
}
```

Compatibility notes:

- `api_version` is currently `1`.
- New clients should call `portal-hub`.
- `preview_base64` is omitted when `--include-preview` is not set or logging is
  disabled.

## Sync

```sh
portal-hub sync get --format v1
```

Response:

```json
{
  "api_version": 1,
  "generated_at": "2026-04-25T00:00:00Z",
  "revision": "0",
  "profile": {
    "hosts": { "hosts": [], "groups": [] },
    "settings": {},
    "snippets": { "snippets": [] }
  },
  "vault": { "keys": [] }
}
```

Replace the sync profile only when the caller has the latest revision:

```sh
portal-hub sync put --expected-revision 0 --format v1 < sync-request.json
```

The request body is a JSON object with `profile` and `vault` fields. Portal Hub
stores `profile` as readable JSON for hosts, settings, and snippets. The `vault`
field stores encrypted private-key blobs; Portal encrypts and decrypts those
keys locally, so Hub never receives the vault passphrase or decrypted private
keys.

If `--expected-revision` is stale, the command exits non-zero and leaves the
stored profile unchanged.

## Web Auth And HTTPS Sync

Run the web server:

```sh
portal-hub web --bind 127.0.0.1:8080 --public-url https://hub.example.test
```

When no user exists, `GET /admin` presents the one-time owner setup wizard. The
wizard asks for an account name, then starts a passkey registration ceremony.

Portal desktop authenticates with OAuth authorization code + PKCE:

```text
GET /oauth/authorize?response_type=code&client_id=portal-desktop&redirect_uri=http://127.0.0.1:PORT/callback&code_challenge=...&code_challenge_method=S256&state=...
POST /oauth/token
```

The browser page served by `GET /oauth/authorize` signs the user in with a
passkey before issuing the OAuth authorization code.

The token response contains a bearer `access_token` and `refresh_token`.
Authenticated clients can call:

```text
GET /api/me
GET /api/sync
PUT /api/sync
```

`PUT /api/sync` accepts `expected_revision`, `profile`, and `vault`. A stale
revision returns HTTP `409 Conflict`.

## Attach

```sh
portal-hub attach \
  --session-id 00000000-0000-0000-0000-000000000001 \
  --target-host example.internal \
  --target-port 22 \
  --target-user john \
  --cols 120 \
  --rows 30
```

Attach uses the process standard input/output as the terminal stream. Closing
the client detaches. Exiting the remote shell ends the session.

## Doctor

```sh
portal-hub doctor --json
```

Reports dependency and state directory checks. A non-zero exit code means one or
more checks failed.

## Prune

```sh
portal-hub prune --dry-run
portal-hub prune --ended-older-than-days 14 --max-log-bytes 16777216
```

Prune prints a JSON report with deleted sessions, truncated logs, and reclaimed
bytes.

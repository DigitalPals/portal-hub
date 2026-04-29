# Portal Hub API v2 Contract

These JSON Schemas are the canonical wire contract for Portal Hub API v2.
Portal desktop and Portal Android should reject unsupported `api_version`
values, but must tolerate additive response fields inside a supported version.

Request schemas are intentionally stricter than response schemas. Responses use
`additionalProperties: true` so Hub can add non-breaking fields without forcing
client upgrades.

Covered surfaces:

- `GET /api/info`
- `GET /api/sessions`
- `DELETE /api/sessions/{id}`
- `GET /api/sessions/terminal` WebSocket start and server control messages
- `GET /api/sync/v2`
- `PUT /api/sync/v2`
- `GET /api/sync/v2/events` SSE event payloads
- Vault enrollment create/list/get/approve payloads

Compatibility rule of thumb:

- Increment `api_version` for breaking wire changes.
- Add fields without incrementing `api_version` only when existing clients can
  safely ignore them.
- Keep enum expansion conservative; older clients may not understand new
  values even when the schema allows them.

# Security Architecture

This document describes the security controls built into WP File Security Pro.

---

## File serving

Protected files are never served directly by the web server. All requests to zone directories are intercepted by WordPress (via `.htaccess` on Apache, or manual `location` blocks on NGINX) and routed through the plugin's PHP handler. The handler:

1. Verifies the nonce (CSRF token).
2. Resolves the requested path with `realpath()` and confirms it is inside the zone directory (prevents path traversal).
3. Checks the user's roles against the zone's allowlist.
4. Streams the file with `readfile()` if access is granted, or shows the denial screen if not.

`X-Robots-Tag: noindex, nofollow` is sent on all file responses.

---

## Path traversal prevention

All path resolution uses `realpath()`. The resolved path must equal the zone root or start with `{zone_root}{DIRECTORY_SEPARATOR}`. This prevents:

- `../` sequences traversing above the zone directory.
- Sibling directory bypass (e.g. `/zone-extra` matching a zone named `/zone`).

---

## Login redirect tokens

`[rbfa_login_link]` uses opaque random tokens stored in short-lived transients (15 minutes). The URL contains only the token — no file path, zone slug, or role information is exposed. After login, the token is consumed (deleted) and access is re-evaluated from scratch.

---

## Redirect URL validation

Zone redirect URLs and the global login URL are validated on save:

- Absolute URLs must start with `http://` or `https://` and pass `esc_url_raw()`.
- Relative paths must start with `/`.
- Any other value (e.g. `javascript:`, `data:`, bare slugs without a leading slash) is rejected and stored as an empty string.

---

## Denial screen HTML

Denial screen HTML is filtered through `wp_kses_post` on both save and read-back. This allows standard formatting tags and inline styles while stripping `<script>` tags, event attributes (`onclick`, etc.), and other vectors.

---

## SQL injection prevention

- All user-supplied filter values use `$wpdb->prepare()` with `%s` placeholders.
- `LIKE` values are escaped with `$wpdb->esc_like()` before binding.
- `ORDER BY` column and direction are validated against a server-side whitelist before being interpolated into the query.

---

## CSRF protection

Every admin form submission includes a WordPress nonce. Nonces are verified before any data is read or written. Download URLs (ZIP and direct file) also include nonces verified before any file content is sent.

---

## Capability gating

The plugin admin panel requires the `manage_wfsp` capability. All POST handlers re-verify this capability before processing. CSV export and ZIP download also enforce the relevant capability checks.

---

## Content-Disposition filenames

Filenames in `Content-Disposition: attachment` headers are passed through `sanitize_file_name()` to strip characters that could be misinterpreted by browsers or proxies (CR, LF, quotes, path separators).

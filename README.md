# WP File Security Pro

A WordPress plugin for role-based file access control. Restrict upload folders to specific user roles, serve files securely through PHP, log all access attempts, and manage custom roles and denial screens — all from a dedicated admin panel.

---

## Features

### Access Control
- **Zone-based protection** — Define named zones (subfolders inside your uploads directory) and assign allowed roles to each. Files are served through PHP, not directly by the web server, so direct URL access is blocked regardless of link sharing
- **Per-zone denial screens** — Create custom HTML pages shown to blocked users, with full control over styling and messaging
- **Per-zone redirect option** — Alternatively, redirect denied users to any URL (e.g. a sales page or membership signup) instead of showing a denial screen
- **Login redirect shortcode** — Add `[rbfa_login_link]` to any denial screen to insert a secure login link that returns the user to the originally-requested file after authentication. Supports alternative login pages (WooCommerce My Account, custom login pages, etc.)
- **X-Robots-Tag header** — All served files include `X-Robots-Tag: noindex, nofollow` to prevent search engine indexing of protected content

### Access Logging
- Full access log with timestamp, username (including guest/unauthenticated users), IP address, file path, and status (Granted / Denied)
- **Filtering** — Datetime range (single `datetime-local` pickers for From and To, supporting one-sided ranges), username, IP address, file path, and status
- **Sortable columns** — Time, IP, Path, and Status — ascending and descending
- **Configurable pagination** — 10, 25, 50, 100, 250, 500, or All rows per page (default 25)
- **CSV export** — Carries all active filters and current sort order; always exports the full dataset regardless of pagination
- **Stats widget** — At-a-glance Granted / Denied / Total counts with a 7-day activity sparkline

### Log Pruning
- **Automatic pruning** — Configure a retention period (days) and enable a daily cron job to delete old entries automatically
- **Manual pruning** — One-click prune button on the Logs tab with confirmation dialog

### Role Management
- Create and manage custom WordPress roles directly from the plugin via a modal dialog
- All plugin-managed roles are prefixed `wfsp_` and persist across plugin reinstalls (stored in `wp_options`, not plugin tables)
- Filter roles by name or by member username on the Roles tab; paginated list (10 per page)
- Add multiple users to a role at once via a searchable, paginated modal
- Remove users from managed roles
- Rename and delete managed roles (built-in WordPress roles are displayed read-only)
- `WFSP Admins` system role — grants access to the plugin admin panel without full administrator access; protected from rename and delete

### File System Integrity
- **`.htaccess` generation** — Automatically writes rewrite rules into all protected zone directories and subdirectories
- **Deep scan** — Recursively checks for missing or incorrect `.htaccess` files across the entire protected tree
- **Hourly cron** — Optionally enable automatic repair of missing or corrupted `.htaccess` files
- **NGINX support** — When NGINX is detected, a dedicated tab generates ready-to-copy `location` blocks covering all configured zones

### Zone Pages
- Each zone automatically gets a front-end page at `/protected-zone/{slug}/`
- No WordPress posts created — pages are served via a custom rewrite rule entirely within the plugin
- Per-zone page title and body content editable from the Zones tab via a split-pane modal editor with live HTML preview and a link to preview the live page
- Page content supports standard HTML and shortcodes (no scripts); sanitised with `wp_kses_post` on save
- Access enforced by the same role/redirect/denial logic as file requests
- Optional site theme wrapping — toggle between themed output and a minimal standalone page in Settings

### Admin Panel
- Top-level WordPress sidebar menu with `manage_wfsp` capability gate
- **Logs tab** — Filtered, sortable, paginated access log with stats widget and export
- **Zones tab** — Zone management with filtering, pagination, two denial screens per zone (anonymous and logged-in), per-zone redirect URLs, file count/size display, unsaved-changes warnings, and automatic detection of unmanaged directories
- **Roles/Users tab** — Custom role and user management with paginated member modal
- **Denial Screens tab** — New/Edit screens in a modal; label filter; pagination (10 per page); HTML editor with sandboxed live preview and unsaved-changes warnings
- **Settings tab** — System settings, zone page theme toggle, log retention configuration, data management, and configuration export/import
- **NGINX Config tab** — Appears automatically when NGINX is detected

---

## Requirements

- WordPress 5.8 or higher
- PHP 7.4 or higher
- Apache with `mod_rewrite` enabled, **or** NGINX (with manual server block configuration)

---

## Installation

1. Download or clone this repository into your WordPress plugins directory:
   ```
   wp-content/plugins/wp-file-security-pro/
   ```
2. Activate the plugin from **Plugins → Installed Plugins** in the WordPress admin
3. Navigate to **WP File Security Pro** in the sidebar to begin configuration

---

## Configuration

### 1. System Settings

Go to **Settings tab** and set your base directory — the folder inside `wp-content/uploads/` that will contain all your protected zones:

```
wp-content/uploads/protected/
```

Optionally enable the hourly `.htaccess` integrity repair cron and configure log retention.

### 2. Create Zones

On the **Zones tab**, add zone rows. Each zone maps a subfolder to a set of allowed roles:

```
uploads/protected/members/     → members role
uploads/protected/premium/     → premium, editor roles
```

For each zone you can select separate denial screens for anonymous and logged-in users, or choose **Redirect to URL**. Logged-in users can also be redirected to a different URL. Click **Save & Sync Zones** to write the configuration, generate `.htaccess` files, and create the zone's directory if it doesn't exist yet.

Each saved zone also gets a front-end page at `/protected-zone/{slug}/`. Click **Edit Page** in the slug cell to customise the title and body content using the split-pane editor.

### 3. Display Files (Optional)

Use the `[folder_files]` shortcode on any page or post to show a browsable, downloadable file list to authorized users:

```
[folder_files folder="members"]
```

### 4. NGINX (if applicable)

If your server runs NGINX, navigate to the **NGINX Config tab** for a generated `location` block. Without this, `.htaccess` files have no effect and files will not be protected.

---

## Login Redirect Shortcode

Add `[rbfa_login_link]` to any denial screen HTML to insert a login link that returns the user to the originally-requested file after successful authentication.

**How it works:**
1. An opaque random token is generated and stored in a short-lived transient (15 minutes)
2. The link points to the configured login page with only the token in the URL — no file path, role, or zone information is exposed
3. After login, access is re-checked. If the user now has access the file is served; if not, the denial screen is shown again with a fresh token

**Attributes (optional):**
```
[rbfa_login_link text="Sign in to download" logout_text="Try a different account"]
```

If the user is already logged in with the wrong role, the link logs them out first and redirects to the login page with the token preserved, so they can authenticate as a different account.

Configure the login page URL per denial screen to support WooCommerce My Account, custom login pages, or any other alternative login setup.

---

## Access Logging

All file requests are logged under the **Logs tab**. The table is filterable, sortable, and paginated.

| Field | Description |
|---|---|
| Time | Date and time of the request |
| User | WordPress username, or `Guest` for unauthenticated requests |
| IP | Client IP address |
| Path | Relative path to the requested file |
| Status | `Granted` or `Denied` |

Guest (unauthenticated) users are fully searchable by typing `guest` in the username filter. Exports always return the complete filtered dataset and preserve the current sort order.

---

## NGINX Configuration

When NGINX is detected, the **NGINX Config tab** provides a warning that `.htaccess` rules are ignored by NGINX, a combined `location` regex block covering all zones, and individual per-zone blocks for complex configurations. After adding the config and running `sudo nginx -s reload`, test by accessing a protected file directly — WordPress should intercept the request.

---

## Security Notes

- Files are served through PHP (`readfile`) — the web server never delivers protected files directly
- `X-Robots-Tag: noindex, nofollow` is sent on all served file responses
- CSRF protection on every admin form via WordPress nonces
- All role and zone operations validated against a managed-role allowlist
- Path traversal prevented by `realpath()` boundary check before any file is served
- Login redirect tokens are opaque — no file path, role, or zone information is in the URL
- Denial screen HTML filtered through a strict `wp_kses` allowlist on both save and read-back
- All `ORDER BY` clauses use a server-side whitelist to prevent SQL injection

---

## Data Management

By default, deactivating or deleting the plugin preserves all data. To enable cleanup on deletion, go to **Settings → Data Management**, check **Remove all plugin data when the plugin is deleted**, and save. Deactivation alone never deletes data.

---

## File Structure

```
wp-file-security-pro/
├── wp-role-folder-protection.php   Entry point — constants and requires
├── uninstall.php                   Data cleanup on plugin deletion
├── includes/
│   ├── class-rbfa-db.php           Database setup, activation/deactivation hooks
│   ├── class-rbfa-zones.php        Zone helpers, .htaccess sync, cron, log pruning
│   ├── class-rbfa-access.php       Access control, file serving, login redirect shortcode
│   ├── class-rbfa-shortcode.php    [folder_files] shortcode
│   └── class-rbfa-export.php       CSV export (hooked to admin_init)
└── admin/
    ├── class-rbfa-admin.php        Menu, assets, POST handlers, tab dispatcher
    └── tabs/
        ├── tab-logs.php            Logs tab
        ├── tab-zones.php           Zones tab
        ├── tab-roles.php           Roles/Users tab
        ├── tab-denial.php          Denial Screens tab
        ├── tab-settings.php        Settings tab
        └── tab-nginx.php           NGINX Config tab
```

---

## Changelog

### 1.1.2
- Settings tab: added Export / Import section — export zones, roles, denial screens, and settings to a JSON file; import from a JSON file with per-section checkboxes, automatic conflict detection (slug/label/role key collisions), and a review screen with Keep existing / Use imported resolution per conflict; role users always merged; only users that exist in the target WordPress install are added on import
- [folder_files] shortcode: Download Current Directory and Download All clicks now recorded in the access log with `[zip]` / `[zip:all]` path prefix, filterable in the Logs tab
- Fixed `[rbfa_zone_link]` shortcode returning empty when used in a denial screen triggered by a zone page request (`/protected-zone/{slug}/`) rather than a direct file request

### 1.1.1
- Roles tab: Create Role moved to modal; added role name and member filters; added pagination (10 per page)
- Denial Screens tab: New/Edit form moved to modal; added label filter; added pagination (10 per page); shortcode reference boxes converted to collapsed accordions
- Zones tab: Unmanaged directories in the base folder are now detected and shown as pre-populated rows ready to save
- Logs tab: Date From / Date To replaced with single `datetime-local` pickers supporting one-sided ranges
- Settings tab: Integrity Repair checkbox defaults to checked and persists across zone saves
- Security: rejected non-`/` relative redirect paths (`javascript:`, `data:`, etc.); `sanitize_file_name()` applied to Content-Disposition filenames; login-redirect token delete made conditional on transient existence; ZIP path boundary check hardened with `DIRECTORY_SEPARATOR` suffix to prevent sibling-directory bypass; removed misleading `str_replace('..',…)` defense in ZIP handler
- Help: all admin contextual help tabs updated to reflect current feature set

### 1.1.0
- Added `WFSP Admins` role — grants plugin admin access without full administrator; protected from rename and delete
- All plugin-managed roles prefixed `wfsp_` and survive reinstall (stored in `wp_options`)
- Added multi-user member modal on Roles tab — searchable, paginated, multi-select
- Added separate anonymous and logged-in denial screens per zone
- Added redirect-to-URL option for logged-in users per zone
- Added zone virtual pages at `/protected-zone/{slug}/` — no WordPress posts created; served via rewrite rules
- Added per-zone page title and body editor (split-pane modal with live HTML preview and live-page link)
- Added zone page theme toggle in Settings — choose between themed (active theme header/footer) and minimal standalone output
- Added file count and total size display per zone on the Zones tab
- Added `[folder_files]` shortcode with collapsible subdirectories, per-directory file counts, sizes, and ZIP download buttons
- Fixed base directory reverting to default on zone save
- Fixed zone directory not being created on save
- Fixed `wp_magic_quotes` slash accumulation in page editor and denial screen editor on repeated save/edit cycles
- Fixed zone virtual page 404 — rewrite rule now self-heals on first admin page load if the activation flush was missed

### 1.0.5
- Added configurable log pruning — auto daily cron and manual button
- Added NGINX Config tab with generated server block configuration
- Added stats dashboard widget with 7-day activity sparkline
- Added `X-Robots-Tag: noindex, nofollow` to all served file responses
- Added per-zone redirect-to-URL option as an alternative to denial screens
- CSV export now preserves the current sort order

### 1.0.4
- Added Settings tab consolidating System Settings and Data Management
- Fixed `[rbfa_login_link]` `text` and `logout_text` attributes
- Improved alternative login page URL support
- Extended zones dirty flag to slug, role, and denial screen changes
- Added unsaved-changes warning to Denial Screens tab

### 1.0.3
- Fixed zone saves — nested form bug was silently discarding role and denial screen selections
- Fixed missing `rbfa_default` row on fresh activation causing zones to not save
- Moved all POST handlers to `admin_init` — resolves headers-already-sent errors
- Added Post/Redirect/Get pattern for all form submissions
- Added success notice after saving zones
- Added `uninstall.php` for optional data cleanup
- Replaced source preview with sandboxed `<iframe srcdoc>` rendered preview

### 1.0.2
- Added `[rbfa_login_link]` shortcode with opaque token redirect system
- Added per-denial-screen login page URL configuration
- Sortable log columns, date+time filters, configurable pagination
- Fixed CSV export headers-already-sent error
- Fixed guest user search in logs filter
- Modern pagination UI

### 1.0.1
- Initial release — zone access control, access logging, denial screens, role management, `.htaccess` integrity cron

---

## License

GNU General Public License v3.0 (GPL-3.0)

This plugin is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.html) for full details.

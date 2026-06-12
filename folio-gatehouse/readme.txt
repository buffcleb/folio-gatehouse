=== Folio Gatehouse ===
Contributors: buffcleb
Tags: file protection, access control, role-based access, download protection, membership
Requires at least: 5.8
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.1.7
License: GPL-3.0-or-later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Role-based file access control. Restrict upload folders to specific user roles, serve files securely through PHP, and log every access attempt.

== Description ==

Folio Gatehouse lets you protect files inside your uploads directory by restricting access to specific WordPress user roles. Files are served through PHP — the web server never delivers them directly — so direct URL access is blocked regardless of link sharing.

**Key features:**

* **Zone-based protection** — define named zones (subfolders inside your uploads directory) and assign allowed roles to each
* **Custom denial screens** — create HTML pages shown to blocked users, with full control over styling and messaging; separate screens for anonymous and logged-in users
* **Redirect on denial** — optionally redirect denied users to any URL (e.g. a sales page or membership signup) instead of showing a denial screen
* **Login redirect shortcode** — `[rbfa_login_link]` inserts a secure login link that returns the user to the originally-requested file after authentication, using an opaque token so no file path is exposed in the URL
* **Zone virtual pages** — each zone automatically gets a front-end page at `/protected-zone/{slug}/` with customisable title and body content, rendered inside your active theme
* **Browsable file listing** — `[rbfa_files]` shortcode renders a collapsible, downloadable file listing for authorised users, with per-directory file counts, sizes, and ZIP download buttons
* **Access logging** — every request is logged with timestamp, username, IP, file path, and status; filterable, sortable, and exportable as CSV
* **Role management** — create and manage custom WordPress roles (`fgh_` prefix) directly from the plugin, with searchable member management
* **`.htaccess` integrity** — automatically writes and repairs rewrite rules across all protected directories; optional hourly cron
* **NGINX support** — dedicated tab generates ready-to-copy `location` blocks when NGINX is detected
* **Export / Import** — back up and transfer zones, roles, denial screens, and settings as a JSON file; conflict resolution on import

= Security =

* Files served through PHP (`readfile`) — web server never delivers protected files directly
* Path traversal blocked by `realpath()` boundary check before any file is served
* Login redirect tokens are opaque — no file path, role, or zone information in the URL
* Denial screen HTML filtered through a strict `wp_kses` allowlist on save and read-back
* CSRF protection on every form via WordPress nonces
* All `ORDER BY` clauses use a server-side whitelist to prevent SQL injection

= Requirements =

* Apache with `mod_rewrite` enabled, **or** NGINX (with manual server block configuration — see the NGINX Config tab)

== Installation ==

1. Upload the `folio-gatehouse` folder to `wp-content/plugins/`
2. Activate the plugin from **Plugins → Installed Plugins**
3. Navigate to **Folio Gatehouse** in the sidebar
4. Go to **Settings** and set your base directory (the folder inside `wp-content/uploads/` that will contain all protected zones)
5. Go to **Zones** and add zone rows — assign a folder slug and the roles that may access it
6. Click **Save & Sync Zones**

If you are running NGINX, visit the **NGINX Config** tab for the server block rules you need to add before protection takes effect.

== Frequently Asked Questions ==

= Does this work with NGINX? =

Yes, but you need to add server block rules manually. The plugin detects NGINX and shows a dedicated tab with ready-to-copy `location` blocks.

= Will my files be accessible via direct URL? =

Not after `.htaccess` rules are in place (Apache) or after you add the NGINX `location` blocks. All matched requests are routed through WordPress and through the plugin's access check before any file content is returned.

= What happens to my data if I deactivate or delete the plugin? =

Deactivation never deletes any data. Deletion only removes data if you explicitly enable that option in **Settings → Data Management**.

= Can I show different denial messages to guests vs logged-in users? =

Yes. Each zone has separate denial screen dropdowns for anonymous visitors and logged-in users who lack the required role.

= Can I use this to protect files for a WooCommerce membership? =

Yes. Create a custom role for your members (or use an existing WooCommerce role), assign it to a zone, and the plugin will enforce access on every file request.

= Does the login redirect shortcode work with custom login pages? =

Yes. Configure the login page URL per denial screen (supports absolute URLs and relative paths like `/my-account`).

== Screenshots ==

1. Zones tab — manage protected directories and assign roles
2. Logs tab — filterable, sortable access log with stats widget
3. Roles tab — create and manage custom roles with member management
4. Denial Screens tab — HTML editor with live sandboxed preview
5. Settings tab — system settings, export/import, and data management

== Changelog ==

= 1.1.7 =
* Standardised all public shortcodes on the plugin's 4-character `rbfa_` prefix: `[rbfa_files]`, `[rbfa_login_link]`, `[rbfa_zone_link]` (meets WordPress.org prefix-length guideline)
* DB migration (v1.9) rewrites shortcode names in existing zone pages and denial screens automatically on upgrade
* Role renames now use core `remove_role()`/`add_role()` instead of a direct `wp_user_roles` option write

= 1.1.6 =
* All plugin-managed role slugs migrated from fsg_ prefix to fgh_ prefix; DB migration (v1.8) renames existing roles, moves user assignments, and updates zone allowed-roles JSON automatically on upgrade
* System role renamed from FSG Admins (fsg_admins) to FGH Admins (fgh_admins)

= 1.1.5 =
* Renamed shortcodes to fgh_ prefix: [fgh_files], [fgh_login_link], [fgh_zone_link]; fsg_ and older names kept as backwards-compatible aliases
* DB migration (v1.7) updates existing zone pages and denial screens to new shortcode names

= 1.1.4 =
* Renamed plugin to Folio Gatehouse (slug folio-gatehouse, text domain folio-gatehouse)
* Fixed shortcode callback: escape size_format() output with esc_html() in file listing
* Added nonce verification to CSV export handler (CSRF protection)
* Sanitize $_SERVER['REQUEST_URI'] before use in access log and path derivation

= 1.1.3 =
* Renamed plugin to Folio Gatehouse (slug folio-sentrygate)
* Role prefix wfsp_ renamed to fsg_; automatic migration on upgrade
* Shortcodes renamed: [fsg_files], [fsg_login_link], [fsg_zone_link]; old names kept as aliases
* Fixed inline stylesheet in zone preview iframe

= 1.1.2 =
* Added Export / Import feature on the Settings tab — export zones, roles, denial screens, and settings to a JSON file; import with conflict detection and per-item resolution; role users always merged; only users that exist in the target install are added
* [folder_files] ZIP download buttons now recorded in the access log with `[zip]` / `[zip:all]` path prefix
* Fixed `[rbfa_zone_link]` returning empty when used in a denial screen triggered by a zone page request

= 1.1.1 =
* Roles tab: Create Role moved to modal; role name and member filters; pagination
* Denial Screens tab: New/Edit form moved to modal; label filter; pagination; shortcode reference cards collapsed by default
* Zones tab: unmanaged directories in the base folder detected and shown as pre-populated rows
* Logs tab: Date From / Date To replaced with single datetime-local pickers supporting one-sided ranges
* Settings tab: Integrity Repair defaults to checked and persists across zone saves
* Security: reject non-`/` relative redirect paths; `sanitize_file_name()` on Content-Disposition headers; conditional transient delete; ZIP boundary check hardened

= 1.1.0 =
* Added FSG Admins system role — plugin admin access without full administrator
* Added multi-user member modal on Roles tab
* Added separate anonymous and logged-in denial screens per zone
* Added redirect-to-URL option for logged-in users per zone
* Added zone virtual pages at `/protected-zone/{slug}/`
* Added per-zone page editor (split-pane modal with live preview)
* Added zone page theme toggle in Settings
* Added file count and total size display per zone
* Added `[folder_files]` shortcode with collapsible subdirectories and ZIP downloads
* Fixed base directory reverting on zone save
* Fixed `wp_magic_quotes` slash accumulation in editors

= 1.0.5 =
* Added configurable log pruning — auto daily cron and manual button
* Added NGINX Config tab with generated server block configuration
* Added stats dashboard widget with 7-day sparkline
* Added `X-Robots-Tag: noindex, nofollow` on all file responses
* Added per-zone redirect-to-URL option

= 1.0.4 =
* Added Settings tab consolidating system settings and data management
* Fixed `[rbfa_login_link]` attribute handling
* Extended zones dirty flag to slug, role, and denial screen changes

= 1.0.3 =
* Fixed zone saves — nested form bug silently discarding selections
* Moved all POST handlers to `admin_init`
* Added Post/Redirect/Get pattern for all form submissions
* Added sandboxed iframe preview for denial screens

= 1.0.2 =
* Added `[rbfa_login_link]` with opaque token redirect system
* Sortable log columns, date+time filters, configurable pagination
* Fixed CSV export headers-already-sent error

= 1.0.1 =
* Initial release

== Upgrade Notice ==

= 1.1.7 =
Public shortcodes renamed to the rbfa_ prefix: [rbfa_files], [rbfa_login_link], [rbfa_zone_link]. A migration rewrites stored zone pages and denial screens automatically; update any of these shortcodes that you typed directly into regular posts or pages.

= 1.1.6 =
Renames all plugin-managed roles from fsg_ to fgh_ prefix automatically on first load. DB migration (v1.8) handles all installs including those upgrading from wfsp_ via fsg_.

= 1.1.5 =
Renames shortcodes to fgh_ prefix. Existing fsg_ and older shortcode names remain registered as backwards-compatible aliases — no manual changes needed on existing pages.

= 1.1.4 =
Plugin renamed to Folio Gatehouse. Security fixes: nonce added to CSV export, REQUEST_URI sanitized, size_format() output escaped.

= 1.1.3 =
Role prefix changed from wfsp_ to fsg_; automatic migration runs on upgrade. Shortcodes renamed — old names remain as aliases.

= 1.1.2 =
Adds export/import, ZIP download logging, and a fix for `[rbfa_zone_link]` on zone pages. Safe to upgrade — no database changes.

= 1.1.1 =
UI improvements across Roles, Denial Screens, Zones, and Logs tabs plus security hardening. Safe to upgrade — no database changes.

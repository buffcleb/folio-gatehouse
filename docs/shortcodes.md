# Shortcodes

The plugin provides three shortcodes, all using the `rbfa_` prefix:

| Shortcode | Purpose |
|---|---|
| `[rbfa_files]` | Browsable, downloadable file listing for a zone |
| `[rbfa_login_link]` | Secure login link for use inside denial screens |
| `[rbfa_zone_link]` | Link to a zone's virtual front-end page |

Earlier names (`fgh_*`, `fsg_*`, `folder_files`) are no longer registered. On upgrade, a database migration automatically rewrites these names in stored zone pages and denial screens. If you used an older name directly in a regular post or page, update it to the `rbfa_` form.

---

## `[rbfa_files]`

Renders a browsable, downloadable file listing for a named zone. Only users whose roles match the zone's allowlist (or administrators) see the listing. All others see nothing.

```
[rbfa_files folder="members"]
```

**Attributes:**

| Attribute | Required | Description |
|---|---|---|
| `folder` | Yes | The zone's folder slug |

**Output:**

- A header bar showing the file count and total size of the zone root, with **Download Current Directory** and **Download All** buttons.
- A flat list of files in the zone root, each with a download link and file size.
- Subdirectories as collapsed `<details>` sections. Each shows file count, total size, and a **Download All** button. Expanding a section reveals its files and nested subdirectories.

Download buttons stream a ZIP archive. The archive is built on the fly and is never written to a public path.

---

## `[rbfa_login_link]`

Inserts a secure login link inside a denial screen. Returns the user to the originally-requested file after successful authentication.

```
[rbfa_login_link text="Sign in to download" logout_text="Try a different account"]
```

**Attributes:**

| Attribute | Default | Description |
|---|---|---|
| `text` | `Log in to access this file` | Link text for unauthenticated visitors |
| `logout_text` | `Log in with a different account` | Link text for logged-in visitors who lack the required role |

Only renders inside a denial screen served by the plugin's access-control handler. Has no output on regular pages.

See [Denial Screens → Shortcodes](denial-screens.md#shortcodes) for full details on the token-based redirect flow.

---

## `[rbfa_zone_link]`

Inserts a link to the zone's virtual front-end page. Only renders inside a denial screen served by the plugin.

```
[rbfa_zone_link text="Visit the members area"]
```

**Attributes:**

| Attribute | Default | Description |
|---|---|---|
| `text` | `Visit the zone page` | Link text |

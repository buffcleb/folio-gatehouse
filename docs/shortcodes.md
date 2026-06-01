# Shortcodes

The plugin provides three shortcodes. All previous names remain registered as backwards-compatible aliases:

| Current name | Aliases (still work) |
|---|---|
| `[fgh_files]` | `[fsg_files]`, `[folder_files]` |
| `[fgh_login_link]` | `[fsg_login_link]`, `[rbfa_login_link]` |
| `[fgh_zone_link]` | `[fsg_zone_link]`, `[rbfa_zone_link]` |

---

## `[fgh_files]`

Renders a browsable, downloadable file listing for a named zone. Only users whose roles match the zone's allowlist (or administrators) see the listing. All others see nothing.

```
[fgh_files folder="members"]
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

## `[fgh_login_link]`

Inserts a secure login link inside a denial screen. Returns the user to the originally-requested file after successful authentication.

```
[fgh_login_link text="Sign in to download" logout_text="Try a different account"]
```

**Attributes:**

| Attribute | Default | Description |
|---|---|---|
| `text` | `Log in to access this file` | Link text for unauthenticated visitors |
| `logout_text` | `Log in with a different account` | Link text for logged-in visitors who lack the required role |

Only renders inside a denial screen served by the plugin's access-control handler. Has no output on regular pages.

See [Denial Screens → Shortcodes](denial-screens.md#shortcodes) for full details on the token-based redirect flow.

---

## `[fgh_zone_link]`

Inserts a link to the zone's virtual front-end page. Only renders inside a denial screen served by the plugin.

```
[fgh_zone_link text="Visit the members area"]
```

**Attributes:**

| Attribute | Default | Description |
|---|---|---|
| `text` | `Visit the zone page` | Link text |

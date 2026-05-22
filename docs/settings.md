# Settings

The **Settings tab** consolidates all system-level configuration.

---

## System Settings

### Base Directory

The subdirectory inside `wp-content/uploads/` that contains all protected zone folders.

```
protected
```

Results in: `wp-content/uploads/protected/`

### Integrity Repair

When checked, an hourly cron job automatically repairs missing or incorrect `.htaccess` files across all zone directories. Default is **on**.

This setting persists independently of zone saves — saving or modifying zones does not change the Integrity Repair value.

### Login Page URL (global default)

The URL of your login page. Used when no per-denial-screen login URL is set. Leave blank to use the WordPress default (`/wp-login.php`). Accepts absolute URLs and bare slugs (e.g. `/my-account`).

---

## Zone Page Settings

### Theme

Controls how zone virtual pages (`/protected-zone/{slug}/`) are rendered:

- **Use active theme** — wraps the page in your theme's `header.php` and `footer.php`.
- **Minimal standalone** — renders only the page content with minimal boilerplate (no theme styles or scripts).

---

## Log Retention

### Retention Period (days)

Records older than this many days are eligible for deletion. Set to `0` to disable automatic pruning.

### Enable Auto-Prune Cron

When checked, a daily WordPress cron job deletes records older than the retention period.

### Prune Now

Click **Prune Logs** to immediately delete all records older than the configured retention period. A confirmation dialog shows the number of records that will be removed.

---

## Data Management

By default, deactivating or deleting the plugin preserves all data (zones, logs, roles, denial screens).

Check **Remove all plugin data when the plugin is deleted** to enable cleanup on deletion. Deactivation alone never deletes data.

---

## Export / Import

### Export

Select which sections to include — **Zones**, **Roles**, **Denial Screens**, **Settings** — and click **Export**. The browser downloads `wfsp-export-YYYY-MM-DD.json`.

Zone rows store denial screen references as label strings rather than database IDs, so the file imports correctly on any site regardless of ID numbering. Use exports to back up your configuration before major changes or to replicate a setup across multiple WordPress installations.

### Import

1. Choose a `.json` file previously exported from this plugin.
2. Select which sections to import using the checkboxes.
3. Click **Upload & Review**.

The plugin parses the file and checks for conflicts — any zone slug, denial screen label, or role key that already exists on this site. If conflicts are found, a review screen lists each one with a choice:

- **Keep existing** (default) — the imported item is skipped; the local version is unchanged.
- **Use imported** — the local item is updated with the imported data.

Non-conflicting items are always added.

**Roles**: if a role does not exist it is created. If it does exist, the display name is kept or updated per your choice. User assignments are **always merged** — any `user_login` values in the import that exist in this WordPress installation are added to the role regardless of the conflict resolution choice.

**Settings**: when included, the import overwrites the current values for base directory, integrity repair cron, zone page theme, and log retention.

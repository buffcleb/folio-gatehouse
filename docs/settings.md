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

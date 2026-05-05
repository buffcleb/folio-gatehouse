# Zones

A **zone** maps a subdirectory inside your base folder to a set of WordPress roles. Any file inside that subdirectory is protected: requests are intercepted by PHP, the visitor's roles are checked, and only authorised users receive the file.

---

## Base folder

All zones live inside a single base folder inside `wp-content/uploads/`. Set the base folder in **Settings → System Settings**. Example:

```
wp-content/uploads/protected/
```

Once saved, the plugin creates the directory if it does not exist and writes the necessary `.htaccess` rules into it.

---

## Creating a zone

1. Open the **Zones tab**.
2. Click **Add Zone** to append a new row.
3. Fill in:
   - **Zone Name** — human-readable label (display only)
   - **Folder Slug** — the subdirectory name, e.g. `members`. Must be unique and URL-safe.
   - **Allowed Roles** — one or more roles whose members can download files from this zone. Administrators always have access.
   - **Denial Screen (Anonymous)** — shown to visitors who are not logged in.
   - **Denial Screen (Logged-in)** — shown to logged-in users who lack the required role. Leave blank to fall back to the anonymous screen.
   - **Redirect (Logged-in)** — optionally redirect authorised-denied logged-in users to a URL instead of showing a denial screen.
4. Click **Save & Sync Zones**.

The plugin will:
- Create `wp-content/uploads/{base}/{slug}/` if it does not exist.
- Write `.htaccess` files into every directory and subdirectory of the zone.
- Register the zone's virtual front-end page at `/protected-zone/{slug}/`.

---

## Unmanaged directories

When you open the Zones tab, the plugin scans the base folder for directories that are not registered as zones. Each unmanaged directory appears as a pre-populated amber row at the bottom of the table. Review the settings and click **Save & Sync Zones** to register it, or click the **×** button to dismiss the row without saving.

---

## Zone virtual pages

Each saved zone automatically gets a front-end page at:

```
/protected-zone/{slug}/
```

No WordPress post is created. The page is served entirely through a custom rewrite rule. Unauthorised visitors see the zone's denial screen or redirect. Authorised users see the page content you configure.

To customise the title and body of a zone page:

1. Click the slug value in the **Folder Slug** column to open the **Edit Page** modal.
2. Edit the title and HTML body. A live preview pane updates as you type.
3. Click **Save Page** — the page editor saves independently from the zone row.

Body content supports standard HTML and shortcodes. Scripts are stripped on save (`wp_kses_post`).

The **Theme** setting in **Settings → Zone Page Settings** controls whether zone pages are wrapped in your active WordPress theme (header/footer) or rendered as minimal standalone pages.

---

## File count and size

Each zone row shows the number of files and total size of the zone directory. This includes all files in subdirectories. The count updates each time the Zones tab is loaded.

---

## Save & Sync Zones

**Save & Sync Zones** is the single action that:

1. Persists all zone rows to `wp_options`.
2. Creates any missing zone directories.
3. Writes/repairs `.htaccess` files across all zone directories.
4. Flushes rewrite rules for zone virtual pages.

If you add, remove, or change roles, always Save & Sync to apply the changes.

---

## Deleting a zone

Click the **×** button on the zone row and then **Save & Sync Zones**. The plugin removes the zone record but does **not** delete the physical directory or its files. Remove the directory manually if desired.

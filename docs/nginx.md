# NGINX Configuration

`.htaccess` files have no effect on NGINX. If your server runs NGINX, you must add server-block rules manually to route protected file requests through WordPress (and therefore through the plugin's access-control handler).

The **NGINX Config tab** appears automatically when the plugin detects that NGINX is running.

---

## Generated configuration

The tab provides two ready-to-copy blocks:

### Combined block

A single `location` regex covering all configured zones:

```nginx
location ~* ^/wp-content/uploads/protected/(members|premium|zone-slug)/(.+)$ {
    try_files $uri /index.php?$args;
}
```

Replace `protected` with your base folder slug and add each zone slug to the alternation group. Use this block for simple setups.

### Per-zone blocks

Individual `location` blocks for each zone, useful when different zones need different caching, rate-limiting, or upstream rules.

---

## Adding the config

1. Open your NGINX site configuration file (e.g. `/etc/nginx/sites-available/your-site.conf`).
2. Paste the block inside the `server {}` context, above any generic `location /` block.
3. Run:
   ```
   sudo nginx -t && sudo nginx -s reload
   ```
4. Test by visiting a protected file URL directly — WordPress should intercept the request and show the appropriate denial screen or serve the file.

---

## Verifying the setup

After adding the NGINX rules:

1. Log in as a user with the correct role and visit a protected file URL — the file should download.
2. Log out and visit the same URL — the denial screen (or redirect) should appear.
3. Check the **Logs tab** to confirm requests are being recorded.

If requests are not being intercepted, confirm the `location` block is inside the correct `server {}` context and that NGINX has been reloaded.

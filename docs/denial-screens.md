# Denial Screens

A **denial screen** is the HTML page shown to a visitor who requests a protected file or zone page but does not have the required role. You can create as many denial screens as you like and assign them to zones independently for anonymous and logged-in users.

---

## Creating a denial screen

1. Open the **Denial Screens tab**.
2. Click **New Denial Screen** to open the editor modal.
3. Fill in:
   - **Label** — internal name used to identify the screen in zone dropdowns.
   - **Login Page URL** *(optional)* — the URL of the login page to use when `[fgh_login_link]` is rendered. Leave blank to use the WordPress default login page. Supports absolute URLs and bare slugs (e.g. `/my-account`).
   - **HTML content** — the full page body. You can use standard HTML, inline CSS, and shortcodes. Scripts are stripped on save.
4. Use the **Preview** pane to see a sandboxed render of the HTML as you type.
5. Click **Save**.

---

## Editing a denial screen

Click **Edit** next to any screen in the list. The editor modal opens pre-populated with the existing content. Make your changes and click **Save**.

Closing the modal with unsaved changes triggers a confirmation prompt.

---

## Filtering and pagination

Use the **Label** filter at the top of the tab to search by name. The list paginates at 10 screens per page.

---

## Shortcodes

Two shortcodes are available inside denial screen HTML. Their reference cards are shown as collapsed accordions in the editor modal — click the arrow to expand.

### `[fgh_login_link]`

Inserts a secure login link that returns the user to the originally-requested file after authentication.

```html
[fgh_login_link text="Sign in to download" logout_text="Try a different account"]
```

**Attributes:**

| Attribute | Default | Description |
|---|---|---|
| `text` | `Log in to access this file` | Link text shown to unauthenticated visitors |
| `logout_text` | `Log in with a different account` | Link text shown to logged-in visitors who lack the required role |

**How it works:**

1. An opaque random token is stored in a 15-minute transient. Only the token appears in the URL — no file path or zone information is exposed.
2. After login, the plugin re-checks access. If the user now has access the file is served; if not, the denial screen is shown again with a fresh token.
3. If the visitor is already logged in with the wrong role, the link logs them out first, then redirects to the login page with the token preserved so they can authenticate as a different account.

### `[fgh_zone_link]`

Inserts a link to the zone's virtual front-end page.

```html
[fgh_zone_link text="View the members area"]
```

**Attributes:**

| Attribute | Default | Description |
|---|---|---|
| `text` | `Visit the zone page` | Link text |

---

## Assigning a denial screen to a zone

On the **Zones tab**, each zone row has two denial screen dropdowns:

- **Denial Screen (Anonymous)** — shown to visitors who are not logged in.
- **Denial Screen (Logged-in)** — shown to logged-in users who lack the required role. If left blank, the anonymous screen is shown.

You can also choose **Redirect to URL** as an alternative to a denial screen for logged-in users.

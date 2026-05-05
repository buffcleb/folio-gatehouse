# Roles

The **Roles/Users tab** lets you create and manage custom WordPress roles without leaving the plugin. All plugin-managed roles are prefixed `wfsp_` and stored in `wp_options`, so they survive plugin deactivation and reinstallation.

---

## WFSP Admins

`WFSP Admins` is a built-in system role created on plugin activation. Members can access the plugin's admin panel (`manage_wfsp` capability) without needing full administrator rights. This role cannot be renamed or deleted.

---

## Creating a role

1. Click **Create Role** to open the modal.
2. Enter a **Role Name** (human-readable). The slug is derived automatically (`wfsp_my_role_name`).
3. Click **Create**.

The role is created immediately and appears in the list. You can then assign it to zones.

---

## Filtering the roles list

Use the filter bar at the top of the Roles tab:

- **Role name** — partial match against the role's display name.
- **Member** — shows only roles that contain at least one user whose login, display name, or email matches the search term.

Both filters are applied together. The list paginates at 10 roles per page.

---

## Managing members

Each role row shows a member count. Click **Manage Members** to open the member modal:

- The **Add Members** pane lets you search users by login, display name, or email. Results paginate (10 per page). Check the users you want to add and click **Add Selected**.
- The **Current Members** pane lists everyone currently in the role. Click **Remove** to remove a user.

Changes take effect immediately; no Save button is needed in the member modal.

---

## Renaming and deleting roles

- **Rename** — click the pencil icon next to the role name. Enter a new display name and confirm. Only the label changes; the slug (`wfsp_*`) stays the same.
- **Delete** — click the trash icon. You will be asked to confirm. Deleting a role removes it from all users.

Built-in WordPress roles (Administrator, Editor, Author, etc.) are shown in a separate read-only section and cannot be modified from this tab.

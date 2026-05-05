<?php
/**
 * Roles/Users tab renderer.
 *
 * Displays all WordPress roles in an accordion. Managed roles (slug starts
 * with wfsp_) show additional controls: add members via modal, rename, delete
 * role, and remove individual users. Built-in roles are listed read-only.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

function rbfa_render_tab_roles() {
    $managed = rbfa_get_managed_roles();

    // All users — passed to JS for the modal.
    $all_wp_users = get_users( [ 'fields' => [ 'ID', 'user_login', 'display_name', 'user_email' ] ] );
    $all_users_js = wp_json_encode( array_values( array_map( function ( $u ) {
        return [
            'id'    => (int) $u->ID,
            'login' => $u->user_login,
            'name'  => $u->display_name,
            'email' => $u->user_email,
        ];
    }, $all_wp_users ) ) );

    // Per-role member ID lists — used to exclude existing members from the modal.
    $role_members = [];
    foreach ( $managed as $rid ) {
        $role_members[ $rid ] = array_map( 'intval', get_users( [ 'role' => $rid, 'fields' => 'ID' ] ) );
    }
    $role_members_js = wp_json_encode( $role_members );
    ?>

    <!-- ── Add Members Modal ─────────────────────────────────────────────────── -->
    <div id="rbfa-user-modal"
         style="display:none; position:fixed; inset:0; background:rgba(0,0,0,.55);
                z-index:999999; align-items:center; justify-content:center;">

        <div style="background:#fff; width:640px; max-width:92vw; max-height:82vh;
                    border-radius:6px; box-shadow:0 8px 32px rgba(0,0,0,.25);
                    display:flex; flex-direction:column; overflow:hidden;">

            <!-- Header -->
            <div style="padding:14px 20px; border-bottom:1px solid #ddd;
                        display:flex; align-items:center; gap:12px;">
                <h3 id="rbfa-modal-title" style="margin:0; flex:1; font-size:15px;">Add Members</h3>
                <button type="button" onclick="rbfaCloseModal()"
                        style="background:none; border:none; font-size:20px; cursor:pointer;
                               color:#666; line-height:1; padding:0 4px;">&times;</button>
            </div>

            <!-- Search -->
            <div style="padding:10px 20px; border-bottom:1px solid #eee;">
                <input type="text" id="rbfa-user-search"
                       placeholder="Search by username, name or email&hellip;"
                       style="width:100%; box-sizing:border-box;">
            </div>

            <!-- User list -->
            <div style="flex:1; overflow-y:auto; padding:0 20px 8px;">
                <table class="widefat" style="border:none;">
                    <thead>
                        <tr>
                            <th style="width:36px; padding:8px 4px;">
                                <input type="checkbox" id="rbfa-select-all" title="Select / deselect this page">
                            </th>
                            <th>Username</th>
                            <th>Name</th>
                            <th>Email</th>
                        </tr>
                    </thead>
                    <tbody id="rbfa-user-tbody"></tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div id="rbfa-modal-pagination"
                 style="padding:4px 20px; border-top:1px solid #eee; min-height:36px;"></div>

            <!-- Footer -->
            <div style="padding:12px 20px; border-top:1px solid #ddd;
                        display:flex; align-items:center; gap:10px; background:#f9f9f9;">
                <span id="rbfa-selected-count" style="color:#666; font-size:13px;">0 selected</span>
                <form method="post" id="rbfa-add-users-form" style="margin-left:auto; display:flex; gap:8px; align-items:center;">
                    <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
                    <input type="hidden" name="role_id" id="rbfa-modal-role-id">
                    <button type="button" onclick="rbfaCloseModal()" class="button">Cancel</button>
                    <button type="submit" name="rbfa_add_user" id="rbfa-add-btn"
                            class="button button-primary" disabled>Add Selected (0)</button>
                </form>
            </div>
        </div>
    </div>

    <!-- ── Create Role ───────────────────────────────────────────────────────── -->
    <div class="rbfa-card">
        <h3>Create Managed Role</h3>
        <p style="color:#666; font-size:13px; margin-top:0;">
            Roles created here are prefixed <code>wfsp_</code> and can be assigned to zones.
            Any existing WordPress role whose slug starts with <code>wfsp_</code> is automatically
            recognised as managed by this plugin.
        </p>
        <form method="post">
            <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
            <input type="text" name="role_name"
                   placeholder="Role display name (slug auto-prefixed wfsp_)"
                   required style="width:300px;">
            <input type="submit" name="rbfa_create_role" value="Create Role" class="button button-primary">
        </form>
    </div>

    <!-- ── Role accordions ───────────────────────────────────────────────────── -->
    <?php foreach ( wp_roles()->roles as $id => $r ) :
        $is_managed = in_array( $id, $managed, true );
        $users      = get_users( [ 'role' => $id ] );
        ?>
        <div class="rbfa-acc">
            <div class="rbfa-acc-h"
                 onclick="var c=this.nextElementSibling; c.style.display=(c.style.display==='block'?'none':'block');">
                <strong><?php echo esc_html( $r['name'] ); ?></strong>
                <span style="color:#666;">(<?php echo count( $users ); ?> user<?php echo count( $users ) !== 1 ? 's' : ''; ?>)</span>
                <?php if ( $is_managed ) : ?>
                    <span style="background:#f0f6fb; color:#2271b1; font-size:11px;
                                 padding:2px 6px; border-radius:3px; margin-left:auto;">Managed</span>
                <?php endif; ?>
            </div>

            <div class="rbfa-acc-c">
                <?php if ( $is_managed ) :
                    $is_system_role = ( $id === 'wfsp_admins' );
                ?>
                <div style="margin-bottom:15px; border-bottom:1px solid #eee;
                            padding-bottom:15px; display:flex; flex-wrap:wrap; gap:8px; align-items:center;">

                    <!-- Add Members button — opens modal -->
                    <button type="button" class="rbfa-btn rbfa-open-modal"
                            data-role-id="<?php echo esc_attr( $id ); ?>"
                            data-role-name="<?php echo esc_attr( $r['name'] ); ?>">+ Add Members</button>

                    <?php if ( ! $is_system_role ) : ?>
                    <!-- Rename form -->
                    <form method="post" style="display:inline-flex; gap:4px; align-items:center;">
                        <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
                        <input type="hidden" name="role_id" value="<?php echo esc_attr( $id ); ?>">
                        <input type="text" name="new_name" placeholder="New display name"
                               required style="width:150px;">
                        <input type="submit" name="rbfa_rename_role" value="Rename" class="rbfa-btn">
                    </form>

                    <!-- Delete role form -->
                    <form method="post" style="margin-left:auto;">
                        <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
                        <input type="hidden" name="role_id" value="<?php echo esc_attr( $id ); ?>">
                        <input type="submit" name="rbfa_delete_role" value="Delete Role"
                               class="rbfa-btn rbfa-danger"
                               onclick="return confirm('Permanently delete this role? This cannot be undone.');">
                    </form>
                    <?php else : ?>
                    <span style="font-size:12px; color:#888; margin-left:4px;">
                        System role — rename and delete are not permitted.
                    </span>
                    <?php endif; ?>
                </div>
                <?php endif; ?>

                <table class="widefat striped">
                    <thead><tr><th>Username</th><th>Name</th><th>Email</th><th>Action</th></tr></thead>
                    <tbody>
                    <?php if ( empty( $users ) ) : ?>
                        <tr><td colspan="4" style="color:#999;">No users in this role.</td></tr>
                    <?php else :
                        foreach ( $users as $u ) :
                            echo '<tr>'
                                . '<td>' . esc_html( $u->user_login ) . '</td>'
                                . '<td>' . esc_html( $u->display_name ) . '</td>'
                                . '<td>' . esc_html( $u->user_email ) . '</td>'
                                . '<td>';
                            if ( $is_managed ) {
                                echo '<form method="post" style="display:inline;">'
                                    . wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce', true, false )
                                    . '<input type="hidden" name="role_id" value="' . esc_attr( $id ) . '">'
                                    . '<input type="hidden" name="user_id" value="' . esc_attr( $u->ID ) . '">'
                                    . '<input type="submit" name="rbfa_remove_user" value="Remove"'
                                    . ' class="rbfa-btn rbfa-danger">'
                                    . '</form>';
                            } else {
                                echo '&mdash;';
                            }
                            echo '</td></tr>';
                        endforeach;
                    endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    <?php endforeach; ?>

    <?php
    // ── Modal JS ─────────────────────────────────────────────────────────────
    $modal_js = <<<JS
(function () {
    var allUsers     = {$all_users_js};
    var roleMembers  = {$role_members_js};
    var openRoleId   = null;
    var filteredList = [];   // current filtered+available users
    var selectedIds  = {};   // id (string) -> true; persists across page turns
    var currentPage  = 1;
    var PER_PAGE     = 10;

    // ── Wire up "Add Members" buttons ─────────────────────────────────────────

    document.querySelectorAll('.rbfa-open-modal').forEach(function (btn) {
        btn.addEventListener('click', function () {
            rbfaOpenModal( this.dataset.roleId, this.dataset.roleName );
        });
    });

    // ── Open / close ─────────────────────────────────────────────────────────

    window.rbfaOpenModal = function ( roleId, roleName ) {
        openRoleId  = roleId;
        selectedIds = {};
        document.getElementById('rbfa-modal-title').textContent = 'Add Members to ' + roleName;
        document.getElementById('rbfa-modal-role-id').value = roleId;
        document.getElementById('rbfa-user-search').value = '';
        document.getElementById('rbfa-select-all').checked = false;
        rbfaRenderUsers('');
        document.getElementById('rbfa-user-modal').style.display = 'flex';
        setTimeout(function(){ document.getElementById('rbfa-user-search').focus(); }, 50);
    };

    window.rbfaCloseModal = function () {
        document.getElementById('rbfa-user-modal').style.display = 'none';
        openRoleId = null;
    };

    document.getElementById('rbfa-user-modal').addEventListener('click', function (e) {
        if ( e.target === this ) rbfaCloseModal();
    });

    // ── Filter + paginate ─────────────────────────────────────────────────────

    // Recomputes filteredList from the current search query and resets to page 1.
    function rbfaRenderUsers( query ) {
        var existing  = roleMembers[ openRoleId ] || [];
        var available = allUsers.filter(function (u) {
            return existing.indexOf(u.id) === -1;
        });
        var q = query.trim().toLowerCase();
        filteredList = q ? available.filter(function (u) {
            return u.login.toLowerCase().indexOf(q) !== -1 ||
                   u.name.toLowerCase().indexOf(q)  !== -1 ||
                   u.email.toLowerCase().indexOf(q) !== -1;
        }) : available;
        rbfaRenderPage(1);
    }

    // Renders the given page of filteredList.
    function rbfaRenderPage( page ) {
        var total      = filteredList.length;
        var totalPages = Math.max(1, Math.ceil(total / PER_PAGE));
        currentPage    = Math.min(Math.max(1, page), totalPages);

        var tbody  = document.getElementById('rbfa-user-tbody');
        var start  = (currentPage - 1) * PER_PAGE;
        var pageUsers = filteredList.slice(start, start + PER_PAGE);

        if ( total === 0 ) {
            var q = document.getElementById('rbfa-user-search').value.trim();
            tbody.innerHTML = '<tr><td colspan="4" style="color:#999; text-align:center; padding:16px;">'
                + ( q ? 'No users match your search.' : 'All users are already members of this role.' )
                + '</td></tr>';
            document.getElementById('rbfa-modal-pagination').innerHTML = '';
            document.getElementById('rbfa-select-all').checked = false;
            rbfaUpdateCount();
            return;
        }

        var rows = pageUsers.map(function (u) {
            var chk = selectedIds[ u.id ] ? ' checked' : '';
            return '<tr>'
                + '<td style="padding:6px 4px;"><input type="checkbox" class="rbfa-ucb" value="' + u.id + '"' + chk + '></td>'
                + '<td style="padding:6px 8px;">' + rbfaEsc(u.login) + '</td>'
                + '<td style="padding:6px 8px;">' + rbfaEsc(u.name)  + '</td>'
                + '<td style="padding:6px 8px;">' + rbfaEsc(u.email) + '</td>'
                + '</tr>';
        });
        tbody.innerHTML = rows.join('');

        // Sync select-all to whether every user on this page is selected.
        var allChecked = pageUsers.length > 0 && pageUsers.every(function (u) { return selectedIds[ u.id ]; });
        document.getElementById('rbfa-select-all').checked = allChecked;

        tbody.querySelectorAll('.rbfa-ucb').forEach(function (cb) {
            cb.addEventListener('change', function () {
                if ( this.checked ) {
                    selectedIds[ this.value ] = true;
                } else {
                    delete selectedIds[ this.value ];
                }
                var allNowChecked = pageUsers.every(function (u) { return selectedIds[ u.id ]; });
                document.getElementById('rbfa-select-all').checked = allNowChecked;
                rbfaUpdateCount();
            });
        });

        rbfaRenderPagination(currentPage, totalPages);
        rbfaUpdateCount();
    }

    function rbfaRenderPagination( page, totalPages ) {
        var el = document.getElementById('rbfa-modal-pagination');
        if ( totalPages <= 1 ) { el.innerHTML = ''; return; }

        var html = '<div style="display:flex; align-items:center; justify-content:center; gap:6px; padding:4px 0;">';

        html += '<button type="button" class="rbfa-pg" data-page="' + (page - 1) + '"'
              + ( page <= 1 ? ' disabled' : '' ) + '>&laquo; Prev</button>';

        html += '<span style="font-size:13px; color:#666;">Page ' + page + ' of ' + totalPages + '</span>';

        html += '<button type="button" class="rbfa-pg" data-page="' + (page + 1) + '"'
              + ( page >= totalPages ? ' disabled' : '' ) + '>Next &raquo;</button>';

        html += '</div>';
        el.innerHTML = html;

        el.querySelectorAll('.rbfa-pg[data-page]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                rbfaRenderPage( parseInt( this.dataset.page, 10 ) );
            });
        });
    }

    // ── Selected count ────────────────────────────────────────────────────────

    function rbfaUpdateCount() {
        var n   = Object.keys(selectedIds).length;
        var btn = document.getElementById('rbfa-add-btn');
        document.getElementById('rbfa-selected-count').textContent = n + ' selected';
        btn.textContent = 'Add Selected (' + n + ')';
        btn.disabled    = n === 0;
    }

    // ── HTML escaping ─────────────────────────────────────────────────────────

    function rbfaEsc( str ) {
        return String(str)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // ── Search ────────────────────────────────────────────────────────────────

    document.getElementById('rbfa-user-search').addEventListener('input', function () {
        rbfaRenderUsers(this.value);
    });

    // ── Select all (current page only) ───────────────────────────────────────

    document.getElementById('rbfa-select-all').addEventListener('change', function () {
        var checked   = this.checked;
        var start     = (currentPage - 1) * PER_PAGE;
        var pageUsers = filteredList.slice(start, start + PER_PAGE);
        pageUsers.forEach(function (u) {
            if ( checked ) { selectedIds[ u.id ] = true; }
            else           { delete selectedIds[ u.id ]; }
        });
        document.querySelectorAll('.rbfa-ucb').forEach(function (cb) { cb.checked = checked; });
        rbfaUpdateCount();
    });

    // ── Form submit ───────────────────────────────────────────────────────────

    document.getElementById('rbfa-add-users-form').addEventListener('submit', function (e) {
        this.querySelectorAll('input[name="user_ids[]"]').forEach(function (el) { el.remove(); });
        var ids = Object.keys(selectedIds);
        if ( ids.length === 0 ) { e.preventDefault(); return; }
        var form = this;
        ids.forEach(function (id) {
            var inp  = document.createElement('input');
            inp.type = 'hidden';
            inp.name = 'user_ids[]';
            inp.value = id;
            form.appendChild(inp);
        });
    });
})();
JS;

    wp_register_script( 'rbfa-roles-modal', false, [], false, true );
    wp_enqueue_script( 'rbfa-roles-modal' );
    wp_add_inline_script( 'rbfa-roles-modal', $modal_js );
}

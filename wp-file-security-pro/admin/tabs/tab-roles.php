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

    // All users — passed to JS for the add-members modal.
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

    // ── Filter + pagination params ─────────────────────────────────────────────
    $f_role   = sanitize_text_field( $_GET['f_role']   ?? '' );
    $f_member = sanitize_text_field( $_GET['f_member'] ?? '' );
    $per_page = 10;
    $paged    = max( 1, (int) ( $_GET['roles_paged'] ?? 1 ) );

    $all_roles = wp_roles()->roles;

    // Filter by role display name or slug.
    if ( $f_role !== '' ) {
        $all_roles = array_filter( $all_roles, function ( $r, $id ) use ( $f_role ) {
            return stripos( $r['name'], $f_role ) !== false
                || stripos( $id,        $f_role ) !== false;
        }, ARRAY_FILTER_USE_BOTH );
    }

    // Filter by member — keep only roles that have at least one matching user.
    if ( $f_member !== '' ) {
        $all_roles = array_filter( $all_roles, function ( $r, $id ) use ( $f_member ) {
            foreach ( get_users( [ 'role' => $id ] ) as $u ) {
                if ( stripos( $u->user_login,   $f_member ) !== false
                  || stripos( $u->display_name, $f_member ) !== false
                  || stripos( $u->user_email,   $f_member ) !== false ) {
                    return true;
                }
            }
            return false;
        }, ARRAY_FILTER_USE_BOTH );
    }

    $total_roles = count( $all_roles );
    $total_pages = max( 1, (int) ceil( $total_roles / $per_page ) );
    $paged       = min( $paged, $total_pages );
    $paged_roles = array_slice( $all_roles, ( $paged - 1 ) * $per_page, $per_page, true );

    // Base args for pagination links — carry active filters.
    $link_args = [ 'page' => 'rbfa-pro', 'tab' => 'roles' ];
    if ( $f_role   !== '' ) $link_args['f_role']   = $f_role;
    if ( $f_member !== '' ) $link_args['f_member'] = $f_member;
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

    <!-- ── Create Role Modal ──────────────────────────────────────────────────── -->
    <div id="rbfa-create-role-modal"
         style="display:none; position:fixed; inset:0; background:rgba(0,0,0,.55);
                z-index:999999; align-items:center; justify-content:center;">

        <div style="background:#fff; width:440px; max-width:92vw; border-radius:6px;
                    box-shadow:0 8px 32px rgba(0,0,0,.25); overflow:hidden;">

            <!-- Header -->
            <div style="padding:14px 20px; border-bottom:1px solid #ddd;
                        display:flex; align-items:center; gap:12px;">
                <h3 style="margin:0; flex:1; font-size:15px;">Create Managed Role</h3>
                <button type="button" id="rbfa-create-role-close"
                        style="background:none; border:none; font-size:20px; cursor:pointer;
                               color:#666; line-height:1; padding:0 4px;">&times;</button>
            </div>

            <!-- Body -->
            <div style="padding:20px;">
                <p style="color:#666; font-size:13px; margin-top:0;">
                    Roles created here are prefixed <code>wfsp_</code> and can be assigned to zones.
                    Any existing WordPress role whose slug already starts with <code>wfsp_</code> is
                    automatically recognised as managed by this plugin.
                </p>
                <form method="post" id="rbfa-create-role-form">
                    <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
                    <p style="margin-bottom:6px;">
                        <label style="font-weight:600; display:block; margin-bottom:4px;">
                            Role display name
                        </label>
                        <input type="text" name="role_name" id="rbfa-new-role-name"
                               placeholder="e.g. Premium Members"
                               required
                               style="width:100%; box-sizing:border-box;">
                        <small id="rbfa-role-slug-preview" style="color:#888; display:block; margin-top:4px;">
                            Slug: <code>wfsp_</code>
                        </small>
                    </p>
                    <div style="display:flex; gap:8px; justify-content:flex-end; margin-top:12px;">
                        <button type="button" id="rbfa-create-role-cancel" class="button">Cancel</button>
                        <input type="submit" name="rbfa_create_role" value="Create Role"
                               class="button button-primary">
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- ── Toolbar: Create button + filter form ───────────────────────────────── -->
    <div class="rbfa-card" style="padding:12px 16px; margin-bottom:8px;">
        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">

            <button type="button" id="rbfa-open-create-role"
                    class="button button-primary">+ Create Managed Role</button>

            <form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>"
                  style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-left:auto;">
                <input type="hidden" name="page" value="rbfa-pro">
                <input type="hidden" name="tab"  value="roles">
                <input type="text" name="f_role"
                       value="<?php echo esc_attr( $f_role ); ?>"
                       placeholder="Filter by role name…"
                       style="width:175px;">
                <input type="text" name="f_member"
                       value="<?php echo esc_attr( $f_member ); ?>"
                       placeholder="Filter by member…"
                       style="width:175px;">
                <input type="submit" value="Filter" class="button">
                <?php if ( $f_role !== '' || $f_member !== '' ) : ?>
                    <a href="<?php echo esc_url( add_query_arg(
                        [ 'page' => 'rbfa-pro', 'tab' => 'roles' ],
                        admin_url( 'admin.php' )
                    ) ); ?>" class="button">Clear</a>
                <?php endif; ?>
            </form>
        </div>
    </div>

    <!-- Role count summary -->
    <p style="color:#666; font-size:13px; margin:0 0 8px;">
        <?php
        if ( $f_role !== '' || $f_member !== '' ) {
            printf(
                'Showing %d of %d role%s matching current filter.',
                count( $paged_roles ),
                $total_roles,
                $total_roles !== 1 ? 's' : ''
            );
        } else {
            printf(
                '%d role%s total.',
                $total_roles,
                $total_roles !== 1 ? 's' : ''
            );
        }
        ?>
    </p>

    <!-- ── Role accordions ───────────────────────────────────────────────────── -->
    <?php if ( empty( $paged_roles ) ) : ?>
        <div style="padding:20px; color:#999; text-align:center; background:#fff; border:1px solid #c3c4c7; border-radius:4px;">
            No roles match your filter.
        </div>
    <?php else :
        foreach ( $paged_roles as $id => $r ) :
            $is_managed    = in_array( $id, $managed, true );
            $is_system_role = ( $id === 'wfsp_admins' );
            $users          = get_users( [ 'role' => $id ] );
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
                    <?php if ( $is_managed ) : ?>
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
        <?php endforeach;
    endif; ?>

    <!-- ── Pagination ────────────────────────────────────────────────────────── -->
    <?php if ( $total_pages > 1 ) : ?>
        <div style="margin-top:16px; display:flex; gap:6px; align-items:center; justify-content:center;">
            <?php if ( $paged > 1 ) : ?>
                <a href="<?php echo esc_url( add_query_arg(
                    array_merge( $link_args, [ 'roles_paged' => $paged - 1 ] ),
                    admin_url( 'admin.php' )
                ) ); ?>" class="button">&laquo; Prev</a>
            <?php endif; ?>

            <span style="color:#666; font-size:13px; padding:0 4px;">
                Page <?php echo $paged; ?> of <?php echo $total_pages; ?>
            </span>

            <?php if ( $paged < $total_pages ) : ?>
                <a href="<?php echo esc_url( add_query_arg(
                    array_merge( $link_args, [ 'roles_paged' => $paged + 1 ] ),
                    admin_url( 'admin.php' )
                ) ); ?>" class="button">Next &raquo;</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    // ── Modal JS ─────────────────────────────────────────────────────────────
    $modal_js = <<<JS
(function () {
    // ── Create Role modal ─────────────────────────────────────────────────────

    var createModal  = document.getElementById('rbfa-create-role-modal');
    var nameInput    = document.getElementById('rbfa-new-role-name');
    var slugPreview  = document.getElementById('rbfa-role-slug-preview');

    function openCreateModal() {
        createModal.style.display = 'flex';
        setTimeout(function(){ nameInput.focus(); }, 50);
    }
    function closeCreateModal() {
        createModal.style.display = 'none';
    }

    document.getElementById('rbfa-open-create-role').addEventListener('click', openCreateModal);
    document.getElementById('rbfa-create-role-close').addEventListener('click', closeCreateModal);
    document.getElementById('rbfa-create-role-cancel').addEventListener('click', closeCreateModal);

    createModal.addEventListener('click', function(e){
        if ( e.target === this ) closeCreateModal();
    });

    // Live slug preview while typing.
    nameInput.addEventListener('input', function(){
        var slug = this.value
            .toLowerCase()
            .replace(/[^a-z0-9_\-\s]/g, '')
            .trim()
            .replace(/[\s_]+/g, '-');
        slugPreview.innerHTML = 'Slug: <code>wfsp_' + ( slug || '' ) + '</code>';
    });

    // ── Add Members modal ─────────────────────────────────────────────────────

    var allUsers     = {$all_users_js};
    var roleMembers  = {$role_members_js};
    var openRoleId   = null;
    var filteredList = [];
    var selectedIds  = {};
    var currentPage  = 1;
    var PER_PAGE     = 10;

    document.querySelectorAll('.rbfa-open-modal').forEach(function (btn) {
        btn.addEventListener('click', function () {
            rbfaOpenModal( this.dataset.roleId, this.dataset.roleName );
        });
    });

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

    function rbfaRenderPage( page ) {
        var total      = filteredList.length;
        var totalPages = Math.max(1, Math.ceil(total / PER_PAGE));
        currentPage    = Math.min(Math.max(1, page), totalPages);

        var tbody     = document.getElementById('rbfa-user-tbody');
        var start     = (currentPage - 1) * PER_PAGE;
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

        var allChecked = pageUsers.length > 0 && pageUsers.every(function (u) { return selectedIds[ u.id ]; });
        document.getElementById('rbfa-select-all').checked = allChecked;

        tbody.querySelectorAll('.rbfa-ucb').forEach(function (cb) {
            cb.addEventListener('change', function () {
                if ( this.checked ) { selectedIds[ this.value ] = true; }
                else                { delete selectedIds[ this.value ]; }
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

    function rbfaUpdateCount() {
        var n   = Object.keys(selectedIds).length;
        var btn = document.getElementById('rbfa-add-btn');
        document.getElementById('rbfa-selected-count').textContent = n + ' selected';
        btn.textContent = 'Add Selected (' + n + ')';
        btn.disabled    = n === 0;
    }

    function rbfaEsc( str ) {
        return String(str)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;')
            .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    document.getElementById('rbfa-user-search').addEventListener('input', function () {
        rbfaRenderUsers(this.value);
    });

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

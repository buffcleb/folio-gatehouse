<?php
/**
 * Roles/Users tab renderer.
 *
 * Displays all WordPress roles in an accordion. Roles created by this plugin
 * ("managed roles") show additional controls: add user, rename, delete role,
 * and remove individual users. Built-in roles are listed read-only.
 *
 * All destructive actions are gated behind the managed-role allowlist so a
 * crafted POST cannot affect built-in roles (administrator, editor, etc.).
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Renders the Roles/Users tab. Called from rbfa_pro_page().
 */
function rbfa_render_tab_roles() {
    $managed = rbfa_get_managed_roles();
    ?>

    <div class="rbfa-card">
        <h3>Create Managed Role</h3>
        <p style="color:#666; font-size:13px; margin-top:0;">
            Roles created here are tracked by the plugin and can be assigned to zones.
        </p>
        <form method="post">
            <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
            <input type="text" name="role_name" placeholder="Role display name" required>
            <input type="submit" name="rbfa_create_role" value="Create Role" class="button button-primary">
        </form>
    </div>

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
                    <span style="background:#f0f6fb; color:#2271b1; font-size:11px; padding:2px 6px; border-radius:3px; margin-left:auto;">Managed</span>
                <?php endif; ?>
            </div>

            <div class="rbfa-acc-c">
                <?php if ( $is_managed ) : ?>
                <div style="margin-bottom:15px; border-bottom:1px solid #eee; padding-bottom:15px; display:flex; flex-wrap:wrap; gap:8px; align-items:center;">
                    <form method="post" style="display:inline-flex; gap:4px; align-items:center;">
                        <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
                        <input type="hidden" name="role_id" value="<?php echo esc_attr( $id ); ?>">
                        <input type="text" name="user_login" placeholder="Username" required style="width:140px;">
                        <input type="submit" name="rbfa_add_user" value="Add User" class="rbfa-btn">
                    </form>
                    <form method="post" style="display:inline-flex; gap:4px; align-items:center;">
                        <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
                        <input type="hidden" name="role_id" value="<?php echo esc_attr( $id ); ?>">
                        <input type="text" name="new_name" placeholder="New display name" required style="width:140px;">
                        <input type="submit" name="rbfa_rename_role" value="Rename" class="rbfa-btn">
                    </form>
                    <form method="post" style="margin-left:auto;">
                        <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
                        <input type="hidden" name="role_id" value="<?php echo esc_attr( $id ); ?>">
                        <input type="submit" name="rbfa_delete_role" value="Delete Role"
                               class="rbfa-btn rbfa-danger"
                               onclick="return confirm('Permanently delete this role? This cannot be undone.');">
                    </form>
                </div>
                <?php endif; ?>

                <table class="widefat striped">
                    <thead><tr><th>User</th><th>Email</th><th>Action</th></tr></thead>
                    <tbody>
                    <?php if ( empty( $users ) ) : ?>
                        <tr><td colspan="3" style="color:#999;">No users in this role.</td></tr>
                    <?php else : ?>
                        <?php foreach ( $users as $u ) :
                            echo '<tr>'
                                . '<td>' . esc_html( $u->display_name ) . '</td>'
                                . '<td>' . esc_html( $u->user_email ) . '</td>'
                                . '<td>';
                            if ( $is_managed ) {
                                echo '<form method="post" style="display:inline;">'
                                    . wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce', true, false )
                                    . '<input type="hidden" name="role_id" value="' . esc_attr( $id ) . '">'
                                    . '<input type="hidden" name="user_id" value="' . esc_attr( $u->ID ) . '">'
                                    . '<input type="submit" name="rbfa_remove_user" value="Remove" class="rbfa-btn rbfa-danger">'
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
}

<?php
/**
 * Settings tab renderer.
 *
 * Consolidates site-wide plugin configuration:
 *  1. System Settings — base directory and cron integrity repair
 *     (previously on the Zones tab)
 *  2. Data Management — uninstall data retention preference
 *     (previously on the Logs tab)
 *
 * Both sections save via the POST handler in class-rbfa-admin.php
 * on admin_init, so no headers-already-sent issues occur.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Renders the Settings tab. Called from rbfa_pro_page().
 */
function rbfa_render_tab_settings() {
    global $wpdb;

    $zone_table = $wpdb->prefix . 'rbfa_zones';
    $base       = rbfa_get_base_folder();
    $upload_dir = wp_upload_dir()['basedir'];
    $issues     = rbfa_get_system_status();
    $delete_on_uninstall      = get_option( 'rbfa_delete_on_uninstall', '0' );
    $delete_roles_on_uninstall = get_option( 'rbfa_delete_roles_on_uninstall', '0' );
    ?>

    <!-- ── System Settings ───────────────────────────────────────────────────── -->
    <div class="rbfa-card" style="margin-top:20px;">
        <h3 style="margin-top:0;">System Settings</h3>
        <p style="color:#666; font-size:13px; margin-top:0;">
            Configure the base uploads directory and automatic integrity repair.
            Changes here are saved and synced to the file system immediately.
        </p>

        <?php if ( ! empty( $issues ) ) : ?>
            <div class="integrity-notice" style="margin-bottom:16px;">
                <strong>🛡️ Security Integrity Alert:</strong>
                <ul style="margin:6px 0 0 0;">
                    <?php foreach ( $issues as $issue ) :
                        echo '<li>⚠️ ' . wp_kses( $issue, [ 'code' => [] ] ) . '</li>';
                    endforeach; ?>
                </ul>
                <p style="margin:6px 0 0 0;">Save settings to trigger a full sync and repair.</p>
            </div>
        <?php else : ?>
            <div class="notice notice-success inline" style="margin-bottom:16px;">
                <p>✅ Deep scan verified: All subdirectories are protected.</p>
            </div>
        <?php endif; ?>

        <form method="post">
            <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
            <input type="hidden" name="confirm_sync" value="1">

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row">
                        <label for="rbfa-base-folder">Base Directory</label>
                    </th>
                    <td>
                        <code>uploads/</code>
                        <input id="rbfa-base-folder" type="text" name="rbfa_base_folder"
                               value="<?php echo esc_attr( $base ); ?>"
                               class="regular-text">
                        <?php echo is_dir( $upload_dir . '/' . $base )
                            ? '<span class="rbfa-status status-ok" style="margin-left:6px;">✅ Exists</span>'
                            : '<span class="rbfa-status status-err" style="margin-left:6px;">❌ Missing</span>'; ?>
                        <p class="description">
                            The folder inside <code>wp-content/uploads/</code> that contains your
                            protected zones. All zone subdirectories must live inside this folder.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Integrity Repair</th>
                    <td>
                        <label>
                            <input type="checkbox" name="cron_enabled" value="1"
                                   <?php checked( get_option( 'rbfa_cron_enabled', '1' ), '1' ); ?>>
                            Enable Hourly Integrity Auto-Repair (Cron Job)
                        </label>
                        <p class="description">
                            When enabled, WordPress will automatically re-create any missing or
                            broken <code>.htaccess</code> protection files every hour.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Zone Page Theme</th>
                    <td>
                        <label>
                            <input type="checkbox" name="rbfa_zone_page_use_theme" value="1"
                                   <?php checked( get_option( 'rbfa_zone_page_use_theme', '1' ), '1' ); ?>>
                            Wrap zone pages with the active site theme
                        </label>
                        <p class="description">
                            When enabled, <code>/protected-zone/{slug}/</code> pages are rendered
                            inside the site's active theme (header, footer, sidebar). When disabled,
                            a minimal standalone HTML page is served instead — useful if the active
                            theme conflicts with the zone page layout.
                        </p>
                    </td>
                </tr>
            </table>

                <tr>
                    <th scope="row">Log Retention</th>
                    <td>
                        <label>
                            <input type="checkbox" name="rbfa_prune_enabled" value="1"
                                   <?php checked( get_option( 'rbfa_prune_enabled', '0' ), '1' ); ?>>
                            Automatically delete log entries older than
                        </label>
                        <input type="number" name="rbfa_prune_days" min="1" max="3650"
                               value="<?php echo esc_attr( (int) get_option( 'rbfa_prune_days', 90 ) ); ?>"
                               style="width:70px;"> days
                        <p class="description">
                            When enabled, the daily cron job will delete access logs older than
                            the configured number of days. A manual prune button is also available
                            on the Logs tab. Recommended: 90–365 days depending on your compliance needs.
                        </p>
                    </td>
                </tr>
            </table>

            <p>
                <input type="submit" name="rbfa_save_system_settings"
                       value="Save &amp; Sync" class="button button-primary">
            </p>
        </form>
    </div>

    <!-- ── Data Management ───────────────────────────────────────────────────── -->
    <div class="rbfa-card" style="margin-top:20px;">
        <h3 style="margin-top:0;">Data Management</h3>
        <p style="color:#666; font-size:13px; margin-top:0;">
            Control what happens to plugin data when the plugin is deleted.
            Deactivating the plugin never deletes any data.
        </p>

        <form method="post">
            <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>

            <table class="form-table" role="presentation">
                <tr>
                    <th scope="row">On Plugin Deletion</th>
                    <td>
                        <label>
                            <input type="checkbox" name="rbfa_delete_on_uninstall" value="1"
                                   <?php checked( $delete_on_uninstall, '1' ); ?>>
                            <strong>Remove all plugin data when the plugin is deleted</strong>
                        </label>
                        <p class="description">
                            When checked, deleting this plugin from the WordPress Plugins screen will
                            permanently remove all plugin database tables
                            (<code>rbfa_access_logs</code>, <code>rbfa_denial_screens</code>,
                            <code>rbfa_zones</code>, <code>rbfa_managed_roles</code>)
                            and all plugin settings. This cannot be undone.
                            Leave unchecked to preserve your data if you reinstall later.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Roles on Deletion</th>
                    <td>
                        <label>
                            <input type="checkbox" name="rbfa_delete_roles_on_uninstall" value="1"
                                   <?php checked( $delete_roles_on_uninstall, '1' ); ?>>
                            <strong>Remove all <code>wfsp_</code> roles when the plugin is deleted</strong>
                        </label>
                        <p class="description">
                            When checked, all WordPress roles whose slug starts with <code>wfsp_</code>
                            (including <code>wfsp_admins</code> and any roles you have created) will be
                            permanently deleted along with their user assignments. Leave unchecked to
                            preserve roles across reinstalls.
                        </p>
                    </td>
                </tr>
            </table>

            <p>
                <input type="submit" name="rbfa_save_data_settings"
                       value="Save Setting" class="button button-primary">
            </p>
        </form>
    </div>
    <?php
}

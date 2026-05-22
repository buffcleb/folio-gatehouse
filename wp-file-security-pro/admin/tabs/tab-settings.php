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

    // Load import review transient if present.
    $import_review_key  = isset( $_GET['rbfa_import_review'] ) ? sanitize_text_field( wp_unslash( $_GET['rbfa_import_review'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- GET param carries import review key from a nonce-verified POST redirect
    $import_review_data = null;
    if ( $import_review_key !== '' ) {
        $import_review_data = get_transient( 'rbfa_import_' . get_current_user_id() . '_' . $import_review_key );
    }
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

    <!-- ── Export / Import ──────────────────────────────────────────────────── -->
    <div class="rbfa-card" style="margin-top:20px;">
        <h3 style="margin-top:0;">Export / Import</h3>

        <div style="display:flex; gap:40px; flex-wrap:wrap; align-items:flex-start;">

            <!-- Export column -->
            <div style="flex:1; min-width:260px;">
                <h4 style="margin-top:0;">Export</h4>
                <form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>">
                    <input type="hidden" name="page"   value="rbfa-pro">
                    <input type="hidden" name="action" value="rbfa_export">
                    <input type="hidden" name="_nonce" value="<?php echo esc_attr( wp_create_nonce( 'rbfa_export' ) ); ?>">

                    <fieldset style="border:none; margin:0; padding:0;">
                        <legend style="font-weight:600; margin-bottom:8px;">Include in export:</legend>
                        <label style="display:block; margin-bottom:4px;">
                            <input type="checkbox" name="include[]" value="zones" checked> Zones
                        </label>
                        <label style="display:block; margin-bottom:4px;">
                            <input type="checkbox" name="include[]" value="roles" checked> Roles
                        </label>
                        <label style="display:block; margin-bottom:4px;">
                            <input type="checkbox" name="include[]" value="denial_screens" checked> Denial Screens
                        </label>
                        <label style="display:block; margin-bottom:12px;">
                            <input type="checkbox" name="include[]" value="settings" checked> Settings
                        </label>
                    </fieldset>

                    <button type="submit" class="button button-primary">Export</button>
                </form>
            </div>

            <!-- Import column -->
            <div style="flex:1; min-width:260px;">
                <h4 style="margin-top:0;">Import</h4>
                <form method="post" enctype="multipart/form-data" action="<?php echo esc_url( admin_url( 'admin.php' ) . '?page=rbfa-pro&tab=settings' ); ?>">
                    <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>

                    <p style="margin-top:0;">
                        <label for="rbfa-import-file" style="display:block; font-weight:600; margin-bottom:6px;">JSON file:</label>
                        <input id="rbfa-import-file" type="file" name="import_file" accept=".json">
                    </p>

                    <fieldset style="border:none; margin:0; padding:0;">
                        <legend style="font-weight:600; margin-bottom:8px;">Import sections:</legend>
                        <label style="display:block; margin-bottom:4px;">
                            <input type="checkbox" name="import_include[]" value="zones" checked> Zones
                        </label>
                        <label style="display:block; margin-bottom:4px;">
                            <input type="checkbox" name="import_include[]" value="roles" checked> Roles
                        </label>
                        <label style="display:block; margin-bottom:4px;">
                            <input type="checkbox" name="import_include[]" value="denial_screens" checked> Denial Screens
                        </label>
                        <label style="display:block; margin-bottom:12px;">
                            <input type="checkbox" name="import_include[]" value="settings" checked> Settings
                        </label>
                    </fieldset>

                    <button type="submit" name="rbfa_import_upload" value="1" class="button button-secondary">Upload &amp; Review</button>
                </form>
            </div>

        </div>
    </div>

    <?php if ( $import_review_key !== '' ) : ?>
    <?php if ( ! $import_review_data ) : ?>
        <div class="notice notice-warning" style="margin-top:20px;"><p>Import session expired. Please upload the file again.</p></div>
    <?php else :
        $r_data      = $import_review_data['data'];
        $r_include   = $import_review_data['include'];
        $r_conflicts = $import_review_data['conflicts'];

        // Build summary counts.
        $counts = [];
        if ( in_array( 'zones', $r_include, true ) && ! empty( $r_data['zones'] ) ) {
            $n = count( $r_data['zones'] );
            $counts[] = $n . ' zone' . ( $n !== 1 ? 's' : '' );
        }
        if ( in_array( 'denial_screens', $r_include, true ) && ! empty( $r_data['denial_screens'] ) ) {
            $n = count( $r_data['denial_screens'] );
            $counts[] = $n . ' denial screen' . ( $n !== 1 ? 's' : '' );
        }
        if ( in_array( 'roles', $r_include, true ) && ! empty( $r_data['roles'] ) ) {
            $n = count( $r_data['roles'] );
            $counts[] = $n . ' role' . ( $n !== 1 ? 's' : '' );
        }
        if ( in_array( 'settings', $r_include, true ) && ! empty( $r_data['settings'] ) ) {
            $counts[] = 'settings';
        }
        $summary_str = $counts ? implode( ', ', $counts ) : 'nothing';
    ?>
    <div class="rbfa-card" style="margin-top:20px; border-color:#dba617;">
        <h3 style="margin-top:0; color:#7a5500;">Review Import</h3>
        <p>Ready to import: <strong><?php echo esc_html( $summary_str ); ?></strong></p>

        <form method="post" action="<?php echo esc_url( admin_url( 'admin.php' ) . '?page=rbfa-pro&tab=settings' ); ?>">
            <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
            <input type="hidden" name="rbfa_import_confirm" value="1">
            <input type="hidden" name="import_key" value="<?php echo esc_attr( $import_review_key ); ?>">

            <?php if ( ! empty( $r_conflicts['denial_screens'] ) ) : ?>
                <h4>Conflicting Denial Screens</h4>
                <table class="widefat" style="max-width:600px;">
                    <thead><tr><th>Label</th><th>Resolution</th></tr></thead>
                    <tbody>
                    <?php foreach ( $r_conflicts['denial_screens'] as $label ) : ?>
                        <tr>
                            <td><?php echo esc_html( $label ); ?></td>
                            <td>
                                <label style="margin-right:12px;">
                                    <input type="radio" name="rbfa_resolve[denial_screens][<?php echo esc_attr( $label ); ?>]" value="keep" checked> Keep existing
                                </label>
                                <label>
                                    <input type="radio" name="rbfa_resolve[denial_screens][<?php echo esc_attr( $label ); ?>]" value="import"> Use imported
                                </label>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <?php if ( ! empty( $r_conflicts['zones'] ) ) : ?>
                <h4>Conflicting Zones</h4>
                <table class="widefat" style="max-width:600px;">
                    <thead><tr><th>Folder Slug</th><th>Resolution</th></tr></thead>
                    <tbody>
                    <?php foreach ( $r_conflicts['zones'] as $slug ) : ?>
                        <tr>
                            <td><code><?php echo esc_html( $slug ); ?></code></td>
                            <td>
                                <label style="margin-right:12px;">
                                    <input type="radio" name="rbfa_resolve[zones][<?php echo esc_attr( $slug ); ?>]" value="keep" checked> Keep existing
                                </label>
                                <label>
                                    <input type="radio" name="rbfa_resolve[zones][<?php echo esc_attr( $slug ); ?>]" value="import"> Use imported
                                </label>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <?php if ( ! empty( $r_conflicts['roles'] ) ) : ?>
                <h4>Conflicting Roles <small style="font-weight:normal; color:#666;">(users will be merged regardless)</small></h4>
                <table class="widefat" style="max-width:600px;">
                    <thead><tr><th>Role Key</th><th>Resolution</th></tr></thead>
                    <tbody>
                    <?php foreach ( $r_conflicts['roles'] as $role_key ) : ?>
                        <tr>
                            <td><code><?php echo esc_html( $role_key ); ?></code></td>
                            <td>
                                <label style="margin-right:12px;">
                                    <input type="radio" name="rbfa_resolve[roles][<?php echo esc_attr( $role_key ); ?>]" value="keep" checked> Keep existing
                                </label>
                                <label>
                                    <input type="radio" name="rbfa_resolve[roles][<?php echo esc_attr( $role_key ); ?>]" value="import"> Use imported
                                </label>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <p style="margin-top:20px;">
                <button type="submit" class="button button-primary">Apply Import</button>
                &nbsp;
                <a href="<?php echo esc_url( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) ); ?>" class="button">Cancel</a>
            </p>
        </form>
    </div>
    <?php endif; ?>
    <?php endif; ?>

    <?php
}

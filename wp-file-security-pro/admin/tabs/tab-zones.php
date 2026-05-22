<?php
/**
 * Zones tab renderer.
 *
 * IMPORTANT — nested <form> fix:
 * The per-page selector is a standalone GET form placed BEFORE the main POST
 * form in the DOM. Both are siblings, never nested. Nested forms are invalid
 * HTML and cause browsers to silently discard inner field values, which was
 * the root cause of roles and denial screen selections not saving.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

function rbfa_render_tab_zones() {
    global $wpdb;

    $msg_table  = $wpdb->prefix . 'rbfa_denial_screens';
    $upload_dir = wp_upload_dir()['basedir'];
    $base       = rbfa_get_base_folder();
    $all_zones  = rbfa_get_zones();
    $all_roles  = wp_roles()->get_names();
    $all_msgs   = $wpdb->get_results( "SELECT id, label FROM $msg_table" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
    $issues     = rbfa_get_system_status();

    // ── Integrity banner ─────────────────────────────────────────────────────
    if ( ! empty( $issues ) ) {
        echo '<div class="integrity-notice"><strong>🛡️ Security Integrity Alert:</strong><ul>';
        foreach ( $issues as $issue ) {
            echo '<li>⚠️ ' . wp_kses( $issue, [ 'code' => [] ] ) . '</li>';
        }
        echo '</ul><p>Click "Save &amp; Sync Zones" to repair security files recursively.</p></div>';
    } else {
        echo '<div class="notice notice-success inline" style="margin-top:15px;"><p>✅ Deep scan verified: All subdirectories are protected.</p></div>';
    }

    // ── Filters ──────────────────────────────────────────────────────────────
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter parameters, no data mutation
    $f_slug   = sanitize_text_field( wp_unslash( $_GET['f_slug']   ?? '' ) );
    $f_denial = (int) ( wp_unslash( $_GET['f_denial'] ?? 0 ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter parameters, no data mutation
    $f_role   = sanitize_key( wp_unslash( $_GET['f_role'] ?? '' ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter parameters, no data mutation

    $filtered_zones = array_values( array_filter( $all_zones, function ( $z ) use ( $f_slug, $f_denial, $f_role ) {
        if ( $f_slug   && stripos( $z['folder_slug'], $f_slug ) === false ) return false;
        if ( $f_denial > 0 && (int) ( $z['denial_id'] ?? 0 ) !== $f_denial ) return false;
        if ( $f_role   && ! in_array( $f_role, $z['roles'] ?? [], true ) )    return false;
        return true;
    } ) );

    // ── Pagination ───────────────────────────────────────────────────────────
    $allowed_per_page = [ 5, 10, 20, 0 ];
    $per_page_raw     = isset( $_GET['per_page'] ) ? (int) $_GET['per_page'] : 5; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter parameters, no data mutation
    $per_page         = in_array( $per_page_raw, $allowed_per_page, true ) ? $per_page_raw : 5;
    $paged            = max( 1, (int) ( wp_unslash( $_GET['paged'] ?? 1 ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter parameters, no data mutation
    $total_zones      = count( $filtered_zones );
    $total_pages      = $per_page > 0 ? (int) ceil( $total_zones / $per_page ) : 1;
    $offset           = $per_page > 0 ? ( $paged - 1 ) * $per_page : 0;
    $page_zones       = $per_page > 0 ? array_slice( $filtered_zones, $offset, $per_page ) : $filtered_zones;

    $active_filters = array_filter( [
        'f_slug'   => $f_slug,
        'f_denial' => $f_denial ?: '',
        'f_role'   => $f_role,
    ] );

    // ── Discover unmanaged directories ────────────────────────────────────────
    // Scan the root of the base protected folder for subdirectories that don't
    // have a corresponding zone configured yet.
    $base_path      = $upload_dir . '/' . $base;
    $unmanaged_dirs = [];
    if ( is_dir( $base_path ) ) {
        $existing_slugs = array_column( $all_zones, 'folder_slug' );
        foreach ( array_diff( scandir( $base_path ), [ '.', '..' ] ) as $item ) {
            if ( is_dir( $base_path . '/' . $item ) && ! in_array( $item, $existing_slugs, true ) ) {
                $unmanaged_dirs[] = $item;
            }
        }
    }
    ?>

    <!-- ── Zone page editor modal ──────────────────────────────────────────── -->
    <div id="rbfa-page-modal"
         style="display:none; position:fixed; inset:0; background:rgba(0,0,0,.55);
                z-index:99999; align-items:center; justify-content:center;">
        <div style="background:#fff; border-radius:6px; padding:24px; width:940px;
                    max-width:97vw; max-height:92vh; display:flex; flex-direction:column;
                    box-shadow:0 6px 30px rgba(0,0,0,.35);">

            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:12px;">
                <h3 style="margin:0;" id="rbfa-pm-heading">Edit Zone Page</h3>
                <a id="rbfa-pm-live-link" href="#" target="_blank" rel="noopener"
                   style="font-size:12px; color:#2271b1; text-decoration:none;">
                    🔗 Preview live page ↗
                </a>
            </div>

            <!-- Title row -->
            <div style="margin-bottom:10px;">
                <label style="font-weight:600; display:block; margin-bottom:4px;">Page Title</label>
                <input type="text" id="rbfa-pm-title" style="width:100%;">
            </div>

            <!-- Split pane: editor | preview -->
            <div style="display:flex; gap:12px; flex:1; min-height:0; margin-bottom:10px;">
                <!-- Left: content editor -->
                <div style="flex:1; display:flex; flex-direction:column; min-width:0;">
                    <label style="font-weight:600; display:block; margin-bottom:4px;">
                        Content
                        <span style="font-weight:400; color:#888; font-size:11px;">
                            — headings, paragraphs, links, images, lists, tables.
                            Shortcodes allowed. No scripts.
                        </span>
                    </label>
                    <textarea id="rbfa-pm-content"
                              style="flex:1; width:100%; min-height:260px; font-family:monospace;
                                     font-size:12px; resize:vertical; box-sizing:border-box;"></textarea>
                </div>
                <!-- Right: live preview -->
                <div style="flex:1; display:flex; flex-direction:column; min-width:0;">
                    <label style="font-weight:600; display:block; margin-bottom:4px;">
                        Preview
                        <span style="font-weight:400; color:#888; font-size:11px;">— updates as you type</span>
                    </label>
                    <iframe id="rbfa-pm-preview" sandbox="allow-same-origin"
                            style="flex:1; width:100%; min-height:260px; border:1px solid #ddd;
                                   border-radius:4px; background:#fff; box-sizing:border-box;"
                            srcdoc="<html><body style='font-family:sans-serif;padding:16px;margin:0;font-size:14px;color:#333;'>
                                    <em style='color:#999;'>Start typing to see a preview…</em>
                                    </body></html>"></iframe>
                </div>
            </div>

            <!-- Footer -->
            <div style="display:flex; align-items:center; justify-content:flex-end; gap:8px;
                        border-top:1px solid #eee; padding-top:12px;">
                <button type="button" id="rbfa-pm-cancel" class="button">Cancel</button>
                <button type="button" id="rbfa-pm-confirm" class="button button-primary">Apply</button>
            </div>
        </div>
    </div>

    <div style="display:flex; gap:20px; align-items:flex-start; margin-top:20px;">

        <!-- ── LEFT: Filter panel (standalone GET form) ───────────────────── -->
        <div class="rbfa-card" style="flex:0 0 200px; margin-top:0;">
            <h3 style="margin-top:0;">Filter Zones</h3>
            <form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>">
                <input type="hidden" name="page"     value="rbfa-pro">
                <input type="hidden" name="tab"      value="config">
                <input type="hidden" name="per_page" value="<?php echo esc_attr( $per_page ); ?>">
                <p style="margin:0 0 8px;">
                    <label style="display:block; font-weight:600; margin-bottom:3px;">Folder Slug</label>
                    <input type="text" name="f_slug" value="<?php echo esc_attr( $f_slug ); ?>"
                           placeholder="e.g. members" style="width:100%;">
                </p>
                <p style="margin:0 0 8px;">
                    <label style="display:block; font-weight:600; margin-bottom:3px;">Denial Screen</label>
                    <select name="f_denial" style="width:100%;">
                        <option value="0">Any</option>
                        <option value="-1" <?php selected( $f_denial, -1 ); ?>>Default (none)</option>
                        <?php foreach ( $all_msgs as $m ) :
                            echo '<option value="' . esc_attr( $m->id ) . '" ' . selected( $f_denial, $m->id, false ) . '>'
                                . esc_html( $m->label ) . '</option>';
                        endforeach; ?>
                    </select>
                </p>
                <p style="margin:0 0 12px;">
                    <label style="display:block; font-weight:600; margin-bottom:3px;">Role</label>
                    <select name="f_role" style="width:100%;">
                        <option value="">Any</option>
                        <?php foreach ( $all_roles as $rid => $rname ) :
                            echo '<option value="' . esc_attr( $rid ) . '" ' . selected( $f_role, $rid, false ) . '>'
                                . esc_html( $rname ) . '</option>';
                        endforeach; ?>
                    </select>
                </p>
                <input type="submit" value="Apply Filters" class="button button-primary" style="width:100%;">
                <?php if ( $f_slug || $f_denial || $f_role ) : ?>
                    <a href="<?php echo esc_url( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'config', 'per_page' => $per_page ], admin_url( 'admin.php' ) ) ); ?>"
                       class="button" style="width:100%; margin-top:6px; text-align:center; box-sizing:border-box;">
                        Clear Filters
                    </a>
                <?php endif; ?>
            </form>
        </div>

        <!-- ── RIGHT: Zone config ────────────────────────────────────────────── -->
        <div style="flex:1; min-width:0;">

            <!--
                Per-page selector: standalone GET form, sibling to the POST form below.
                It must NEVER be nested inside the POST form — browsers silently
                discard inputs from nested forms, breaking the zone save.
            -->
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>"
                      style="display:flex; align-items:center; gap:6px;">
                    <input type="hidden" name="page" value="rbfa-pro">
                    <input type="hidden" name="tab"  value="config">
                    <?php foreach ( $active_filters as $k => $v ) : ?>
                        <input type="hidden" name="<?php echo esc_attr( $k ); ?>" value="<?php echo esc_attr( $v ); ?>">
                    <?php endforeach; ?>
                    <label for="rbfa-zones-per-page" style="font-weight:600; white-space:nowrap;">Zones per page:</label>
                    <select id="rbfa-zones-per-page" name="per_page" onchange="this.form.submit()">
                        <?php foreach ( [ 5, 10, 20 ] as $n ) :
                            echo "<option value='" . absint( $n ) . "'" . selected( $per_page, $n, false ) . ">" . absint( $n ) . "</option>";
                        endforeach; ?>
                        <option value="0" <?php selected( $per_page, 0 ); ?>>All</option>
                    </select>
                </form>
                <span style="color:#666; font-size:13px;">
                    Showing <?php echo absint( count( $page_zones ) ); ?> of <?php echo absint( $total_zones ); ?> zone(s)
                </span>
            </div>

            <!--
                Main POST form: system settings + zone table.
                This is the ONLY POST form. The per-page and filter forms above
                are separate GET forms and are NOT nested inside this one.
            -->
            <form method="post">
                <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>

                <!-- Unsaved-changes banner — hidden until JS marks dirty -->
                <div id="rbfa-unsaved-banner"
                     style="display:none; align-items:center; gap:12px;
                            background:#fff8e5; border:1px solid #f0a500;
                            border-radius:4px; padding:10px 14px; margin-bottom:12px;">
                    <span style="font-size:18px;">⚠</span>
                    <span style="flex:1; font-weight:600; color:#856404;">
                        You have unsaved zone changes. Click <em>Save &amp; Sync Zones</em> to apply them,
                        or your changes will be lost if you leave this tab.
                    </span>
                </div>

                <!-- Zone table -->
                <table class="widefat striped" id="z-table">
                    <thead>
                        <tr>
                            <th>Folder Slug</th>
                            <th>Status</th>
                            <th>Roles</th>
                            <th>Shortcode</th>
                            <th>On Deny <small style="font-weight:400; color:#888;">(Anon / Auth)</small></th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ( $page_zones as $i => $z ) :
                        $zone_path = $upload_dir . '/' . $base . '/' . $z['folder_slug'];
                        $f_exists  = is_dir( $zone_path );
                        if ( $f_exists ) {
                            $z_files = rbfa_admin_count_files( $zone_path );
                            $z_size  = rbfa_admin_dir_size( $zone_path );
                        }

                        // Page title/content come from the zone DB row; fall back to defaults.
                        $z_pg_title = ! empty( $z['page_title'] )
                            ? $z['page_title']
                            : ucwords( str_replace( [ '-', '_' ], ' ', $z['folder_slug'] ) );
                        $z_pg_body  = ! empty( $z['page_content'] )
                            ? $z['page_content']
                            : '[folder_files folder="' . esc_attr( $z['folder_slug'] ) . '"]';
                        $z_page_url = rbfa_zone_page_url( $z['folder_slug'] );
                        ?>
                        <tr>
                            <td>
                                <code>/</code>
                                <input type="text" name="folders[<?php echo absint( $i ); ?>]"
                                       value="<?php echo esc_attr( $z['folder_slug'] ); ?>">
                                <input type="hidden" name="page_titles[<?php echo absint( $i ); ?>]"
                                       id="rbfa-ptitle-<?php echo absint( $i ); ?>"
                                       value="<?php echo esc_attr( $z_pg_title ); ?>">
                                <input type="hidden" name="page_contents[<?php echo absint( $i ); ?>]"
                                       id="rbfa-pcontent-<?php echo absint( $i ); ?>"
                                       value="<?php echo esc_attr( $z_pg_body ); ?>">
                                <br>
                                <button type="button" class="rbfa-btn rbfa-edit-page-btn"
                                        style="margin-top:5px; font-size:11px;"
                                        data-idx="<?php echo absint( $i ); ?>"
                                        data-slug="<?php echo esc_attr( $z['folder_slug'] ); ?>"
                                        data-page-url="<?php echo esc_attr( $z_page_url ); ?>">
                                    📄 Edit Page
                                </button>
                                <br>
                                <a href="<?php echo esc_url( $z_page_url ); ?>"
                                   target="_blank"
                                   style="font-size:10px; color:#888; text-decoration:none;">
                                    /protected-zone/<?php echo esc_html( $z['folder_slug'] ); ?>/ ↗
                                </a>
                            </td>
                            <td>
                                <?php if ( $f_exists ) :
                                    echo '<span class="rbfa-status status-ok">✅ Exists</span>';
                                    echo '<br><small style="color:#666; white-space:nowrap;">'
                                        . esc_html( $z_files . ' file' . ( $z_files !== 1 ? 's' : '' ) )
                                        . ' &middot; ' . esc_html( size_format( $z_size ) )
                                        . '</small>';
                                else :
                                    echo '<span class="rbfa-status status-err">❌ Missing</span>';
                                endif; ?>
                            </td>
                            <td>
                                <div class="rbfa-scroll">
                                    <?php foreach ( $all_roles as $rid => $rname ) :
                                        echo '<label>'
                                            . '<input type="checkbox" name="roles[' . absint( $i ) . '][]" value="' . esc_attr( $rid ) . '" '
                                            . checked( in_array( $rid, $z['roles'] ?? [], true ), true, false ) . '> '
                                            . esc_html( $rname )
                                            . '</label><br>';
                                    endforeach; ?>
                                </div>
                            </td>
                            <td>
                                <!-- Shortcode reflects current saved slug -->
                                <code>[folder_files folder="<?php echo esc_attr( $z['folder_slug'] ); ?>"]</code>
                            </td>
                            <td>
                                <?php
                                $has_redirect = ! empty( $z['redirect_url'] ?? '' );
                                $row_id       = 'zone-row-' . absint( $i );
                                ?>
                                <div style="display:flex; flex-direction:column; gap:4px;">
                                    <div>
                                        <label style="font-size:11px; color:#888; display:block;">&#128100; Anonymous</label>
                                        <select name="denial_ids[<?php echo absint( $i ); ?>]"
                                                id="<?php echo esc_attr( $row_id ); ?>-denial"
                                                onchange="rbfaToggleRedirect(this, '<?php echo esc_attr( $row_id ); ?>')">
                                            <option value="0">Default</option>
                                            <option value="-1" <?php selected( $has_redirect, true ); ?>>
                                                ↪ Redirect to URL
                                            </option>
                                            <?php foreach ( $all_msgs as $m ) :
                                                echo '<option value="' . esc_attr( $m->id ) . '" '
                                                    . ( ! $has_redirect ? selected( $z['denial_id'] ?? 0, $m->id, false ) : '' ) . '>'
                                                    . esc_html( $m->label ) . '</option>';
                                            endforeach; ?>
                                        </select>
                                        <div id="<?php echo esc_attr( $row_id ); ?>-redirect"
                                             style="<?php echo $has_redirect ? '' : 'display:none;'; ?> margin-top:4px;">
                                            <input type="text"
                                                   name="redirect_urls[<?php echo absint( $i ); ?>]"
                                                   value="<?php echo esc_attr( $z['redirect_url'] ?? '' ); ?>"
                                                   placeholder="https://example.com/page"
                                                   style="width:100%;">
                                        </div>
                                    </div>
                                    <div>
                                        <?php
                                        $has_redirect_auth = ! empty( $z['redirect_url_auth'] ?? '' );
                                        ?>
                                        <label style="font-size:11px; color:#888; display:block;">&#128274; Logged In</label>
                                        <select name="denial_ids_auth[<?php echo absint( $i ); ?>]"
                                                id="<?php echo esc_attr( $row_id ); ?>-auth-denial"
                                                onchange="rbfaToggleRedirect(this, '<?php echo esc_attr( $row_id ); ?>-auth')">
                                            <option value="0">Default</option>
                                            <option value="-1" <?php selected( $has_redirect_auth, true ); ?>>
                                                ↪ Redirect to URL
                                            </option>
                                            <?php foreach ( $all_msgs as $m ) :
                                                echo '<option value="' . esc_attr( $m->id ) . '" '
                                                    . ( ! $has_redirect_auth ? selected( $z['denial_id_auth'] ?? 0, $m->id, false ) : '' ) . '>'
                                                    . esc_html( $m->label ) . '</option>';
                                            endforeach; ?>
                                        </select>
                                        <div id="<?php echo esc_attr( $row_id ); ?>-auth-redirect"
                                             style="<?php echo $has_redirect_auth ? '' : 'display:none;'; ?> margin-top:4px;">
                                            <input type="text"
                                                   name="redirect_urls_auth[<?php echo absint( $i ); ?>]"
                                                   value="<?php echo esc_attr( $z['redirect_url_auth'] ?? '' ); ?>"
                                                   placeholder="https://example.com/page"
                                                   style="width:100%;">
                                        </div>
                                    </div>
                                </div>
                            </td>
                            <td>
                                <button type="button" class="rbfa-btn rbfa-danger"
                                        onclick="this.closest('tr').remove()">Remove</button>
                            </td>
                        </tr>
                    <?php endforeach; ?>

                    <?php if ( ! empty( $unmanaged_dirs ) ) :
                        // Rows for unmanaged directories start after the visible zone rows.
                        $u_offset = count( $page_zones );
                        ?>
                        <tr>
                            <td colspan="6"
                                style="background:#fff8e5; border-top:2px solid #f0a500;
                                       padding:8px 12px; font-size:12px; font-weight:600; color:#856404;">
                                ⚠ <?php echo count( $unmanaged_dirs ); ?> unmanaged director<?php echo count( $unmanaged_dirs ) === 1 ? 'y' : 'ies'; ?> found
                                — configure roles below and click <em>Save &amp; Sync Zones</em>, or click Remove to skip.
                            </td>
                        </tr>
                        <?php foreach ( $unmanaged_dirs as $u_i => $dir_slug ) :
                            $u_idx      = $u_offset + $u_i;
                            $u_row_id   = 'zone-row-' . $u_idx;
                            $u_pg_title = ucwords( str_replace( [ '-', '_' ], ' ', $dir_slug ) );
                            $u_pg_body  = '[folder_files folder="' . esc_attr( $dir_slug ) . '"]';
                            $u_dir_path = $base_path . '/' . $dir_slug;
                            $u_files    = rbfa_admin_count_files( $u_dir_path );
                            $u_size     = rbfa_admin_dir_size( $u_dir_path );
                            $u_page_url = rbfa_zone_page_url( $dir_slug );
                            ?>
                            <tr style="background:#fffbe6;">
                                <td>
                                    <code>/</code>
                                    <input type="text" name="folders[<?php echo absint( $u_idx ); ?>]"
                                           value="<?php echo esc_attr( $dir_slug ); ?>">
                                    <input type="hidden" name="page_titles[<?php echo absint( $u_idx ); ?>]"
                                           id="rbfa-ptitle-<?php echo absint( $u_idx ); ?>"
                                           value="<?php echo esc_attr( $u_pg_title ); ?>">
                                    <input type="hidden" name="page_contents[<?php echo absint( $u_idx ); ?>]"
                                           id="rbfa-pcontent-<?php echo absint( $u_idx ); ?>"
                                           value="<?php echo esc_attr( $u_pg_body ); ?>">
                                    <br>
                                    <button type="button" class="rbfa-btn rbfa-edit-page-btn"
                                            style="margin-top:5px; font-size:11px;"
                                            data-idx="<?php echo absint( $u_idx ); ?>"
                                            data-slug="<?php echo esc_attr( $dir_slug ); ?>"
                                            data-page-url="<?php echo esc_attr( $u_page_url ); ?>">
                                        📄 Edit Page
                                    </button>
                                    <br>
                                    <a href="<?php echo esc_url( $u_page_url ); ?>"
                                       target="_blank"
                                       style="font-size:10px; color:#888; text-decoration:none;">
                                        /protected-zone/<?php echo esc_html( $dir_slug ); ?>/ ↗
                                    </a>
                                </td>
                                <td>
                                    <span class="rbfa-status" style="background:#fff8e5; color:#856404;">⚠ Unmanaged</span>
                                    <br>
                                    <small style="color:#666; white-space:nowrap;">
                                        <?php echo esc_html( $u_files . ' file' . ( $u_files !== 1 ? 's' : '' ) ); ?>
                                        &middot; <?php echo esc_html( size_format( $u_size ) ); ?>
                                    </small>
                                </td>
                                <td>
                                    <div class="rbfa-scroll">
                                        <?php foreach ( $all_roles as $rid => $rname ) :
                                            echo '<label>'
                                                . '<input type="checkbox" name="roles[' . absint( $u_idx ) . '][]" value="' . esc_attr( $rid ) . '"> '
                                                . esc_html( $rname )
                                                . '</label><br>';
                                        endforeach; ?>
                                    </div>
                                </td>
                                <td>
                                    <em style="color:#999; font-size:11px;">Save to generate</em>
                                </td>
                                <td>
                                    <div style="display:flex; flex-direction:column; gap:4px;">
                                        <div>
                                            <label style="font-size:11px; color:#888; display:block;">&#128100; Anonymous</label>
                                            <select name="denial_ids[<?php echo absint( $u_idx ); ?>]"
                                                    id="<?php echo esc_attr( $u_row_id ); ?>-denial"
                                                    onchange="rbfaToggleRedirect(this, '<?php echo esc_attr( $u_row_id ); ?>')">
                                                <option value="0">Default</option>
                                                <option value="-1">↪ Redirect to URL</option>
                                                <?php foreach ( $all_msgs as $m ) :
                                                    echo '<option value="' . esc_attr( $m->id ) . '">' . esc_html( $m->label ) . '</option>';
                                                endforeach; ?>
                                            </select>
                                            <div id="<?php echo esc_attr( $u_row_id ); ?>-redirect" style="display:none; margin-top:4px;">
                                                <input type="text" name="redirect_urls[<?php echo absint( $u_idx ); ?>]"
                                                       placeholder="https://example.com/page" style="width:100%;">
                                            </div>
                                        </div>
                                        <div>
                                            <label style="font-size:11px; color:#888; display:block;">&#128274; Logged In</label>
                                            <select name="denial_ids_auth[<?php echo absint( $u_idx ); ?>]"
                                                    id="<?php echo esc_attr( $u_row_id ); ?>-auth-denial"
                                                    onchange="rbfaToggleRedirect(this, '<?php echo esc_attr( $u_row_id ); ?>-auth')">
                                                <option value="0">Default</option>
                                                <option value="-1">↪ Redirect to URL</option>
                                                <?php foreach ( $all_msgs as $m ) :
                                                    echo '<option value="' . esc_attr( $m->id ) . '">' . esc_html( $m->label ) . '</option>';
                                                endforeach; ?>
                                            </select>
                                            <div id="<?php echo esc_attr( $u_row_id ); ?>-auth-redirect" style="display:none; margin-top:4px;">
                                                <input type="text" name="redirect_urls_auth[<?php echo absint( $u_idx ); ?>]"
                                                       placeholder="https://example.com/page" style="width:100%;">
                                            </div>
                                        </div>
                                    </div>
                                </td>
                                <td>
                                    <button type="button" class="rbfa-btn rbfa-danger rbfa-remove-unmanaged"
                                            onclick="rbfaRemoveUnmanaged(this);">Remove</button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>

                    </tbody>
                </table>

                <!-- Modern pagination -->
                <?php rbfa_render_pagination( $paged, $total_pages, array_merge(
                    [ 'tab' => 'config', 'per_page' => $per_page ],
                    $active_filters
                ) ); ?>

                <p style="margin-top:16px;">
                    <button type="button" class="rbfa-btn" id="rbfa-add-zone">+ Add Zone</button>
                    <input type="submit" name="rbfa_save_zones"
                           value="Save &amp; Sync Zones" class="button button-primary">
                </p>
            </form><!-- end main POST form -->

        </div>
    </div>

    <?php
    // ── Add Zone JS ──────────────────────────────────────────────────────────
    // Role checkboxes and denial options are encoded via wp_json_encode to
    // guarantee correct escaping regardless of what role names contain.
    $role_options_html   = '';
    foreach ( $all_roles as $rid => $rname ) {
        $role_options_html .= '<label><input type="checkbox" name="roles[__IDX__][]" value="'
            . esc_attr( $rid ) . '"> ' . esc_html( $rname ) . '</label><br>';
    }
    $denial_options_html = '<option value="0">Default</option>';
    foreach ( $all_msgs as $m ) {
        $denial_options_html .= '<option value="' . esc_attr( $m->id ) . '">'
            . esc_html( $m->label ) . '</option>';
    }

    $encoded_roles  = wp_json_encode( $role_options_html );
    $encoded_denial = wp_json_encode( $denial_options_html );

    // Also build denial options with the redirect choice included.
    $denial_with_redirect = '<option value="0">Default</option><option value="-1">↪ Redirect to URL</option>';
    foreach ( $all_msgs as $m ) {
        $denial_with_redirect .= '<option value="' . esc_attr( $m->id ) . '">' . esc_html( $m->label ) . '</option>';
    }
    $encoded_denial_redirect = wp_json_encode( $denial_with_redirect );

    $zone_js = '(function(){'
        . "\n    var roleHtml         = " . $encoded_roles . ";\n"
        . "    var denialHtml       = " . $encoded_denial . ";\n"
        . "    var denialRedirectHtml = " . $encoded_denial_redirect . ";\n"
        . '    var isDirty          = false;
    // Show/hide the redirect URL field based on the denial dropdown selection.
    window.rbfaToggleRedirect = function( sel, rowId ) {
        var div = document.getElementById( rowId + \'-redirect\' );
        if ( div ) div.style.display = sel.value === \'-1\' ? \'block\' : \'none\';
    };
    // Show the unsaved-changes banner and enable the beforeunload warning.
    function markDirty() {
        if ( isDirty ) return;
        isDirty = true;
        var banner = document.getElementById("rbfa-unsaved-banner");
        if ( banner ) banner.style.display = "flex";
    }
    // Clear dirty state when the save form is submitted (PRG cycle resets page).
    var form = document.querySelector("form[method=\'post\']");
    if ( form ) {
        form.addEventListener("submit", function(){ isDirty = false; });
    }
    // Warn the user before navigating away with unsaved zone changes.
    window.addEventListener("beforeunload", function( e ){
        if ( ! isDirty ) return;
        e.preventDefault();
        e.returnValue = "You have unsaved zone changes. Leave anyway?";
    });
    // Add Zone button — inserts a new row and marks dirty.
    document.getElementById("rbfa-add-zone").addEventListener("click", function(){
        var tb = document.querySelector("#z-table tbody");
        var i  = tb.rows.length;
        var r  = tb.insertRow();
        var rowRoleHtml = roleHtml.replace(/__IDX__/g, i);
        var rid = \'zone-row-\' + i;
        r.innerHTML =
              "<td>"
            +   "/ <input type=\'text\' name=\'folders[" + i + "]\' placeholder=\'zone-slug\'"
            +          " oninput=\'rbfaUpdatePageBtn(this, " + i + ")\'>"
            +   "<input type=\'hidden\' name=\'page_titles[" + i + "]\' id=\'rbfa-ptitle-" + i + "\' value=\'\'>"
            +   "<input type=\'hidden\' name=\'page_contents[" + i + "]\' id=\'rbfa-pcontent-" + i + "\' value=\'\'>"
            +   "<br><button type=\'button\' class=\'rbfa-btn rbfa-edit-page-btn\'"
            +          " style=\'margin-top:5px; font-size:11px;\'"
            +          " id=\'rbfa-pagebtn-" + i + "\'"
            +          " data-idx=\'" + i + "\' data-slug=\'\' data-page-url=\'\'>"
            +     "📄 Edit Page"
            +   "</button>"
            +   "<br><span id=\'rbfa-pageurl-" + i + "\' style=\'font-size:10px; color:#999;\'></span>"
            + "</td>"
            + "<td><span class=\'rbfa-status\' style=\'color:#f0a500; background:#fff8e5;\'>⚠ Unsaved</span></td>"
            + "<td><div class=\'rbfa-scroll\'>" + rowRoleHtml + "</div></td>"
            + "<td><em style=\'color:#999; font-size:11px;\'>Save to generate</em></td>"
            + "<td>"
            +   "<div style=\'display:flex; flex-direction:column; gap:4px;\'>"
            +     "<div>"
            +       "<label style=\'font-size:11px; color:#888; display:block;\'>&#128100; Anonymous</label>"
            +       "<select name=\'denial_ids[" + i + "]\' id=\'" + rid + "-denial\'"
            +              " onchange=\'rbfaToggleRedirect(this, \"" + rid + "\")\'>"
            +       denialRedirectHtml + "</select>"
            +       "<div id=\'" + rid + "-redirect\' style=\'display:none; margin-top:4px;\'>"
            +         "<input type=\'text\' name=\'redirect_urls[" + i + "]\'"
            +                " placeholder=\'https://example.com/page\' style=\'width:100%;\'>"
            +       "</div>"
            +     "</div>"
            +     "<div>"
            +       "<label style=\'font-size:11px; color:#888; display:block;\'>&#128274; Logged In</label>"
            +       "<select name=\'denial_ids_auth[" + i + "]\' id=\'" + rid + "-auth-denial\'"
            +              " onchange=\'rbfaToggleRedirect(this, \"" + rid + "-auth\")\'>"
            +       denialRedirectHtml + "</select>"
            +       "<div id=\'" + rid + "-auth-redirect\' style=\'display:none; margin-top:4px;\'>"
            +         "<input type=\'text\' name=\'redirect_urls_auth[" + i + "]\'"
            +                " placeholder=\'https://example.com/page\' style=\'width:100%;\'>"
            +       "</div>"
            +     "</div>"
            +   "</div>"
            + "</td>"
            + "<td><button type=\'button\' class=\'rbfa-btn rbfa-danger\'"
            + " onclick=\'this.closest(\"tr\").remove(); markDirty();\'>Remove</button></td>";
        markDirty();
    });
    // Mark dirty when any existing Remove button in the table is clicked.
    var table = document.querySelector("#z-table");
    if ( table ) {
        table.addEventListener("click", function( e ){
            if ( e.target && e.target.matches("button.rbfa-danger") ) {
                markDirty();
            }
        });
        // Mark dirty when any folder slug input, role checkbox, or
        // denial screen dropdown changes on an existing zone row.
        table.addEventListener("input", function( e ){
            if ( e.target && (
                e.target.matches("input[type=\'text\']") ||
                e.target.matches("input[type=\'checkbox\']") ||
                e.target.matches("select")
            ) ) {
                markDirty();
            }
        });
        // select elements fire "change" not "input"
        table.addEventListener("change", function( e ){
            if ( e.target && e.target.matches("select") ) {
                markDirty();
            }
        });
    }
    // ── Page editor modal ──────────────────────────────────────────────────────
    var pmModal    = document.getElementById(\'rbfa-page-modal\');
    var pmHeading  = document.getElementById(\'rbfa-pm-heading\');
    var pmTitle    = document.getElementById(\'rbfa-pm-title\');
    var pmContent  = document.getElementById(\'rbfa-pm-content\');
    var pmPreview  = document.getElementById(\'rbfa-pm-preview\');
    var pmLiveLink = document.getElementById(\'rbfa-pm-live-link\');
    var pmConfirm  = document.getElementById(\'rbfa-pm-confirm\');
    var pmCancel   = document.getElementById(\'rbfa-pm-cancel\');
    var pmIdx      = null;
    var pmDebounce = null;
    // Update the preview iframe (debounced so it isn\'t thrashing on every keystroke).
    function rbfaRefreshPreview() {
        var titleHtml = pmTitle.value
            ? \'<h1 style="margin-top:0;">\' + pmTitle.value.replace(/</g,\'&lt;\') + \'</h1>\'
            : \'\';
        pmPreview.srcdoc =
            \'<html><head><style>\'
            + \'body{font-family:sans-serif;padding:16px;margin:0;font-size:14px;color:#333;line-height:1.6;}\'
            + \'h1,h2,h3{line-height:1.2;} img{max-width:100%;}\'
            + \'</style></head><body>\'
            + titleHtml
            + pmContent.value
            + \'</body></html>\';
    }
    pmTitle.addEventListener(\'input\', function() {
        clearTimeout(pmDebounce);
        pmDebounce = setTimeout(rbfaRefreshPreview, 280);
    });
    pmContent.addEventListener(\'input\', function() {
        clearTimeout(pmDebounce);
        pmDebounce = setTimeout(rbfaRefreshPreview, 280);
    });
    // Open modal, pre-populate fields from hidden inputs.
    document.addEventListener(\'click\', function( e ) {
        if ( ! e.target || ! e.target.matches(\'.rbfa-edit-page-btn\') ) return;
        pmIdx = e.target.getAttribute(\'data-idx\');
        var slug     = e.target.getAttribute(\'data-slug\') || \'\';
        var pageUrl  = e.target.getAttribute(\'data-page-url\') || \'\';
        var titleIn  = document.getElementById(\'rbfa-ptitle-\'   + pmIdx);
        var bodyIn   = document.getElementById(\'rbfa-pcontent-\' + pmIdx);
        pmHeading.textContent = slug ? \'Edit Page — \' + slug : \'Edit Zone Page\';
        pmTitle.value   = titleIn ? titleIn.value : \'\';
        pmContent.value = bodyIn  ? bodyIn.value  : \'\';
        if ( pageUrl ) {
            pmLiveLink.href  = pageUrl;
            pmLiveLink.style.display = \'\';
        } else {
            pmLiveLink.style.display = \'none\';
        }
        rbfaRefreshPreview();
        pmModal.style.display = \'flex\';
        pmContent.focus();
    });
    pmConfirm.addEventListener(\'click\', function() {
        if ( pmIdx === null ) return;
        var titleIn = document.getElementById(\'rbfa-ptitle-\'   + pmIdx);
        var bodyIn  = document.getElementById(\'rbfa-pcontent-\' + pmIdx);
        if ( titleIn ) titleIn.value = pmTitle.value;
        if ( bodyIn )  bodyIn.value  = pmContent.value;
        pmModal.style.display = \'none\';
        pmIdx = null;
        markDirty();
    });
    pmCancel.addEventListener(\'click\', function() {
        pmModal.style.display = \'none\';
        pmIdx = null;
    });
    // Close on backdrop click.
    pmModal.addEventListener(\'click\', function( e ) {
        if ( e.target === pmModal ) {
            pmModal.style.display = \'none\';
            pmIdx = null;
        }
    });
    // For new zone rows: update button data-slug and URL label as the user types the slug.
    window.rbfaUpdatePageBtn = function( input, idx ) {
        var slug = input.value.replace(/[^a-z0-9-_]/gi, \'\').toLowerCase();
        var btn  = document.getElementById(\'rbfa-pagebtn-\' + idx);
        var lbl  = document.getElementById(\'rbfa-pageurl-\' + idx);
        if ( btn ) {
            btn.setAttribute(\'data-slug\', slug);
            // No live page URL until saved; clear data-page-url so the modal hides the link.
            btn.setAttribute(\'data-page-url\', \'\');
        }
        if ( lbl ) {
            lbl.textContent = slug ? \'/protected-zone/\' + slug + \'/\' : \'\';
        }
    };
    // Remove an unmanaged directory row. When the last one is gone, also
    // remove the header separator row that precedes them.
    window.rbfaRemoveUnmanaged = function( btn ) {
        var row = btn.closest(\'tr\');
        row.remove();
        markDirty();
        // If no unmanaged rows remain, remove the amber header row too.
        var remaining = document.querySelectorAll(\'.rbfa-remove-unmanaged\');
        if ( remaining.length === 0 ) {
            var headerRows = document.querySelectorAll(\'#z-table td[colspan="6"]\');
            headerRows.forEach(function(td){ td.closest(\'tr\').remove(); });
        }
    };
})();';

    wp_register_script( 'rbfa-zones', false, [], RBFA_VERSION, true );
    wp_enqueue_script( 'rbfa-zones' );
    wp_add_inline_script( 'rbfa-zones', $zone_js );
}

function rbfa_admin_count_files( $dir ) {
    if ( ! is_dir( $dir ) ) return 0;
    $count = 0;
    foreach ( array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] ) as $item ) {
        $path = $dir . '/' . $item;
        if ( is_file( $path ) ) $count++;
        elseif ( is_dir( $path ) ) $count += rbfa_admin_count_files( $path );
    }
    return $count;
}

function rbfa_admin_dir_size( $dir ) {
    if ( ! is_dir( $dir ) ) return 0;
    $size = 0;
    foreach ( array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] ) as $item ) {
        $path = $dir . '/' . $item;
        if ( is_file( $path ) ) $size += filesize( $path );
        elseif ( is_dir( $path ) ) $size += rbfa_admin_dir_size( $path );
    }
    return $size;
}

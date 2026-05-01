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
    $all_msgs   = $wpdb->get_results( "SELECT id, label FROM $msg_table" );
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
    $f_slug   = sanitize_text_field( $_GET['f_slug']   ?? '' );
    $f_denial = (int) ( $_GET['f_denial'] ?? 0 );
    $f_role   = sanitize_key( $_GET['f_role'] ?? '' );

    $filtered_zones = array_values( array_filter( $all_zones, function ( $z ) use ( $f_slug, $f_denial, $f_role ) {
        if ( $f_slug   && stripos( $z['folder_slug'], $f_slug ) === false ) return false;
        if ( $f_denial > 0 && (int) ( $z['denial_id'] ?? 0 ) !== $f_denial ) return false;
        if ( $f_role   && ! in_array( $f_role, $z['roles'] ?? [], true ) )    return false;
        return true;
    } ) );

    // ── Pagination ───────────────────────────────────────────────────────────
    $allowed_per_page = [ 5, 10, 20, 0 ];
    $per_page_raw     = isset( $_GET['per_page'] ) ? (int) $_GET['per_page'] : 5;
    $per_page         = in_array( $per_page_raw, $allowed_per_page, true ) ? $per_page_raw : 5;
    $paged            = max( 1, (int) ( $_GET['paged'] ?? 1 ) );
    $total_zones      = count( $filtered_zones );
    $total_pages      = $per_page > 0 ? (int) ceil( $total_zones / $per_page ) : 1;
    $offset           = $per_page > 0 ? ( $paged - 1 ) * $per_page : 0;
    $page_zones       = $per_page > 0 ? array_slice( $filtered_zones, $offset, $per_page ) : $filtered_zones;

    $active_filters = array_filter( [
        'f_slug'   => $f_slug,
        'f_denial' => $f_denial ?: '',
        'f_role'   => $f_role,
    ] );
    ?>

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
                            echo "<option value='$n'" . selected( $per_page, $n, false ) . ">$n</option>";
                        endforeach; ?>
                        <option value="0" <?php selected( $per_page, 0 ); ?>>All</option>
                    </select>
                </form>
                <span style="color:#666; font-size:13px;">
                    Showing <?php echo count( $page_zones ); ?> of <?php echo $total_zones; ?> zone(s)
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
                            <th>On Deny</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php foreach ( $page_zones as $i => $z ) :
                        $f_exists = is_dir( $upload_dir . '/' . $base . '/' . $z['folder_slug'] ); ?>
                        <tr>
                            <td>
                                <code>/</code>
                                <input type="text" name="folders[<?php echo $i; ?>]"
                                       value="<?php echo esc_attr( $z['folder_slug'] ); ?>">
                            </td>
                            <td>
                                <?php echo $f_exists
                                    ? '<span class="rbfa-status status-ok">✅ Exists</span>'
                                    : '<span class="rbfa-status status-err">❌ Missing</span>'; ?>
                            </td>
                            <td>
                                <div class="rbfa-scroll">
                                    <?php foreach ( $all_roles as $rid => $rname ) :
                                        echo '<label>'
                                            . '<input type="checkbox" name="roles[' . $i . '][]" value="' . esc_attr( $rid ) . '" '
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
                                $row_id       = 'zone-row-' . $i;
                                ?>
                                <select name="denial_ids[<?php echo $i; ?>]"
                                        id="<?php echo $row_id; ?>-denial"
                                        onchange="rbfaToggleRedirect(this, '<?php echo $row_id; ?>')">
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
                                <div id="<?php echo $row_id; ?>-redirect"
                                     style="<?php echo $has_redirect ? '' : 'display:none;'; ?> margin-top:4px;">
                                    <input type="text"
                                           name="redirect_urls[<?php echo $i; ?>]"
                                           value="<?php echo esc_attr( $z['redirect_url'] ?? '' ); ?>"
                                           placeholder="https://example.com/page"
                                           style="width:100%;">
                                </div>
                            </td>
                            <td>
                                <button type="button" class="rbfa-btn rbfa-danger"
                                        onclick="this.closest('tr').remove()">Remove</button>
                            </td>
                        </tr>
                    <?php endforeach; ?>
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

    $zone_js = <<<ZONEJS
(function(){
    var roleHtml         = {$encoded_roles};
    var denialHtml       = {$encoded_denial};
    var denialRedirectHtml = {$encoded_denial_redirect};
    var isDirty          = false;

    // Show/hide the redirect URL field based on the denial dropdown selection.
    window.rbfaToggleRedirect = function( sel, rowId ) {
        var div = document.getElementById( rowId + '-redirect' );
        if ( div ) div.style.display = sel.value === '-1' ? 'block' : 'none';
    };

    // Show the unsaved-changes banner and enable the beforeunload warning.
    function markDirty() {
        if ( isDirty ) return;
        isDirty = true;
        var banner = document.getElementById("rbfa-unsaved-banner");
        if ( banner ) banner.style.display = "flex";
    }

    // Clear dirty state when the save form is submitted (PRG cycle resets page).
    var form = document.querySelector("form[method='post']");
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
        var rid = 'zone-row-' + i;
        r.innerHTML =
              "<td>/ <input type='text' name='folders[" + i + "]' placeholder='zone-slug'></td>"
            + "<td><span class='rbfa-status' style='color:#f0a500; background:#fff8e5;'>⚠ Unsaved</span></td>"
            + "<td><div class='rbfa-scroll'>" + rowRoleHtml + "</div></td>"
            + "<td><em style='color:#999; font-size:11px;'>Save to generate</em></td>"
            + "<td>"
            +   "<select name='denial_ids[" + i + "]' id='" + rid + "-denial'"
            +          " onchange='rbfaToggleRedirect(this, \"" + rid + "\")'>"
            +   denialRedirectHtml + "</select>"
            +   "<div id='" + rid + "-redirect' style='display:none; margin-top:4px;'>"
            +     "<input type='text' name='redirect_urls[" + i + "]'"
            +            " placeholder='https://example.com/page' style='width:100%;'>"
            +   "</div>"
            + "</td>"
            + "<td><button type='button' class='rbfa-btn rbfa-danger'"
            + " onclick='this.closest(\"tr\").remove(); markDirty();'>Remove</button></td>";
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
                e.target.matches("input[type='text']") ||
                e.target.matches("input[type='checkbox']") ||
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
})();
ZONEJS;

    wp_register_script( 'rbfa-zones', false, [], false, true );
    wp_enqueue_script( 'rbfa-zones' );
    wp_add_inline_script( 'rbfa-zones', $zone_js );
}

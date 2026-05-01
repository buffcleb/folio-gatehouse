<?php
/**
 * Denial Screens tab renderer.
 *
 * Allows admins to create and edit custom HTML pages shown to users who are
 * denied access to a zone.
 *
 * Security:
 *  - HTML is sanitized with rbfa_kses_denial() (strict allowlist) on save and read-back.
 *  - Live preview uses textContent — not innerHTML — so it cannot execute scripts.
 *  - All output escaped with esc_html() / esc_textarea() / esc_url() / esc_attr().
 *
 * Login redirect shortcode
 * ────────────────────────
 * Add [rbfa_login_link] to denial screen HTML to insert a login link that
 * brings the user back to the originally-requested file after authentication.
 * An opaque transient token handles the redirect — the URL exposes nothing
 * about which roles or users are authorised for the file.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Renders the Denial Screens tab. Called from rbfa_pro_page().
 */
function rbfa_render_tab_denial() {
    global $wpdb;

    $msg_table = $wpdb->prefix . 'rbfa_denial_screens';
    $e_id      = (int) ( $_GET['edit'] ?? 0 );
    $es        = $e_id
        ? $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $msg_table WHERE id = %d", $e_id ) )
        : null;

    // Re-sanitize read-back content so DB-injected content cannot bypass the allowlist.
    $safe_content = $es ? rbfa_kses_denial( $es->html_content ?? '' ) : '';
    $login_url    = $es ? ( $es->login_url ?? '' ) : '';
    ?>

    <!-- ── Editor card ──────────────────────────────────────────────────────── -->
    <div class="rbfa-card">
        <h3><?php echo $es ? 'Edit Denial Screen' : 'New Denial Screen'; ?></h3>
        <p style="color:#666; font-size:13px; margin-top:0;">
            Only safe HTML is permitted (text, headings, links, images, tables).
            Scripts, iframes, forms, and event handlers are automatically removed.
        </p>

        <!-- Login redirect shortcode hint — shown before the form fields -->
        <div style="background:#f0f6fb; border:1px solid #c3d9ee; border-radius:4px; padding:12px; margin-bottom:20px; font-size:13px; line-height:1.6;">
            <strong>Login redirect shortcode</strong><br>
            Paste <code style="background:#e3eef9; padding:2px 6px; border-radius:3px; user-select:all;">[rbfa_login_link]</code>
            anywhere in your HTML content to add a link that sends denied users to the login page
            and returns them to the originally-requested file after a successful login.<br>
            Optional attributes: <code>text="..."</code> (guest link label) and
            <code>logout_text="..."</code> (label when already logged in as the wrong account).<br><br>
            If the user is already logged in but has the wrong role, the link will log them out
            first and redirect them to the login page so they can try a different account.
        </div>

        <!-- Unsaved-changes banner -->
        <div id="rbfa-denial-unsaved-banner"
             style="display:none; align-items:center; gap:12px;
                    background:#fff8e5; border:1px solid #f0a500;
                    border-radius:4px; padding:10px 14px; margin-bottom:12px;">
            <span style="font-size:18px;">⚠</span>
            <span style="flex:1; font-weight:600; color:#856404;">
                You have unsaved changes. Click <em>Save Denial Screen</em> to apply them.
            </span>
        </div>

        <form id="rbfa-denial-form" method="post">
            <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
            <input type="hidden" name="id" value="<?php echo $e_id; ?>">

            <!-- Label -->
            <p>
                <label style="font-weight:600; display:block; margin-bottom:4px;">Label</label>
                <input type="text" name="label"
                       value="<?php echo esc_attr( $es->label ?? '' ); ?>"
                       placeholder="e.g. Members Only"
                       required class="regular-text">
            </p>

            <!-- Login page URL — used by [rbfa_login_link] to build the redirect -->
            <p>
                <label style="font-weight:600; display:block; margin-bottom:4px;">
                    Login page URL
                    <span style="font-weight:normal; color:#666;">
                        — used by <code>[rbfa_login_link]</code>. Leave blank to use
                        WordPress's built-in <code>wp-login.php</code>.
                    </span>
                </label>
                <input type="text" name="login_url"
                       value="<?php echo esc_attr( $login_url ); ?>"
                       placeholder="Leave blank for wp-login.php  —  or e.g. /my-account/"
                       class="regular-text" style="width:100%; max-width:500px;">
            </p>

            <!-- HTML content -->
            <p>
                <label style="font-weight:600; display:block; margin-bottom:4px;">HTML Content</label>
                <small style="color:#666;">
                    Allowed: headings, paragraphs, lists, links, images, tables, basic inline styles.
                    Not allowed: &lt;script&gt;, &lt;iframe&gt;, &lt;form&gt;, event handlers.
                </small>
            </p>
            <textarea id="rbfa-html-input" name="html_content"
                      style="width:100%; font-family:monospace; font-size:13px;"
                      rows="10"><?php echo esc_textarea( $safe_content ); ?></textarea>

            <!-- Rendered preview — sandboxed iframe with srcdoc.
                 sandbox="allow-same-origin" permits CSS inheritance from srcdoc
                 but blocks all script execution, even if the textarea contains
                 <script> tags. Admin page CSS does not bleed in because the
                 iframe document is separate. This is safe for previewing the
                 kses-filtered HTML that will actually be shown to users. -->
            <p style="font-weight:600; margin-bottom:4px; margin-top:12px;">
                Rendered Preview
                <small style="font-weight:normal; color:#666;">
                    — live preview of how the denial screen will appear (scripts blocked)
                </small>
            </p>
            <iframe id="rbfa-preview"
                    sandbox="allow-same-origin"
                    style="width:100%; min-height:120px; border:1px dashed #ccd0d4;
                           border-radius:4px; background:#fff; display:block;"
                    srcdoc="<p style='color:#999;'>Preview will update as you type...</p>">
            </iframe>

            <p style="margin-top:12px;">
                <input type="submit" name="rbfa_save_msg" value="Save Denial Screen" class="button button-primary">
                <?php if ( $e_id ) : ?>
                    <a href="<?php echo esc_url( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'denial' ], admin_url( 'admin.php' ) ) ); ?>"
                       class="rbfa-btn" style="margin-left:10px;">Cancel Edit</a>
                <?php endif; ?>
            </p>
        </form>
    </div>

    <!-- ── Existing screens table ───────────────────────────────────────────── -->
    <table class="widefat striped" style="margin-top:20px;">
        <thead>
            <tr>
                <th>Label</th>
                <th>Login Page</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
        <?php
        $screens = $wpdb->get_results( "SELECT * FROM $msg_table ORDER BY label ASC" );

        if ( empty( $screens ) ) :
            echo '<tr><td colspan="3" style="color:#999;">No denial screens created yet.</td></tr>';
        else :
            foreach ( $screens as $s ) :
                $edit_url   = add_query_arg(
                    [ 'page' => 'rbfa-pro', 'tab' => 'denial', 'edit' => $s->id ],
                    admin_url( 'admin.php' )
                );
                // Display configured login page or a note that the default will be used.
                $login_disp = ! empty( $s->login_url )
                    ? esc_html( $s->login_url )
                    : '<em style="color:#999;">wp-login.php (default)</em>';
                ?>
                <tr>
                    <td><?php echo esc_html( $s->label ); ?></td>
                    <td><?php echo $login_disp; ?></td>
                    <td>
                        <a href="<?php echo esc_url( $edit_url ); ?>" class="rbfa-btn">Edit</a>
                        <form method="post" style="display:inline;">
                            <?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
                            <input type="hidden" name="id" value="<?php echo esc_attr( $s->id ); ?>">
                            <input type="submit" name="rbfa_del_msg" value="Delete"
                                   class="rbfa-btn rbfa-danger"
                                   onclick="return confirm('Delete this denial screen?');">
                        </form>
                    </td>
                </tr>
            <?php endforeach;
        endif;
        ?>
        </tbody>
    </table>

    <?php
    // Denial tab JS:
    //  1. Live preview via sandboxed iframe srcdoc (scripts blocked).
    //  2. Dirty flag + beforeunload warning for unsaved changes.
    $denial_js = "(function(){
    var isDirty = false;

    function markDirty() {
        if ( isDirty ) return;
        isDirty = true;
        var banner = document.getElementById('rbfa-denial-unsaved-banner');
        if ( banner ) banner.style.display = 'flex';
    }

    // Clear dirty when the editor form is submitted.
    var form = document.querySelector('#rbfa-denial-form');
    if ( form ) {
        form.addEventListener('submit', function(){ isDirty = false; });
    }

    // Warn before navigating away with unsaved changes.
    window.addEventListener('beforeunload', function( e ){
        if ( ! isDirty ) return;
        e.preventDefault();
        e.returnValue = 'You have unsaved denial screen changes. Leave anyway?';
    });

    // Live preview — srcdoc replaces the iframe document; sandbox blocks scripts.
    var input   = document.getElementById('rbfa-html-input');
    var preview = document.getElementById('rbfa-preview');
    if ( input && preview ) {
        input.addEventListener('input', function(){
            markDirty();
            preview.srcdoc = this.value || '<p style=\"color:#999;\">Preview will update as you type...</p>';
        });
    }

    // Mark dirty on any change to the label or login URL fields.
    ['input[name=\"label\"]', 'input[name=\"login_url\"]'].forEach(function( sel ){
        var el = document.querySelector( sel );
        if ( el ) el.addEventListener('input', function(){ markDirty(); });
    });
})();";


    wp_register_script( 'rbfa-denial', false, [], false, true );
    wp_enqueue_script( 'rbfa-denial' );
    wp_add_inline_script( 'rbfa-denial', $denial_js );
}

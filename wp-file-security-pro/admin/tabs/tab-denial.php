<?php
/**
 * Denial Screens tab renderer.
 *
 * Allows admins to create and edit custom HTML pages shown to users who are
 * denied access to a zone.
 *
 * Security:
 *  - HTML is sanitized with rbfa_kses_denial() (strict allowlist) on save and read-back.
 *  - Live preview uses a sandboxed iframe srcdoc — scripts are blocked.
 *  - All output escaped with esc_html() / esc_textarea() / esc_url() / esc_attr().
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

function rbfa_render_tab_denial() {
    global $wpdb;

    $msg_table = $wpdb->prefix . 'rbfa_denial_screens';

    // ── Edit mode ──────────────────────────────────────────────────────────────
    $e_id = (int) ( $_GET['edit'] ?? 0 ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only, opens edit modal
    $es   = $e_id
        ? $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $msg_table WHERE id = %d", $e_id ) )
        : null;

    $safe_content = $es ? rbfa_kses_denial( $es->html_content ?? '' ) : '';

    // Data passed to JS so it can auto-open the modal when editing.
    $edit_data_js = ( $e_id && $es ) ? wp_json_encode( [
        'id'           => $e_id,
        'label'        => $es->label       ?? '',
        'login_url'    => $es->login_url   ?? '',
        'html_content' => $safe_content,
    ] ) : 'null';

    // ── Filter + pagination ────────────────────────────────────────────────────
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter parameters, no data mutation
    $f_label  = sanitize_text_field( wp_unslash( $_GET['f_label'] ?? '' ) );
    $per_page = 10;
    $paged    = max( 1, (int) ( $_GET['denial_paged'] ?? 1 ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only filter parameters, no data mutation

    if ( $f_label !== '' ) {
        $like    = '%' . $wpdb->esc_like( $f_label ) . '%';
        $total   = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $msg_table WHERE label LIKE %s", $like ) );
        $screens = $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM $msg_table WHERE label LIKE %s ORDER BY label ASC LIMIT %d OFFSET %d",
            $like, $per_page, ( $paged - 1 ) * $per_page
        ) );
    } else {
        $total   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $msg_table" );
        $screens = $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM $msg_table ORDER BY label ASC LIMIT %d OFFSET %d",
            $per_page, ( $paged - 1 ) * $per_page
        ) );
    }

    $total_pages = max( 1, (int) ceil( $total / $per_page ) );
    $paged       = min( $paged, $total_pages );

    $link_args = [ 'page' => 'rbfa-pro', 'tab' => 'denial' ];
    if ( $f_label !== '' ) $link_args['f_label'] = $f_label;
    ?>

    <!-- ── Denial Screen Editor Modal ────────────────────────────────────────── -->
    <div id="rbfa-denial-modal"
         style="display:none; position:fixed; inset:0; background:rgba(0,0,0,.55);
                z-index:999999; align-items:flex-start; justify-content:center;
                overflow-y:auto; padding:40px 16px;">

        <div style="background:#fff; width:860px; max-width:96vw; border-radius:6px;
                    box-shadow:0 8px 32px rgba(0,0,0,.25); overflow:hidden; margin:auto;">

            <!-- Modal header -->
            <div style="padding:14px 20px; border-bottom:1px solid #ddd;
                        display:flex; align-items:center; gap:12px; position:sticky; top:0; background:#fff; z-index:1;">
                <h3 id="rbfa-dm-title" style="margin:0; flex:1; font-size:15px;">New Denial Screen</h3>
                <button type="button" id="rbfa-dm-close"
                        style="background:none; border:none; font-size:20px; cursor:pointer;
                               color:#666; line-height:1; padding:0 4px;">&times;</button>
            </div>

            <!-- Modal body -->
            <div style="padding:20px;">

                <!-- Shortcode reference -->
                <div style="background:#f0f6fb; border:1px solid #c3d9ee; border-radius:4px;
                            padding:12px 14px; margin-bottom:20px; font-size:13px; line-height:1.7;">
                    <strong style="font-size:14px;">Available shortcodes</strong>

                    <!-- [rbfa_login_link] accordion -->
                    <div style="margin-top:10px; border:1px solid #c3d9ee; border-radius:4px; background:#fff;">
                        <button type="button"
                                onclick="var d=this.nextElementSibling; var open=d.style.display!=='none'; d.style.display=open?'none':'block'; this.querySelector('.rbfa-sc-arrow').textContent=open?'▶':'▼';"
                                style="width:100%; text-align:left; background:none; border:none;
                                       padding:8px 12px; cursor:pointer; display:flex; align-items:center; gap:8px;">
                            <span class="rbfa-sc-arrow" style="font-size:10px; color:#888;">▶</span>
                            <code style="background:#e3eef9; padding:2px 6px; border-radius:3px; user-select:all;">[rbfa_login_link]</code>
                            <span style="color:#555;">&nbsp;— Login and return to the <strong>file</strong></span>
                        </button>
                        <div style="display:none; padding:0 12px 10px; border-top:1px solid #e3eef9;">
                            <p style="margin:8px 0 4px; color:#444;">
                                Sends the denied user to the login page. After a successful login the
                                original file is served immediately. If the user is already logged in
                                with the wrong role the link logs them out first so they can try a
                                different account.
                            </p>
                            <p style="margin:0;">
                                Attributes: <code>text="Sign in to download"</code>
                                &nbsp;<code>logout_text="Try a different account"</code>
                            </p>
                        </div>
                    </div>

                    <!-- [rbfa_zone_link] accordion -->
                    <div style="margin-top:6px; border:1px solid #c3d9ee; border-radius:4px; background:#fff;">
                        <button type="button"
                                onclick="var d=this.nextElementSibling; var open=d.style.display!=='none'; d.style.display=open?'none':'block'; this.querySelector('.rbfa-sc-arrow').textContent=open?'▶':'▼';"
                                style="width:100%; text-align:left; background:none; border:none;
                                       padding:8px 12px; cursor:pointer; display:flex; align-items:center; gap:8px;">
                            <span class="rbfa-sc-arrow" style="font-size:10px; color:#888;">▶</span>
                            <code style="background:#e3eef9; padding:2px 6px; border-radius:3px; user-select:all;">[rbfa_zone_link]</code>
                            <span style="color:#555;">&nbsp;— Login and return to the <strong>zone page</strong></span>
                        </button>
                        <div style="display:none; padding:0 12px 10px; border-top:1px solid #e3eef9;">
                            <p style="margin:8px 0 4px; color:#444;">
                                Same login / logout behaviour as <code>[rbfa_login_link]</code>, but after
                                authentication the user is taken to the zone&rsquo;s
                                <code>/protected-zone/{slug}/</code> page rather than directly downloading
                                the file. Use this when you want users to see the full file listing first.
                            </p>
                            <p style="margin:0;">
                                Attributes: <code>text="Log in to view this content"</code>
                                &nbsp;<code>logout_text="Try a different account"</code>
                            </p>
                        </div>
                    </div>

                    <p style="margin:10px 0 0; color:#555; font-size:12px;">
                        Both shortcodes use an opaque one-time token — the URL never exposes file
                        paths, role names, or zone information. The token expires after 15&nbsp;minutes.
                        Configure the <strong>Login page URL</strong> field below to use WooCommerce
                        My Account, a custom login page, or any other login URL.
                    </p>
                </div>

                <p style="color:#666; font-size:13px; margin-top:0;">
                    Only safe HTML is permitted (text, headings, links, images, tables).
                    Scripts, iframes, forms, and event handlers are automatically removed.
                </p>

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
                    <input type="hidden" name="id" id="rbfa-dm-id" value="0">

                    <!-- Label -->
                    <p>
                        <label style="font-weight:600; display:block; margin-bottom:4px;">Label</label>
                        <input type="text" name="label" id="rbfa-dm-label"
                               placeholder="e.g. Members Only"
                               required class="regular-text">
                    </p>

                    <!-- Login page URL -->
                    <p>
                        <label style="font-weight:600; display:block; margin-bottom:4px;">
                            Login page URL
                            <span style="font-weight:normal; color:#666;">
                                — used by <code>[rbfa_login_link]</code>. Leave blank to use
                                WordPress&rsquo;s built-in <code>wp-login.php</code>.
                            </span>
                        </label>
                        <input type="text" name="login_url" id="rbfa-dm-login-url"
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
                              rows="10"></textarea>

                    <!-- Rendered preview -->
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

                    <p style="margin-top:12px; display:flex; gap:8px; align-items:center;">
                        <input type="submit" name="rbfa_save_msg" value="Save Denial Screen"
                               class="button button-primary">
                        <button type="button" id="rbfa-dm-cancel" class="button">Cancel</button>
                    </p>
                </form>
            </div>
        </div>
    </div>

    <!-- ── Toolbar: New button + filter ──────────────────────────────────────── -->
    <div class="rbfa-card" style="padding:12px 16px; margin-bottom:8px;">
        <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">

            <button type="button" id="rbfa-open-new-denial"
                    class="button button-primary">+ New Denial Screen</button>

            <form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>"
                  style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-left:auto;">
                <input type="hidden" name="page" value="rbfa-pro">
                <input type="hidden" name="tab"  value="denial">
                <input type="text" name="f_label"
                       value="<?php echo esc_attr( $f_label ); ?>"
                       placeholder="Filter by label…"
                       style="width:200px;">
                <input type="submit" value="Filter" class="button">
                <?php if ( $f_label !== '' ) : ?>
                    <a href="<?php echo esc_url( add_query_arg(
                        [ 'page' => 'rbfa-pro', 'tab' => 'denial' ],
                        admin_url( 'admin.php' )
                    ) ); ?>" class="button">Clear</a>
                <?php endif; ?>
            </form>
        </div>
    </div>

    <!-- Count summary -->
    <p style="color:#666; font-size:13px; margin:0 0 8px;">
        <?php
        if ( $f_label !== '' ) {
            printf(
                '%d of %d denial screen%s matching &ldquo;%s&rdquo;.',
                count( $screens ),
                $total,
                $total !== 1 ? 's' : '',
                esc_html( $f_label )
            );
        } else {
            printf( '%d denial screen%s total.', $total, $total !== 1 ? 's' : '' );
        }
        ?>
    </p>

    <!-- ── Screens table ──────────────────────────────────────────────────────── -->
    <table class="widefat striped">
        <thead>
            <tr>
                <th>Label</th>
                <th>Login Page</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
        <?php if ( empty( $screens ) ) : ?>
            <tr>
                <td colspan="3" style="color:#999;">
                    <?php echo $f_label !== '' ? 'No denial screens match your filter.' : 'No denial screens created yet.'; ?>
                </td>
            </tr>
        <?php else :
            foreach ( $screens as $s ) :
                $login_disp = ! empty( $s->login_url )
                    ? esc_html( $s->login_url )
                    : '<em style="color:#999;">wp-login.php (default)</em>';
                ?>
                <tr>
                    <td><?php echo esc_html( $s->label ); ?></td>
                    <td><?php echo $login_disp; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $login_disp is either esc_html() output or a static safe HTML string ?></td>
                    <td>
                        <button type="button" class="rbfa-btn rbfa-edit-denial"
                                data-id="<?php echo esc_attr( $s->id ); ?>"
                                data-label="<?php echo esc_attr( $s->label ); ?>"
                                data-login-url="<?php echo esc_attr( $s->login_url ?? '' ); ?>"
                                data-html="<?php echo esc_attr( rbfa_kses_denial( $s->html_content ?? '' ) ); ?>">
                            Edit
                        </button>
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
        endif; ?>
        </tbody>
    </table>

    <!-- ── Pagination ─────────────────────────────────────────────────────────── -->
    <?php if ( $total_pages > 1 ) : ?>
        <div style="margin-top:16px; display:flex; gap:6px; align-items:center; justify-content:center;">
            <?php if ( $paged > 1 ) : ?>
                <a href="<?php echo esc_url( add_query_arg(
                    array_merge( $link_args, [ 'denial_paged' => $paged - 1 ] ),
                    admin_url( 'admin.php' )
                ) ); ?>" class="button">&laquo; Prev</a>
            <?php endif; ?>
            <span style="color:#666; font-size:13px; padding:0 4px;">
                Page <?php echo $paged; ?> of <?php echo $total_pages; ?>
            </span>
            <?php if ( $paged < $total_pages ) : ?>
                <a href="<?php echo esc_url( add_query_arg(
                    array_merge( $link_args, [ 'denial_paged' => $paged + 1 ] ),
                    admin_url( 'admin.php' )
                ) ); ?>" class="button">Next &raquo;</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php
    $denial_js = "(function(){
    var modal    = document.getElementById('rbfa-denial-modal');
    var titleEl  = document.getElementById('rbfa-dm-title');
    var idInput  = document.getElementById('rbfa-dm-id');
    var labelIn  = document.getElementById('rbfa-dm-label');
    var loginIn  = document.getElementById('rbfa-dm-login-url');
    var htmlIn   = document.getElementById('rbfa-html-input');
    var preview  = document.getElementById('rbfa-preview');
    var banner   = document.getElementById('rbfa-denial-unsaved-banner');
    var isDirty  = false;

    // ── Dirty tracking ─────────────────────────────────────────────────────────

    function markDirty() {
        if ( isDirty ) return;
        isDirty = true;
        if ( banner ) banner.style.display = 'flex';
    }

    function clearDirty() {
        isDirty = false;
        if ( banner ) banner.style.display = 'none';
    }

    document.getElementById('rbfa-denial-form').addEventListener('submit', function(){
        clearDirty();
    });

    window.addEventListener('beforeunload', function(e){
        if ( ! isDirty ) return;
        e.preventDefault();
        e.returnValue = 'You have unsaved denial screen changes. Leave anyway?';
    });

    // ── Open / close ───────────────────────────────────────────────────────────

    function openModal( data ) {
        if ( data ) {
            titleEl.textContent       = 'Edit Denial Screen';
            idInput.value             = data.id;
            labelIn.value             = data.label;
            loginIn.value             = data.loginUrl;
            htmlIn.value              = data.htmlContent;
        } else {
            titleEl.textContent = 'New Denial Screen';
            idInput.value       = '0';
            labelIn.value       = '';
            loginIn.value       = '';
            htmlIn.value        = '';
        }
        clearDirty();
        refreshPreview();
        modal.style.display = 'flex';
        modal.scrollTop     = 0;
        setTimeout(function(){ labelIn.focus(); }, 50);
    }

    function closeModal() {
        if ( isDirty && ! confirm('You have unsaved changes. Close without saving?') ) return;
        modal.style.display = 'none';
        clearDirty();
    }

    document.getElementById('rbfa-open-new-denial').addEventListener('click', function(){
        openModal(null);
    });

    document.getElementById('rbfa-dm-close').addEventListener('click', closeModal);
    document.getElementById('rbfa-dm-cancel').addEventListener('click', closeModal);

    modal.addEventListener('click', function(e){
        if ( e.target === this ) closeModal();
    });

    // ── Edit buttons in the table ──────────────────────────────────────────────

    document.querySelectorAll('.rbfa-edit-denial').forEach(function(btn){
        btn.addEventListener('click', function(){
            openModal({
                id:          this.dataset.id,
                label:       this.dataset.label,
                loginUrl:    this.dataset.loginUrl,
                htmlContent: this.dataset.html,
            });
        });
    });

    // ── Live preview ───────────────────────────────────────────────────────────

    function refreshPreview() {
        if ( preview ) {
            preview.srcdoc = htmlIn.value
                || '<p style=\"color:#999;\">Preview will update as you type...</p>';
        }
    }

    htmlIn.addEventListener('input', function(){
        markDirty();
        refreshPreview();
    });

    labelIn.addEventListener('input', markDirty);
    loginIn.addEventListener('input', markDirty);

    // ── Auto-open for edit (set by PHP when ?edit= is in URL) ─────────────────

    var editData = {$edit_data_js};
    if ( editData ) {
        openModal({
            id:          editData.id,
            label:       editData.label,
            loginUrl:    editData.login_url,
            htmlContent: editData.html_content,
        });
    }
})();";

    wp_register_script( 'rbfa-denial', false, [], false, true );
    wp_enqueue_script( 'rbfa-denial' );
    wp_add_inline_script( 'rbfa-denial', $denial_js );
}

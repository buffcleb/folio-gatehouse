<?php
/**
 * Admin panel — menu registration, asset enqueueing, form handlers, tab dispatcher.
 *
 * This file wires up the top-level admin menu item, enqueues shared CSS/JS,
 * processes all POST form submissions (with nonce and capability checks), and
 * then dispatches rendering to the appropriate tab file.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Load individual tab renderers.
require_once RBFA_DIR . 'admin/tabs/tab-logs.php';
require_once RBFA_DIR . 'admin/tabs/tab-zones.php';
require_once RBFA_DIR . 'admin/tabs/tab-roles.php';
require_once RBFA_DIR . 'admin/tabs/tab-denial.php';
require_once RBFA_DIR . 'admin/tabs/tab-settings.php';
require_once RBFA_DIR . 'admin/tabs/tab-nginx.php';

// ─── POST handler (admin_init — before any output is sent) ───────────────────

add_action( 'admin_init', 'rbfa_handle_admin_post' );

/**
 * Processes all plugin POST form submissions.
 *
 * Hooked to admin_init so it runs before WordPress sends any HTML output.
 * This allows wp_redirect() to work cleanly without "headers already sent"
 * warnings — the same reason the CSV export lives on admin_init.
 *
 * Only acts when the request targets this plugin's admin page.
 */
function rbfa_sanitize_redirect( $raw ) {
	$raw = trim( $raw );
	if ( $raw === '' ) return '';
	return preg_match( '#^https?://#i', $raw ) ? esc_url_raw( $raw ) : sanitize_text_field( $raw );
}

function rbfa_handle_admin_post() {
	// Only handle POSTs to our own page.
	if ( ! isset( $_POST['rbfa_nonce'] ) ) {
		return;
	}
	if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'rbfa-pro' ) {
		return;
	}
	if ( ! current_user_can( 'manage_wfsp' ) ) {
		wp_die( esc_html__( 'You do not have permission to perform this action.', 'wp-file-security-pro' ) );
	}

	// Verify nonce — dies automatically on failure.
	check_admin_referer( 'rbfa_admin_action', 'rbfa_nonce' );

	// WordPress applies addslashes() to $_POST via wp_magic_quotes(). Unslash
	// once here so sanitisation functions receive the original user input and
	// repeated save/edit cycles don't accumulate backslashes.
	$_POST = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

	global $wpdb;

	$zone_table  = $wpdb->prefix . 'rbfa_zones';
	$role_table  = $wpdb->prefix . 'rbfa_managed_roles';
	$msg_table   = $wpdb->prefix . 'rbfa_denial_screens';
	$current_tab = sanitize_key( $_GET['tab'] ?? 'logs' );

	// ── Zone save ────────────────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_save_zones'] ) ) {
		// Base folder is managed exclusively on the Settings tab — do not read
		// it from $_POST here, as the Zones form has no such field and would
		// silently reset it to the fallback default on every zone save.

		// Delete and re-insert all non-default zone rows.
		$wpdb->query( $wpdb->prepare( "DELETE FROM $zone_table WHERE is_default = %d", 0 ) );

		$seen        = [];
		$saved_count = 0;
		foreach ( (array) ( $_POST['folders'] ?? [] ) as $i => $f ) {
			$slug = sanitize_title( $f );
			if ( empty( $slug ) || in_array( $slug, $seen, true ) ) continue;
			$roles = array_map( 'sanitize_key', (array) ( $_POST['roles'][ $i ] ?? [] ) );
			// Sanitize redirect URLs — must be absolute or relative; empty = no redirect.
			$redirect_url      = rbfa_sanitize_redirect( $_POST['redirect_urls'][ $i ] ?? '' );
			$redirect_url_auth = rbfa_sanitize_redirect( $_POST['redirect_urls_auth'][ $i ] ?? '' );

			$wpdb->insert(
				$zone_table,
				[
					'folder_slug'      => $slug,
					'allowed_roles'    => wp_json_encode( $roles ),
					'denial_id'        => (int) ( $_POST['denial_ids'][ $i ] ?? 0 ),
					'denial_id_auth'   => (int) ( $_POST['denial_ids_auth'][ $i ] ?? 0 ),
					'redirect_url'     => $redirect_url,
					'redirect_url_auth' => $redirect_url_auth,
					'page_title'       => sanitize_text_field( $_POST['page_titles'][ $i ] ?? '' ),
					'page_content'     => wp_kses_post( $_POST['page_contents'][ $i ] ?? '' ),
				],
				[ '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s' ]
			);

			$seen[] = $slug;
			$saved_count++;
		}

		rbfa_sync_all();

		set_transient(
			'rbfa_admin_notice_' . get_current_user_id(),
			[
				'type'    => 'success',
				'message' => sprintf( 'Zones saved: <strong>%d</strong>.', $saved_count ),
			],
			30
		);
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'config' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Role creation ─────────────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_create_role'] ) ) {
		$display_name = sanitize_text_field( $_POST['role_name'] ?? '' );
		$base_slug    = sanitize_key( $display_name );
		// All plugin-managed roles are prefixed with wfsp_ for automatic detection.
		$id = strpos( $base_slug, 'wfsp_' ) === 0 ? $base_slug : 'wfsp_' . $base_slug;
		if ( $id !== 'wfsp_' && ! get_role( $id ) ) {
			add_role( $id, $display_name, [ 'read' => true ] );
		}
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Role rename ───────────────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_rename_role'] ) ) {
		$role_id = sanitize_key( $_POST['role_id'] ?? '' );
		if ( $role_id === 'wfsp_admins' ) {
			wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
			exit;
		}
		if ( in_array( $role_id, rbfa_get_managed_roles(), true ) ) {
			global $wp_roles;
			$wp_roles->roles[ $role_id ]['name'] = sanitize_text_field( $_POST['new_name'] ?? '' );
			update_option( $wpdb->prefix . 'user_roles', $wp_roles->roles );
		}
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Add users to managed role ─────────────────────────────────────────────
	if ( isset( $_POST['rbfa_add_user'] ) ) {
		$role_id = sanitize_key( $_POST['role_id'] ?? '' );
		if ( in_array( $role_id, rbfa_get_managed_roles(), true ) ) {
			foreach ( (array) ( $_POST['user_ids'] ?? [] ) as $uid ) {
				$u = get_userdata( (int) $uid );
				if ( $u ) $u->add_role( $role_id );
			}
		}
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Remove user from managed role ─────────────────────────────────────────
	if ( isset( $_POST['rbfa_remove_user'] ) ) {
		$role_id = sanitize_key( $_POST['role_id'] ?? '' );
		if ( in_array( $role_id, rbfa_get_managed_roles(), true ) ) {
			$u = get_user_by( 'id', (int) ( $_POST['user_id'] ?? 0 ) );
			if ( $u ) $u->remove_role( $role_id );
		}
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Delete managed role ───────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_delete_role'] ) ) {
		$role_id = sanitize_key( $_POST['role_id'] ?? '' );
		if ( $role_id === 'wfsp_admins' ) {
			wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
			exit;
		}
		if ( in_array( $role_id, rbfa_get_managed_roles(), true ) ) {
			remove_role( $role_id );
			$wpdb->delete( $role_table, [ 'role_id' => $role_id ], [ '%s' ] );
		}
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Save denial screen ────────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_save_msg'] ) ) {
		$raw_login_url   = trim( $_POST['login_url'] ?? '' );
		$login_url_clean = '';
		if ( $raw_login_url !== '' ) {
			$login_url_clean = ( strpos( $raw_login_url, 'http' ) === 0 )
				? esc_url_raw( $raw_login_url )
				: sanitize_text_field( $raw_login_url );
		}
		$data = [
			'label'        => sanitize_text_field( $_POST['label'] ?? '' ),
			'html_content' => rbfa_kses_denial( $_POST['html_content'] ?? '' ),
			'login_url'    => $login_url_clean,
		];
		if ( ! empty( $_POST['id'] ) ) {
			$wpdb->update( $msg_table, $data, [ 'id' => (int) $_POST['id'] ], [ '%s', '%s', '%s' ], [ '%d' ] );
		} else {
			$wpdb->insert( $msg_table, $data, [ '%s', '%s', '%s' ] );
		}
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'denial' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Delete denial screen ──────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_del_msg'] ) ) {
		$wpdb->delete( $msg_table, [ 'id' => (int) ( $_POST['id'] ?? 0 ) ], [ '%d' ] );
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'denial' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Manual log prune ─────────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_manual_prune'] ) ) {
		$deleted = rbfa_manual_prune_logs();
		set_transient( 'rbfa_admin_notice_' . get_current_user_id(),
			[ 'type' => 'success', 'message' => sprintf( 'Manual prune complete. <strong>%d</strong> log entr%s deleted.', $deleted, $deleted === 1 ? 'y' : 'ies' ) ], 30 );
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'logs' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── System settings (from Settings tab) ─────────────────────────────────
	if ( isset( $_POST['rbfa_save_system_settings'] ) ) {
		global $wpdb;
		$zone_table = $wpdb->prefix . 'rbfa_zones';
		$base_slug  = sanitize_title( $_POST['rbfa_base_folder'] ?? 'list_files' );
		if ( empty( $base_slug ) ) $base_slug = 'list_files';

		// Upsert the rbfa_default row with the new base slug.
		$exists = $wpdb->get_var( $wpdb->prepare(
			"SELECT id FROM $zone_table WHERE folder_slug = %s AND is_default = %d",
			'rbfa_default', 1
		) );
		if ( $exists ) {
			$wpdb->update( $zone_table, [ 'allowed_roles' => $base_slug ],
				[ 'folder_slug' => 'rbfa_default', 'is_default' => 1 ], [ '%s' ], [ '%s', '%d' ] );
		} else {
			$wpdb->insert( $zone_table,
				[ 'folder_slug' => 'rbfa_default', 'allowed_roles' => $base_slug, 'denial_id' => 0, 'is_default' => 1 ],
				[ '%s', '%s', '%d', '%d' ] );
		}

		update_option( 'rbfa_cron_enabled',           isset( $_POST['cron_enabled'] )               ? '1' : '0' );
		update_option( 'rbfa_zone_page_use_theme',    isset( $_POST['rbfa_zone_page_use_theme'] )    ? '1' : '0' );
		update_option( 'rbfa_prune_enabled',          isset( $_POST['rbfa_prune_enabled'] )          ? '1' : '0' );
		$prune_days = max( 1, (int) ( $_POST['rbfa_prune_days'] ?? 90 ) );
		update_option( 'rbfa_prune_days', $prune_days );
		if ( isset( $_POST['confirm_sync'] ) ) rbfa_sync_all();

		set_transient( 'rbfa_admin_notice_' . get_current_user_id(),
			[ 'type' => 'success', 'message' => 'System settings saved and synced.' ], 30 );
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Data retention setting ────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_save_data_settings'] ) ) {
		update_option( 'rbfa_delete_on_uninstall',       isset( $_POST['rbfa_delete_on_uninstall'] )       ? '1' : '0' );
		update_option( 'rbfa_delete_roles_on_uninstall', isset( $_POST['rbfa_delete_roles_on_uninstall'] ) ? '1' : '0' );
		set_transient(
			'rbfa_admin_notice_' . get_current_user_id(),
			[ 'type' => 'success', 'message' => 'Data retention setting saved.' ],
			30
		);
		wp_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) );
		exit;
	}
}

// ─── Contextual help ─────────────────────────────────────────────────────────

add_action( 'load-toplevel_page_rbfa-pro', 'rbfa_add_help_tabs' );

/**
 * Registers contextual help tabs for each plugin admin tab.
 *
 * Hooked to load-toplevel_page_rbfa-pro so get_current_screen() is available
 * and the correct tab's help is shown based on the current ?tab= parameter.
 */
function rbfa_add_help_tabs() {
    $screen      = get_current_screen();
    $current_tab = sanitize_key( $_GET['tab'] ?? 'logs' );

    // ── Sidebar (shown on every tab) ─────────────────────────────────────────
    $screen->set_help_sidebar(
        '<p><strong>WP File Security Pro</strong></p>'
        . '<p>Version ' . RBFA_VERSION . '</p>'
        . '<p><a href="https://github.com/buffcleb/WP-File-Security-Pro" target="_blank" rel="noopener">GitHub repository ↗</a></p>'
        . '<p><a href="https://github.com/buffcleb/WP-File-Security-Pro/issues" target="_blank" rel="noopener">Report an issue ↗</a></p>'
    );

    // ── Per-tab help content ──────────────────────────────────────────────────
    switch ( $current_tab ) {

        case 'logs':
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-logs-overview',
                'title'   => 'Access Log',
                'content' =>
                    '<p>Every file request inside a protected zone is recorded here — granted and denied — with a timestamp, the WordPress username (or <em>Guest</em> for unauthenticated visitors), the client IP address, the relative file path, and the outcome.</p>'
                    . '<p>Use the filter controls to narrow results by date range, username, IP address, file path, or status. Multiple filters are combined with AND logic.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-logs-export',
                'title'   => 'Export &amp; Pruning',
                'content' =>
                    '<p><strong>CSV Export</strong> — downloads the complete filtered dataset in the current sort order regardless of the pagination setting. The exported file is named <code>access-log-{date}.csv</code>.</p>'
                    . '<p><strong>Manual Prune</strong> — immediately deletes all log entries older than the configured retention period. A confirmation dialog is shown before deletion.</p>'
                    . '<p><strong>Automatic Pruning</strong> — configure the retention period and enable the daily cron in the <strong>Settings</strong> tab. The cron runs once per day and deletes entries older than the threshold.</p>',
            ] );
            break;

        case 'config':
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-zones-overview',
                'title'   => 'What is a Zone?',
                'content' =>
                    '<p>A <strong>zone</strong> is a subfolder inside your base uploads directory that is protected by this plugin. Each zone has a <strong>folder slug</strong> (the subdirectory name) and a list of <strong>allowed roles</strong>.</p>'
                    . '<p>Files inside a zone are served through PHP — the web server never delivers them directly. A visitor without an allowed role receives a denial screen or is redirected.</p>'
                    . '<p>Zones are stored under your configured base directory, e.g. <code>uploads/protected/members/</code>. The directory is created automatically when you save.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-zones-denial',
                'title'   => 'Denial &amp; Redirect',
                'content' =>
                    '<p>Each zone supports two independent denial actions — one for <strong>anonymous</strong> (not logged in) visitors and one for <strong>logged-in</strong> users who lack the required role.</p>'
                    . '<p>For each, you can choose:</p>'
                    . '<ul><li><strong>Default</strong> — a plain 403 message.</li>'
                    . '<li><strong>A denial screen</strong> — custom HTML you create on the Denial Screens tab.</li>'
                    . '<li><strong>Redirect to URL</strong> — send the user to any URL (sales page, sign-up, etc.).</li></ul>'
                    . '<p>Logged-in users also have a separate redirect URL field so you can send them somewhere different from anonymous visitors.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-zones-pages',
                'title'   => 'Zone Pages',
                'content' =>
                    '<p>Each zone automatically gets a front-end page at <code>/protected-zone/{slug}/</code>. No WordPress post is created — the URL is handled entirely by the plugin via a rewrite rule.</p>'
                    . '<p>Click <strong>Edit Page</strong> in the slug cell to open the page editor. The left panel is a safe-HTML editor (shortcodes are supported); the right panel shows a live preview as you type. Click <strong>Apply</strong> to write the changes back, then <strong>Save &amp; Sync Zones</strong> to persist them.</p>'
                    . '<p>The default title is the humanised zone slug and the default body contains the <code>[folder_files]</code> shortcode for that zone.</p>'
                    . '<p>Access to the zone page is enforced by the same role rules as file access.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-zones-shortcode',
                'title'   => '[folder_files]',
                'content' =>
                    '<p>Place <code>[folder_files folder="slug"]</code> on any page or post to render a browsable file listing for authorised users.</p>'
                    . '<p>The shortcode shows:</p>'
                    . '<ul><li>A header bar with the total file count, total size, and two download buttons — <em>Download Current Directory</em> (files only, no subdirectories) and <em>Download All</em> (recursive ZIP).</li>'
                    . '<li>A flat list of files in the zone root.</li>'
                    . '<li>Each subdirectory as a collapsible section (collapsed by default) showing the directory\'s file count, size, and its own download button.</li></ul>'
                    . '<p>ZIP downloads are nonce-protected and verify zone access before streaming.</p>',
            ] );
            break;

        case 'roles':
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-roles-overview',
                'title'   => 'Managed Roles',
                'content' =>
                    '<p>A <strong>managed role</strong> is any WordPress role whose slug starts with <code>wfsp_</code>. This prefix is applied automatically when you create a role here.</p>'
                    . '<p>Because roles are stored in <code>wp_options</code> (not in plugin tables), managed roles <strong>survive plugin uninstall and reinstall</strong>. You can optionally remove them on deletion via <strong>Settings → Data Management</strong>.</p>'
                    . '<p>Built-in WordPress roles (<em>Administrator</em>, <em>Editor</em>, etc.) are displayed in the accordion for reference but cannot be renamed or deleted from this screen.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-roles-wfsp-admins',
                'title'   => 'WFSP Admins',
                'content' =>
                    '<p>The <strong>WFSP Admins</strong> role (<code>wfsp_admins</code>) is created by the plugin on activation and grants the <code>manage_wfsp</code> capability.</p>'
                    . '<p>Any user with this role can access the WP File Security Pro admin panel without needing full <em>Administrator</em> access. This is useful for delegating file security management to a non-admin staff member.</p>'
                    . '<p>This role is <strong>protected</strong> — it cannot be renamed or deleted from the admin panel to prevent accidental lock-out.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-roles-members',
                'title'   => 'Adding Members',
                'content' =>
                    '<p>Click <strong>+ Add Members</strong> inside any managed role accordion to open the member modal.</p>'
                    . '<p>The modal lists all WordPress users who are not already members of the role. Use the search box to filter by username, display name, or email. Select one or more users using the checkboxes — selections persist as you page through results — then click <strong>Add Selected</strong>.</p>'
                    . '<p>To remove a user from a role, click <strong>Remove</strong> next to their name in the role\'s user table.</p>',
            ] );
            break;

        case 'denial':
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-denial-overview',
                'title'   => 'Denial Screens',
                'content' =>
                    '<p>A <strong>denial screen</strong> is custom HTML shown to a visitor who is blocked from accessing a file or zone page. You can create as many screens as you need and assign different ones to each zone — separately for anonymous and logged-in users.</p>'
                    . '<p>HTML is filtered through a strict allowlist on both save and read-back. Permitted elements include headings, paragraphs, lists, links, images, and tables. Scripts, iframes, forms, and event handlers are automatically removed.</p>'
                    . '<p>The live preview updates as you type. It is rendered in a sandboxed iframe — scripts are blocked even if you paste them in, so the preview is safe to use.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-denial-shortcodes',
                'title'   => 'Login Shortcodes',
                'content' =>
                    '<p>Two shortcodes are available for use inside denial screen HTML:</p>'
                    . '<p><code>[rbfa_login_link]</code> — renders a login link. After a successful login the user is served the <strong>original file</strong> immediately.</p>'
                    . '<p><code>[rbfa_zone_link]</code> — renders a login link. After a successful login the user is taken to the <strong>zone\'s page</strong> (<code>/protected-zone/{slug}/</code>) instead of the file directly. Use this when you want users to browse the zone listing first.</p>'
                    . '<p>Both shortcodes accept optional <code>text="..."</code> (guest link label) and <code>logout_text="..."</code> (label shown when the visitor is already logged in with the wrong role — clicking will log them out and redirect to the login page).</p>'
                    . '<p>Tokens are opaque one-time values that expire after 15 minutes. No file path, role name, or zone information is ever exposed in the URL.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-denial-login-url',
                'title'   => 'Login Page URL',
                'content' =>
                    '<p>The <strong>Login page URL</strong> field controls where the login shortcodes point. Leave it blank to use WordPress\'s default <code>wp-login.php</code>.</p>'
                    . '<p>Accepted values:</p>'
                    . '<ul><li>Blank — uses <code>wp-login.php</code>.</li>'
                    . '<li>Absolute URL — e.g. <code>https://example.com/my-account/</code></li>'
                    . '<li>Relative path — e.g. <code>/my-account/</code></li>'
                    . '<li>Bare slug — e.g. <code>my-account</code> (resolved against the site root)</li></ul>'
                    . '<p>This is the login page URL for this denial screen only. Different denial screens can point to different login pages.</p>',
            ] );
            break;

        case 'settings':
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-settings-system',
                'title'   => 'System Settings',
                'content' =>
                    '<p><strong>Base Directory</strong> — the folder inside <code>wp-content/uploads/</code> that contains all your protected zone subdirectories. All zones must be inside this folder. Changing it does not move existing files — update your zone directories manually if you rename it.</p>'
                    . '<p><strong>Integrity Repair Cron</strong> — when enabled, a WordPress cron job runs hourly and re-creates any missing or incorrect <code>.htaccess</code> files across the entire protected tree. Useful if another plugin or server process occasionally removes files.</p>'
                    . '<p><strong>Zone Page Theme</strong> — when enabled (default), zone pages at <code>/protected-zone/{slug}/</code> are rendered inside the active site theme using its header and footer. Disable this if your theme conflicts with the zone page layout; a minimal standalone HTML page will be served instead.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-settings-logs',
                'title'   => 'Log Retention',
                'content' =>
                    '<p><strong>Automatic pruning</strong> — enable the daily cron and set a retention period in days. The cron runs once per day and deletes all log entries older than the threshold. Recommended: 90–365 days depending on your compliance needs.</p>'
                    . '<p><strong>Manual prune</strong> — available on the <strong>Logs</strong> tab. Immediately deletes all entries older than the configured retention period.</p>'
                    . '<p>Setting the retention period to 0 days disables pruning (both auto and manual) even if the cron is enabled.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-settings-data',
                'title'   => 'Data Management',
                'content' =>
                    '<p>By default, deactivating or deleting the plugin <strong>preserves all data</strong> — database tables, options, and log entries.</p>'
                    . '<p><strong>Remove all plugin data on deletion</strong> — when checked, deleting the plugin from the Plugins screen permanently drops all plugin database tables and options. This cannot be undone. Deactivation alone never triggers this cleanup.</p>'
                    . '<p><strong>Remove wfsp_ roles on deletion</strong> — when checked, all WordPress roles whose slug starts with <code>wfsp_</code> (including WFSP Admins and any roles you created) are permanently deleted along with their user assignments. Leave unchecked to preserve roles across reinstalls.</p>',
            ] );
            break;
    }
}

// ─── Menu registration ────────────────────────────────────────────────────────

add_action( 'admin_menu', 'rbfa_register_admin_menu' );

/**
 * Registers the top-level "WP File Security Pro" menu item in the sidebar.
 *
 * Position 80 places it near the bottom of the sidebar, above Settings.
 * The dashicons-shield icon reinforces the security purpose of the plugin.
 */
function rbfa_register_admin_menu() {
	add_menu_page(
		'WP File Security Pro',        // Page <title>
		'WP File Security Pro',        // Sidebar label
		'manage_wfsp',                 // Required capability
		'rbfa-pro',                    // Menu slug
		'rbfa_pro_page',               // Callback
		'dashicons-shield',            // Icon
		80                             // Position
	);
}

// ─── Admin asset enqueueing ───────────────────────────────────────────────────

add_action( 'admin_enqueue_scripts', 'rbfa_enqueue_admin_assets' );

/**
 * Enqueues shared CSS for the plugin admin pages.
 *
 * The hook identifier for top-level menu pages follows the pattern
 * "toplevel_page_{menu-slug}". Only loads on the plugin's own page.
 *
 * @param string $hook Current admin page hook suffix.
 */
function rbfa_enqueue_admin_assets( $hook ) {
	if ( $hook !== 'toplevel_page_rbfa-pro' ) {
		return;
	}

	// Register a handle with no src so we can attach inline styles to it.
	wp_register_style( 'rbfa-admin', false );
	wp_enqueue_style( 'rbfa-admin' );

	wp_add_inline_style( 'rbfa-admin', '
		/* ── Buttons ── */
		.rbfa-btn {
			background: #fff; border: 1px solid #ccd0d4; padding: 5px 12px;
			border-radius: 4px; cursor: pointer; font-size: 12px;
			color: #2271b1; text-decoration: none; display: inline-block;
		}
		.rbfa-danger { color: #d63638; border-color: #d63638; }

		/* ── Cards ── */
		.rbfa-card {
			background: #fff; border: 1px solid #ccd0d4;
			padding: 20px; border-radius: 4px; margin-top: 20px;
		}

		/* ── Accordion (roles tab) ── */
		.rbfa-acc { border: 1px solid #ccd0d4; border-radius: 4px; margin-top: 10px; overflow: hidden; }
		.rbfa-acc-h { padding: 10px; background: #f6f7f7; cursor: pointer; display: flex; justify-content: space-between; }
		.rbfa-acc-c { padding: 15px; display: none; border-top: 1px solid #eee; background: #fff; }

		/* ── Role checkbox scroll area (zones tab) ── */
		.rbfa-scroll { max-height: 120px; overflow: auto; padding: 10px; border: 1px solid #ddd; background: #fff; position: relative; }
		.rbfa-scroll::after { content: "↕ Scroll"; display: block; font-size: 9px; text-align: center; color: #999; margin-top: 5px; }

		/* ── Status badges ── */
		.rbfa-status { font-weight: bold; font-size: 10px; padding: 2px 6px; border-radius: 3px; }
		.status-ok  { color: #2271b1; background: #f0f6fb; }
		.status-err { color: #d63638; background: #fcf0f1; }

		/* ── Integrity alert banner ── */
		.integrity-notice {
			background: #fff8e5; border-left: 4px solid #ffb900;
			padding: 12px; margin: 15px 0;
		}

		/* ── Modern pagination ── */
		.rbfa-pagination {
			display: flex; align-items: center; justify-content: center;
			gap: 4px; margin-top: 16px;
		}
		.rbfa-pagination a,
		.rbfa-pagination span {
			display: inline-flex; align-items: center; justify-content: center;
			min-width: 32px; height: 32px; padding: 0 8px;
			border: 1px solid #ccd0d4; border-radius: 6px;
			font-size: 13px; text-decoration: none; color: #2271b1;
			background: #fff; transition: background 0.15s;
		}
		.rbfa-pagination .current {
			background: #2271b1; color: #fff; border-color: #2271b1; font-weight: 600;
		}
		.rbfa-pagination a:hover { background: #f0f6fb; }
		.rbfa-pagination .dots { border: none; background: none; color: #999; }
	' );
}

// ─── Main page callback ───────────────────────────────────────────────────────

/**
 * Main admin page callback — capability check, POST handling, tab dispatch.
 *
 * All POST actions are processed here before any output is generated.
 * Output is then handed off to the appropriate tab renderer.
 */
function rbfa_pro_page() {
	// Hard capability gate — no output rendered if the user lacks manage_wfsp.
	if ( ! current_user_can( 'manage_wfsp' ) ) {
		wp_die( esc_html__( 'You do not have permission to access this page.', 'wp-file-security-pro' ) );
	}

	global $wpdb;

	$zone_table = $wpdb->prefix . 'rbfa_zones';
	$role_table = $wpdb->prefix . 'rbfa_managed_roles';
	$msg_table  = $wpdb->prefix . 'rbfa_denial_screens';
	$current_tab = sanitize_key( $_GET['tab'] ?? 'logs' );

	// ── Render page shell and dispatch to tab ────────────────────────────────
	// All POST handling is done in rbfa_handle_admin_post() on admin_init
	// (before any output) to avoid "headers already sent" errors from wp_redirect().

	// Display any queued admin notice (stored via transient by POST handlers).
	$notice_key = 'rbfa_admin_notice_' . get_current_user_id();
	$notice     = get_transient( $notice_key );
	if ( $notice ) {
		delete_transient( $notice_key );
		$type  = $notice['type'] === 'error' ? 'notice-error' : 'notice-success';
		// Message is pre-escaped at set time — only esc_html was used on user values.
		printf(
			'<div class="notice %s is-dismissible" style="margin-top:15px;"><p>%s</p></div>',
			esc_attr( $type ),
			$notice['message'] // already sanitized when stored
		);
	}

	echo '<div class="wrap"><h1>WP File Security Pro</h1>';
	echo '<h2 class="nav-tab-wrapper">';

	$tabs = [
		'logs'     => 'Logs',
		'config'   => 'Zones',
		'roles'    => 'Roles/Users',
		'denial'   => 'Denial Screens',
		'settings' => 'Settings',
	];
	// Add NGINX tab only when NGINX is detected as the web server.
	if ( rbfa_is_nginx() ) {
		$tabs['nginx'] = 'NGINX Config';
	}

	foreach ( $tabs as $slug => $label ) {
		$url   = add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => $slug ], admin_url( 'admin.php' ) );
		$class = ( $current_tab === $slug ) ? 'nav-tab nav-tab-active' : 'nav-tab';
		echo "<a href='" . esc_url( $url ) . "' class='" . esc_attr( $class ) . "'>" . esc_html( $label ) . '</a>';
	}

	echo '</h2>';

	// Dispatch to the matching tab renderer.
	switch ( $current_tab ) {
		case 'logs':
			rbfa_render_tab_logs();
			break;
		case 'config':
			rbfa_render_tab_zones();
			break;
		case 'roles':
			rbfa_render_tab_roles();
			break;
		case 'denial':
			rbfa_render_tab_denial();
			break;
		case 'settings':
			rbfa_render_tab_settings();
			break;
		case 'nginx':
			rbfa_render_tab_nginx();
			break;
		default:
			rbfa_render_tab_logs();
	}

	echo '</div>'; // .wrap
}

// ─── Shared pagination helper ─────────────────────────────────────────────────

/**
 * Renders a modern pagination bar.
 *
 * Outputs numbered page links with previous/next arrows. The current page
 * is highlighted. All existing GET parameters are preserved so filters,
 * sort state, and per-page settings survive page changes.
 *
 * @param int   $current     Current page number (1-based).
 * @param int   $total_pages Total number of pages.
 * @param array $extra_args  Additional query args to merge into page links.
 */
function rbfa_render_pagination( $current, $total_pages, $extra_args = [] ) {
	if ( $total_pages <= 1 ) {
		return;
	}

	$base_args = array_merge( [ 'page' => 'rbfa-pro' ], $extra_args );

	echo '<div class="rbfa-pagination">';

	// Previous arrow.
	if ( $current > 1 ) {
		$url = add_query_arg( array_merge( $base_args, [ 'paged' => $current - 1 ] ), admin_url( 'admin.php' ) );
		echo '<a href="' . esc_url( $url ) . '" aria-label="Previous">&laquo;</a>';
	} else {
		echo '<span class="dots">&laquo;</span>';
	}

	// Page number links with ellipsis for large ranges.
	for ( $p = 1; $p <= $total_pages; $p++ ) {
		// Always show first page, last page, and pages near the current page.
		$near_current = ( abs( $p - $current ) <= 2 );
		$is_edge      = ( $p === 1 || $p === $total_pages );

		if ( ! $near_current && ! $is_edge ) {
			// Show a single ellipsis at the gap boundary.
			if ( $p === 2 || $p === $total_pages - 1 ) {
				echo '<span class="dots">…</span>';
			}
			continue;
		}

		if ( $p === $current ) {
			echo '<span class="current" aria-current="page">' . $p . '</span>';
		} else {
			$url = add_query_arg( array_merge( $base_args, [ 'paged' => $p ] ), admin_url( 'admin.php' ) );
			echo '<a href="' . esc_url( $url ) . '">' . $p . '</a>';
		}
	}

	// Next arrow.
	if ( $current < $total_pages ) {
		$url = add_query_arg( array_merge( $base_args, [ 'paged' => $current + 1 ] ), admin_url( 'admin.php' ) );
		echo '<a href="' . esc_url( $url ) . '" aria-label="Next">&raquo;</a>';
	} else {
		echo '<span class="dots">&raquo;</span>';
	}

	echo '</div>';
}

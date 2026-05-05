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

		update_option( 'rbfa_cron_enabled', isset( $_POST['cron_enabled'] ) ? '1' : '0' );
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

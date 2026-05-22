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
add_action( 'admin_init', 'rbfa_handle_export' );

/**
 * Processes all plugin POST form submissions.
 *
 * Hooked to admin_init so it runs before WordPress sends any HTML output.
 * This allows wp_redirect() to work cleanly without "headers already sent"
 * warnings — the same reason the CSV export lives on admin_init.
 *
 * Only acts when the request targets this plugin's admin page.
 */
/**
 * Handles the plugin configuration export (GET request).
 *
 * Hooked to admin_init. Checks capability and nonce, then builds a JSON
 * payload containing the sections selected by the user and sends it as a
 * file download.
 */
function rbfa_handle_export() {
	if ( ! isset( $_GET['action'] ) || $_GET['action'] !== 'rbfa_export' ) {
		return;
	}
	if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'rbfa-pro' ) {
		return;
	}
	if ( ! current_user_can( 'manage_wfsp' ) ) {
		wp_die( esc_html__( 'You do not have permission to perform this action.', 'file-security-pro' ) );
	}
	if ( ! isset( $_GET['_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_nonce'] ) ), 'rbfa_export' ) ) {
		wp_die( esc_html__( 'Security check failed.', 'file-security-pro' ) );
	}

	$include = isset( $_GET['include'] ) ? array_map( 'sanitize_key', array_map( 'wp_unslash', (array) $_GET['include'] ) ) : [];

	// If nothing selected, output empty JSON and exit cleanly.
	if ( empty( $include ) ) {
		header( 'Content-Type: application/json; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="wfsp-export-' . gmdate( 'Y-m-d' ) . '.json"' );
		echo '{}';
		exit;
	}

	global $wpdb;
	$msg_table = $wpdb->prefix . 'rbfa_denial_screens';

	$data = [
		'plugin'      => 'file-security-pro',
		'version'     => RBFA_VERSION,
		'exported_at' => gmdate( 'c' ),
	];

	// Build denial_screen id→label map regardless of whether screens are included,
	// so zone denial_label fields can be populated.
	$denial_map = [];
	$all_screens = $wpdb->get_results( "SELECT id, label FROM $msg_table", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
	foreach ( $all_screens as $screen ) {
		$denial_map[ (int) $screen['id'] ] = $screen['label'];
	}

	if ( in_array( 'denial_screens', $include, true ) ) {
		$screens = $wpdb->get_results( "SELECT label, html_content, login_url FROM $msg_table ORDER BY id ASC", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
		$data['denial_screens'] = $screens ?: [];
	}

	if ( in_array( 'zones', $include, true ) ) {
		$raw_zones = rbfa_get_zones();
		$export_zones = [];
		foreach ( $raw_zones as $zone ) {
			$roles = json_decode( $zone['allowed_roles'] ?? '[]', true );
			$export_zones[] = [
				'folder_slug'       => $zone['folder_slug'],
				'roles'             => is_array( $roles ) ? $roles : [],
				'denial_label'      => $denial_map[ (int) ( $zone['denial_id'] ?? 0 ) ] ?? '',
				'denial_label_auth' => $denial_map[ (int) ( $zone['denial_id_auth'] ?? 0 ) ] ?? '',
				'redirect_url'      => $zone['redirect_url'] ?? '',
				'redirect_url_auth' => $zone['redirect_url_auth'] ?? '',
				'page_title'        => $zone['page_title'] ?? '',
				'page_content'      => $zone['page_content'] ?? '',
			];
		}
		$data['zones'] = $export_zones;
	}

	if ( in_array( 'roles', $include, true ) ) {
		$managed = rbfa_get_managed_roles();
		$wp_roles_obj = wp_roles();
		$export_roles = [];
		foreach ( $managed as $role_key ) {
			$role_data = $wp_roles_obj->roles[ $role_key ] ?? null;
			if ( ! $role_data ) continue;
			$users = get_users( [ 'role' => $role_key, 'fields' => [ 'user_login' ] ] );
			$logins = array_map( function( $u ) { return $u->user_login; }, $users );
			$export_roles[] = [
				'role_key'     => $role_key,
				'display_name' => $role_data['name'],
				'users'        => $logins,
			];
		}
		$data['roles'] = $export_roles;
	}

	if ( in_array( 'settings', $include, true ) ) {
		$data['settings'] = [
			'rbfa_base_folder'       => rbfa_get_base_folder(),
			'rbfa_cron_enabled'      => get_option( 'rbfa_cron_enabled', '1' ),
			'rbfa_zone_page_use_theme' => get_option( 'rbfa_zone_page_use_theme', '1' ),
			'rbfa_prune_enabled'     => get_option( 'rbfa_prune_enabled', '0' ),
			'rbfa_prune_days'        => (int) get_option( 'rbfa_prune_days', 90 ),
		];
	}

	$filename = 'wfsp-export-' . gmdate( 'Y-m-d' ) . '.json';
	header( 'Content-Type: application/json; charset=utf-8' );
	header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
	header( 'Cache-Control: no-cache, no-store, must-revalidate' );
	echo wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE );
	exit;
}

function rbfa_sanitize_redirect( $raw ) {
	$raw = trim( $raw );
	if ( $raw === '' ) return '';
	if ( preg_match( '#^https?://#i', $raw ) ) {
		return esc_url_raw( $raw );
	}
	// Relative paths must start with / — reject anything that looks like a
	// non-HTTP scheme (javascript:, data:, vbscript:, etc.).
	if ( ! str_starts_with( $raw, '/' ) ) {
		return '';
	}
	return sanitize_text_field( $raw );
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
		wp_die( esc_html__( 'You do not have permission to perform this action.', 'file-security-pro' ) );
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
	$current_tab = sanitize_key( wp_unslash( $_GET['tab'] ?? 'logs' ) );

	// ── Zone save ────────────────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_save_zones'] ) ) {
		// Base folder is managed exclusively on the Settings tab — do not read
		// it from $_POST here, as the Zones form has no such field and would
		// silently reset it to the fallback default on every zone save.

		// Delete and re-insert all non-default zone rows.
		$wpdb->query( $wpdb->prepare( "DELETE FROM $zone_table WHERE is_default = %d", 0 ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input

		$seen        = [];
		$saved_count = 0;
		foreach ( (array) ( $_POST['folders'] ?? [] ) as $i => $f ) {
			$slug = sanitize_title( $f );
			if ( empty( $slug ) || in_array( $slug, $seen, true ) ) continue;
			$roles = array_map( 'sanitize_key', (array) ( $_POST['roles'][ $i ] ?? [] ) );
			// Sanitize redirect URLs — must be absolute or relative; empty = no redirect.
			$redirect_url      = rbfa_sanitize_redirect( $_POST['redirect_urls'][ $i ] ?? '' );
			$redirect_url_auth = rbfa_sanitize_redirect( $_POST['redirect_urls_auth'][ $i ] ?? '' );

			$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
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
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'config' ], admin_url( 'admin.php' ) ) );
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
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Role rename ───────────────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_rename_role'] ) ) {
		$role_id = sanitize_key( $_POST['role_id'] ?? '' );
		if ( $role_id === 'wfsp_admins' ) {
			wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
			exit;
		}
		if ( in_array( $role_id, rbfa_get_managed_roles(), true ) ) {
			global $wp_roles;
			$wp_roles->roles[ $role_id ]['name'] = sanitize_text_field( $_POST['new_name'] ?? '' );
			update_option( $wpdb->prefix . 'user_roles', $wp_roles->roles );
		}
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
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
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Remove user from managed role ─────────────────────────────────────────
	if ( isset( $_POST['rbfa_remove_user'] ) ) {
		$role_id = sanitize_key( $_POST['role_id'] ?? '' );
		if ( in_array( $role_id, rbfa_get_managed_roles(), true ) ) {
			$u = get_user_by( 'id', (int) ( $_POST['user_id'] ?? 0 ) );
			if ( $u ) $u->remove_role( $role_id );
		}
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Delete managed role ───────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_delete_role'] ) ) {
		$role_id = sanitize_key( $_POST['role_id'] ?? '' );
		if ( $role_id === 'wfsp_admins' ) {
			wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
			exit;
		}
		if ( in_array( $role_id, rbfa_get_managed_roles(), true ) ) {
			remove_role( $role_id );
			$wpdb->delete( $role_table, [ 'role_id' => $role_id ], [ '%s' ] ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
		}
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'roles' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Save denial screen ────────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_save_msg'] ) ) {
		$raw_login_url   = trim( $_POST['login_url'] ?? '' );
		$login_url_clean = '';
		if ( $raw_login_url !== '' ) {
			if ( preg_match( '#^https?://#i', $raw_login_url ) ) {
				$login_url_clean = esc_url_raw( $raw_login_url );
			} elseif ( str_starts_with( $raw_login_url, '/' ) ) {
				// Relative path — accept only paths starting with /
				$login_url_clean = sanitize_text_field( $raw_login_url );
			}
			// Any other value (javascript:, data:, bare words) is silently dropped.
		}
		$data = [
			'label'        => sanitize_text_field( $_POST['label'] ?? '' ),
			'html_content' => rbfa_kses_denial( $_POST['html_content'] ?? '' ),
			'login_url'    => $login_url_clean,
		];
		if ( ! empty( $_POST['id'] ) ) {
			$wpdb->update( $msg_table, $data, [ 'id' => (int) $_POST['id'] ], [ '%s', '%s', '%s' ], [ '%d' ] ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
		} else {
			$wpdb->insert( $msg_table, $data, [ '%s', '%s', '%s' ] ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
		}
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'denial' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Delete denial screen ──────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_del_msg'] ) ) {
		$wpdb->delete( $msg_table, [ 'id' => (int) ( $_POST['id'] ?? 0 ) ], [ '%d' ] ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'denial' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Manual log prune ─────────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_manual_prune'] ) ) {
		$deleted = rbfa_manual_prune_logs();
		set_transient( 'rbfa_admin_notice_' . get_current_user_id(),
			[ 'type' => 'success', 'message' => sprintf( 'Manual prune complete. <strong>%d</strong> log entr%s deleted.', $deleted, $deleted === 1 ? 'y' : 'ies' ) ], 30 );
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'logs' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── System settings (from Settings tab) ─────────────────────────────────
	if ( isset( $_POST['rbfa_save_system_settings'] ) ) {
		global $wpdb;
		$zone_table = $wpdb->prefix . 'rbfa_zones';
		$base_slug  = sanitize_title( $_POST['rbfa_base_folder'] ?? 'list_files' );
		if ( empty( $base_slug ) ) $base_slug = 'list_files';

		// Upsert the rbfa_default row with the new base slug.
		$exists = $wpdb->get_var( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
			"SELECT id FROM $zone_table WHERE folder_slug = %s AND is_default = %d",
			'rbfa_default', 1
		) );
		if ( $exists ) {
			$wpdb->update( $zone_table, [ 'allowed_roles' => $base_slug ], // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
				[ 'folder_slug' => 'rbfa_default', 'is_default' => 1 ], [ '%s' ], [ '%s', '%d' ] );
		} else {
			$wpdb->insert( $zone_table, // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
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
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) );
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
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Import Phase 1 — Upload & analyze ────────────────────────────────────
	if ( isset( $_POST['rbfa_import_upload'] ) ) {
		$tmp = $_FILES['import_file']['tmp_name'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- file tmp_name is a system-generated path validated via is_uploaded_file()
		if ( empty( $tmp ) || ! is_uploaded_file( $tmp ) ) {
			set_transient( 'rbfa_admin_notice_' . get_current_user_id(),
				[ 'type' => 'error', 'message' => 'No file uploaded or upload error.' ], 30 );
			wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) );
			exit;
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$raw  = file_get_contents( $tmp );
		$data = json_decode( $raw, true );

		if ( ! is_array( $data ) || ! in_array( $data['plugin'] ?? '', [ 'file-security-pro', 'file-security-pro' ], true ) ) {
			set_transient( 'rbfa_admin_notice_' . get_current_user_id(),
				[ 'type' => 'error', 'message' => 'Invalid import file.' ], 30 );
			wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) );
			exit;
		}

		$include = isset( $_POST['import_include'] ) ? array_map( 'sanitize_key', (array) $_POST['import_include'] ) : [];

		// Detect conflicts.
		$conflicts = [];

		if ( in_array( 'denial_screens', $include, true ) && ! empty( $data['denial_screens'] ) ) {
			$existing_labels = $wpdb->get_col( "SELECT label FROM $msg_table" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
			foreach ( $data['denial_screens'] as $screen ) {
				$label = $screen['label'] ?? '';
				if ( in_array( $label, $existing_labels, true ) ) {
					$conflicts['denial_screens'][] = $label;
				}
			}
		}

		if ( in_array( 'zones', $include, true ) && ! empty( $data['zones'] ) ) {
			$existing_zones = rbfa_get_zones();
			$existing_slugs = array_column( $existing_zones, 'folder_slug' );
			foreach ( $data['zones'] as $zone ) {
				$slug = $zone['folder_slug'] ?? '';
				if ( in_array( $slug, $existing_slugs, true ) ) {
					$conflicts['zones'][] = $slug;
				}
			}
		}

		if ( in_array( 'roles', $include, true ) && ! empty( $data['roles'] ) ) {
			$wp_roles_obj = wp_roles();
			foreach ( $data['roles'] as $role ) {
				$role_key = $role['role_key'] ?? '';
				if ( isset( $wp_roles_obj->roles[ $role_key ] ) ) {
					$conflicts['roles'][] = $role_key;
				}
			}
		}

		$key = wp_generate_password( 16, false );
		set_transient(
			'rbfa_import_' . get_current_user_id() . '_' . $key,
			[ 'data' => $data, 'include' => $include, 'conflicts' => $conflicts ],
			1800
		);

		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings', 'rbfa_import_review' => $key ], admin_url( 'admin.php' ) ) );
		exit;
	}

	// ── Import Phase 2 — Apply ────────────────────────────────────────────────
	if ( isset( $_POST['rbfa_import_confirm'] ) ) {
		$import_key     = sanitize_text_field( $_POST['import_key'] ?? '' );
		$transient_name = 'rbfa_import_' . get_current_user_id() . '_' . $import_key;
		$stored         = get_transient( $transient_name );
		delete_transient( $transient_name );

		if ( ! $stored ) {
			set_transient( 'rbfa_admin_notice_' . get_current_user_id(),
				[ 'type' => 'error', 'message' => 'Import session expired. Please upload the file again.' ], 30 );
			wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) );
			exit;
		}

		$data     = $stored['data'];
		$include  = $stored['include'];
		$resolve  = isset( $_POST['rbfa_resolve'] ) ? (array) $_POST['rbfa_resolve'] : [];

		$summary = [];

		// 1. Denial screens (must be first so IDs are known for zones).
		$label_to_id = [];
		// Pre-build from ALL existing screens.
		$existing_screens_raw = $wpdb->get_results( "SELECT id, label FROM $msg_table", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
		foreach ( $existing_screens_raw as $row ) {
			$label_to_id[ $row['label'] ] = (int) $row['id'];
		}

		if ( in_array( 'denial_screens', $include, true ) && ! empty( $data['denial_screens'] ) ) {
			$imported_screens = 0;
			foreach ( $data['denial_screens'] as $screen ) {
				$label     = sanitize_text_field( $screen['label'] ?? '' );
				$content   = rbfa_kses_denial( $screen['html_content'] ?? '' );
				$login_url = rbfa_sanitize_redirect( $screen['login_url'] ?? '' );

				if ( isset( $label_to_id[ $label ] ) ) {
					// Conflict: check resolution.
					$res = sanitize_key( $resolve['denial_screens'][ $label ] ?? 'keep' );
					if ( $res === 'import' ) {
						$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
							$msg_table,
							[ 'html_content' => $content, 'login_url' => $login_url ],
							[ 'id' => $label_to_id[ $label ] ],
							[ '%s', '%s' ],
							[ '%d' ]
						);
						$imported_screens++;
					}
					// 'keep' — leave label_to_id as-is (existing ID preserved).
				} else {
					$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
						$msg_table,
						[ 'label' => $label, 'html_content' => $content, 'login_url' => $login_url ],
						[ '%s', '%s', '%s' ]
					);
					$new_id = (int) $wpdb->insert_id;
					$label_to_id[ $label ] = $new_id;
					$imported_screens++;
				}
			}
			$summary[] = $imported_screens . ' denial screen' . ( $imported_screens !== 1 ? 's' : '' );
		}

		// 2. Zones.
		if ( in_array( 'zones', $include, true ) && ! empty( $data['zones'] ) ) {
			$existing_zones = rbfa_get_zones();
			$existing_slugs = array_column( $existing_zones, 'folder_slug' );
			$imported_zones = 0;

			foreach ( $data['zones'] as $zone ) {
				$slug             = sanitize_title( $zone['folder_slug'] ?? '' );
				$roles            = array_map( 'sanitize_key', (array) ( $zone['roles'] ?? [] ) );
				$denial_label     = $zone['denial_label'] ?? '';
				$denial_label_auth = $zone['denial_label_auth'] ?? '';
				$denial_id        = $label_to_id[ $denial_label ] ?? 0;
				$denial_id_auth   = $label_to_id[ $denial_label_auth ] ?? 0;
				$redirect_url     = rbfa_sanitize_redirect( $zone['redirect_url'] ?? '' );
				$redirect_url_auth = rbfa_sanitize_redirect( $zone['redirect_url_auth'] ?? '' );
				$page_title       = sanitize_text_field( $zone['page_title'] ?? '' );
				$page_content     = wp_kses_post( $zone['page_content'] ?? '' );

				$row = [
					'folder_slug'       => $slug,
					'allowed_roles'     => wp_json_encode( $roles ),
					'denial_id'         => $denial_id,
					'denial_id_auth'    => $denial_id_auth,
					'redirect_url'      => $redirect_url,
					'redirect_url_auth' => $redirect_url_auth,
					'page_title'        => $page_title,
					'page_content'      => $page_content,
					'is_default'        => 0,
				];
				$formats = [ '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s', '%d' ];

				if ( in_array( $slug, $existing_slugs, true ) ) {
					$res = sanitize_key( $resolve['zones'][ $slug ] ?? 'keep' );
					if ( $res === 'import' ) {
						$wpdb->update( $zone_table, $row, [ 'folder_slug' => $slug ], $formats, [ '%s' ] ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
						$imported_zones++;
					}
				} else {
					$wpdb->insert( $zone_table, $row, $formats ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
					$imported_zones++;
				}
			}

			rbfa_sync_all();
			$summary[] = $imported_zones . ' zone' . ( $imported_zones !== 1 ? 's' : '' );
		}

		// 3. Roles.
		if ( in_array( 'roles', $include, true ) && ! empty( $data['roles'] ) ) {
			global $wp_roles;
			$imported_roles = 0;

			foreach ( $data['roles'] as $role ) {
				$role_key    = sanitize_key( $role['role_key'] ?? '' );
				$display     = sanitize_text_field( $role['display_name'] ?? $role_key );
				$users_list  = (array) ( $role['users'] ?? [] );

				// Only process wfsp_ prefixed roles.
				if ( strpos( $role_key, 'wfsp_' ) !== 0 ) continue;

				if ( ! get_role( $role_key ) ) {
					add_role( $role_key, $display, [ 'read' => true ] );
					$imported_roles++;
				} else {
					$res = sanitize_key( $resolve['roles'][ $role_key ] ?? 'keep' );
					if ( $res === 'import' ) {
						$wp_roles->roles[ $role_key ]['name'] = $display;
						update_option( $wpdb->prefix . 'user_roles', $wp_roles->roles );
						$imported_roles++;
					}
				}

				// Always add users (they are merged regardless of conflict resolution).
				foreach ( $users_list as $login ) {
					$u = get_user_by( 'login', sanitize_user( $login ) );
					if ( $u ) {
						$u->add_role( $role_key );
					}
				}
			}
			$summary[] = $imported_roles . ' role' . ( $imported_roles !== 1 ? 's' : '' );
		}

		// 4. Settings.
		if ( in_array( 'settings', $include, true ) && ! empty( $data['settings'] ) ) {
			$s = $data['settings'];

			// Base folder — upsert the rbfa_default row.
			$base_slug = sanitize_title( $s['rbfa_base_folder'] ?? 'list_files' );
			if ( empty( $base_slug ) ) $base_slug = 'list_files';
			$exists = $wpdb->get_var( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
				"SELECT id FROM $zone_table WHERE folder_slug = %s AND is_default = %d",
				'rbfa_default', 1
			) );
			if ( $exists ) {
				$wpdb->update( $zone_table, [ 'allowed_roles' => $base_slug ], // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
					[ 'folder_slug' => 'rbfa_default', 'is_default' => 1 ], [ '%s' ], [ '%s', '%d' ] );
			} else {
				$wpdb->insert( $zone_table, // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom plugin table, no appropriate caching layer
					[ 'folder_slug' => 'rbfa_default', 'allowed_roles' => $base_slug, 'denial_id' => 0, 'is_default' => 1 ],
					[ '%s', '%s', '%d', '%d' ] );
			}

			update_option( 'rbfa_cron_enabled',        sanitize_text_field( $s['rbfa_cron_enabled'] ?? '1' ) );
			update_option( 'rbfa_zone_page_use_theme', sanitize_text_field( $s['rbfa_zone_page_use_theme'] ?? '1' ) );
			update_option( 'rbfa_prune_enabled',       sanitize_text_field( $s['rbfa_prune_enabled'] ?? '0' ) );
			update_option( 'rbfa_prune_days',          max( 1, (int) ( $s['rbfa_prune_days'] ?? 90 ) ) );

			$summary[] = 'settings';
		}

		$msg = 'Import complete: ' . ( $summary ? implode( ', ', $summary ) . ' imported.' : 'nothing to import.' );
		set_transient( 'rbfa_admin_notice_' . get_current_user_id(),
			[ 'type' => 'success', 'message' => esc_html( $msg ) ], 30 );
		wp_safe_redirect( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'settings' ], admin_url( 'admin.php' ) ) );
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
    $current_tab = sanitize_key( wp_unslash( $_GET['tab'] ?? 'logs' ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only GET filter, no data mutation

    // ── Sidebar (shown on every tab) ─────────────────────────────────────────
    $screen->set_help_sidebar(
        '<p><strong>File Security Pro</strong></p>'
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
                    . '<p>The stats bar at the top shows all-time Granted / Denied / Total counts and a 7-day activity sparkline.</p>'
                    . '<p>Columns are sortable — click <strong>Time</strong>, <strong>IP</strong>, <strong>Path</strong>, or <strong>Status</strong> to sort ascending or descending. The current sort order is preserved when you export.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-logs-filter',
                'title'   => 'Filtering',
                'content' =>
                    '<p>Use the filter panel on the left to narrow results. All active filters are combined with AND logic.</p>'
                    . '<ul>'
                    . '<li><strong>From / To</strong> — each is a single datetime picker combining date and time. Setting only <em>From</em> returns all records on or after that moment; setting only <em>To</em> returns all records up to that moment; setting both applies a range.</li>'
                    . '<li><strong>Username</strong> — partial match against the WordPress login name. Type <code>guest</code> to find unauthenticated requests.</li>'
                    . '<li><strong>IP Address</strong> — partial match, useful for subnet filtering (e.g. <code>192.168</code>).</li>'
                    . '<li><strong>File Path</strong> — partial match against the stored relative path.</li>'
                    . '<li><strong>Status</strong> — <em>Granted</em>, <em>Denied</em>, or <em>All</em>.</li>'
                    . '</ul>'
                    . '<p>The <strong>Clear Filters</strong> button appears when any filter is active and resets the form.</p>',
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
                    . '<p>Zones are stored under your configured base directory, e.g. <code>uploads/protected/members/</code>. The directory is created automatically when you save and sync.</p>'
                    . '<p><strong>Unmanaged directory detection</strong> — if the plugin finds a subdirectory inside the base folder that has no matching zone record, it appears at the bottom of the table highlighted in amber with an <em>Unmanaged</em> badge. Configure the roles and denial settings for it and click <strong>Save &amp; Sync Zones</strong> to bring it under management, or click <strong>Remove</strong> to dismiss it without saving.</p>',
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
                    . '<p>Access to the zone page is enforced by the same role rules as file access. The <strong>Zone Page Theme</strong> setting (in Settings) controls whether the page uses your active site theme or a minimal standalone layout.</p>',
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
                    . '<p>Built-in WordPress roles (<em>Administrator</em>, <em>Editor</em>, etc.) are displayed in the accordion for reference but cannot be renamed or deleted from this screen.</p>'
                    . '<p>Use the <strong>Filter by role name</strong> field to search by display name or slug. Use <strong>Filter by member</strong> to find all roles that contain a particular user. Results are paginated at 10 roles per page.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-roles-create',
                'title'   => 'Creating Roles',
                'content' =>
                    '<p>Click <strong>+ Create Managed Role</strong> to open the role creation modal.</p>'
                    . '<p>Enter a display name — the slug is generated automatically with the <code>wfsp_</code> prefix. A live slug preview is shown as you type so you can confirm the final slug before saving.</p>'
                    . '<p>To <strong>rename</strong> a role, expand its accordion and use the rename form. To <strong>delete</strong> a role, click <em>Delete Role</em> inside the accordion. Both operations are blocked for the system <strong>WFSP Admins</strong> role.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-roles-wfsp-admins',
                'title'   => 'WFSP Admins',
                'content' =>
                    '<p>The <strong>WFSP Admins</strong> role (<code>wfsp_admins</code>) is created by the plugin on activation and grants the <code>manage_wfsp</code> capability.</p>'
                    . '<p>Any user with this role can access the File Security Pro admin panel without needing full <em>Administrator</em> access. This is useful for delegating file security management to a non-admin staff member.</p>'
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
                    . '<p>Use the <strong>Filter by label</strong> field to search existing screens. Results are paginated at 10 per page.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-denial-editor',
                'title'   => 'Editor Modal',
                'content' =>
                    '<p>Click <strong>+ New Denial Screen</strong> to open the editor in a modal. Click <strong>Edit</strong> on any existing screen to open it for editing — no page reload required.</p>'
                    . '<p>The editor contains:</p>'
                    . '<ul><li><strong>Label</strong> — an internal name used when assigning the screen to a zone.</li>'
                    . '<li><strong>Login page URL</strong> — controls where the login shortcodes point (see the Login Page URL help tab).</li>'
                    . '<li><strong>HTML Content</strong> — the page body shown to blocked users.</li>'
                    . '<li><strong>Rendered Preview</strong> — a sandboxed live preview that updates as you type. Scripts are blocked in the preview even if pasted in.</li></ul>'
                    . '<p>An unsaved-changes warning appears if you try to close the modal with pending edits.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-denial-shortcodes',
                'title'   => 'Login Shortcodes',
                'content' =>
                    '<p>Two shortcodes are available for use inside denial screen HTML:</p>'
                    . '<p><code>[rbfa_login_link]</code> — renders a login link. After a successful login the user is served the <strong>original file</strong> immediately.</p>'
                    . '<p><code>[rbfa_zone_link]</code> — renders a login link. After a successful login the user is taken to the <strong>zone\'s page</strong> (<code>/protected-zone/{slug}/</code>) instead of the file directly. Use this when you want users to browse the zone listing first.</p>'
                    . '<p>Both shortcodes accept optional <code>text="..."</code> (guest link label) and <code>logout_text="..."</code> (label shown when the visitor is already logged in with the wrong role — clicking will log them out and redirect to the login page).</p>'
                    . '<p>Tokens are opaque one-time values that expire after 15 minutes. No file path, role name, or zone information is ever exposed in the URL.</p>'
                    . '<p>Shortcode reference cards inside the editor modal are collapsed by default — click any card to expand it.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-denial-login-url',
                'title'   => 'Login Page URL',
                'content' =>
                    '<p>The <strong>Login page URL</strong> field controls where the login shortcodes point. Leave it blank to use WordPress\'s default <code>wp-login.php</code>.</p>'
                    . '<p>Accepted values:</p>'
                    . '<ul><li>Blank — uses <code>wp-login.php</code>.</li>'
                    . '<li>Absolute URL starting with <code>https://</code> — e.g. <code>https://example.com/my-account/</code></li>'
                    . '<li>Root-relative path starting with <code>/</code> — e.g. <code>/my-account/</code></li></ul>'
                    . '<p>Any other value (including bare slugs or non-http schemes) is rejected and treated as blank.</p>'
                    . '<p>This is the login page URL for this denial screen only. Different denial screens can point to different login pages.</p>',
            ] );
            break;

        case 'settings':
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-settings-system',
                'title'   => 'System Settings',
                'content' =>
                    '<p><strong>Base Directory</strong> — the folder inside <code>wp-content/uploads/</code> that contains all your protected zone subdirectories. All zones must be inside this folder. Changing it does not move existing files — update your zone directories manually if you rename it.</p>'
                    . '<p><strong>Integrity Repair Cron</strong> — when enabled (default), a WordPress cron job runs hourly and re-creates any missing or incorrect <code>.htaccess</code> files across the entire protected tree. This setting is preserved when you save zones — changing zones will not uncheck it.</p>'
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
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-settings-export',
                'title'   => 'Export',
                'content' =>
                    '<p>The <strong>Export</strong> section downloads a <code>.json</code> file containing the data you select. Use the checkboxes to choose which sections to include: <strong>Zones</strong>, <strong>Roles</strong>, <strong>Denial Screens</strong>, and/or <strong>Settings</strong>.</p>'
                    . '<p>Zone rows carry denial screen references as label strings rather than database IDs, so the file imports correctly on any site regardless of ID numbering.</p>'
                    . '<p>Use exports to back up your configuration before major changes or to replicate a setup across multiple WordPress installations.</p>',
            ] );
            $screen->add_help_tab( [
                'id'      => 'rbfa-help-settings-import',
                'title'   => 'Import',
                'content' =>
                    '<p>Choose a <code>.json</code> file previously exported from this plugin, select which sections to import, and click <strong>Upload &amp; Review</strong>.</p>'
                    . '<p><strong>Conflict resolution</strong> — if any imported zone slug, denial screen label, or role key already exists, a review screen lists each conflict with a radio button: <em>Keep existing</em> (default) or <em>Use imported</em>. Non-conflicting items are always added.</p>'
                    . '<p><strong>Zones</strong> are added to the existing list; conflicting slugs are skipped or overwritten per your choice.</p>'
                    . '<p><strong>Denial Screens</strong> are added; conflicting labels are skipped or updated per your choice.</p>'
                    . '<p><strong>Roles</strong> are created if they do not exist, or their display name updated if you choose <em>Use imported</em>. Users are <strong>always merged</strong> — any user logins in the import file that exist in this WordPress installation are added to the role, regardless of the conflict resolution choice.</p>'
                    . '<p><strong>Settings</strong> overwrite the current values for base directory, integrity repair, zone page theme, and log retention.</p>',
            ] );
            break;
    }
}

// ─── Menu registration ────────────────────────────────────────────────────────

add_action( 'admin_menu', 'rbfa_register_admin_menu' );

/**
 * Registers the top-level "File Security Pro" menu item in the sidebar.
 *
 * Position 80 places it near the bottom of the sidebar, above Settings.
 * The dashicons-shield icon reinforces the security purpose of the plugin.
 */
function rbfa_register_admin_menu() {
	add_menu_page(
		'File Security Pro',           // Page <title>
		'File Security Pro',           // Sidebar label
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
	wp_register_style( 'rbfa-admin', false, [], RBFA_VERSION );
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
		wp_die( esc_html__( 'You do not have permission to access this page.', 'file-security-pro' ) );
	}

	global $wpdb;

	$zone_table = $wpdb->prefix . 'rbfa_zones';
	$role_table = $wpdb->prefix . 'rbfa_managed_roles';
	$msg_table  = $wpdb->prefix . 'rbfa_denial_screens';
	$current_tab = sanitize_key( wp_unslash( $_GET['tab'] ?? 'logs' ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only GET filter, no data mutation

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
			$notice['message'] // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- already sanitized via esc_html/wp_kses when stored
		);
	}

	echo '<div class="wrap"><h1>File Security Pro</h1>';
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
			echo '<span class="current" aria-current="page">' . absint( $p ) . '</span>';
		} else {
			$url = add_query_arg( array_merge( $base_args, [ 'paged' => $p ] ), admin_url( 'admin.php' ) );
			echo '<a href="' . esc_url( $url ) . '">' . absint( $p ) . '</a>';
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

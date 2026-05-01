<?php
/**
 * Zone management, .htaccess generation, integrity scanning, and cron sync.
 *
 * A "zone" is a protected subfolder inside the uploads base directory.
 * Each zone has an allowed-roles list and an optional custom denial screen.
 * This module keeps the filesystem (.htaccess files) in sync with the DB
 * configuration and provides all data-getter helpers used by other modules.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ─── Data getters ────────────────────────────────────────────────────────────

/**
 * Returns the base folder slug (the root protected directory inside uploads).
 *
 * The slug is stored in the `allowed_roles` column of the special
 * rbfa_default row (is_default = 1). This dual-use of the column is
 * intentional; the default row has no meaningful role list of its own.
 *
 * @return string Base folder slug, e.g. "protected".
 */
function rbfa_get_base_folder() {
	global $wpdb;

	$slug = $wpdb->get_var(
		$wpdb->prepare(
			"SELECT allowed_roles FROM {$wpdb->prefix}rbfa_zones WHERE folder_slug = %s",
			'rbfa_default'
		)
	);

	// Fall back to a sensible default if no base folder has been configured yet.
	return $slug ?: 'list_files';
}

/**
 * Returns all non-default zones from the database.
 *
 * Each result row is augmented with a `roles` key containing the decoded
 * array of allowed role slugs (stored as JSON in the DB).
 *
 * @return array[] Array of zone rows with an additional `roles` key.
 */
function rbfa_get_zones() {
	global $wpdb;

	$results = $wpdb->get_results(
		"SELECT * FROM {$wpdb->prefix}rbfa_zones WHERE is_default = 0",
		ARRAY_A
	);

	// Decode JSON role arrays; fall back to empty array on invalid JSON.
	// Also expose redirect_url as a top-level key for convenience.
	foreach ( $results as &$row ) {
		$decoded             = json_decode( $row['allowed_roles'], true );
		$row['roles']        = is_array( $decoded ) ? $decoded : [];
		$row['redirect_url'] = $row['redirect_url'] ?? '';
	}

	return $results;
}

/**
 * Returns the list of role slugs managed by this plugin.
 *
 * Only roles in this list may be acted on by the role management tab.
 * Built-in WordPress roles are never included.
 *
 * @return string[] Array of role slug strings.
 */
function rbfa_get_managed_roles() {
	global $wpdb;
	return $wpdb->get_col( "SELECT role_id FROM {$wpdb->prefix}rbfa_managed_roles" );
}

// ─── .htaccess management ────────────────────────────────────────────────────

/**
 * Returns the .htaccess content that redirects all direct file requests
 * through WordPress (index.php), enabling PHP-level access control.
 *
 * The WordPress index path is derived dynamically from home_url() so the
 * rule works correctly when WordPress is installed in a subdirectory.
 *
 * @return string .htaccess file content.
 */
function rbfa_get_htaccess_template() {
	$index_path = parse_url( home_url( '/index.php' ), PHP_URL_PATH );

	return "<IfModule mod_rewrite.c>\n"
		. "RewriteEngine On\n"
		. "RewriteCond %{REQUEST_FILENAME} -f\n"
		. "RewriteRule ^(.*)$ $index_path [L]\n"
		. "</IfModule>";
}

/**
 * Recursively scans a directory tree for missing or incorrect .htaccess files.
 *
 * Depth is capped at $max_depth to prevent runaway recursion on unusually
 * deep or circular upload trees.
 *
 * @param string   $dir       Absolute path to scan.
 * @param string[] $issues    Reference array; problem descriptions are appended here.
 * @param int      $depth     Current recursion depth (internal, do not pass).
 * @param int      $max_depth Maximum recursion depth before stopping.
 */
function rbfa_deep_scan_htaccess( $dir, &$issues, $depth = 0, $max_depth = 5 ) {
	if ( ! is_dir( $dir ) || $depth > $max_depth ) {
		return;
	}

	$ht_file  = $dir . '/.htaccess';
	$rel_path = str_replace( wp_upload_dir()['basedir'], 'uploads', $dir );

	if ( ! file_exists( $ht_file ) ) {
		$issues[] = 'Missing .htaccess in <code>' . esc_html( $rel_path ) . '</code>';
	} else {
		$content = file_get_contents( $ht_file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( strpos( $content, 'RewriteRule ^(.*)$' ) === false ) {
			$issues[] = 'Incorrect .htaccess in <code>' . esc_html( $rel_path ) . '</code>';
		}
	}

	// Recurse into subdirectories.
	$items = array_diff( scandir( $dir ), [ '.', '..' ] );
	foreach ( $items as $item ) {
		$path = $dir . '/' . $item;
		if ( is_dir( $path ) ) {
			rbfa_deep_scan_htaccess( $path, $issues, $depth + 1, $max_depth );
		}
	}
}

/**
 * Returns a list of integrity issues across the entire protected tree.
 *
 * @return string[] Human-readable issue descriptions (empty = all clear).
 */
function rbfa_get_system_status() {
	$base      = rbfa_get_base_folder();
	$base_path = wp_upload_dir()['basedir'] . '/' . $base;
	$issues    = [];

	if ( ! is_dir( $base_path ) ) {
		$issues[] = "Base directory 'uploads/" . esc_html( $base ) . "' is missing.";
	} else {
		rbfa_deep_scan_htaccess( $base_path, $issues );
	}

	return $issues;
}

/**
 * Recursively writes the correct .htaccess into a directory and all subdirs.
 *
 * Creates missing directories with wp_mkdir_p. Depth is capped to match
 * the scan limit so sync and scan always cover the same tree.
 *
 * @param string $dir       Absolute path to sync.
 * @param string $content   .htaccess content to write.
 * @param int    $depth     Current recursion depth (internal).
 * @param int    $max_depth Maximum recursion depth.
 */
function rbfa_sync_directories_recursive( $dir, $content, $depth = 0, $max_depth = 5 ) {
	if ( $depth > $max_depth ) {
		return;
	}

	if ( ! is_dir( $dir ) ) {
		wp_mkdir_p( $dir );
	}

	// phpcs:ignore WordPress.WP.AlternativeFunctions
	file_put_contents( $dir . '/.htaccess', $content );

	$items = array_diff( scandir( $dir ), [ '.', '..' ] );
	foreach ( $items as $item ) {
		$path = $dir . '/' . $item;
		if ( is_dir( $path ) ) {
			rbfa_sync_directories_recursive( $path, $content, $depth + 1, $max_depth );
		}
	}
}

/**
 * Syncs all .htaccess files across the entire protected tree.
 *
 * A single recursive call from the base path is sufficient — all zone
 * subdirectories live inside it so they are covered automatically.
 */
function rbfa_sync_all() {
	$base_path = wp_upload_dir()['basedir'] . '/' . rbfa_get_base_folder();
	$ht        = rbfa_get_htaccess_template();
	rbfa_sync_directories_recursive( $base_path, $ht );
}

// ─── Cron ─────────────────────────────────────────────────────────────────────

/**
 * WordPress cron hook: runs the full sync if the cron option is enabled.
 *
 * The cron job is registered on activation (class-rbfa-db.php) and fires
 * hourly. It auto-repairs any .htaccess files that have gone missing or
 * been corrupted since the last sync.
 */
add_action( 'rbfa_hourly_integrity_check', 'rbfa_run_cron_sync' );

function rbfa_run_cron_sync() {
	if ( get_option( 'rbfa_cron_enabled' ) === '1' ) {
		rbfa_sync_all();
	}
}

// ─── Log prune cron ───────────────────────────────────────────────────────────

add_action( 'rbfa_daily_log_prune', 'rbfa_run_cron_log_prune' );

/**
 * Daily cron hook: deletes log entries older than the configured retention period.
 * Only runs if auto-prune is enabled and a positive retention days value is set.
 */
function rbfa_run_cron_log_prune() {
    $enabled = get_option( 'rbfa_prune_enabled', '0' );
    $days    = (int) get_option( 'rbfa_prune_days', 90 );
    if ( $enabled !== '1' || $days < 1 ) return;
    global $wpdb;
    $wpdb->query( $wpdb->prepare(
        "DELETE FROM {$wpdb->prefix}rbfa_access_logs WHERE time < DATE_SUB(NOW(), INTERVAL %d DAY)",
        $days
    ) );
}

/**
 * Manually prune logs older than the configured retention period.
 *
 * @return int Number of rows deleted.
 */
function rbfa_manual_prune_logs() {
    $days = (int) get_option( 'rbfa_prune_days', 90 );
    if ( $days < 1 ) return 0;
    global $wpdb;
    $wpdb->query( $wpdb->prepare(
        "DELETE FROM {$wpdb->prefix}rbfa_access_logs WHERE time < DATE_SUB(NOW(), INTERVAL %d DAY)",
        $days
    ) );
    return (int) $wpdb->rows_affected;
}

/**
 * Detects whether the current web server is NGINX.
 *
 * Checks SERVER_SOFTWARE header. Returns true if NGINX is identified.
 * Used to conditionally show the NGINX configuration tab.
 *
 * @return bool
 */
function rbfa_is_nginx() {
    $software = strtolower( $_SERVER['SERVER_SOFTWARE'] ?? '' );
    return strpos( $software, 'nginx' ) !== false;
}

<?php
/**
 * CSV export handler.
 *
 * Hooked to admin_init — which fires before WordPress sends any HTML output —
 * so that the CSV headers can be set cleanly without triggering the
 * "headers already sent" warning that occurs when output starts first.
 *
 * The export always returns the FULL filtered dataset, not just the
 * current page, so exports are complete regardless of the pagination setting.
 *
 * Guest users (user_id = 0) are correctly identified as "Guest" and are
 * searchable by typing "guest" (or any partial match) in the username filter.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action( 'admin_init', 'rbfa_handle_csv_export' );

/**
 * Detects an export request, applies filters, and streams a CSV file.
 *
 * Triggered by ?page=rbfa-pro&action=export_csv (GET request).
 * Capability check is enforced before any data is read or output is sent.
 */
function rbfa_handle_csv_export() {
	// Only run when the correct page and action are present.
	if ( ! isset( $_GET['page'], $_GET['action'] )
		|| $_GET['page']   !== 'rbfa-pro'
		|| $_GET['action'] !== 'export_csv'
	) {
		return;
	}

	// Enforce admin capability — reject anyone who cannot manage options.
	if ( ! current_user_can( 'manage_wfsp' ) ) {
		wp_die( esc_html__( 'You do not have permission to export logs.', 'wp-file-security-pro' ) );
	}

	global $wpdb;

	// ── Collect and sanitize filter parameters ──────────────────────────────
	// phpcs:disable WordPress.Security.NonceVerification.Recommended -- export mirrors the filter state of the Logs tab, read-only

	$f_start_dt = sanitize_text_field( wp_unslash( $_GET['start_dt'] ?? '' ) );
	$f_end_dt   = sanitize_text_field( wp_unslash( $_GET['end_dt']   ?? '' ) );
	$f_user     = sanitize_text_field( wp_unslash( $_GET['f_user']   ?? '' ) );
	$f_ip         = sanitize_text_field( wp_unslash( $_GET['f_ip']       ?? '' ) );
	$f_file       = sanitize_text_field( wp_unslash( $_GET['f_file']     ?? '' ) );
	$f_status     = sanitize_text_field( wp_unslash( $_GET['f_status']   ?? '' ) );

	// phpcs:enable WordPress.Security.NonceVerification.Recommended

	// ── Build WHERE clause ──────────────────────────────────────────────────

	$where  = [];
	$values = [];

	if ( $f_start_dt && $f_end_dt ) {
		$where[]  = 'time BETWEEN %s AND %s';
		$values[] = str_replace( 'T', ' ', $f_start_dt );
		$values[] = str_replace( 'T', ' ', $f_end_dt );
	} elseif ( $f_start_dt ) {
		$where[]  = 'time >= %s';
		$values[] = str_replace( 'T', ' ', $f_start_dt );
	} elseif ( $f_end_dt ) {
		$where[]  = 'time <= %s';
		$values[] = str_replace( 'T', ' ', $f_end_dt );
	}

	// Partial IP match — useful for filtering by subnet prefix.
	if ( $f_ip ) {
		$where[]  = 'ip_address LIKE %s';
		$values[] = '%' . $wpdb->esc_like( $f_ip ) . '%';
	}

	// Partial file path match — case-insensitive on most MySQL collations.
	if ( $f_file ) {
		$where[]  = 'file_path LIKE %s';
		$values[] = '%' . $wpdb->esc_like( $f_file ) . '%';
	}

	// Exact status match: 'Granted' or 'Denied'.
	if ( $f_status ) {
		$where[]  = 'status = %s';
		$values[] = $f_status;
	}

	// ── Query the full dataset (no LIMIT — export is always complete) ───────

	// Respect the current sort state so exports match what the admin sees.
	// Column is whitelisted to prevent SQL injection via the orderby param.
	$allowed_export_cols = [ 'time' => 'time', 'ip_address' => 'ip_address', 'file_path' => 'file_path', 'status' => 'status' ];
	// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only sort state mirrors Logs tab
	$export_col = ( isset( $_GET['orderby'] ) && array_key_exists( sanitize_key( wp_unslash( $_GET['orderby'] ) ), $allowed_export_cols ) )
		? $allowed_export_cols[ sanitize_key( wp_unslash( $_GET['orderby'] ) ) ] : 'time';
	$export_dir = ( isset( $_GET['order'] ) && strtoupper( sanitize_key( wp_unslash( $_GET['order'] ) ) ) === 'ASC' ) ? 'ASC' : 'DESC';
	// phpcs:enable WordPress.Security.NonceVerification.Recommended

	$sql = "SELECT * FROM {$wpdb->prefix}rbfa_access_logs";
	if ( $where ) {
		$sql .= ' WHERE ' . implode( ' AND ', $where );
	}
	$sql .= " ORDER BY $export_col $export_dir"; // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- ORDER BY column whitelisted; values bound via prepare() when present

	$logs = $values
		? $wpdb->get_results( $wpdb->prepare( $sql, $values ), ARRAY_A ) // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		: $wpdb->get_results( $sql, ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared

	// ── Post-filter by username (requires PHP-side resolution) ──────────────

	if ( $f_user ) {
		/*
		 * Guest rows have user_id = 0. We check whether the search term
		 * matches "guest" (case-insensitive) for those rows, and check
		 * user_login for registered users. This allows partial matches like
		 * "gue" to match Guest rows, and "jsmith" to match registered users.
		 */
		$logs = array_filter( $logs, function ( $row ) use ( $f_user ) {
			if ( (int) $row['user_id'] === 0 ) {
				return stripos( 'guest', $f_user ) !== false;
			}
			$u = get_userdata( $row['user_id'] );
			return $u && stripos( $u->user_login, $f_user ) !== false;
		} );
	}

	// ── Stream the CSV response ─────────────────────────────────────────────

	$filename = 'wp-file-security-logs-' . gmdate( 'Y-m-d' ) . '.csv';

	// These headers must be sent before any output — this is why the handler
	// is on admin_init rather than inside the page callback.
	header( 'Content-Type: text/csv; charset=utf-8' );
	header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
	header( 'Pragma: no-cache' );
	header( 'Expires: 0' );

	$out = fopen( 'php://output', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions

	// UTF-8 BOM — ensures Excel interprets the file encoding correctly.
	fwrite( $out, "\xEF\xBB\xBF" ); // phpcs:ignore WordPress.WP.AlternativeFunctions

	// Column headers row.
	fputcsv( $out, [ 'Time', 'Username', 'Roles', 'IP', 'Path', 'Status' ] );

	// Data rows.
	foreach ( $logs as $row ) {
		if ( (int) $row['user_id'] === 0 ) {
			$username = 'Guest';
		} else {
			$u        = get_userdata( $row['user_id'] );
			$username = $u ? $u->user_login : 'Guest';
		}

		fputcsv( $out, [
			$row['time'],
			$username,
			$row['user_roles'],
			$row['ip_address'],
			$row['file_path'],
			$row['status'],
		] );
	}

	fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	exit;
}

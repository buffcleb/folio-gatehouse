<?php
/**
 * Plugin uninstall handler.
 *
 * WordPress calls this file automatically when an admin deletes the plugin
 * from the Plugins screen (not on deactivation). This is the WordPress-
 * recommended approach for data cleanup on deletion — using uninstall.php
 * is preferred over register_uninstall_hook() because it runs in a clean
 * context with no other plugin code loaded.
 *
 * Data is only removed if the admin has opted in via the "Remove data on
 * plugin deletion" checkbox on the Logs tab. This matches the convention
 * used by plugins like WooCommerce, Yoast SEO, and Gravity Forms — never
 * delete user data silently, always require an explicit opt-in.
 *
 * @package WPFileSecurityPro
 */

// WordPress sets this constant before calling uninstall.php.
// Exit immediately if called directly to prevent unauthorized execution.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Only delete data if the admin explicitly opted in.
if ( get_option( 'rbfa_delete_on_uninstall' ) !== '1' ) {
    return;
}

global $wpdb;

// ── Remove all plugin database tables ────────────────────────────────────────

$tables = [
    $wpdb->prefix . 'rbfa_access_logs',
    $wpdb->prefix . 'rbfa_denial_screens',
    $wpdb->prefix . 'rbfa_zones',
    $wpdb->prefix . 'rbfa_managed_roles',
];

foreach ( $tables as $table ) {
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL
    $wpdb->query( "DROP TABLE IF EXISTS `$table`" );
}

// ── Remove all plugin options ─────────────────────────────────────────────────

$options = [
    'rbfa_cron_enabled',
    'rbfa_delete_on_uninstall',
];

foreach ( $options as $option ) {
    delete_option( $option );
}

// ── Remove any lingering transients ───────────────────────────────────────────

// Clean up per-user admin notice transients (stored as rbfa_admin_notice_{user_id}).
$wpdb->query(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_rbfa_%' OR option_name LIKE '_transient_timeout_rbfa_%'"
);

// Clean up login-redirect token transients (stored as rbfa_redir_{token}).
// These are already short-lived (15 min) but clean up immediately on uninstall.
$wpdb->query(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_rbfa_redir_%' OR option_name LIKE '_transient_timeout_rbfa_redir_%'"
);

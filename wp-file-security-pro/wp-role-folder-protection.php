<?php
/**
 * Plugin Name: WP File Security Pro
 * Description: Role-based file access control with zone management, access logging, and .htaccess integrity checking.
 * Version:     1.0.5
 * License:     GPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 *
 * @package WPFileSecurityPro
 */

// Prevent direct file access — WordPress must bootstrap this file.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// ─── Plugin constants ────────────────────────────────────────────────────────
define( 'RBFA_VERSION',  '1.0.1' );
define( 'RBFA_DIR',      plugin_dir_path( __FILE__ ) );
define( 'RBFA_BASENAME', plugin_basename( __FILE__ ) );

// ─── Load all modules ────────────────────────────────────────────────────────

// Database setup, activation/deactivation hooks, and cron scheduling.
require_once RBFA_DIR . 'includes/class-rbfa-db.php';

// Zone data helpers, .htaccess generation, integrity scanning, and sync.
require_once RBFA_DIR . 'includes/class-rbfa-zones.php';

// Core front-end access control: request interception, role checking, file serving.
require_once RBFA_DIR . 'includes/class-rbfa-access.php';

// [folder_files] shortcode and recursive directory listing.
require_once RBFA_DIR . 'includes/class-rbfa-shortcode.php';

// CSV export handler, hooked to admin_init before any output is sent.
require_once RBFA_DIR . 'includes/class-rbfa-export.php';

// Admin menu registration, asset enqueueing, and tab dispatcher.
require_once RBFA_DIR . 'admin/class-rbfa-admin.php';

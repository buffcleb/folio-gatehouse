<?php
/**
 * [folder_files] shortcode.
 *
 * Renders a browsable, downloadable file listing for a named zone.
 * Only users whose roles match the zone's allowlist (or administrators)
 * will see the listing. All others receive an empty string.
 *
 * Usage: [folder_files folder="zone-slug"]
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_shortcode( 'folder_files', 'rbfa_shortcode_folder_files' );

/**
 * Shortcode handler for [folder_files].
 *
 * @param  array $atts Shortcode attributes. Accepts 'folder' (zone slug).
 * @return string HTML file listing, or empty string if access is denied.
 */
function rbfa_shortcode_folder_files( $atts ) {
	$atts = shortcode_atts( [ 'folder' => '' ], $atts, 'folder_files' );

	// A folder slug is required.
	if ( empty( $atts['folder'] ) ) {
		return '';
	}

	$current_user = wp_get_current_user();

	foreach ( rbfa_get_zones() as $zone ) {
		if ( $zone['folder_slug'] !== $atts['folder'] ) {
			continue;
		}

		// Check that the current user has at least one matching role.
		$has_access = ! empty( array_intersect( $zone['roles'] ?? [], (array) $current_user->roles ) )
		              || current_user_can( 'administrator' );

		if ( ! $has_access ) {
			return ''; // Silently return nothing for unauthorized users.
		}

		$up   = wp_upload_dir();
		$base = rbfa_get_base_folder();

		$dir = $up['basedir'] . '/' . $base . '/' . $atts['folder'];
		$url = $up['baseurl'] . '/' . $base . '/' . $atts['folder'];

		return '<div class="rbfa-container">' . rbfa_scan_recursive_shortcode( $dir, $url, '' ) . '</div>';
	}

	return ''; // Zone not found or access denied.
}

/**
 * Recursively builds an HTML file/folder listing for a directory.
 *
 * .htaccess files are excluded from the listing. Files are rendered as
 * download links; directories are rendered as nested lists.
 *
 * @param  string $dir Absolute path to the directory.
 * @param  string $url Absolute URL corresponding to $dir.
 * @param  string $rel Relative path from the zone root (used for URL building).
 * @return string HTML unordered list.
 */
function rbfa_scan_recursive_shortcode( $dir, $url, $rel ) {
	if ( ! is_dir( $dir ) ) {
		return '';
	}

	// Exclude navigation entries and .htaccess from the listing.
	$items = array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] );
	$out   = '<ul style="list-style:none; margin-left:20px;">';

	foreach ( $items as $item ) {
		$path    = $dir . '/' . $item;
		$sub_rel = $rel . '/' . $item;

		if ( is_dir( $path ) ) {
			$out .= '<li style="margin-top:5px;">'
				. '<strong>📁 ' . esc_html( $item ) . '</strong>'
				. rbfa_scan_recursive_shortcode( $path, $url, $sub_rel )
				. '</li>';
		} else {
			$size = size_format( filesize( $path ) );
			$href = esc_url( $url . '/' . ltrim( $sub_rel, '/' ) );
			$out .= '<li>📄 <a href="' . $href . '" download="' . esc_attr( $item ) . '">'
				. esc_html( $item )
				. '</a> <small style="color:#888;">(' . $size . ')</small></li>';
		}
	}

	return $out . '</ul>';
}

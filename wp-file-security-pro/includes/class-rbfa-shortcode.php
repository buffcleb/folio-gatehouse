<?php
/**
 * [folder_files] shortcode.
 *
 * Renders a browsable, downloadable file listing for a named zone.
 * Only users whose roles match the zone's allowlist (or administrators)
 * will see the listing. All others receive an empty string.
 *
 * Top-level view shows direct file count + size with two download buttons
 * (current directory only, and recursive). Subdirectories are collapsed
 * <details> elements showing file count, total size, and a Download All button.
 *
 * Usage: [folder_files folder="zone-slug"]
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_shortcode( 'folder_files', 'rbfa_shortcode_folder_files' );
add_action( 'init', 'rbfa_handle_zip_download' );

// ─── Shortcode entry point ────────────────────────────────────────────────────

function rbfa_shortcode_folder_files( $atts ) {
	$atts = shortcode_atts( [ 'folder' => '' ], $atts, 'folder_files' );
	if ( empty( $atts['folder'] ) ) {
		return '';
	}

	$current_user = wp_get_current_user();

	foreach ( rbfa_get_zones() as $zone ) {
		if ( $zone['folder_slug'] !== $atts['folder'] ) {
			continue;
		}

		$has_access = ! empty( array_intersect( $zone['roles'] ?? [], (array) $current_user->roles ) )
		              || current_user_can( 'administrator' );
		if ( ! $has_access ) {
			return '';
		}

		$up   = wp_upload_dir();
		$base = rbfa_get_base_folder();
		$dir  = $up['basedir'] . '/' . $base . '/' . $atts['folder'];
		$url  = $up['baseurl'] . '/' . $base . '/' . $atts['folder'];

		if ( ! is_dir( $dir ) ) {
			return '';
		}

		rbfa_enqueue_shortcode_styles();

		$count      = rbfa_count_direct_files( $dir );
		$size       = rbfa_size_direct_files( $dir );
		$dl_current = rbfa_zip_url( $atts['folder'], '', false );
		$dl_all     = rbfa_zip_url( $atts['folder'], '', true );

		$label_count = $count . ' file' . ( $count !== 1 ? 's' : '' );
		$label_size  = size_format( $size );

		$out  = '<div class="rbfa-container">';

		// Top-level header bar.
		$out .= '<div class="rbfa-header">';
		$out .= '<span class="rbfa-meta">' . esc_html( $label_count ) . ' &middot; ' . esc_html( $label_size ) . '</span>';
		$out .= '<div class="rbfa-actions">';
		$out .= '<a href="' . esc_url( $dl_current ) . '" class="rbfa-dl-btn">&#8595; Download Current Directory</a>';
		$out .= '<a href="' . esc_url( $dl_all ) . '" class="rbfa-dl-btn">&#8595; Download All</a>';
		$out .= '</div>';
		$out .= '</div>';

		// Direct files in this directory.
		$out .= rbfa_render_file_list( $dir, $url );

		// Subdirectories as collapsed sections.
		$out .= rbfa_render_subdirs( $dir, $url, $atts['folder'], '' );

		$out .= '</div>';

		return $out;
	}

	return '';
}

// ─── Rendering helpers ────────────────────────────────────────────────────────

/**
 * Renders a flat <ul> of files in $dir (no recursion).
 */
function rbfa_render_file_list( $dir, $url ) {
	if ( ! is_dir( $dir ) ) {
		return '';
	}

	$items = array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] );
	$out   = '';

	foreach ( $items as $item ) {
		$path = $dir . '/' . $item;
		if ( ! is_file( $path ) ) {
			continue;
		}
		$size = size_format( filesize( $path ) );
		$href = esc_url( $url . '/' . $item );
		$out .= '<li class="rbfa-file">&#128196; <a href="' . $href . '" download="' . esc_attr( $item ) . '">'
		     . esc_html( $item ) . '</a>'
		     . ' <span class="rbfa-size">(' . $size . ')</span></li>';
	}

	if ( $out === '' ) {
		return '';
	}

	return '<ul class="rbfa-file-list">' . $out . '</ul>';
}

/**
 * Renders subdirectories of $dir as collapsed <details> elements.
 * Recursively applies the same treatment to nested subdirs.
 *
 * @param string $dir         Absolute filesystem path.
 * @param string $url         Public URL corresponding to $dir.
 * @param string $zone_slug   Zone slug (for building download URLs).
 * @param string $rel         Relative path from the zone root to $dir.
 */
function rbfa_render_subdirs( $dir, $url, $zone_slug, $rel ) {
	if ( ! is_dir( $dir ) ) {
		return '';
	}

	$items = array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] );
	$out   = '';

	foreach ( $items as $item ) {
		$path     = $dir . '/' . $item;
		$sub_url  = $url . '/' . $item;
		$sub_rel  = trim( $rel . '/' . $item, '/' );

		if ( ! is_dir( $path ) ) {
			continue;
		}

		$count  = rbfa_count_files_recursive( $path );
		$size   = rbfa_size_recursive( $path );
		$dl_url = rbfa_zip_url( $zone_slug, $sub_rel, true );

		$label = '(' . $count . ' file' . ( $count !== 1 ? 's' : '' ) . ', ' . size_format( $size ) . ')';

		$out .= '<details class="rbfa-subdir">';
		$out .= '<summary class="rbfa-subdir-summary">';
		$out .= '&#128193; <strong>' . esc_html( $item ) . '</strong> ';
		$out .= '<span class="rbfa-meta">' . esc_html( $label ) . '</span>';
		$out .= ' <a href="' . esc_url( $dl_url ) . '" class="rbfa-dl-btn rbfa-dl-sm"'
		     . ' onclick="event.stopPropagation()">&#8595; Download All</a>';
		$out .= '</summary>';
		$out .= rbfa_render_file_list( $path, $sub_url );
		$out .= rbfa_render_subdirs( $path, $sub_url, $zone_slug, $sub_rel );
		$out .= '</details>';
	}

	return $out;
}

// ─── Filesystem helpers ───────────────────────────────────────────────────────

function rbfa_count_direct_files( $dir ) {
	$count = 0;
	foreach ( array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] ) as $item ) {
		if ( is_file( $dir . '/' . $item ) ) {
			$count++;
		}
	}
	return $count;
}

function rbfa_size_direct_files( $dir ) {
	$size = 0;
	foreach ( array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] ) as $item ) {
		$path = $dir . '/' . $item;
		if ( is_file( $path ) ) {
			$size += filesize( $path );
		}
	}
	return $size;
}

function rbfa_count_files_recursive( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return 0;
	}
	$count = 0;
	foreach ( array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] ) as $item ) {
		$path = $dir . '/' . $item;
		if ( is_file( $path ) ) {
			$count++;
		} elseif ( is_dir( $path ) ) {
			$count += rbfa_count_files_recursive( $path );
		}
	}
	return $count;
}

function rbfa_size_recursive( $dir ) {
	if ( ! is_dir( $dir ) ) {
		return 0;
	}
	$size = 0;
	foreach ( array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] ) as $item ) {
		$path = $dir . '/' . $item;
		if ( is_file( $path ) ) {
			$size += filesize( $path );
		} elseif ( is_dir( $path ) ) {
			$size += rbfa_size_recursive( $path );
		}
	}
	return $size;
}

// ─── ZIP download ─────────────────────────────────────────────────────────────

/**
 * Builds a nonce-protected URL for a ZIP download of a zone directory.
 *
 * @param string $zone      Zone slug.
 * @param string $subdir    Relative subdirectory path within the zone ('' = zone root).
 * @param bool   $recursive Whether to include subdirectories in the ZIP.
 */
function rbfa_zip_url( $zone, $subdir, $recursive ) {
	return add_query_arg( [
		'rbfa_download' => '1',
		'zone'          => rawurlencode( $zone ),
		'subdir'        => rawurlencode( $subdir ),
		'recursive'     => $recursive ? '1' : '0',
		'_nonce'        => wp_create_nonce( 'rbfa_dl_' . $zone ),
	], home_url( '/' ) );
}

/**
 * Handles ?rbfa_download=1 requests by streaming a ZIP archive.
 *
 * Hooked to `init` so headers can be sent before any output.
 * Verifies the nonce and the user's zone access before serving any data.
 */
function rbfa_handle_zip_download() {
	if ( empty( $_GET['rbfa_download'] ) || $_GET['rbfa_download'] !== '1' ) {
		return;
	}

	$zone      = sanitize_key( wp_unslash( $_GET['zone']   ?? '' ) );
	$subdir    = sanitize_text_field( urldecode( wp_unslash( $_GET['subdir'] ?? '' ) ) );
	$recursive = ! empty( $_GET['recursive'] ) && sanitize_key( wp_unslash( $_GET['recursive'] ) ) === '1';
	$nonce     = sanitize_text_field( wp_unslash( $_GET['_nonce'] ?? '' ) );

	if ( ! $zone || ! wp_verify_nonce( $nonce, 'rbfa_dl_' . $zone ) ) {
		wp_die( 'Security check failed.', 403 );
	}

	// Verify zone access.
	$current_user = wp_get_current_user();
	$has_access   = false;
	foreach ( rbfa_get_zones() as $z ) {
		if ( $z['folder_slug'] !== $zone ) {
			continue;
		}
		$has_access = ! empty( array_intersect( $z['roles'] ?? [], (array) $current_user->roles ) )
		              || current_user_can( 'administrator' );
		break;
	}

	if ( ! $has_access ) {
		wp_die( 'Access denied.', 403 );
	}

	// Resolve and validate the target path.
	$up       = wp_upload_dir();
	$base     = rbfa_get_base_folder();
	$zone_dir = $up['basedir'] . '/' . $base . '/' . $zone;

	$subdir = trim( $subdir, '/\\' );
	$target = $subdir ? $zone_dir . '/' . $subdir : $zone_dir;

	$real_target = realpath( $target );
	$real_zone   = realpath( $zone_dir );

	// realpath() is the authoritative boundary check. We require the resolved
	// target to equal the zone root or be a direct descendant (separated by a
	// directory separator). The separator suffix prevents a sibling directory
	// like /zone-extra/ from matching a zone named /zone/.
	if (
		! $real_target ||
		! $real_zone ||
		( $real_target !== $real_zone && strpos( $real_target, $real_zone . DIRECTORY_SEPARATOR ) !== 0 )
	) {
		wp_die( 'Invalid path.', 400 );
	}

	// Log the download before streaming — consistent with per-file access logging.
	// Path format: "[zip] zone/subdir/" or "[zip:all] zone/" so it is filterable
	// in the Logs tab by typing "[zip" in the Path filter.
	$log_path = '[zip' . ( $recursive ? ':all' : '' ) . '] '
	          . $zone . ( $subdir ? '/' . $subdir : '' ) . '/';
	rbfa_log_access( $current_user, $log_path, 'Granted' );

	if ( ! class_exists( 'ZipArchive' ) ) {
		wp_die( 'ZIP support is not available on this server.' );
	}

	$tmp = tempnam( sys_get_temp_dir(), 'rbfa_' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
	$zip = new ZipArchive();

	if ( $zip->open( $tmp, ZipArchive::OVERWRITE ) !== true ) {
		wp_die( 'Could not create ZIP file.' );
	}

	rbfa_zip_add_files( $zip, $real_target, $real_target, $recursive );
	$zip->close();

	$basename = $subdir ? basename( $subdir ) : $zone;
	$filename = sanitize_file_name( $basename ) . '.zip';

	header( 'Content-Type: application/zip' );
	header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
	header( 'Content-Length: ' . filesize( $tmp ) );
	header( 'Pragma: no-cache' );
	header( 'Expires: 0' );

	readfile( $tmp );        // phpcs:ignore WordPress.WP.AlternativeFunctions
	unlink( $tmp );          // phpcs:ignore WordPress.WP.AlternativeFunctions
	exit;
}

/**
 * Recursively adds files from $dir into the ZipArchive.
 *
 * @param ZipArchive $zip       The open archive.
 * @param string     $base_dir  Root path (used to compute archive-relative names).
 * @param string     $dir       Current directory being added.
 * @param bool       $recursive Whether to descend into subdirectories.
 */
function rbfa_zip_add_files( ZipArchive $zip, $base_dir, $dir, $recursive ) {
	foreach ( array_diff( scandir( $dir ), [ '.', '..', '.htaccess' ] ) as $item ) {
		$path         = $dir . '/' . $item;
		$archive_name = ltrim( str_replace( $base_dir, '', $path ), '/' );

		if ( is_file( $path ) ) {
			$zip->addFile( $path, $archive_name );
		} elseif ( $recursive && is_dir( $path ) ) {
			rbfa_zip_add_files( $zip, $base_dir, $path, true );
		}
	}
}

// ─── Frontend styles ──────────────────────────────────────────────────────────

function rbfa_enqueue_shortcode_styles() {
	if ( wp_style_is( 'rbfa-shortcode', 'enqueued' ) ) {
		return;
	}
	wp_register_style( 'rbfa-shortcode', false, [], RBFA_VERSION );
	wp_enqueue_style( 'rbfa-shortcode' );
	wp_add_inline_style( 'rbfa-shortcode', '
		.rbfa-container { font-family: inherit; }

		.rbfa-header {
			display: flex;
			align-items: center;
			gap: 10px;
			padding: 8px 12px;
			background: #f6f7f7;
			border: 1px solid #ddd;
			border-radius: 4px;
			margin-bottom: 10px;
			flex-wrap: wrap;
		}
		.rbfa-header .rbfa-actions { margin-left: auto; display: flex; gap: 6px; flex-wrap: wrap; }

		.rbfa-meta { color: #666; font-size: 13px; }
		.rbfa-size { color: #888; font-size: 12px; }

		.rbfa-dl-btn {
			display: inline-block;
			padding: 4px 10px;
			background: #2271b1;
			color: #fff;
			border-radius: 3px;
			font-size: 12px;
			text-decoration: none;
			white-space: nowrap;
		}
		.rbfa-dl-btn:hover { background: #135e96; color: #fff; }
		.rbfa-dl-sm { padding: 2px 8px; font-size: 11px; }

		.rbfa-file-list {
			list-style: none;
			margin: 0 0 6px 0;
			padding: 0;
		}
		.rbfa-file { padding: 3px 0; font-size: 14px; }
		.rbfa-file a { text-decoration: none; color: #2271b1; }
		.rbfa-file a:hover { text-decoration: underline; }

		.rbfa-subdir {
			border: 1px solid #ddd;
			border-radius: 4px;
			margin: 6px 0;
		}
		.rbfa-subdir-summary {
			display: flex;
			align-items: center;
			gap: 8px;
			padding: 7px 12px;
			background: #f6f7f7;
			cursor: pointer;
			list-style: none;
			flex-wrap: wrap;
		}
		.rbfa-subdir-summary::-webkit-details-marker { display: none; }
		.rbfa-subdir-summary::before { content: "▶"; font-size: 10px; color: #888; transition: transform 0.15s; }
		.rbfa-subdir[open] > .rbfa-subdir-summary::before { transform: rotate(90deg); }
		.rbfa-subdir-summary .rbfa-dl-btn { margin-left: auto; }

		.rbfa-subdir > .rbfa-file-list,
		.rbfa-subdir > .rbfa-subdir {
			margin-left: 16px;
			margin-top: 6px;
		}
		.rbfa-subdir[open] > .rbfa-file-list { display: block; margin: 8px 8px 4px 24px; }
	' );
}

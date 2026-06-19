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
	foreach ( rbfa_load_zone_rows() as $row ) {
		if ( (int) $row['is_default'] === 1 ) {
			// Base folder slug is stored in allowed_roles on the default row.
			return $row['allowed_roles'] ?: 'list_files';
		}
	}

	// Fall back to a sensible default if no base folder has been configured yet.
	return 'list_files';
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
	$zones = [];

	foreach ( rbfa_load_zone_rows() as $row ) {
		if ( (int) $row['is_default'] === 1 ) {
			continue; // The default row holds the base folder slug, not a zone.
		}

		// Decode JSON role arrays; fall back to empty array on invalid JSON.
		// Also expose redirect_url as a top-level key for convenience.
		$decoded             = json_decode( $row['allowed_roles'], true );
		$row['roles']        = is_array( $decoded ) ? $decoded : [];
		$row['redirect_url'] = $row['redirect_url'] ?? '';
		$zones[]             = $row;
	}

	return $zones;
}

/**
 * Loads every row of the zones table once, with object-cache backing.
 *
 * Both rbfa_get_zones() and rbfa_get_base_folder() read the same table, so
 * this fetches all rows in a single query and lets each caller filter what it
 * needs. The result is stored in the object cache: with WordPress's default
 * (non-persistent) cache this acts as per-request memoization — one query per
 * request no matter how many times the zones are read — and with a persistent
 * object cache (Redis/Memcached) repeat requests serve from cache with zero
 * queries. rbfa_flush_zone_cache() must be called after any write to the table.
 *
 * @return array[] Raw associative rows from the zones table.
 */
function rbfa_load_zone_rows() {
	$cached = wp_cache_get( 'rbfa_all_zones', 'rbfa' );
	if ( is_array( $cached ) ) {
		return $cached;
	}

	global $wpdb;
	$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- result cached via wp_cache_set below
		"SELECT * FROM {$wpdb->prefix}rbfa_zones",
		ARRAY_A
	);
	if ( ! is_array( $rows ) ) {
		$rows = [];
	}

	wp_cache_set( 'rbfa_all_zones', $rows, 'rbfa' );
	return $rows;
}

/**
 * Invalidates the cached zone rows. Call after any insert/update/delete on the
 * zones table so the next read reflects the change (essential on sites running
 * a persistent object cache).
 */
function rbfa_flush_zone_cache() {
	wp_cache_delete( 'rbfa_all_zones', 'rbfa' );
}

/**
 * Returns the list of role slugs managed by this plugin.
 *
 * Only roles in this list may be acted on by the role management tab.
 * Built-in WordPress roles are never included.
 *
 * @return string[] Array of role slug strings.
 */
/**
 * Returns all plugin-managed role slugs.
 *
 * A role is considered managed if its slug starts with "fgh_". This
 * prefix-based detection means managed roles survive plugin uninstall and
 * reinstall without needing a database record — WordPress stores roles in
 * wp_options, which is unaffected by the plugin's table cleanup.
 *
 * @return string[]
 */
function rbfa_get_managed_roles() {
	return array_values( array_filter(
		array_keys( wp_roles()->roles ),
		function ( $role_id ) {
			return strpos( $role_id, 'fgh_' ) === 0;
		}
	) );
}

// ─── Virtual zone pages (rewrite-based) ──────────────────────────────────────

/*
 * Each zone gets a virtual front-end page at:
 *   {site}/protected-zone/{zone-slug}/
 *
 * No WordPress post is created. The plugin registers a rewrite rule that maps
 * this URL to a custom query var, then intercepts the request on
 * template_redirect to enforce role access and render the page inside the
 * active theme's shell.
 *
 * The page title and body HTML are stored in the zone DB row (page_title and
 * page_content columns). Shortcodes in page_content are processed on output.
 */

add_action( 'init', 'rbfa_register_zone_rewrite' );

/**
 * Registers the rewrite rule for zone virtual pages.
 * A flush is triggered on plugin activation/deactivation (class-rbfa-db.php).
 */
function rbfa_register_zone_rewrite() {
    add_rewrite_rule(
        '^protected-zone/([^/]+)/?$',
        'index.php?rbfa_zone=$matches[1]',
        'top'
    );
}

add_action( 'admin_init', 'rbfa_ensure_zone_rewrite_flushed' );

/**
 * Flushes rewrite rules if the zone rule is missing from the stored rule set.
 *
 * Catches cases where the plugin was already active when the rewrite rule was
 * first introduced (activation hook fires before init, so an early flush would
 * miss the rule). Runs on admin_init so init has already fired and the rule is
 * registered before we check and flush.
 */
function rbfa_ensure_zone_rewrite_flushed() {
    $rules = (array) get_option( 'rewrite_rules' );
    if ( ! array_key_exists( '^protected-zone/([^/]+)/?$', $rules ) ) {
        flush_rewrite_rules( false );
    }
}

add_filter( 'query_vars', 'rbfa_register_zone_query_var' );

/** Exposes the rbfa_zone query variable to WordPress. */
function rbfa_register_zone_query_var( $vars ) {
    $vars[] = 'rbfa_zone';
    return $vars;
}

add_action( 'template_redirect', 'rbfa_handle_zone_page_request' );

/**
 * Intercepts requests for virtual zone pages.
 *
 * Enforces role-based access using the same redirect/denial logic as file
 * requests, then renders the page inside the active theme (get_header /
 * get_footer) so it inherits the site's look and feel.
 */
function rbfa_handle_zone_page_request() {
    $zone_slug = get_query_var( 'rbfa_zone' );
    if ( empty( $zone_slug ) ) {
        return;
    }

    $zones = rbfa_get_zones();
    $zone  = null;
    foreach ( $zones as $z ) {
        if ( $z['folder_slug'] === $zone_slug ) {
            $zone = $z;
            break;
        }
    }

    if ( ! $zone ) {
        wp_die( esc_html__( 'Zone not found.', 'folio-gatehouse' ), '404 Not Found', [ 'response' => 404 ] );
    }

    $page_url = home_url( '/protected-zone/' . $zone_slug . '/' );
    $roles    = $zone['roles'] ?? [];

    if ( ! empty( $roles ) ) {
        $user       = wp_get_current_user();
        $has_access = in_array( 'administrator', (array) $user->roles, true )
                      || ! empty( array_intersect( $roles, (array) $user->roles ) );

        if ( ! $has_access ) {
            if ( is_user_logged_in() ) {
                if ( ! empty( $zone['redirect_url_auth'] ) ) {
                    wp_redirect( esc_url_raw( $zone['redirect_url_auth'] ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- admin-configured URL may be external
                    exit;
                }
                $denial_id = (int) ( $zone['denial_id_auth'] ?? 0 ) > 0
                    ? (int) $zone['denial_id_auth']
                    : (int) ( $zone['denial_id'] ?? 0 );
            } else {
                if ( ! empty( $zone['redirect_url'] ) ) {
                    wp_redirect( esc_url_raw( $zone['redirect_url'] ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- admin-configured URL may be external
                    exit;
                }
                $denial_id = (int) ( $zone['denial_id'] ?? 0 );
                if ( $denial_id === 0 ) {
                    wp_redirect( wp_login_url( $page_url ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- admin-configured URL may be external
                    exit;
                }
            }
            rbfa_deny_access( $denial_id, $page_url );
        }
    }

    // Resolve title and body — fall back to humanised slug / shortcode.
    $title = ! empty( $zone['page_title'] )
        ? $zone['page_title']
        : ucwords( str_replace( [ '-', '_' ], ' ', $zone_slug ) );

    $body_raw = ! empty( $zone['page_content'] )
        ? $zone['page_content']
        : '[rbfa_files folder="' . esc_attr( $zone_slug ) . '"]';

    $body_html = wp_kses_post( do_shortcode( $body_raw ) );

    status_header( 200 );

    if ( get_option( 'rbfa_zone_page_use_theme', '1' ) === '1' ) {
        /*
         * Themed output — render inside the active theme's shell.
         *
         * WP's query resolved to a 404 (no post found for this URL). We fix
         * the query flags so themes don't render their 404 template or hide
         * the content wrapper. This must happen before get_header() fires.
         */
        global $wp_query;
        $wp_query->is_404  = false;
        $wp_query->is_page = true;

        add_filter( 'document_title_parts', function ( $parts ) use ( $title ) {
            $parts['title'] = $title;
            return $parts;
        } );
        add_filter( 'body_class', function ( $classes ) {
            $classes[] = 'rbfa-zone-page';
            return $classes;
        } );

        get_header();
        echo '<div class="rbfa-zone-page-content entry-content" style="max-width:960px;margin:0 auto;padding:20px 0;">';
        echo '<h1 class="entry-title">' . esc_html( $title ) . '</h1>';
        echo $body_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- sanitized via wp_kses_post
        echo '</div>';
        get_footer();

    } else {
        /*
         * Minimal standalone output — no theme wrapper. Useful when the active
         * theme's template conflicts with the zone page layout.
         */
        $site_name = esc_html( get_bloginfo( 'name' ) );
        echo '<!DOCTYPE html><html ' . get_language_attributes() . '>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- get_language_attributes() is a core WP function that outputs safe HTML
        echo '<head><meta charset="' . esc_attr( get_bloginfo( 'charset' ) ) . '">';
        echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
        echo '<title>' . esc_html( $title ) . ' &mdash; ' . esc_html( $site_name ) . '</title>';
        wp_head();
        echo '</head><body class="rbfa-zone-page">';
        echo '<div style="max-width:960px;margin:0 auto;padding:30px 20px;font-family:sans-serif;">';
        echo '<h1>' . esc_html( $title ) . '</h1>';
        echo $body_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- sanitized via wp_kses_post
        echo '</div>';
        wp_footer();
        echo '</body></html>';
    }

    exit;
}

/**
 * Returns the canonical front-end URL for a zone's virtual page.
 *
 * @param  string $zone_slug Zone folder slug.
 * @return string Absolute URL.
 */
function rbfa_zone_page_url( $zone_slug ) {
    return home_url( '/protected-zone/' . rawurlencode( $zone_slug ) . '/' );
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
	$index_path = wp_parse_url( home_url( '/index.php' ), PHP_URL_PATH );

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

	// Pre-create any zone directories that don't exist yet, so the recursive
	// sync below picks them up and writes the correct .htaccess into them.
	foreach ( rbfa_get_zones() as $zone ) {
		$zone_path = $base_path . '/' . $zone['folder_slug'];
		if ( ! is_dir( $zone_path ) ) {
			wp_mkdir_p( $zone_path );
		}
	}

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
    $wpdb->query( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom plugin table, no appropriate caching layer
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
    $wpdb->query( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom plugin table, no appropriate caching layer
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
    $software = strtolower( $_SERVER['SERVER_SOFTWARE'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- $_SERVER values are not subject to WP magic quotes
    return strpos( $software, 'nginx' ) !== false;
}

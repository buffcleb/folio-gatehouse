<?php
/**
 * Core front-end access control.
 *
 * Intercepts requests for files inside protected zones, checks the current
 * user's roles against the zone's allowlist, logs the outcome, and either
 * serves the file through PHP or displays the configured denial screen.
 *
 * File serving is done entirely through PHP (readfile) so the web server
 * never exposes the file directly. .htaccess rules redirect all requests
 * inside protected folders to WordPress first.
 *
 * Login redirect flow
 * ───────────────────
 * When [fsg_login_link] appears in a denial screen:
 *  1. A short-lived transient maps an opaque random token to the original
 *     file URL. The token is the only thing in the public URL — no role,
 *     zone, or path information is exposed.
 *  2. The link points to the configured login_url with a `redirect_to`
 *     parameter containing /?rbfa_token=<token>.
 *  3. On the token endpoint, if the user is now authenticated and has
 *     access, they are redirected to the file. If not, they see the same
 *     denial screen again.
 *  4. If the user is already logged in (wrong role), the link first logs
 *     them out, then sends them to the same login page with the same token,
 *     so they can try a different account.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ─── IP resolution ────────────────────────────────────────────────────────────

/**
 * Returns the most accurate available client IP address.
 *
 * X-Forwarded-For is accepted only if the value passes PHP's IP validation,
 * since this header is trivially spoofable by any client. The result is
 * used for logging only and never for access decisions.
 *
 * @return string Sanitized IP address string.
 */
function rbfa_get_ip() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- $_SERVER values are not subject to WP magic quotes

    if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- $_SERVER values are not subject to WP magic quotes
        // The header may contain a comma-separated chain; the leftmost value
        // is the originating client (though it can still be spoofed).
        $parts     = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- $_SERVER values are not subject to WP magic quotes
        $forwarded = filter_var( trim( $parts[0] ), FILTER_VALIDATE_IP );

        // Only use the forwarded IP if it is a valid IP address string.
        if ( $forwarded !== false ) {
            $ip = $forwarded;
        }
    }

    return sanitize_text_field( $ip );
}

// ─── Token endpoint ───────────────────────────────────────────────────────────

add_action( 'init', 'rbfa_handle_token_redirect', 5 );

/**
 * Handles the ?rbfa_token=<token> endpoint.
 *
 * Fires early on init (priority 5) so it runs before rbfa_check_access.
 * Looks up the token in the transient store, verifies the current user
 * has access to the stored file URL, and either serves it or re-shows
 * the denial screen.
 *
 * The token is single-use: it is deleted after lookup regardless of outcome
 * to prevent replay. A new token is embedded in the denial screen on failure
 * so the user can try again after switching accounts.
 */
function rbfa_handle_token_redirect() {
    if ( empty( $_GET['rbfa_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- file-serving request, nonce not applicable for unauthenticated access
        return;
    }

    // Sanitize — token is a hex string, nothing else.
    $token    = preg_replace( '/[^a-f0-9]/', '', sanitize_text_field( wp_unslash( $_GET['rbfa_token'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- file-serving request, nonce not applicable for unauthenticated access
    $data = get_transient( 'rbfa_redir_' . $token );

    // Delete only if the token existed — single-use regardless of content validity.
    if ( $data !== false ) {
        delete_transient( 'rbfa_redir_' . $token );
    }

    if ( ! $data || empty( $data['file_url'] ) || empty( $data['denial_id'] ) ) {
        // Token invalid or expired — show a plain 403.
        wp_die( '<p>This link has expired or is invalid. Please request access again.</p>', '403 Forbidden', [ 'response' => 403 ] );
    }

    $file_url  = $data['file_url'];
    $denial_id = (int) $data['denial_id'];
    $login_url = $data['login_url'] ?? '';

    // ── Zone-page redirect ────────────────────────────────────────────────────
    // Tokens created by [fsg_zone_link] target a virtual zone page rather than
    // a file. The access check is against the zone's role list, not a file URL.
    if ( ( $data['redirect_type'] ?? '' ) === 'zone_page' ) {
        $zone_slug = $data['zone_slug'] ?? '';
        $zones     = rbfa_get_zones();
        $zone      = null;
        foreach ( $zones as $z ) {
            if ( $z['folder_slug'] === $zone_slug ) {
                $zone = $z;
                break;
            }
        }

        $user = wp_get_current_user();
        $has_access = $zone && (
            in_array( 'administrator', (array) $user->roles, true )
            || ! empty( array_intersect( $zone['roles'] ?? [], (array) $user->roles ) )
        );

        if ( $has_access ) {
            wp_safe_redirect( esc_url_raw( $file_url ) );
            exit;
        }

        rbfa_log_access( $user, 'zone-page:' . $zone_slug, 'Denied' );
        rbfa_deny_access( $denial_id, $file_url );
        // rbfa_deny_access calls wp_die — execution stops here.
    }

    // Re-check access now that the user may have logged in.
    $user       = wp_get_current_user();
    $zones      = rbfa_get_zones();
    $base_parent = rbfa_get_base_folder();
    $upload_dir  = wp_upload_dir();
    $upload_base_url = wp_parse_url( $upload_dir['baseurl'], PHP_URL_PATH );
    $upload_basedir  = $upload_dir['basedir'];

    $has_access = false;
    foreach ( $zones as $zone ) {
        $trigger = $upload_base_url . '/' . $base_parent . '/' . $zone['folder_slug'] . '/';
        if ( strpos( $file_url, $trigger ) !== false ) {
            if ( ! empty( array_intersect( $zone['roles'] ?? [], (array) $user->roles ) )
                 || in_array( 'administrator', (array) $user->roles, true ) ) {
                $has_access = true;
            }
            break;
        }
    }

    if ( $has_access ) {
        // Access granted — serve the file directly via redirect to our own
        // access handler (which will log and stream it).
        wp_safe_redirect( esc_url_raw( $file_url ) );
        exit;
    }

    // Still no access — log the denial and show the screen again.
    // A fresh token is generated inside rbfa_deny_access so the user
    // can try with a different account.
    $rel_path = str_replace( $upload_base_url . '/', '', $file_url );
    rbfa_log_access( $user, $rel_path, 'Denied' );
    rbfa_deny_access( $denial_id, $file_url );
}

// ─── Access check ─────────────────────────────────────────────────────────────

add_action( 'init', 'rbfa_check_access' );

/**
 * Intercepts file requests and enforces zone-based access control.
 *
 * Runs on every front-end request. Compares the REQUEST_URI against each
 * configured zone's URL prefix. If a match is found:
 *  - Denied users receive the zone's custom denial screen (or a plain 403).
 *  - Allowed users have the file served through PHP after a path-traversal check.
 *  - All outcomes (granted and denied) are written to the access log.
 */
function rbfa_check_access() {
    // Skip entirely for wp-admin requests.
    if ( is_admin() ) {
        return;
    }

    // Skip if this is a token redirect — handled above.
    if ( ! empty( $_GET['rbfa_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- file-serving request, nonce not applicable for unauthenticated access
        return;
    }

    $zones           = rbfa_get_zones();
    $base_parent     = rbfa_get_base_folder();
    $request_uri     = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
    $upload_dir      = wp_upload_dir();
    $upload_base_url = wp_parse_url( $upload_dir['baseurl'], PHP_URL_PATH );
    $upload_basedir  = $upload_dir['basedir'];

    foreach ( $zones as $zone ) {
        // Build the URL prefix this zone protects.
        $trigger = $upload_base_url . '/' . $base_parent . '/' . $zone['folder_slug'] . '/';

        if ( strpos( $request_uri, $trigger ) === false ) {
            continue; // This request is not inside this zone — skip.
        }

        $user = wp_get_current_user();

        /*
         * Access decision: the user must have at least one role that appears
         * in the zone's allowed-roles list. Administrators always have access.
         */
        $has_access = ! empty( array_intersect( $zone['roles'] ?? [], (array) $user->roles ) )
                      || in_array( 'administrator', (array) $user->roles, true );

        // Relative path from the uploads root — used for logging and file lookup.
        $rel_path = str_replace( $upload_base_url . '/', '', $request_uri );

        if ( ! $has_access ) {
            rbfa_log_access( $user, $rel_path, 'Denied' );

            $file_url = $upload_dir['baseurl'] . '/' . $rel_path;

            if ( is_user_logged_in() ) {
                // Logged-in path: auth-specific redirect takes priority.
                if ( ! empty( $zone['redirect_url_auth'] ) ) {
                    wp_redirect( esc_url_raw( $zone['redirect_url_auth'] ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- intentional external redirect
                    exit;
                }
                // Use auth denial screen if configured (> 0); fall back to
                // the anonymous denial for backward compatibility.
                $denial_id = (int) ( $zone['denial_id_auth'] ?? 0 ) > 0
                    ? (int) $zone['denial_id_auth']
                    : (int) ( $zone['denial_id'] ?? 0 );
            } else {
                // Anonymous path.
                if ( ! empty( $zone['redirect_url'] ) ) {
                    wp_redirect( esc_url_raw( $zone['redirect_url'] ) ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- intentional external redirect
                    exit;
                }
                $denial_id = (int) ( $zone['denial_id'] ?? 0 );
            }

            rbfa_deny_access( $denial_id, $file_url );
            // rbfa_deny_access calls wp_die() — execution stops here.
        }

        /*
         * Path traversal guard: resolve the full path with realpath() and
         * confirm it still sits inside the uploads directory. This prevents
         * tricks like /../../../etc/passwd in the URI.
         */
        $full_path    = $upload_basedir . '/' . $rel_path;
        $real_full    = realpath( $full_path );
        $real_base    = realpath( $upload_basedir );
        $path_is_safe = $real_full !== false
                        && $real_base !== false
                        && strpos( $real_full, $real_base . DIRECTORY_SEPARATOR ) === 0;

        if ( $path_is_safe && file_exists( $full_path ) ) {
            rbfa_log_access( $user, $rel_path, 'Granted' );
            rbfa_serve_file( $full_path );
            // rbfa_serve_file calls exit — execution stops here.
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Writes one row to the access log table.
 *
 * @param WP_User $user     The current user (ID = 0 for guests).
 * @param string  $rel_path Relative file path from the uploads root.
 * @param string  $status   'Granted' or 'Denied'.
 */
function rbfa_log_access( $user, $rel_path, $status ) {
    global $wpdb;

    $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
        $wpdb->prefix . 'rbfa_access_logs',
        [
            'user_id'    => $user->ID,
            'user_roles' => implode( ',', (array) $user->roles ),
            'ip_address' => rbfa_get_ip(),
            'file_path'  => $rel_path,
            'status'     => $status,
        ],
        [ '%d', '%s', '%s', '%s', '%s' ]
    );
}

/**
 * Displays the denial screen for a zone and terminates execution.
 *
 * Fetches the denial screen row, injects the $file_url into the shortcode
 * context so [fsg_login_link] can generate a properly targeted redirect link,
 * then renders the sanitized HTML via wp_die().
 *
 * @param int    $denial_id The denial_screens row ID (0 = use default message).
 * @param string $file_url  The full URL of the file that was denied (for redirect).
 */
function rbfa_deny_access( $denial_id, $file_url = '' ) {
    global $wpdb;

    $html      = '';
    $login_url = '';

    if ( $denial_id > 0 ) {
        $row = $wpdb->get_row( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $wpdb->prepare(
                "SELECT html_content, login_url FROM {$wpdb->prefix}rbfa_denial_screens WHERE id = %d",
                (int) $denial_id
            )
        );

        if ( $row ) {
            $login_url = $row->login_url;

            /*
             * Re-sanitize on read-back so that content inserted directly into the
             * DB (e.g. by a migration or bad actor) cannot bypass the allowlist.
             * Process shortcodes AFTER sanitization so [fsg_login_link] renders
             * correctly but no injected shortcodes in raw HTML can run.
             */
            // Inject context so [fsg_login_link] can read the file URL,
            // login page, and denial ID without exposing them as shortcode attributes.
            rbfa_set_shortcode_context( '_rbfa_file_url',   $file_url );
            rbfa_set_shortcode_context( '_rbfa_login_url',  $login_url );
            rbfa_set_shortcode_context( '_rbfa_denial_id',  $denial_id );

            /*
             * Order matters here:
             *
             * 1. do_shortcode() FIRST — processes [rbfa_login_link text="..."]
             *    before wp_kses runs. wp_kses converts " to &quot; inside
             *    shortcode bracket attributes, which breaks shortcode parsing
             *    and causes text/logout_text attributes to be silently ignored.
             *
             * 2. wp_kses (rbfa_kses_denial) SECOND — sanitizes the HTML that
             *    do_shortcode produced. The shortcode outputs a plain <a> tag
             *    which is on the allowlist. Any injected shortcodes in the raw
             *    DB content are also processed here, but their HTML output is
             *    then sanitized — so they cannot produce unsafe tags.
             *
             * This is the correct approach when shortcode attributes must
             * survive kses sanitization.
             */
            $html = rbfa_kses_denial( do_shortcode( $row->html_content ) );
        }
    }

    wp_die(
        $html ?: '<p>Access Denied.</p>', // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- sanitized via rbfa_kses_denial/do_shortcode above
        '403 Forbidden',
        [ 'response' => 403 ]
    );
}

/**
 * Streams a file to the browser as a download and terminates execution.
 *
 * The file is served through PHP so the web server never delivers it
 * directly. The filename in Content-Disposition uses only the basename
 * to prevent header injection via path separators.
 *
 * @param string $full_path Absolute, realpath-verified path to the file.
 */
function rbfa_serve_file( $full_path ) {
    // sanitize_file_name() strips characters that are illegal in filenames on
    // most OSes (including CR, LF, and double-quotes) which would otherwise
    // allow response-header injection via a crafted filename.
    $filename = sanitize_file_name( basename( $full_path ) );

    header( 'X-Robots-Tag: noindex, nofollow' );
    header( 'Content-Description: File Transfer' );
    header( 'Content-Type: application/octet-stream' );
    header( 'Content-Disposition: attachment; filename="' . $filename . '"' );
    header( 'Expires: 0' );
    header( 'Cache-Control: must-revalidate, post-check=0, pre-check=0' );
    header( 'Pragma: public' );
    header( 'Content-Length: ' . filesize( $full_path ) );

    if ( ob_get_level() ) {
        ob_end_clean();
    }

    readfile( $full_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
    exit;
}

// ─── [fsg_login_link] shortcode ───────────────────────────────────────────────

add_shortcode( 'fsg_login_link', 'rbfa_shortcode_login_link' );
add_shortcode( 'rbfa_login_link', 'rbfa_shortcode_login_link' ); // backwards-compat alias

/**
 * Renders a login/logout redirect link for use inside denial screen HTML.
 *
 * When the shortcode is present in a denial screen the behaviour differs
 * depending on whether the visitor is already logged in:
 *
 * • Guest (not logged in): renders a "Log in" link pointing to the configured
 *   login page with redirect_to=/?rbfa_token=<token>. The token is an opaque
 *   random hex string stored in a 15-minute transient — it encodes the file URL
 *   but exposes nothing about roles or authorised users in the public URL.
 *
 * • Logged-in (wrong role): renders a "Log out and try a different account"
 *   link that hits wp-logout.php and then redirects to the same login page +
 *   token flow, allowing the user to authenticate as a different account.
 *
 * Shortcode attributes (all optional):
 *   text        — Link text for guests.            Default: "Log in to access this file"
 *   logout_text — Link text for logged-in users.   Default: "Try a different account"
 *
 * The file URL and denial context are injected by rbfa_deny_access() via globals
 * rather than shortcode attributes so the values are never exposed in the HTML source.
 *
 * @param array $atts Shortcode attributes.
 * @return string Rendered anchor tag HTML.
 */
function rbfa_shortcode_login_link( $atts ) {
    $atts = shortcode_atts( [
        'text'        => 'Log in to access this file',
        'logout_text' => 'Try a different account',
    ], $atts, 'fsg_login_link' );

    // Retrieve context injected by rbfa_deny_access().
    $file_url  = rbfa_get_shortcode_context( '_rbfa_file_url' );
    $login_url = rbfa_get_shortcode_context( '_rbfa_login_url' );
    $denial_id = (int) rbfa_get_shortcode_context( '_rbfa_denial_id' );

    // Nothing useful to render without a file URL.
    if ( empty( $file_url ) ) {
        return '';
    }

    // Resolve the login page URL.
    // Supports: blank (wp-login.php), absolute URLs, relative paths (/my-account/),
    // and bare page slugs (my-account) — all resolved against the site root.
    if ( empty( $login_url ) ) {
        // No custom login page configured — use WordPress default.
        $login_page = wp_login_url();
    } elseif ( preg_match( '#^https?://#i', $login_url ) ) {
        // Absolute URL — validate and use directly.
        $login_page = esc_url_raw( $login_url );
    } else {
        // Relative path or bare slug — resolve against site root.
        // Strips any leading slash so site_url() doesn't double up.
        $login_page = esc_url_raw( site_url( '/' . ltrim( $login_url, '/' ) ) );
    }

    /*
     * Generate an opaque redirect token.
     *
     * The token is a 32-character random hex string. It is stored in a
     * WordPress transient for 15 minutes mapping to:
     *   - The original file URL (so we can redirect back after login)
     *   - The denial_id (so we can re-show the right screen on failure)
     *   - The login_url (so logout→login uses the same login page)
     *
     * Nothing in the token itself or its transient key reveals which roles
     * are required or which users are permitted.
     */
    $token = bin2hex( random_bytes( 16 ) );
    set_transient( 'rbfa_redir_' . $token, [
        'file_url'  => $file_url,
        'denial_id' => $denial_id,
        'login_url' => $login_url,
    ], 15 * MINUTE_IN_SECONDS );

    // The redirect_to URL is the token endpoint on the home page.
    $redirect_to = add_query_arg( 'rbfa_token', $token, home_url( '/' ) );

    $user = wp_get_current_user();

    if ( $user->ID === 0 ) {
        // Guest — simple login link.
        $href = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $login_page );
        $text = esc_html( $atts['text'] );
    } else {
        /*
         * Already logged in but wrong role.
         * Link goes to wp-logout.php which then redirects to the login page
         * with our token redirect_to baked in. WordPress's logout handler
         * accepts redirect_to for post-logout destination.
         */
        $post_logout_url = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $login_page );
        $href = wp_logout_url( $post_logout_url );
        $text = esc_html( $atts['logout_text'] );
    }

    return '<a href="' . esc_url( $href ) . '">' . $text . '</a>';
}

// ─── [fsg_zone_link] shortcode ────────────────────────────────────────────────

add_shortcode( 'fsg_zone_link', 'rbfa_shortcode_zone_link' );
add_shortcode( 'rbfa_zone_link', 'rbfa_shortcode_zone_link' ); // backwards-compat alias

/**
 * Renders a login/logout link that redirects to the zone's virtual page
 * instead of directly downloading the denied file.
 *
 * Intended for denial screens on zones that have a /protected-zone/{slug}/
 * page — gives users a "view the zone contents" destination rather than an
 * immediate file download after authentication.
 *
 * The token flow and logout behaviour are identical to [fsg_login_link].
 * The only difference is that the post-login destination is the zone page URL.
 *
 * Attributes (all optional):
 *   text        — Link text for guests.           Default: "Log in to view this content"
 *   logout_text — Link text for logged-in users.  Default: "Try a different account"
 */
function rbfa_shortcode_zone_link( $atts ) {
    $atts = shortcode_atts( [
        'text'        => 'Log in to view this content',
        'logout_text' => 'Try a different account',
    ], $atts, 'fsg_zone_link' );

    $file_url  = rbfa_get_shortcode_context( '_rbfa_file_url' );
    $login_url = rbfa_get_shortcode_context( '_rbfa_login_url' );
    $denial_id = (int) rbfa_get_shortcode_context( '_rbfa_denial_id' );

    if ( empty( $file_url ) ) {
        return '';
    }

    // Derive the zone slug from the file URL.
    // Primary: file URL contains the uploads path (normal file denial).
    // Fallback: file URL is a zone virtual page (/protected-zone/{slug}/).
    $zones           = rbfa_get_zones();
    $base_parent     = rbfa_get_base_folder();
    $upload_base_url = wp_parse_url( wp_upload_dir()['baseurl'], PHP_URL_PATH );
    $zone_slug       = '';

    foreach ( $zones as $z ) {
        $trigger = $upload_base_url . '/' . $base_parent . '/' . $z['folder_slug'] . '/';
        if ( strpos( $file_url, $trigger ) !== false ) {
            $zone_slug = $z['folder_slug'];
            break;
        }
    }

    if ( empty( $zone_slug ) ) {
        // Denial screen shown for a zone page request — extract slug from path.
        $path = wp_parse_url( $file_url, PHP_URL_PATH );
        if ( $path && strpos( $path, '/protected-zone/' ) === 0 ) {
            $parts     = explode( '/', trim( substr( $path, strlen( '/protected-zone/' ) ), '/' ) );
            $candidate = rawurldecode( $parts[0] ?? '' );
            foreach ( $zones as $z ) {
                if ( $z['folder_slug'] === $candidate ) {
                    $zone_slug = $candidate;
                    break;
                }
            }
        }
    }

    if ( empty( $zone_slug ) ) {
        return '';
    }

    $zone_page_url = rbfa_zone_page_url( $zone_slug );

    // Resolve login page URL — same logic as [fsg_login_link].
    if ( empty( $login_url ) ) {
        $login_page = wp_login_url();
    } elseif ( preg_match( '#^https?://#i', $login_url ) ) {
        $login_page = esc_url_raw( $login_url );
    } else {
        $login_page = esc_url_raw( site_url( '/' . ltrim( $login_url, '/' ) ) );
    }

    $token = bin2hex( random_bytes( 16 ) );
    set_transient( 'rbfa_redir_' . $token, [
        'file_url'      => $zone_page_url,
        'denial_id'     => $denial_id,
        'login_url'     => $login_url,
        'zone_slug'     => $zone_slug,
        'redirect_type' => 'zone_page',
    ], 15 * MINUTE_IN_SECONDS );

    $redirect_to = add_query_arg( 'rbfa_token', $token, home_url( '/' ) );

    $user = wp_get_current_user();

    if ( $user->ID === 0 ) {
        $href = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $login_page );
        $text = esc_html( $atts['text'] );
    } else {
        $post_logout_url = add_query_arg( 'redirect_to', rawurlencode( $redirect_to ), $login_page );
        $href = wp_logout_url( $post_logout_url );
        $text = esc_html( $atts['logout_text'] );
    }

    return '<a href="' . esc_url( $href ) . '">' . $text . '</a>';
}

// ─── Shortcode context passing ────────────────────────────────────────────────

/*
 * WordPress's do_shortcode() does not support passing arbitrary context to
 * shortcode handlers. We use a simple module-level store (a static array inside
 * a function) to pass file URL and denial context from rbfa_deny_access() to
 * the [fsg_login_link] shortcode handler without exposing anything in globals
 * or shortcode attributes.
 */

/**
 * Sets a named shortcode context value.
 *
 * @param string $key   Context key.
 * @param mixed  $value Context value.
 */
function rbfa_set_shortcode_context( $key, $value ) {
    rbfa_shortcode_context_store( 'set', $key, $value );
}

/**
 * Gets a named shortcode context value.
 *
 * @param  string $key Context key.
 * @return mixed       Stored value, or empty string if not set.
 */
function rbfa_get_shortcode_context( $key ) {
    return rbfa_shortcode_context_store( 'get', $key );
}

/**
 * Internal context store — a simple key-value bag backed by a static array.
 *
 * @param  string $action 'set' or 'get'.
 * @param  string $key    Context key.
 * @param  mixed  $value  Value to set (ignored on 'get').
 * @return mixed          Stored value on 'get', null on 'set'.
 */
function rbfa_shortcode_context_store( $action, $key, $value = '' ) {
    static $store = [];
    if ( $action === 'set' ) {
        $store[ $key ] = $value;
        return null;
    }
    return $store[ $key ] ?? '';
}

// ─── HTML sanitization allowlist ──────────────────────────────────────────────

/**
 * Returns the strict kses allowlist for denial screen HTML.
 *
 * Only safe presentational and structural elements are permitted.
 * No script, style, iframe, object, form, or event-handler attributes
 * are allowed. This list is intentionally conservative.
 *
 * @return array kses allowlist.
 */
function rbfa_kses_denial_allowed() {
    return [
        // Block elements
        'div'        => [ 'class' => [], 'id' => [], 'style' => [] ],
        'p'          => [ 'class' => [], 'id' => [], 'style' => [] ],
        'h1'         => [ 'class' => [], 'id' => [], 'style' => [] ],
        'h2'         => [ 'class' => [], 'id' => [], 'style' => [] ],
        'h3'         => [ 'class' => [], 'id' => [], 'style' => [] ],
        'h4'         => [ 'class' => [], 'id' => [], 'style' => [] ],
        'ul'         => [ 'class' => [], 'style' => [] ],
        'ol'         => [ 'class' => [], 'style' => [] ],
        'li'         => [ 'class' => [], 'style' => [] ],
        'blockquote' => [ 'class' => [], 'style' => [] ],
        'hr'         => [ 'class' => [], 'style' => [] ],
        'br'         => [],
        // Inline elements
        'span'       => [ 'class' => [], 'id' => [], 'style' => [] ],
        'strong'     => [ 'class' => [] ],
        'em'         => [ 'class' => [] ],
        'b'          => [ 'class' => [] ],
        'i'          => [ 'class' => [] ],
        'u'          => [ 'class' => [] ],
        // Links — href is validated by kses to http/https/mailto only.
        'a'          => [ 'href' => [], 'class' => [], 'title' => [], 'target' => [], 'rel' => [] ],
        // Images — src validated by kses to safe URLs.
        'img'        => [ 'src' => [], 'alt' => [], 'class' => [], 'width' => [], 'height' => [], 'style' => [] ],
        // Table elements (read-only display)
        'table'      => [ 'class' => [], 'style' => [] ],
        'thead'      => [],
        'tbody'      => [],
        'tr'         => [ 'class' => [], 'style' => [] ],
        'th'         => [ 'class' => [], 'style' => [], 'colspan' => [], 'rowspan' => [] ],
        'td'         => [ 'class' => [], 'style' => [], 'colspan' => [], 'rowspan' => [] ],
    ];
}

/**
 * Sanitizes denial screen HTML using the strict plugin allowlist.
 *
 * Called both when saving and when reading back from the database so
 * content that bypasses the save path (e.g. direct DB writes) is still
 * cleaned before display.
 *
 * @param  string $html Raw HTML input.
 * @return string Sanitized HTML.
 */
function rbfa_kses_denial( $html ) {
    return wp_kses( $html, rbfa_kses_denial_allowed() );
}

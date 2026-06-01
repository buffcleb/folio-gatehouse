<?php
/**
 * Database setup and lifecycle hooks.
 *
 * Handles plugin activation (table creation, cron scheduling) and
 * deactivation (cron teardown). Tables are created idempotently via
 * dbDelta so upgrades are safe.
 *
 * The denial_screens table includes a login_url column used by the
 * [fsg_login_link] shortcode to send denied users to a login page
 * that redirects back to the originally-requested file on success.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ─── Activation ───────────────────────────────────────────────────────────────

register_activation_hook( RBFA_DIR . 'role-folder-protection.php', 'rbfa_activate' );

/**
 * Runs on plugin activation.
 *
 * Creates all required database tables and schedules the hourly
 * .htaccess integrity cron if not already scheduled.
 */
function rbfa_activate() {
    global $wpdb;

    $charset = $wpdb->get_charset_collate();

    // Access log — records every file request with user, IP, path, and outcome.
    $log_table = $wpdb->prefix . 'rbfa_access_logs';

    /*
     * Denial screens — stores admin-authored HTML shown to blocked users.
     * login_url: the login page to direct users to when [fsg_login_link] is
     * used in the screen HTML. Defaults to wp-login.php if blank.
     */
    $msg_table = $wpdb->prefix . 'rbfa_denial_screens';

    /*
     * Zones table — one row per protected folder.
     * Special case: the row where folder_slug = 'rbfa_default' and is_default = 1
     * stores the base folder slug in allowed_roles (dual-use column). All other
     * rows store a JSON-encoded array of role slugs in allowed_roles.
     */
    $zone_table = $wpdb->prefix . 'rbfa_zones';

    // Managed roles — tracks which WP roles were created by this plugin.
    $managed_table = $wpdb->prefix . 'rbfa_managed_roles';

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';

    $sql_log = "CREATE TABLE $log_table (
        id         bigint(20)   NOT NULL AUTO_INCREMENT,
        time       datetime     DEFAULT CURRENT_TIMESTAMP,
        user_id    bigint(20),
        user_roles text,
        ip_address varchar(45)  DEFAULT '',
        file_path  text,
        status     varchar(50),
        PRIMARY KEY (id)
    ) $charset;";

    $sql_msg = "CREATE TABLE $msg_table (
        id           bigint(20)   NOT NULL AUTO_INCREMENT,
        label        varchar(100),
        html_content longtext,
        login_url    varchar(500) DEFAULT '',
        PRIMARY KEY (id)
    ) $charset;";

    $sql_zone = "CREATE TABLE $zone_table (
        id                  bigint(20)    NOT NULL AUTO_INCREMENT,
        folder_slug         varchar(100)  NOT NULL,
        allowed_roles       text,
        denial_id           bigint(20)    DEFAULT 0,
        denial_id_auth      bigint(20)    DEFAULT 0,
        redirect_url        varchar(500)  DEFAULT '',
        redirect_url_auth   varchar(500)  DEFAULT '',
        is_default          tinyint(1)    DEFAULT 0,
        page_title          varchar(200)  DEFAULT '',
        page_content        longtext,
        PRIMARY KEY (id)
    ) $charset;";

    $sql_managed = "CREATE TABLE $managed_table (
        id      bigint(20)   NOT NULL AUTO_INCREMENT,
        role_id varchar(100) NOT NULL,
        PRIMARY KEY (id)
    ) $charset;";

    dbDelta( [ $sql_log, $sql_msg, $sql_zone, $sql_managed ] );

    /*
     * Seed the rbfa_default row if it does not already exist.
     * This row stores the base folder slug in its allowed_roles column.
     * Without it, the zone save handler has nothing to UPDATE against and
     * silently does nothing — zones cannot be saved on a fresh install.
     */
    $existing = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name from $wpdb->prefix, not user input
        $wpdb->prepare(
            "SELECT id FROM $zone_table WHERE folder_slug = %s AND is_default = %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name from $wpdb->prefix
            'rbfa_default', 1
        )
    );
    if ( ! $existing ) {
        $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom plugin table, no caching layer
            $zone_table,
            [
                'folder_slug'   => 'rbfa_default',
                'allowed_roles' => 'list_files', // default base folder slug
                'denial_id'     => 0,
                'is_default'    => 1,
            ],
            [ '%s', '%s', '%d', '%d' ]
        );
    }

    // Schedule hourly integrity cron only if not already registered.
    if ( ! wp_next_scheduled( 'rbfa_hourly_integrity_check' ) ) {
        wp_schedule_event( time(), 'hourly', 'rbfa_hourly_integrity_check' );
    }

    // Schedule daily log prune cron only if not already registered.
    if ( ! wp_next_scheduled( 'rbfa_daily_log_prune' ) ) {
        wp_schedule_event( time(), 'daily', 'rbfa_daily_log_prune' );
    }

    rbfa_ensure_wfsp_role();

    // Register the zone rewrite rule before flushing — the activation hook fires
    // before init, so rbfa_register_zone_rewrite() hasn't run yet at this point.
    rbfa_register_zone_rewrite();
    flush_rewrite_rules( false );
}

/**
 * Creates the FSG Admins role and grants the manage_wfsp capability
 * to both that role and the built-in administrator role.
 *
 * Safe to call on every page load — both add_role() and add_cap() are
 * no-ops when the role/cap already exists.
 */
function rbfa_ensure_wfsp_role() {
    if ( ! get_role( 'fsg_admins' ) ) {
        add_role( 'fsg_admins', 'FSG Admins', [ 'manage_wfsp' => true ] );
    }

    $admin_role = get_role( 'administrator' );
    if ( $admin_role && ! $admin_role->has_cap( 'manage_wfsp' ) ) {
        $admin_role->add_cap( 'manage_wfsp' );
    }
}

add_action( 'init', 'rbfa_ensure_wfsp_role' );

// ─── DB migrations ────────────────────────────────────────────────────────────

add_action( 'init', 'rbfa_run_db_migrations' );

/**
 * Applies incremental schema and data changes to existing installs.
 *
 * Each migration is gated by a version_compare check so only the steps not
 * yet applied are executed. dbDelta is safe to re-run — it adds missing
 * columns without touching existing data.
 */
function rbfa_run_db_migrations() {
    $db_version = get_option( 'rbfa_db_version', '0' );

    if ( version_compare( $db_version, '1.6', '>=' ) ) {
        return;
    }

    // v1.4 — zone table schema additions (page_title, page_content, etc.)
    if ( version_compare( $db_version, '1.4', '<' ) ) {
        global $wpdb;
        $charset    = $wpdb->get_charset_collate();
        $zone_table = $wpdb->prefix . 'rbfa_zones';

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $sql = "CREATE TABLE $zone_table (
            id                  bigint(20)    NOT NULL AUTO_INCREMENT,
            folder_slug         varchar(100)  NOT NULL,
            allowed_roles       text,
            denial_id           bigint(20)    DEFAULT 0,
            denial_id_auth      bigint(20)    DEFAULT 0,
            redirect_url        varchar(500)  DEFAULT '',
            redirect_url_auth   varchar(500)  DEFAULT '',
            is_default          tinyint(1)    DEFAULT 0,
            page_title          varchar(200)  DEFAULT '',
            page_content        longtext,
            PRIMARY KEY (id)
        ) $charset;";

        dbDelta( $sql );
        update_option( 'rbfa_db_version', '1.4' );
        $db_version = '1.4';
    }

    // v1.5 — rename all wfsp_-prefixed roles to fsg_-prefixed roles.
    if ( version_compare( $db_version, '1.5', '<' ) ) {
        rbfa_migrate_wfsp_to_fsg();
        update_option( 'rbfa_db_version', '1.5' );
        $db_version = '1.5';
    }

    // v1.6 — update shortcode names in existing zone pages and denial screens.
    if ( version_compare( $db_version, '1.6', '<' ) ) {
        rbfa_migrate_shortcode_names();
        update_option( 'rbfa_db_version', '1.6' );
    }
}

/**
 * v1.6 migration: replaces old shortcode names with new names in stored content.
 *
 * Zone pages (rbfa_zones.page_content):
 *   [folder_files  →  [fsg_files
 *
 * Denial screens (rbfa_denial_screens.html_content):
 *   [rbfa_login_link  →  [fsg_login_link
 *   [rbfa_zone_link   →  [fsg_zone_link
 *
 * Uses MySQL REPLACE() for an atomic in-place update — no PHP row iteration needed.
 * Safe to re-run: REPLACE() on an already-updated string is a no-op.
 */
function rbfa_migrate_shortcode_names() {
    global $wpdb;

    $zone_table = $wpdb->prefix . 'rbfa_zones';
    $msg_table  = $wpdb->prefix . 'rbfa_denial_screens';

    // Update [folder_files in zone page_content.
    $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- one-time migration; table name from $wpdb->prefix
        "UPDATE $zone_table SET page_content = REPLACE(page_content, '[folder_files', '[fsg_files') WHERE page_content LIKE '%[folder_files%'" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- shortcode strings are hardcoded constants
    );

    // Update [rbfa_login_link and [rbfa_zone_link in denial screen html_content.
    $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- one-time migration; table name from $wpdb->prefix
        "UPDATE $msg_table SET html_content = REPLACE(REPLACE(html_content, '[rbfa_login_link', '[fsg_login_link'), '[rbfa_zone_link', '[fsg_zone_link') WHERE html_content LIKE '%[rbfa_login_link%' OR html_content LIKE '%[rbfa_zone_link%'" // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- shortcode strings are hardcoded constants
    );
}

/**
 * v1.5 migration: renames all wfsp_* WordPress roles to fsg_*.
 *
 * For each wfsp_* role found in wp_user_roles:
 *  - Creates the fsg_* equivalent with identical capabilities.
 *  - Moves every user from the old role to the new one.
 *  - Removes the old role.
 *  - Updates rbfa_managed_roles records.
 *  - Updates allowed_roles JSON arrays in rbfa_zones.
 *
 * Safe to re-run: add_role() is a no-op if the target already exists.
 */
function rbfa_migrate_wfsp_to_fsg() {
    global $wpdb;

    $zone_table    = $wpdb->prefix . 'rbfa_zones';
    $managed_table = $wpdb->prefix . 'rbfa_managed_roles';
    $wp_roles      = wp_roles();

    // Collect all roles still carrying the wfsp_ prefix.
    $to_migrate = [];
    foreach ( $wp_roles->roles as $slug => $data ) {
        if ( strpos( $slug, 'wfsp_' ) === 0 ) {
            $to_migrate[ $slug ] = $data;
        }
    }

    foreach ( $to_migrate as $old_slug => $role_data ) {
        $new_slug = 'fsg_' . substr( $old_slug, strlen( 'wfsp_' ) );

        // Create the replacement role — no-op if it already exists.
        if ( ! get_role( $new_slug ) ) {
            add_role( $new_slug, $role_data['name'], $role_data['capabilities'] );
        }

        // Move every user from the old role to the new one.
        foreach ( get_users( [ 'role' => $old_slug ] ) as $user ) {
            $user->add_role( $new_slug );
            $user->remove_role( $old_slug );
        }

        // Delete the now-empty old role.
        remove_role( $old_slug );

        // Update rbfa_managed_roles table.
        $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-time migration, caching not applicable
            $managed_table,
            [ 'role_id' => $new_slug ],
            [ 'role_id' => $old_slug ],
            [ '%s' ],
            [ '%s' ]
        );
    }

    // Update allowed_roles JSON arrays in zone rows (non-default rows only).
    $zones = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- one-time migration; table name from $wpdb->prefix
        "SELECT id, allowed_roles FROM $zone_table WHERE is_default = 0", // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- table name from $wpdb->prefix
        ARRAY_A
    );

    foreach ( $zones as $zone ) {
        $roles = json_decode( $zone['allowed_roles'] ?? '[]', true );
        if ( ! is_array( $roles ) ) {
            continue;
        }

        $updated   = false;
        $new_roles = [];
        foreach ( $roles as $role ) {
            if ( strpos( $role, 'wfsp_' ) === 0 ) {
                $new_roles[] = 'fsg_' . substr( $role, strlen( 'wfsp_' ) );
                $updated     = true;
            } else {
                $new_roles[] = $role;
            }
        }

        if ( $updated ) {
            $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-time migration
                $zone_table,
                [ 'allowed_roles' => wp_json_encode( $new_roles ) ],
                [ 'id' => (int) $zone['id'] ],
                [ '%s' ],
                [ '%d' ]
            );
        }
    }
}

// ─── Deactivation ─────────────────────────────────────────────────────────────

register_deactivation_hook( RBFA_DIR . 'role-folder-protection.php', 'rbfa_deactivate' );

/**
 * Runs on plugin deactivation.
 *
 * Removes the scheduled cron event. Does NOT drop tables — data is
 * preserved so it survives deactivation/reactivation cycles.
 */
function rbfa_deactivate() {
    wp_clear_scheduled_hook( 'rbfa_hourly_integrity_check' );
    wp_clear_scheduled_hook( 'rbfa_daily_log_prune' );
    flush_rewrite_rules( false );
}

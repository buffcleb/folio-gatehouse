<?php
/**
 * Database setup and lifecycle hooks.
 *
 * Handles plugin activation (table creation, cron scheduling) and
 * deactivation (cron teardown). Tables are created idempotently via
 * dbDelta so upgrades are safe.
 *
 * The denial_screens table includes a login_url column used by the
 * [rbfa_login_link] shortcode to send denied users to a login page
 * that redirects back to the originally-requested file on success.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// ─── Activation ───────────────────────────────────────────────────────────────

register_activation_hook( RBFA_DIR . 'wp-role-folder-protection.php', 'rbfa_activate' );

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
     * login_url: the login page to direct users to when [rbfa_login_link] is
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
    $existing = $wpdb->get_var(
        $wpdb->prepare(
            "SELECT id FROM $zone_table WHERE folder_slug = %s AND is_default = %d",
            'rbfa_default', 1
        )
    );
    if ( ! $existing ) {
        $wpdb->insert(
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
 * Creates the WFSP_Admins role and grants the manage_wfsp capability
 * to both that role and the built-in administrator role.
 *
 * Safe to call on every page load — both add_role() and add_cap() are
 * no-ops when the role/cap already exists.
 */
function rbfa_ensure_wfsp_role() {
    if ( ! get_role( 'wfsp_admins' ) ) {
        add_role( 'wfsp_admins', 'WFSP Admins', [ 'manage_wfsp' => true ] );
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
 * Applies incremental schema changes to existing installs.
 *
 * dbDelta adds missing columns without touching existing data, so it is safe
 * to re-run. A version option gates the check to avoid running on every request.
 */
function rbfa_run_db_migrations() {
    if ( get_option( 'rbfa_db_version' ) === '1.4' ) {
        return;
    }

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
}

// ─── Deactivation ─────────────────────────────────────────────────────────────

register_deactivation_hook( RBFA_DIR . 'wp-role-folder-protection.php', 'rbfa_deactivate' );

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

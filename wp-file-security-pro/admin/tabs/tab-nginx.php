<?php
/**
 * NGINX Configuration tab.
 *
 * Shown only when NGINX is detected as the web server (rbfa_is_nginx()).
 * Provides ready-to-copy server block snippets for each configured zone,
 * replacing the .htaccess-based protection that only works on Apache.
 *
 * The generated config mirrors the logic of the .htaccess rules:
 *  - All requests inside a protected zone path are passed through PHP
 *    (via try_files to index.php) so WordPress can perform the access check.
 *  - Direct file serving by NGINX is disabled for protected paths.
 *
 * Important: This tab is informational only. The admin must copy the
 * generated config into their NGINX server block manually (or via their
 * host's control panel). The plugin cannot write to nginx.conf directly.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Renders the NGINX Config tab. Called from rbfa_pro_page().
 */
function rbfa_render_tab_nginx() {
    $zones       = rbfa_get_zones();
    $base        = rbfa_get_base_folder();
    $upload_dir  = wp_upload_dir();
    $upload_url  = wp_parse_url( $upload_dir['baseurl'], PHP_URL_PATH );
    $site_root   = rtrim( ABSPATH, '/' );

    // Build the protected path prefix for each zone.
    $zone_paths = [];
    foreach ( $zones as $zone ) {
        $zone_paths[] = $upload_url . '/' . $base . '/' . $zone['folder_slug'] . '/';
    }

    // Build a single NGINX location block covering all zones using a regex.
    $escaped_upload = preg_quote( $upload_url . '/' . $base . '/', '#' );

    $zone_slugs = array_map( function ( $z ) {
        return preg_quote( $z['folder_slug'], '#' );
    }, $zones );

    $zone_pattern = empty( $zone_slugs )
        ? '(YOUR_ZONE_SLUG)'
        : '(' . implode( '|', $zone_slugs ) . ')';

    $regex_pattern = '^' . $escaped_upload . $zone_pattern . '/';

    // Generate the full nginx config snippet.
    $nginx_config = "# ──────────────────────────────────────────────────────────────────────
# File Security Pro — NGINX configuration
# Add this inside your server {} block.
# Generated: " . gmdate( 'Y-m-d H:i:s' ) . " UTC
# ──────────────────────────────────────────────────────────────────────

# Protected zones: intercept all requests and route through WordPress.
# WordPress performs the role-based access check before serving the file.
location ~* " . $regex_pattern . " {
    # Do not serve files directly — always pass through PHP/WordPress.
    try_files \$uri /index.php\$is_args\$args;

    # Prevent NGINX from logging file paths (optional, for privacy).
    # access_log off;

    # Block search engine indexing at the server level.
    add_header X-Robots-Tag \"noindex, nofollow\" always;
}

# If WordPress is in a subdirectory, adjust the try_files target:
# try_files \$uri /SUBDIR/index.php\$is_args\$args;
";

    ?>
    <div class="rbfa-card" style="margin-top:20px;">
        <h3 style="margin-top:0;">NGINX Detected</h3>
        <p style="color:#d63638; font-weight:600; margin-top:0;">
            ⚠️ Your server is running NGINX. The <code>.htaccess</code> files this plugin
            writes are <strong>only processed by Apache</strong> — they have no effect on NGINX.
            Your protected zone files are currently <strong>not protected</strong> at the server level.
        </p>
        <p style="color:#555;">
            Copy the configuration block below into your NGINX <code>server {}</code> block,
            then reload NGINX (<code>sudo nginx -s reload</code>). This replicates the same
            rewrite logic the plugin uses on Apache — all requests to protected zone paths
            are passed through WordPress for access checking before any file is served.
        </p>
        <p style="color:#555;">
            After adding this config, you do <strong>not</strong> need to disable the
            plugin's .htaccess generation — those files are simply ignored by NGINX.
        </p>
    </div>

    <?php if ( empty( $zones ) ) : ?>
        <div class="notice notice-warning inline" style="margin-top:15px;">
            <p>No zones are configured yet. Add zones on the <a href="<?php echo esc_url( add_query_arg( ['page'=>'rbfa-pro','tab'=>'config'], admin_url('admin.php') ) ); ?>">Zones tab</a> and then return here for the generated config.</p>
        </div>
    <?php else : ?>

    <!-- Zone path reference -->
    <div class="rbfa-card" style="margin-top:20px;">
        <h3 style="margin-top:0;">Protected Zone Paths</h3>
        <table class="widefat striped">
            <thead>
                <tr><th>Zone</th><th>Protected URL Path</th><th>Filesystem Path</th></tr>
            </thead>
            <tbody>
            <?php foreach ( $zones as $zone ) :
                $url_path  = $upload_url . '/' . $base . '/' . $zone['folder_slug'] . '/';
                $disk_path = $upload_dir['basedir'] . '/' . $base . '/' . $zone['folder_slug'] . '/';
            ?>
                <tr>
                    <td><strong><?php echo esc_html( $zone['folder_slug'] ); ?></strong></td>
                    <td><code><?php echo esc_html( $url_path ); ?></code></td>
                    <td><code><?php echo esc_html( $disk_path ); ?></code></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Generated config block -->
    <div class="rbfa-card" style="margin-top:20px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <h3 style="margin-top:0; margin-bottom:0;">Generated NGINX Configuration</h3>
            <button type="button" class="button" id="rbfa-copy-nginx"
                    onclick="
                        var el = document.getElementById('rbfa-nginx-config');
                        navigator.clipboard.writeText(el.value).then(function(){
                            document.getElementById('rbfa-copy-nginx').textContent = '✅ Copied!';
                            setTimeout(function(){ document.getElementById('rbfa-copy-nginx').textContent = 'Copy to Clipboard'; }, 2000);
                        });
                    ">Copy to Clipboard</button>
        </div>
        <textarea id="rbfa-nginx-config" readonly
                  style="width:100%; font-family:monospace; font-size:12px; background:#f9f9f9;
                         border:1px solid #ccd0d4; border-radius:4px; padding:12px;
                         min-height:200px; resize:vertical; color:#333;"
                  rows="16"><?php echo esc_textarea( $nginx_config ); ?></textarea>
        <p style="color:#666; font-size:12px; margin-top:8px;">
            💡 After adding this to your NGINX config and reloading, test by attempting to access
            a file in a protected zone — you should be redirected through WordPress rather than
            receiving the file directly.
        </p>
    </div>

    <!-- Per-zone individual blocks (for sites with complex configs) -->
    <div class="rbfa-card" style="margin-top:20px;">
        <h3 style="margin-top:0;">Individual Zone Blocks</h3>
        <p style="color:#666; font-size:13px;">
            Use these if your NGINX setup requires separate location blocks per zone
            rather than the combined regex block above.
        </p>
        <?php foreach ( $zones as $zone ) :
            $zone_url  = $upload_url . '/' . $base . '/' . $zone['folder_slug'] . '/';
            $per_zone  = "location ^~ " . $zone_url . " {\n";
            $per_zone .= "    try_files \$uri /index.php\$is_args\$args;\n";
            $per_zone .= "    add_header X-Robots-Tag \"noindex, nofollow\" always;\n";
            $per_zone .= "}\n";
        ?>
            <p style="font-weight:600; margin-bottom:4px;">
                Zone: <code><?php echo esc_html( $zone['folder_slug'] ); ?></code>
            </p>
            <textarea readonly
                      style="width:100%; font-family:monospace; font-size:12px; background:#f9f9f9;
                             border:1px solid #ccd0d4; border-radius:4px; padding:8px;
                             height:80px; resize:vertical; margin-bottom:12px;"
                      ><?php echo esc_textarea( $per_zone ); ?></textarea>
        <?php endforeach; ?>
    </div>

    <?php endif; ?>
    <?php
}

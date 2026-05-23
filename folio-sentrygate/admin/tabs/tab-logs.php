<?php
/**
 * Logs tab renderer.
 *
 * Displays the access log table with:
 *  - Left-hand filter panel (date+time range, username, IP, path, status)
 *  - Sortable column headers (Time, IP, Path, Status)
 *  - Configurable rows-per-page dropdown (10, 25, 50, 100, 250, 500, All)
 *  - Modern paginated navigation
 *  - Export button that carries the active filters through to the CSV export
 *
 * Guest rows (user_id = 0) are correctly resolved to "Guest" and are
 * searchable by typing "guest" in the username filter.
 *
 * @package WPFileSecurityPro
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the Logs tab. Called from rbfa_pro_page() in class-rbfa-admin.php.
 */
function rbfa_render_tab_logs() {
	global $wpdb;

	// ── Collect and sanitize filter parameters from GET ─────────────────────
	// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only filter parameters, no data mutation

	// datetime-local format: "YYYY-MM-DDTHH:MM" — convert to MySQL by replacing T with space.
	$f_start_dt = sanitize_text_field( wp_unslash( $_GET['start_dt'] ?? '' ) );
	$f_end_dt   = sanitize_text_field( wp_unslash( $_GET['end_dt']   ?? '' ) );
	$f_user     = sanitize_text_field( wp_unslash( $_GET['f_user']   ?? '' ) );
	$f_ip         = sanitize_text_field( wp_unslash( $_GET['f_ip']       ?? '' ) );
	$f_file       = sanitize_text_field( wp_unslash( $_GET['f_file']     ?? '' ) );
	$f_status     = sanitize_text_field( wp_unslash( $_GET['f_status']   ?? '' ) );

	// ── Sorting ─────────────────────────────────────────────────────────────
	// Column names are whitelisted to prevent SQL injection via the orderby param.
	$allowed_cols = [
		'time'       => 'time',
		'ip_address' => 'ip_address',
		'file_path'  => 'file_path',
		'status'     => 'status',
	];
	$sort_col    = ( isset( $_GET['orderby'] ) && array_key_exists( sanitize_key( wp_unslash( $_GET['orderby'] ) ), $allowed_cols ) )
	               ? $allowed_cols[ sanitize_key( wp_unslash( $_GET['orderby'] ) ) ] : 'time';
	$sort_dir    = ( isset( $_GET['order'] ) && strtoupper( sanitize_key( wp_unslash( $_GET['order'] ) ) ) === 'ASC' ) ? 'ASC' : 'DESC';
	$sort_toggle = $sort_dir === 'DESC' ? 'ASC' : 'DESC';

	// ── Pagination ──────────────────────────────────────────────────────────
	$allowed_per_page = [ 10, 25, 50, 100, 250, 500, 0 ]; // 0 = All
	$per_page_raw     = isset( $_GET['per_page'] ) ? (int) $_GET['per_page'] : 25;
	$per_page         = in_array( $per_page_raw, $allowed_per_page, true ) ? $per_page_raw : 25;
	$paged            = max( 1, absint( wp_unslash( $_GET['paged'] ?? 1 ) ) );

	// phpcs:enable WordPress.Security.NonceVerification.Recommended
	$offset           = $per_page > 0 ? ( $paged - 1 ) * $per_page : 0;

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
	if ( $f_ip )     { $where[] = 'ip_address LIKE %s'; $values[] = '%' . $wpdb->esc_like( $f_ip )   . '%'; }
	if ( $f_file )   { $where[] = 'file_path LIKE %s';  $values[] = '%' . $wpdb->esc_like( $f_file ) . '%'; }
	if ( $f_status ) { $where[] = 'status = %s';        $values[] = $f_status; }

	$where_sql = $where ? 'WHERE ' . implode( ' AND ', $where ) : '';

	// ── Count total matching rows (for pagination) ──────────────────────────
	$count_sql  = "SELECT COUNT(*) FROM {$wpdb->prefix}rbfa_access_logs $where_sql"; // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- WHERE values bound via prepare(); no ORDER BY
	$total_logs = (int) ( $values
		? $wpdb->get_var( $wpdb->prepare( $count_sql, $values ) ) // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- SQL variable built from prefix-derived table and sanitised WHERE clause
		: $wpdb->get_var( $count_sql ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
	$total_pages = $per_page > 0 ? (int) ceil( $total_logs / $per_page ) : 1;

	// ── Fetch current page of rows ──────────────────────────────────────────
	// $sort_col is whitelisted above — safe to interpolate directly.
	if ( $per_page > 0 ) {
		$rows_sql   = "SELECT * FROM {$wpdb->prefix}rbfa_access_logs $where_sql ORDER BY $sort_col $sort_dir LIMIT %d OFFSET %d"; // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- ORDER BY column whitelisted above; LIMIT/OFFSET cast to int
		$row_values = array_merge( $values, [ $per_page, $offset ] );
	} else {
		$rows_sql   = "SELECT * FROM {$wpdb->prefix}rbfa_access_logs $where_sql ORDER BY $sort_col $sort_dir"; // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- ORDER BY column whitelisted above
		$row_values = $values;
	}
	$log_rows = $row_values
		? $wpdb->get_results( $wpdb->prepare( $rows_sql, $row_values ) ) // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- SQL variable built from whitelisted ORDER BY column and sanitised WHERE clause
		: $wpdb->get_results( $rows_sql ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

	// ── Username filter (PHP-side; resolves guest vs registered users) ───────
	if ( $f_user ) {
		$log_rows = array_filter( $log_rows, function ( $l ) use ( $f_user ) {
			// Rows with user_id = 0 are guest (unauthenticated) requests.
			if ( (int) $l->user_id === 0 ) {
				return stripos( 'guest', $f_user ) !== false;
			}
			$u = get_userdata( $l->user_id );
			return $u && stripos( $u->user_login, $f_user ) !== false;
		} );
	}

	// ── Build persistent query args (filters + sort + per-page) ─────────────
	// These are merged into sort/pagination URLs so state is never lost.
	$active_filters = array_filter( [
		'start_dt' => $f_start_dt,
		'end_dt'   => $f_end_dt,
		'f_user'   => $f_user,
		'f_ip'     => $f_ip,
		'f_file'   => $f_file,
		'f_status' => $f_status,
	] );

	$state_args = array_merge(
		[ 'page' => 'rbfa-pro', 'tab' => 'logs', 'per_page' => $per_page ],
		$active_filters
	);

	// ── Sort URL builder ─────────────────────────────────────────────────────
	$make_sort_url = function ( $col ) use ( $state_args, $sort_col, $sort_toggle ) {
		$dir = ( $sort_col === $col ) ? $sort_toggle : 'DESC';
		return esc_url( add_query_arg( array_merge( $state_args, [ 'orderby' => $col, 'order' => $dir ] ), admin_url( 'admin.php' ) ) );
	};
	$sort_arrow = function ( $col ) use ( $sort_col, $sort_dir ) {
		if ( $sort_col !== $col ) return ' <span style="color:#ccc;">&#8597;</span>';
		return $sort_dir === 'ASC'
			? ' <span style="color:#2271b1;">&#8593;</span>'
			: ' <span style="color:#2271b1;">&#8595;</span>';
	};

	// ── Stats for widget ───────────────────────────────────────────────────────
	$stat_total   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}rbfa_access_logs" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- custom plugin table, no appropriate caching layer
	$stat_granted = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}rbfa_access_logs WHERE status='Granted'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- custom plugin table, no appropriate caching layer
	$stat_denied  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}rbfa_access_logs WHERE status='Denied'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- custom plugin table, no appropriate caching layer

	// 7-day daily activity for the sparkline (granted + denied per day).
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- custom plugin table, no appropriate caching layer
	$sparkline_rows = $wpdb->get_results( "
		SELECT DATE(time) as day, SUM(status='Granted') as granted, SUM(status='Denied') as denied
		FROM {$wpdb->prefix}rbfa_access_logs
		WHERE time >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
		GROUP BY DATE(time)
		ORDER BY day ASC
	", ARRAY_A );

	// Build a full 7-day array (fill gaps with zeros).
	$sparkline = [];
	for ( $d = 6; $d >= 0; $d-- ) {
		$day = gmdate( 'Y-m-d', strtotime( "-{$d} days" ) );
		$sparkline[ $day ] = [ 'granted' => 0, 'denied' => 0 ];
	}
	foreach ( $sparkline_rows as $row ) {
		if ( isset( $sparkline[ $row['day'] ] ) ) {
			$sparkline[ $row['day'] ]['granted'] = (int) $row['granted'];
			$sparkline[ $row['day'] ]['denied']  = (int) $row['denied'];
		}
	}

	// Export carries active filters and current sort order.
	$export_url = add_query_arg(
		array_merge( [ 'page' => 'rbfa-pro', 'action' => 'export_csv' ], $active_filters,
			( $sort_col !== 'time' || $sort_dir !== 'DESC' )
				? [ 'orderby' => $sort_col, 'order' => $sort_dir ] : [] ),
		admin_url( 'admin.php' )
	);

	// Prune settings for manual prune button display.
	$prune_enabled = get_option( 'rbfa_prune_enabled', '0' );
	$prune_days    = (int) get_option( 'rbfa_prune_days', 90 );
	?>

	<!-- ── Stats widget ──────────────────────────────────────────────────────── -->
	<div style="display:flex; gap:16px; align-items:stretch; margin-top:20px; flex-wrap:wrap;">

		<!-- Total granted card -->
		<div class="rbfa-card" style="flex:1; min-width:140px; margin-top:0; text-align:center; border-top:3px solid #2271b1;">
			<div style="font-size:32px; font-weight:700; color:#2271b1; line-height:1.2;">
				<?php echo number_format( $stat_granted ); ?>
			</div>
			<div style="color:#555; font-size:13px; margin-top:4px;">✅ Granted</div>
		</div>

		<!-- Total denied card -->
		<div class="rbfa-card" style="flex:1; min-width:140px; margin-top:0; text-align:center; border-top:3px solid #d63638;">
			<div style="font-size:32px; font-weight:700; color:#d63638; line-height:1.2;">
				<?php echo number_format( $stat_denied ); ?>
			</div>
			<div style="color:#555; font-size:13px; margin-top:4px;">❌ Denied</div>
		</div>

		<!-- Total all-time card -->
		<div class="rbfa-card" style="flex:1; min-width:140px; margin-top:0; text-align:center; border-top:3px solid #6c757d;">
			<div style="font-size:32px; font-weight:700; color:#444; line-height:1.2;">
				<?php echo number_format( $stat_total ); ?>
			</div>
			<div style="color:#555; font-size:13px; margin-top:4px;">📊 Total</div>
		</div>

		<!-- 7-day sparkline card -->
		<div class="rbfa-card" style="flex:2; min-width:260px; margin-top:0;">
			<div style="font-size:12px; font-weight:600; color:#555; margin-bottom:8px;">Last 7 Days</div>
			<?php
			// Build inline SVG sparkline.
			$all_vals = array_merge(
				array_column( array_values( $sparkline ), 'granted' ),
				array_column( array_values( $sparkline ), 'denied' )
			);
			$max_val  = max( 1, max( $all_vals ) );
			$sw       = 240; $sh = 50; $n = count( $sparkline );
			$step     = $sw / max( 1, $n - 1 );
			$days     = array_keys( $sparkline );

			// Granted polyline points.
			$g_pts = []; $d_pts = [];
			foreach ( array_values( $sparkline ) as $idx => $vals ) {
				$x      = round( $idx * $step );
				$g_pts[] = $x . ',' . round( $sh - ( $vals['granted'] / $max_val ) * $sh );
				$d_pts[] = $x . ',' . round( $sh - ( $vals['denied']  / $max_val ) * $sh );
			}
			?>
			<svg viewBox="0 0 <?php echo absint( $sw ); ?> <?php echo absint( $sh ); ?>" style="width:100%; height:50px; overflow:visible;">
				<!-- X-axis labels -->
				<?php foreach ( $days as $idx => $day ) :
					$x = round( $idx * $step );
					$label = gmdate( 'M j', strtotime( $day ) );
				?>
				<text x="<?php echo absint( $x ); ?>" y="<?php echo absint( $sh + 14 ); ?>" text-anchor="middle"
				      font-size="8" fill="#999"><?php echo esc_html( $label ); ?></text>
				<?php endforeach; ?>
				<!-- Granted line (blue) -->
				<polyline points="<?php echo esc_attr( implode( ' ', $g_pts ) ); ?>"
				          fill="none" stroke="#2271b1" stroke-width="2" stroke-linejoin="round"/>
				<!-- Denied line (red) -->
				<polyline points="<?php echo esc_attr( implode( ' ', $d_pts ) ); ?>"
				          fill="none" stroke="#d63638" stroke-width="2" stroke-linejoin="round"/>
			</svg>
			<div style="font-size:10px; color:#888; margin-top:18px;">
				<span style="color:#2271b1;">●</span> Granted &nbsp;
				<span style="color:#d63638;">●</span> Denied
			</div>
		</div>
	</div>

	<!-- ── Manual prune ───────────────────────────────────────────────────────── -->
	<?php if ( $prune_days > 0 ) : ?>
	<div style="margin-top:12px; display:flex; align-items:center; gap:12px;">
		<form method="post" onsubmit="return confirm('Delete all log entries older than <?php echo absint( $prune_days ); ?> days? This cannot be undone.');">
			<?php wp_nonce_field( 'rbfa_admin_action', 'rbfa_nonce' ); ?>
			<input type="submit" name="rbfa_manual_prune"
				   value="Prune Logs Older Than <?php echo absint( $prune_days ); ?> Days"
				   class="button">
		</form>
		<span style="color:#666; font-size:12px;">
			Auto-prune is <?php echo $prune_enabled === '1' ? '<strong>enabled</strong> (runs daily)' : 'disabled'; ?>.
			Configure in <a href="<?php echo esc_url( add_query_arg( ['page'=>'rbfa-pro','tab'=>'settings'], admin_url('admin.php') ) ); ?>">Settings</a>.
		</span>
	</div>
	<?php endif; ?>

	<div style="display:flex; gap:20px; align-items:flex-start; margin-top:20px;">

		<!-- ── LEFT: Filter panel ─────────────────────────────────────────── -->
		<div class="rbfa-card" style="flex:0 0 230px; margin-top:0;">
			<h3 style="margin-top:0;">Filter Logs</h3>
			<form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>">
				<input type="hidden" name="page"     value="rbfa-pro">
				<input type="hidden" name="tab"      value="logs">
				<input type="hidden" name="per_page" value="<?php echo esc_attr( $per_page ); ?>">
				<?php if ( $sort_col !== 'time' || $sort_dir !== 'DESC' ) : ?>
					<input type="hidden" name="orderby" value="<?php echo esc_attr( $sort_col ); ?>">
					<input type="hidden" name="order"   value="<?php echo esc_attr( $sort_dir ); ?>">
				<?php endif; ?>

				<p style="margin:0 0 4px;">
					<label style="display:block; font-weight:600; margin-bottom:3px;">From</label>
					<input type="datetime-local" name="start_dt"
					       value="<?php echo esc_attr( $f_start_dt ); ?>"
					       style="width:100%; box-sizing:border-box;">
				</p>
				<p style="margin:0 0 8px;">
					<label style="display:block; font-weight:600; margin-bottom:3px;">To</label>
					<input type="datetime-local" name="end_dt"
					       value="<?php echo esc_attr( $f_end_dt ); ?>"
					       style="width:100%; box-sizing:border-box;">
				</p>
				<p style="margin:0 0 8px;">
					<label style="display:block; font-weight:600; margin-bottom:3px;">Username</label>
					<!-- Type "guest" to find unauthenticated requests. -->
					<input type="text" name="f_user" value="<?php echo esc_attr( $f_user ); ?>" placeholder='e.g. jsmith or "guest"' style="width:100%;">
				</p>
				<p style="margin:0 0 8px;">
					<label style="display:block; font-weight:600; margin-bottom:3px;">IP Address</label>
					<input type="text" name="f_ip" value="<?php echo esc_attr( $f_ip ); ?>" placeholder="e.g. 192.168" style="width:100%;">
				</p>
				<p style="margin:0 0 8px;">
					<label style="display:block; font-weight:600; margin-bottom:3px;">File Path</label>
					<input type="text" name="f_file" value="<?php echo esc_attr( $f_file ); ?>" placeholder="e.g. members/" style="width:100%;">
				</p>
				<p style="margin:0 0 12px;">
					<label style="display:block; font-weight:600; margin-bottom:3px;">Status</label>
					<select name="f_status" style="width:100%;">
						<option value="">All</option>
						<option value="Granted" <?php selected( $f_status, 'Granted' ); ?>>Granted</option>
						<option value="Denied"  <?php selected( $f_status, 'Denied' );  ?>>Denied</option>
					</select>
				</p>

				<input type="submit" value="Apply Filters" class="button button-primary" style="width:100%;">
				<?php if ( $f_start_dt || $f_end_dt || $f_user || $f_ip || $f_file || $f_status ) : ?>
					<a href="<?php echo esc_url( add_query_arg( [ 'page' => 'rbfa-pro', 'tab' => 'logs', 'per_page' => $per_page ], admin_url( 'admin.php' ) ) ); ?>"
					   class="button" style="width:100%; margin-top:6px; text-align:center; box-sizing:border-box;">
						Clear Filters
					</a>
				<?php endif; ?>
			</form>
		</div>

		<!-- ── RIGHT: Table + controls ──────────────────────────────────────── -->
		<div style="flex:1; min-width:0;">

			<!-- Top bar: rows-per-page (left) + export button (right) -->
			<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">

				<!-- Rows per page — submits immediately on change -->
				<form method="get" action="<?php echo esc_url( admin_url( 'admin.php' ) ); ?>"
				      style="display:flex; align-items:center; gap:6px;">
					<input type="hidden" name="page" value="rbfa-pro">
					<input type="hidden" name="tab"  value="logs">
					<?php foreach ( $active_filters as $k => $v ) : ?>
						<input type="hidden" name="<?php echo esc_attr( $k ); ?>" value="<?php echo esc_attr( $v ); ?>">
					<?php endforeach; ?>
					<?php if ( $sort_col !== 'time' || $sort_dir !== 'DESC' ) : ?>
						<input type="hidden" name="orderby" value="<?php echo esc_attr( $sort_col ); ?>">
						<input type="hidden" name="order"   value="<?php echo esc_attr( $sort_dir ); ?>">
					<?php endif; ?>
					<label for="rbfa-per-page" style="font-weight:600; white-space:nowrap;">Rows per page:</label>
					<select id="rbfa-per-page" name="per_page" onchange="this.form.submit()">
						<?php foreach ( [ 10, 25, 50, 100, 250, 500 ] as $n ) :
							echo "<option value='" . absint( $n ) . "'" . selected( $per_page, $n, false ) . ">" . absint( $n ) . "</option>";
						endforeach; ?>
						<option value="0" <?php selected( $per_page, 0 ); ?>>All</option>
					</select>
				</form>

				<!-- Export button — carries active filters; export returns full dataset -->
				<a href="<?php echo esc_url( $export_url ); ?>" class="button">Export to CSV</a>
			</div>

			<!-- Log table -->
			<table class="widefat striped">
				<thead>
					<tr>
						<th><a href="<?php echo esc_url( $make_sort_url( 'time' ) ); ?>" style="text-decoration:none; color:inherit;">
							Time<?php echo $sort_arrow( 'time' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $sort_arrow returns static safe HTML spans ?>
						</a></th>
						<th>User</th>
						<th><a href="<?php echo esc_url( $make_sort_url( 'ip_address' ) ); ?>" style="text-decoration:none; color:inherit;">
							IP<?php echo $sort_arrow( 'ip_address' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $sort_arrow returns static safe HTML spans ?>
						</a></th>
						<th><a href="<?php echo esc_url( $make_sort_url( 'file_path' ) ); ?>" style="text-decoration:none; color:inherit;">
							Path<?php echo $sort_arrow( 'file_path' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $sort_arrow returns static safe HTML spans ?>
						</a></th>
						<th><a href="<?php echo esc_url( $make_sort_url( 'status' ) ); ?>" style="text-decoration:none; color:inherit;">
							Status<?php echo $sort_arrow( 'status' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $sort_arrow returns static safe HTML spans ?>
						</a></th>
					</tr>
				</thead>
				<tbody>
				<?php foreach ( $log_rows as $l ) :
					// Resolve user_id to a display name; 0 = unauthenticated guest.
					$username = ( (int) $l->user_id === 0 )
					            ? 'Guest'
					            : ( ( $u = get_userdata( $l->user_id ) ) ? $u->user_login : 'Guest' );
					echo '<tr>'
						. '<td>' . esc_html( $l->time )       . '</td>'
						. '<td><strong>' . esc_html( $username )    . '</strong></td>'
						. '<td>' . esc_html( $l->ip_address )  . '</td>'
						. '<td>' . esc_html( $l->file_path )   . '</td>'
						. '<td>' . esc_html( $l->status )      . '</td>'
						. '</tr>';
				endforeach; ?>
				</tbody>
			</table>

			<!-- Modern pagination -->
			<?php
			rbfa_render_pagination( $paged, $total_pages, array_merge(
				[ 'tab' => 'logs', 'per_page' => $per_page ],
				$active_filters,
				( $sort_col !== 'time' || $sort_dir !== 'DESC' )
					? [ 'orderby' => $sort_col, 'order' => $sort_dir ]
					: []
			) );
			?>
		</div>
	</div>
	<?php
}

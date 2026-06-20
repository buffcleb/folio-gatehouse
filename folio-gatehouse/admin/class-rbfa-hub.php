<?php
/**
 * The shared "Folio" admin menu + suite dashboard.
 *
 * Every Folio plugin ships an identical copy of this helper. The first one to
 * run during admin_menu registers the top-level "Folio" menu (the rest detect it
 * and skip), and each plugin then hangs its own page beneath it — so the whole
 * Folio suite lives under one menu instead of a separate top-level item each.
 *
 * The dashboard auto-discovers installed plugins whose folder starts with
 * "folio-" and shows the suite at a glance.
 *
 * @package WPFileSecurityPro
 */

defined( 'ABSPATH' ) || exit;

/**
 * Registers the shared Folio parent menu and renders the suite dashboard.
 */
class Rbfa_Hub {

	/** Shared top-level menu slug, identical across every Folio plugin. */
	const SLUG = 'folio-hub';

	/**
	 * Ensure the shared "Folio" top-level menu exists. Idempotent across plugins:
	 * only the first caller in a request creates it.
	 *
	 * @return void
	 */
	public static function ensure_parent() {
		if ( self::parent_exists() ) {
			return;
		}
		add_menu_page(
			__( 'Folio', 'folio-gatehouse' ),
			__( 'Folio', 'folio-gatehouse' ),
			'manage_options',
			self::SLUG,
			array( __CLASS__, 'render' ),
			'dashicons-shield-alt',
			80
		);
		// Rename the auto-created first submenu (mirrors the parent slug) to "Dashboard".
		add_submenu_page(
			self::SLUG,
			__( 'Folio', 'folio-gatehouse' ),
			__( 'Dashboard', 'folio-gatehouse' ),
			'manage_options',
			self::SLUG,
			array( __CLASS__, 'render' )
		);
	}

	/**
	 * Whether the shared Folio menu is already registered this request.
	 *
	 * @return bool
	 */
	private static function parent_exists() {
		global $menu;
		if ( is_array( $menu ) ) {
			foreach ( $menu as $item ) {
				if ( isset( $item[2] ) && self::SLUG === $item[2] ) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * The Folio suite and short descriptions, keyed by plugin folder slug.
	 *
	 * @return array<string,array<string,string>>
	 */
	private static function suite() {
		return array(
			'folio-gatehouse'  => array(
				'name' => __( 'Folio Gatehouse', 'folio-gatehouse' ),
				'desc' => __( 'Restrict files in your uploads directory to specific user roles.', 'folio-gatehouse' ),
				'page' => 'rbfa-pro',
			),
			'folio-drawbridge' => array(
				'name' => __( 'Folio Drawbridge', 'folio-gatehouse' ),
				'desc' => __( 'Encrypted file vaults with secure, two-factor external sharing.', 'folio-gatehouse' ),
				'page' => '',
			),
			'folio-keep'       => array(
				'name' => __( 'Folio Keep', 'folio-gatehouse' ),
				'desc' => __( 'Turn WordPress into a SAML 2.0 Identity Provider.', 'folio-gatehouse' ),
				'page' => '',
			),
			'folio-portcullis' => array(
				'name' => __( 'Folio Portcullis', 'folio-gatehouse' ),
				'desc' => __( 'Sign in to WordPress via SAML 2.0 single sign-on.', 'folio-gatehouse' ),
				'page' => 'folio-portcullis',
			),
			'folio-barbican'   => array(
				'name' => __( 'Folio Barbican', 'folio-gatehouse' ),
				'desc' => __( 'Sign in to WordPress via OpenID Connect / OAuth.', 'folio-gatehouse' ),
				'page' => 'folio-barbican',
			),
		);
	}

	/**
	 * Render the suite dashboard.
	 *
	 * @return void
	 */
	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$installed = get_plugins();

		echo '<div class="wrap"><h1>' . esc_html__( 'Folio', 'folio-gatehouse' ) . '</h1>';
		echo '<p class="description" style="max-width:680px">'
			. esc_html__( 'Folio is a family of WordPress access and data-protection plugins. The ones installed on this site are shown below.', 'folio-gatehouse' )
			. '</p>';
		echo '<table class="widefat striped" style="max-width:860px;margin-top:12px"><thead><tr>'
			. '<th>' . esc_html__( 'Plugin', 'folio-gatehouse' ) . '</th>'
			. '<th>' . esc_html__( 'Status', 'folio-gatehouse' ) . '</th>'
			. '<th>' . esc_html__( 'Version', 'folio-gatehouse' ) . '</th>'
			. '<th></th></tr></thead><tbody>';

		foreach ( self::suite() as $slug => $info ) {
			$found  = self::find_installed( $installed, $slug );
			$active = $found && is_plugin_active( $found );
			if ( ! $found ) {
				$status  = '<span style="color:#646970">' . esc_html__( 'Not installed', 'folio-gatehouse' ) . '</span>';
				$version = '—';
				$action  = '';
			} else {
				$data    = $installed[ $found ];
				$version = esc_html( (string) $data['Version'] );
				$status  = $active
					? '<strong style="color:#00a32a">' . esc_html__( 'Active', 'folio-gatehouse' ) . '</strong>'
					: '<span style="color:#996800">' . esc_html__( 'Inactive', 'folio-gatehouse' ) . '</span>';
				$action  = ( $active && '' !== $info['page'] )
					? '<a href="' . esc_url( admin_url( 'admin.php?page=' . $info['page'] ) ) . '">' . esc_html__( 'Settings', 'folio-gatehouse' ) . '</a>'
					: '';
			}
			echo '<tr><td><strong>' . esc_html( $info['name'] ) . '</strong><br><span class="description">' . esc_html( $info['desc'] ) . '</span></td>'
				. '<td>' . wp_kses_post( $status ) . '</td>'
				. '<td>' . wp_kses_post( $version ) . '</td>'
				. '<td>' . wp_kses_post( $action ) . '</td></tr>';
		}

		echo '</tbody></table></div>';
	}

	/**
	 * The installed plugin file (dir/file.php) for a folder slug, or '' if absent.
	 *
	 * @param array<string,array<string,mixed>> $installed get_plugins() result.
	 * @param string                            $slug      Plugin folder slug.
	 * @return string
	 */
	private static function find_installed( array $installed, $slug ) {
		foreach ( array_keys( $installed ) as $file ) {
			if ( 0 === strpos( $file, $slug . '/' ) ) {
				return $file;
			}
		}
		return '';
	}
}

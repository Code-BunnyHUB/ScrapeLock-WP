<?php
/**
 * ScrapeLock 3.12.12 — WordPress finds exactly one plugin file in the ScrapeLock folder: scrapelock.php.
 *
 *   WP_DIR=/path/to/wordpress php t_31212_plugin_file.php
 *
 * 3.12.11 shipped the Lockdown guard as includes/lockdown-guard.php, with its own "Plugin Name:" header (it is copied
 * as is to mu-plugins/). WordPress reads the headers of the .php files in a plugin's folder and in its sub-folders one
 * level down, and after "Upload Plugin" the "Activate Plugin" button pointed at the first one found:
 * scrapelock/includes/lockdown-guard.php. Activating it ended in "The plugin does not have a valid header." (WP-CLI's
 * "wp plugin activate scrapelock" was not affected). Since 3.12.12 the guard is includes/lockdown/guard.php, two
 * levels down, where WordPress does not look.
 *
 * A. get_plugins( '/scrapelock' ) (what Plugin_Upgrader::plugin_info() uses for the "Activate Plugin" button) lists
 *    only scrapelock.php.
 * B. No other shipped .php file in the plugin folder or one level down carries a "Plugin Name:" header in its first
 *    8 KB (the bytes get_file_data() reads), checked on the files themselves.
 * C. The guard template is includes/lockdown/guard.php and still carries its header for the mu-plugins list.
 *
 * Only on a test WordPress; changes nothing.
 */

$wp_dir = getenv( 'WP_DIR' );
if ( ! $wp_dir ) {
	fwrite( STDERR, "WP_DIR is required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

// The folder as WordPress names it: plugin_basename() follows a symlinked plugin folder (as in CI) back to its name
// under wp-content/plugins, where basename( dirname( PNCP_FILE ) ) would give the target's name.
$folder = dirname( plugin_basename( PNCP_FILE ) );
$root   = WP_PLUGIN_DIR . '/' . $folder;

/* ---------- A. what the "Activate Plugin" button after an upload points at ---------- */
wp_clean_plugins_cache( false );
$found = array_keys( get_plugins( '/' . $folder ) );
t( 'A get_plugins( /' . $folder . ' ): μόνο το scrapelock.php', array( 'scrapelock.php' ) === $found, implode( ', ', $found ) );
$all = get_plugins();
t( 'A get_plugins(): το ' . $folder . '/scrapelock.php υπάρχει με όνομα και έκδοση', isset( $all[ $folder . '/scrapelock.php' ] ) && '' !== $all[ $folder . '/scrapelock.php' ]['Name'] && PNCP_VERSION === $all[ $folder . '/scrapelock.php' ]['Version'] );
t( 'A validate_plugin(): χωρίς σφάλμα για το κύριο αρχείο', 0 === validate_plugin( $folder . '/scrapelock.php' ) );

/* ---------- B. no second header in the folder or one level down ---------- */
$headers = array();
$files   = array_merge( glob( $root . '/*.php' ), glob( $root . '/*/*.php' ) );
foreach ( $files as $file ) {
	$head = (string) file_get_contents( $file, false, null, 0, 8192 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
	if ( preg_match( '/^(?:[ \t]*<\?php)?[ \t\/*#@]*Plugin Name:(.*)$/mi', $head ) ) {
		$headers[] = substr( $file, strlen( $root ) + 1 );
	}
}
t( 'B κεφαλίδα "Plugin Name:" μόνο στο scrapelock.php (' . count( $files ) . ' αρχεία .php)', array( 'scrapelock.php' ) === $headers, implode( ', ', $headers ) );

/* ---------- C. the guard template ---------- */
$template = PNCP_Seal::guard_template();
t( 'C ο φύλακας: includes/lockdown/guard.php, δύο επίπεδα μέσα', realpath( $root . '/includes/lockdown/guard.php' ) === realpath( $template ) && is_readable( $template ) );
t( 'C ο φύλακας κρατά την κεφαλίδα του για τη λίστα των mu-plugins', false !== strpos( PNCP_Seal::code(), 'Plugin Name: ScrapeLock Lockdown guard' ) );
t( 'C το παλιό includes/lockdown-guard.php δεν υπάρχει', ! file_exists( $root . '/includes/lockdown-guard.php' ) );

echo $fails ? "\n$fails FAIL\n" : "\nOK\n";
exit( $fails ? 1 : 0 );

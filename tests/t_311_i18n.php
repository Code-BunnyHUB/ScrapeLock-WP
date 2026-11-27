<?php
/**
 * ScrapeLock 3.11 — the shipped Greek translation, in real WordPress.
 *
 *   WP_DIR=/path/to/wordpress php t_311_i18n.php
 *
 * Checks: languages/scrapelock-el.po has exactly the strings of languages/scrapelock.pot, every one translated with
 * the same placeholders and HTML tags; the .mo has the same strings as the .po; the strings that make-pot used to
 * miss or split are in the .pot as whole sentences; with the site in Greek the plugin loads its own languages/
 * folder (also the way WordPress 6.2 to 6.6 do it, through pncp_load_textdomain() on init) and a language pack in
 * wp-content/languages/plugins/ still wins.
 *
 * Changes nothing in the database (the locale is switched for this process only).
 */

$wp_dir = getenv( 'WP_DIR' );
if ( ! $wp_dir ) {
	fwrite( STDERR, "WP_DIR is required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . WPINC . '/pomo/po.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

$lang = dirname( __DIR__ ) . '/languages/';

/** The entries of a .po / .pot file, keyed by msgid (and plural). */
function entries_of( $file ) {
	$po = new PO();
	$po->import_from_file( $file );
	$out = array();
	foreach ( $po->entries as $e ) {
		$out[ $e->singular . "\x04" . (string) $e->plural ] = $e;
	}
	return $out;
}
function placeholders( $s ) {
	preg_match_all( '/%(?:\d+\$)?[-+ 0#]*\d*(?:\.\d+)?[sdfuxXc%]|<\/?[a-zA-Z][^>]*>/', $s, $m );
	sort( $m[0] );
	return $m[0];
}

$pot = entries_of( $lang . 'scrapelock.pot' );
$po  = entries_of( $lang . 'scrapelock-el.po' );
t( 'the .pot has strings', count( $pot ) > 2000, (string) count( $pot ) );
t( 'the Greek .po has exactly the strings of the .pot', array() === array_diff_key( $pot, $po ) && array() === array_diff_key( $po, $pot ), count( array_diff_key( $pot, $po ) ) . ' missing, ' . count( array_diff_key( $po, $pot ) ) . ' extra' );
$bad = array();
foreach ( $po as $e ) {
	$pairs = $e->is_plural ? array( array( $e->singular, $e->translations[0] ?? '' ), array( $e->plural, $e->translations[1] ?? '' ) ) : array( array( $e->singular, $e->translations[0] ?? '' ) );
	foreach ( $pairs as $p ) {
		if ( '' === trim( $p[1] ) || placeholders( $p[0] ) !== placeholders( $p[1] ) ) {
			$bad[] = substr( $p[0], 0, 60 );
		}
	}
}
t( 'every Greek string is translated with the same placeholders and tags', ! $bad, implode( ' | ', array_slice( $bad, 0, 5 ) ) );

$mo = new MO();
$mo->import_from_file( $lang . 'scrapelock-el.mo' );
$same = count( $mo->entries ) === count( $po );
foreach ( $po as $k => $e ) {
	$m = $mo->entries[ $e->key() ] ?? null;
	if ( ! $m || $m->translations !== $e->translations ) {
		$same = false;
		break;
	}
}
t( 'the .mo has the same strings and translations as the .po', $same, count( $mo->entries ) . ' / ' . count( $po ) );

t( 'the .pot has the hour form of the temporary block length', isset( $pot[ "A temporary block lasts %d hour\x04A temporary block lasts %d hours" ] ) );
t( 'the .pot has the Trusted Proxy notice as one sentence', isset( $pot[ "ScrapeLock reads the visitor IP from a header without checking the proxy (as in 1.4), so it can be spoofed: fix it in the %s.\x04" ] ) );
t( 'the .pot has the Trusted Proxy label as one sentence', isset( $pot[ "<strong>Trusted Proxy:</strong> the header is read only from proxies you trust.\x04" ] ) );
t( 'no half sentences are left in the .pot', ! isset( $pot[ "Trusted Proxy:\x04" ] ) && ! isset( $pot[ "the header is read only from proxies you trust.\x04" ] ) );

// The plugin's own languages/ folder, with the site in Greek.
t( 'pncp_load_textdomain() runs on init', 0 === has_action( 'init', 'pncp_load_textdomain' ) );
$pack = WP_LANG_DIR . '/plugins/scrapelock-el.mo';
t( 'no language pack on the test site (the shipped file is what is tested)', ! file_exists( $pack ) );
add_filter(
	'locale',
	static function () {
		return 'el';
	}
);
unload_textdomain( 'scrapelock' );
pncp_load_textdomain(); // What WordPress 6.2 to 6.6 rely on (no "Domain Path" loading there).
t( 'with the site in Greek (and no language pack) the shipped translation is loaded', 'Αποθήκευση αλλαγών' === __( 'Save changes', 'scrapelock' ), __( 'Save changes', 'scrapelock' ) );
t( 'the hour form is in Greek (Emergency Mode list)', false !== strpos( PNCP_Options::emergency_label( 'ban_minutes', 120 ), 'ώρες' ), PNCP_Options::emergency_label( 'ban_minutes', 120 ) );
// 3.12.13: no load_plugin_textdomain() (Plugin Check). As on WordPress 6.2 to 6.6 (the version is changed for this
// process only), pncp_load_textdomain() loads the shipped file at once, also after an unload_textdomain(), which
// stops just-in-time loading.
$real_wp_version = $GLOBALS['wp_version'];
unload_textdomain( 'scrapelock' );
$GLOBALS['wp_version'] = '6.6.2';
pncp_load_textdomain();
$GLOBALS['wp_version'] = $real_wp_version;
t( 'as on WordPress 6.6: the shipped translation is loaded at once', is_textdomain_loaded( 'scrapelock' ) && 'Αποθήκευση αλλαγών' === __( 'Save changes', 'scrapelock' ), __( 'Save changes', 'scrapelock' ) );
$pncp_calls = array_filter( token_get_all( (string) file_get_contents( dirname( __DIR__ ) . '/scrapelock.php' ) ), static function ( $tok ) { return is_array( $tok ) && T_STRING === $tok[0] && 'load_plugin_textdomain' === $tok[1]; } );
t( 'no load_plugin_textdomain() call in the plugin (comments aside)', ! $pncp_calls );

// A language pack in wp-content/languages/plugins/ is still read first.
wp_mkdir_p( dirname( $pack ) );
$pack_po = new PO();
$pack_po->set_header( 'Content-Type', 'text/plain; charset=UTF-8' );
$pack_po->add_entry(
	new Translation_Entry(
		array(
			'singular'     => 'Save changes',
			'translations' => array( 'PACK' ),
		)
	)
);
$pack_mo = new MO();
$pack_mo->set_header( 'Content-Type', 'text/plain; charset=UTF-8' );
$pack_mo->add_entry( $pack_po->entries['Save changes'] );
$pack_mo->export_to_file( $pack );
// In a new process: WordPress lists the language files once per request.
$child = 'define("WP_USE_THEMES", false); require ' . var_export( $wp_dir . '/wp-load.php', true ) . '; add_filter("locale", function () { return "el"; }); unload_textdomain("scrapelock"); pncp_load_textdomain(); echo __("Save changes", "scrapelock");';
$got   = (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' -r ' . escapeshellarg( $child ) . ' 2>&1' );
t( 'a language pack in wp-content/languages/plugins/ wins over the shipped file', 'PACK' === trim( $got ), $got );
$child = str_replace( 'unload_textdomain("scrapelock"); pncp_load_textdomain();', 'unload_textdomain("scrapelock"); $GLOBALS["wp_version"] = "6.6.2"; pncp_load_textdomain();', $child );
$got   = (string) shell_exec( escapeshellarg( PHP_BINARY ) . ' -r ' . escapeshellarg( $child ) . ' 2>&1' );
t( '...also as on WordPress 6.6 (loaded at once)', 'PACK' === trim( $got ), $got );
wp_delete_file( $pack );
unload_textdomain( 'scrapelock' );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );

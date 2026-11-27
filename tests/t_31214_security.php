<?php
/**
 * ScrapeLock 3.13.0 — πέντε διορθώσεις ασφαλείας, σε πραγματικό WordPress.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="php wp-cli.phar --path=…"] php t_31214_security.php
 *
 * A. Η παλιά υπογραφή X-ScrapeLock-Self (χρόνος + HMAC, 10 λεπτά, χωρίς διαδρομή, χωρίς nonce) δίδασκε τη
 *    διεύθυνση από την οποία ερχόταν, μία φορά ΑΝΑ διεύθυνση: όποιος έβλεπε ένα υπογεγραμμένο αίτημα μπορούσε να
 *    το ξαναστείλει από πολλές διευθύνσεις μέσα σε 10 λεπτά και να τις κάνει όλες «διευθύνσεις του server» (καμία
 *    παγίδα, κανένας αποκλεισμός, κανένα όριο). Τώρα: δεν στέλνεται, δεν διδάσκει τίποτα (replay από δύο
 *    διευθύνσεις μέσω HTTP), η νέα υπογραφή περνά τα πραγματικά αιτήματα του site προς τον εαυτό του (απλό
 *    wp_remote_get(), PNCP_Self_Check::request()) και η διεύθυνσή τους μαθαίνεται από την πλευρά που τα έστειλε
 *    (seen()). Δεν υπογράφεται http:// όταν το site είναι https:// (ένα redirect σε https:// του ίδιου host
 *    υπογράφεται). Μία φορά (purge_legacy()): οι διευθύνσεις που μάθαμε μένουν μόνο αν τις είδε και η πλευρά που
 *    στέλνει (OUTBOUND, 24 ώρες).
 * B. CrowdSec: αλλαγή host χωρίς νέο κλειδί → το κλειδί σβήνεται, με μήνυμα (φόρμα / import, WP-CLI settings set,
 *    restore παλιάς έκδοσης)· ίδιος host → μένει· http:// μόνο για loopback / ιδιωτικό δίκτυο.
 * C. Παγίδα / «ban στο πρώτο probe»: browser χωρίς Sec-Fetch (παλιό Safari / Firefox) που φορτώνει <img> ή
 *    <script> (Accept χωρίς text/html) δεν μετράει· navigation (text/html) μετράει όπως πριν (3ο σε 10 λεπτά)·
 *    curl με «Accept: οτιδήποτε» αποκλείεται αμέσως. Και μέσω HTTP με το /.env.
 * D. Σύνδεση: δεύτερο κλείδωμα του λογαριασμού μέσα σε 6 ώρες → κανένα email, το token (και ο σύνδεσμος του
 *    πρώτου email) μένει έγκυρο· μετά από 6 ώρες νέο email.
 * E. DNS: προϋπολογισμός εξαντλημένος → ο αληθινός Applebot (μη επαληθεύσιμος τώρα) περνά με 4× το όριο σελίδων,
 *    χωρίς τα αυστηρότερα όρια και χωρίς παράβαση· ο ψεύτικος που αποτυγχάνει στην επαλήθευση μένει 403·
 *    πρώτα ανά /24 (ένα δίκτυο δεν εξαντλεί όλο τον προϋπολογισμό της οικογένειας).
 *
 * Μόνο σε WordPress δοκιμών· οι ρυθμίσεις και οι διευθύνσεις του server επιστρέφουν στο τέλος.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/plugin.php';
require_once ABSPATH . 'wp-admin/includes/user.php';
require_once ABSPATH . 'wp-admin/includes/template.php'; // add_settings_error(), as in wp-admin and WP-CLI.

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Login::flush(); // Its own copy of the settings.
	PNCP_Ip::reset();
}

/** Ένα νέο αίτημα στο $_SERVER: ο «επισκέπτης» με X-Test-IP (όπως ο harness στον server). */
function as_request( $ip, $ua, $headers = array(), $uri = '/' ) {
	foreach ( array_keys( $_SERVER ) as $k ) {
		if ( 0 === strpos( $k, 'HTTP_' ) ) {
			unset( $_SERVER[ $k ] );
		}
	}
	$_SERVER['REMOTE_ADDR']    = '127.0.0.1';
	$_SERVER['REQUEST_METHOD'] = 'GET';
	$_SERVER['REQUEST_URI']    = $uri;
	$_SERVER['HTTP_HOST']      = (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST ) . ( wp_parse_url( home_url( '/' ), PHP_URL_PORT ) ? ':' . wp_parse_url( home_url( '/' ), PHP_URL_PORT ) : '' );
	$_SERVER['HTTP_X_TEST_IP'] = $ip;
	if ( '' !== $ua ) {
		$_SERVER['HTTP_USER_AGENT'] = $ua;
	}
	foreach ( $headers as $k => $v ) {
		$_SERVER[ $k ] = $v;
	}
	PNCP_Ip::reset();
	PNCP_Server_Ips::forget();
}

/** check() για σελίδα ($count: μετράει στα όρια). */
function verdict( $count = false ) {
	$v = PNCP_Bots::check( 'page', $count );
	return is_array( $v ) ? $v['code'] . ' ' . $v['reason'] : 'pass';
}

/** Αίτημα HTTP: [κωδικός, σώμα]. */
function http( $path, $ip, $ua, $headers = array() ) {
	global $base;
	$ch = curl_init( $base . $path );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER     => array_merge( array( 'X-Test-IP: ' . $ip, 'User-Agent: ' . $ua ), $headers ),
			CURLOPT_TIMEOUT        => 60,
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

/** Τυχαία δημόσια διεύθυνση (νέοι μετρητές σε κάθε εκτέλεση). */
function rand_ip( $prefix = null ) {
	return ( null === $prefix ? '45.' . wp_rand( 1, 250 ) . '.' . wp_rand( 1, 250 ) : $prefix ) . '.' . wp_rand( 1, 250 );
}

/** Ένα token της παλιάς κεφαλίδας X-ScrapeLock-Self, όπως το έφτιαχνε η 3.12.13 (έγκυρο). */
function legacy_token( $time = null ) {
	$time = null === $time ? time() : (int) $time;
	return $time . '.' . substr( hash_hmac( 'sha256', 'pncp-self|' . $time, (string) get_option( PNCP_Server_Ips::KEY_OPTION ) ), 0, 40 );
}

function forget_learned() {
	delete_transient( PNCP_Server_Ips::OUTBOUND );
	update_option(
		PNCP_Server_Ips::OPTION,
		array(
			'ips'     => array(),
			'host'    => implode( ',', PNCP_Server_Ips::own_hosts() ),
			'time'    => time(),
			'learned' => array(),
			'const'   => md5( implode( ',', PNCP_Server_Ips::const_ips() ) ),
			'v'       => PNCP_Server_Ips::LEARNED_VERSION,
		),
		true
	);
	wp_cache_flush();
}

$saved_settings = PNCP_Options::stored();
$saved_self     = get_option( PNCP_Server_Ips::OPTION, null );
$saved_out      = get_transient( PNCP_Server_Ips::OUTBOUND );
$wp_ua          = 'WordPress/6.9; ' . home_url( '/' );
$safari15       = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15';
$img_accept     = 'image/webp,image/png,image/svg+xml,image/*;q=0.8,video/*;q=0.8,*/*;q=0.5';
$doc_accept     = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';

settings(
	array(
		'enabled'                 => 1,
		'monitor_mode'            => 0,
		'monitor_until'           => 0,
		'block_bots'              => 1,
		'require_browser_headers' => 1,
		'block_headless'          => 1,
		'early_mode'              => 0,
		'precheck'                => 0,
		'ip_header'               => 'remote_addr',
		'trusted_proxies'         => '',
		'cdn_secret'              => '',
		'cdn_only'                => 0,
		'countries_block'         => '',
		'allow_ips'               => '',
	)
);
PNCP_Log::clear();

/* ---------- A. Η παλιά υπογραφή δεν διδάσκει τίποτα· η νέα περνά τα αιτήματα του site ---------- */
forget_learned();
$args = PNCP_Server_Ips::sign( array( 'headers' => array() ), home_url( '/' ) );
t( 'A sign(): X-ScrapeLock-Sig στα αιτήματα προς το site', isset( $args['headers'][ PNCP_Server_Ips::SIG_HEADER ] ) && '' !== $args['headers'][ PNCP_Server_Ips::SIG_HEADER ], wp_json_encode( $args ) );
t( 'A sign(): η παλιά X-ScrapeLock-Self δεν στέλνεται πια', ! isset( $args['headers'][ PNCP_Server_Ips::HEADER ] ), wp_json_encode( $args ) );

// Replay μέσω HTTP: ένα έγκυρο παλιό token από δύο διευθύνσεις, με WordPress User-Agent (χωρίς browser headers).
$token   = legacy_token();
$replays = array( '203.0.113.201', '198.51.100.202' );
$codes   = array();
foreach ( $replays as $ip ) {
	list( $codes[] ) = http( '/', $ip, $wp_ua, array( PNCP_Server_Ips::HEADER . ': ' . $token ) );
}
wp_cache_flush();
$learned = PNCP_Server_Ips::stored()['learned'];
t( 'A replay του παλιού token από δύο διευθύνσεις: 403 και τα δύο', array( 403, 403 ) === $codes, wp_json_encode( $codes ) );
t( 'A ... καμία διεύθυνση δεν μαθαίνεται (pncp_server_ips[learned] άδειο)', ! array_intersect( $replays, array_keys( $learned ) ), wp_json_encode( $learned ) );
$c = PNCP_Precheck::config();
t( 'A ... ούτε στο self_ips του pre-cache check', ! isset( $c['self_ips'][0]['203.0.113.201'] ) && ! isset( $c['self_ips'][0]['198.51.100.202'] ), wp_json_encode( isset( $c['self_ips'] ) ? $c['self_ips'] : null ) );
foreach ( $replays as $ip ) {
	as_request( $ip, $wp_ua, array( 'HTTP_X_SCRAPELOCK_SELF' => $token ) );
	t( "A unit: παλιό token από $ip: όχι αίτημα του server, 403 no_browser", ! PNCP_Server_Ips::is_request() && '403 no_browser' === verdict(), verdict() );
}
t( 'A unit: ... και πάλι τίποτα δεν μαθαίνεται', ! array_intersect( $replays, PNCP_Server_Ips::stored_ips() ) );

// Η νέα υπογραφή: περνά από οποιαδήποτε διεύθυνση, μία φορά· στον παραλήπτη δεν διδάσκει διεύθυνση.
$sig = PNCP_Server_Ips::sig_token( 'GET', home_url( '/' ) );
as_request( '203.0.113.203', $wp_ua, array( 'HTTP_X_SCRAPELOCK_SIG' => $sig ) );
t( 'A νέα υπογραφή: περνά', PNCP_Server_Ips::is_request() && 'pass' === verdict(), verdict() );
as_request( '198.51.100.204', $wp_ua, array( 'HTTP_X_SCRAPELOCK_SIG' => $sig ) );
t( 'A νέα υπογραφή ξανά από άλλη διεύθυνση (replay): 403', ! PNCP_Server_Ips::is_request() && '403 no_browser' === verdict(), verdict() );
t( 'A ... καμία από τις δύο δεν μαθαίνεται από τον παραλήπτη', ! array_intersect( array( '203.0.113.203', '198.51.100.204' ), PNCP_Server_Ips::stored_ips() ) );

// Τα πραγματικά αιτήματα του site προς τον εαυτό του, «μέσω CDN» από 203.0.113.210 (X-Test-IP).
forget_learned();
$r    = wp_remote_get(
	home_url( '/' ),
	array(
		'timeout'    => 30,
		'user-agent' => $wp_ua,
		'headers'    => array( 'X-Test-IP' => '203.0.113.210' ),
	)
);
$code = (int) wp_remote_retrieve_response_code( $r );
wp_cache_flush();
t( 'A wp_remote_get() του site (WordPress UA, χωρίς browser headers): 200', 200 === $code, is_wp_error( $r ) ? $r->get_error_message() : (string) $code );
t( 'A ... η διεύθυνση μαθαίνεται από την πλευρά που έστειλε (seen()) και μπαίνει στο pre-cache check', in_array( '203.0.113.210', PNCP_Server_Ips::stored_ips(), true ) && in_array( '203.0.113.210', PNCP_Server_Ips::outbound_ips(), true ), wp_json_encode( get_option( PNCP_Server_Ips::OPTION ) ) );
$self = PNCP_Self_Check::request(
	home_url( '/' ),
	array(
		'timeout' => 30,
		'headers' => array( 'X-Test-IP' => '203.0.113.211' ),
	),
	'self'
);
$code = is_wp_error( $self['response'] ) ? 0 : (int) wp_remote_retrieve_response_code( $self['response'] );
t( 'A PNCP_Self_Check::request() (ο έλεγχος «Check again», headless UA): 200 από τον δημόσιο δρόμο', 200 === $code && 'public' === $self['via'], $code . ' ' . $self['via'] . ' ' . wp_json_encode( $self['public'] ) );
$r = wp_remote_head( home_url( '/?pncp-head=1' ), array( 'headers' => array( 'X-Test-IP' => '203.0.113.212' ), 'user-agent' => $wp_ua ) );
t( 'A HEAD του site (π.χ. cache preload): 200', 200 === (int) wp_remote_retrieve_response_code( $r ), is_wp_error( $r ) ? $r->get_error_message() : (string) wp_remote_retrieve_response_code( $r ) );

// https site: δεν υπογράφεται http:// (θα το διάβαζε όποιος είναι στη μέση)· το redirect σε https:// του ίδιου host υπογράφεται.
$https = static function ( $url ) {
	return preg_replace( '#^http://#', 'https://', $url );
};
add_filter( 'home_url', $https );
add_filter( 'site_url', $https );
$host   = (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST );
$plain  = PNCP_Server_Ips::sign( array( 'headers' => array() ), 'http://' . $host . '/' );
$secure = PNCP_Server_Ips::sign( array( 'headers' => array() ), 'https://' . $host . '/' );
t( 'A https site: αίτημα σε http:// χωρίς υπογραφή', ! isset( $plain['headers'][ PNCP_Server_Ips::SIG_HEADER ] ), wp_json_encode( $plain ) );
t( 'A https site: αίτημα σε https:// με υπογραφή', isset( $secure['headers'][ PNCP_Server_Ips::SIG_HEADER ] ) );
$push = PNCP_Server_Ips::sign( array( 'headers' => array(), 'pncp_http_sig' => true ), 'http://' . $host . '/?pncp_precheck_sync=1' );
t( 'A https site: η εναλλακτική http:// του PNCP_Precheck::push_web() (pncp_http_sig) υπογράφεται', isset( $push['headers'][ PNCP_Server_Ips::SIG_HEADER ] ) );
$loc     = 'https://' . $host . '/after/';
$headers = array( 'Accept' => '*/*' );
$data    = null;
$opts    = array( 'type' => 'GET' );
PNCP_Server_Ips::unsign_redirect( $loc, $headers, $data, $opts );
t( 'A https site: redirect http → https του ίδιου host: υπογράφεται για τη νέα διαδρομή', isset( $headers[ PNCP_Server_Ips::SIG_HEADER ] ) && 'ok' === PNCP_Server_Ips::verify( $headers[ PNCP_Server_Ips::SIG_HEADER ], 'GET', '/after/', PNCP_Server_Ips::own_hosts(), PNCP_Server_Ips::sig_key(), time() )['result'], wp_json_encode( $headers ) );
$loc     = 'http://' . $host . '/plain/';
$headers = array( PNCP_Server_Ips::SIG_HEADER => 'x', PNCP_Server_Ips::HEADER => 'y' );
PNCP_Server_Ips::unsign_redirect( $loc, $headers, $data, $opts );
t( 'A https site: redirect σε http://: καμία υπογραφή (ούτε η παλιά κεφαλίδα)', array() === $headers, wp_json_encode( $headers ) );
remove_filter( 'home_url', $https );
remove_filter( 'site_url', $https );

// Καθαρισμός μία φορά: μένουν μόνο όσες είδε και η πλευρά που στέλνει.
delete_transient( PNCP_Server_Ips::OUTBOUND );
set_transient( PNCP_Server_Ips::OUTBOUND, array( '203.0.113.220' => time() ), DAY_IN_SECONDS );
update_option(
	PNCP_Server_Ips::OPTION,
	array(
		'ips'     => array(),
		'host'    => implode( ',', PNCP_Server_Ips::own_hosts() ),
		'time'    => time(),
		'learned' => array(
			'203.0.113.220'  => time(),
			'198.51.100.221' => time(),
			'198.51.100.222' => time() - DAY_IN_SECONDS,
		),
		'const'   => md5( implode( ',', PNCP_Server_Ips::const_ips() ) ),
	),
	true
);
$dropped = PNCP_Server_Ips::purge_legacy();
$state   = PNCP_Server_Ips::stored();
t( 'A purge_legacy(): οι 2 που έμαθε μόνο η παλιά κεφαλίδα φεύγουν, μένει αυτή του OUTBOUND', 2 === $dropped && array( '203.0.113.220' ) === array_keys( $state['learned'] ) && PNCP_Server_Ips::LEARNED_VERSION === $state['v'], $dropped . ' ' . wp_json_encode( $state ) );
$c = PNCP_Precheck::config();
t( 'A ... και το pre-cache check δεν τις έχει πια', ! isset( $c['self_ips'][0]['198.51.100.221'] ), wp_json_encode( isset( $c['self_ips'] ) ? $c['self_ips'] : null ) );
t( 'A purge_legacy() δεύτερη φορά: τίποτα (μία φορά)', 0 === PNCP_Server_Ips::purge_legacy() );
PNCP_Server_Ips::refresh();
t( 'A refresh(): κρατά την έκδοση και τη διεύθυνση', PNCP_Server_Ips::LEARNED_VERSION === PNCP_Server_Ips::stored()['v'] && isset( PNCP_Server_Ips::stored()['learned']['203.0.113.220'] ) );

/* ---------- B. CrowdSec: νέος host, το κλειδί δεν πηγαίνει εκεί ---------- */
$prepare_msgs = static function ( $prepared ) {
	return implode( ' | ', wp_list_pluck( $prepared['messages'], 'message' ) );
};
settings(
	array(
		'crowdsec_mode' => 'lapi',
		'crowdsec_url'  => 'https://lapi.example.com:8080',
		'crowdsec_key'  => 'secret-key-1',
	)
);
$p = PNCP_Settings_Io::prepare( array( 'crowdsec_url' => 'https://evil.example.net:8080' ) );
t( 'B import / settings set: άλλος host χωρίς νέο κλειδί → το κλειδί σβήνεται', 'https://evil.example.net:8080' === $p['settings']['crowdsec_url'] && '' === $p['settings']['crowdsec_key'], wp_json_encode( array( $p['settings']['crowdsec_url'], $p['settings']['crowdsec_key'] ) ) );
t( 'B ... με μήνυμα («key cleared because the address changed»)', false !== strpos( $prepare_msgs( $p ), 'cleared because the address changed' ), $prepare_msgs( $p ) );
$p = PNCP_Settings_Io::prepare( array( 'crowdsec_url' => 'https://lapi.example.com:8443/other/' ) );
t( 'B ίδιος host (άλλη θύρα / διαδρομή): το κλειδί μένει', 'secret-key-1' === $p['settings']['crowdsec_key'], $p['settings']['crowdsec_key'] );
$p = PNCP_Settings_Io::prepare(
	array(
		'crowdsec_url' => 'https://new.example.org',
		'crowdsec_key' => 'secret-key-2',
	)
);
t( 'B άλλος host μαζί με νέο κλειδί: το νέο κλειδί', 'secret-key-2' === $p['settings']['crowdsec_key'] && false === strpos( $prepare_msgs( $p ), 'cleared' ), $prepare_msgs( $p ) );
$clean = PNCP_Options::sanitize( array_merge( PNCP_Options::stored(), array( 'crowdsec_url' => 'https://other.example.net/', 'crowdsec_key' => '' ) ) );
t( 'B η φόρμα (sanitize(), κενό πεδίο κλειδιού): άλλος host → κλειδί κενό', '' === $clean['crowdsec_key'] );
foreach ( array( 'http://lapi.example.com:8080', 'http://203.0.113.9:8080' ) as $url ) {
	$p = PNCP_Settings_Io::prepare( array( 'crowdsec_url' => $url ) );
	t( "B http:// σε δημόσιο host ($url): απορρίπτεται, μένει η αποθηκευμένη, το κλειδί μένει", 'https://lapi.example.com:8080' === $p['settings']['crowdsec_url'] && 'secret-key-1' === $p['settings']['crowdsec_key'] && false !== strpos( $prepare_msgs( $p ), 'https://' ), $p['settings']['crowdsec_url'] . ' ' . $prepare_msgs( $p ) );
}
foreach ( array( 'http://127.0.0.1:8080', 'http://[::1]:8080', 'http://10.0.0.5:8080', 'http://192.168.1.20:8080', 'http://localhost:8080', 'http://crowdsec:8080', 'http://lapi.internal:8080' ) as $url ) {
	t( "B http:// σε loopback / ιδιωτικό ($url): δεκτό", PNCP_Options::crowdsec_url_ok( $url ) );
}
t( 'B https:// σε οποιονδήποτε host: δεκτό', PNCP_Options::crowdsec_url_ok( 'https://blocklist.example.com/list.txt' ) );
t( 'B άλλο σχήμα (ftp://): όχι', ! PNCP_Options::crowdsec_url_ok( 'ftp://example.com/' ) );
// http:// προς ιδιωτικό, μετά αλλαγή host σε άλλο ιδιωτικό: κι εκεί σβήνεται.
settings(
	array(
		'crowdsec_url' => 'http://127.0.0.1:8080',
		'crowdsec_key' => 'secret-key-1',
	)
);
$p = PNCP_Settings_Io::prepare( array( 'crowdsec_url' => 'http://10.0.0.7:8080' ) );
t( 'B ιδιωτικό → άλλο ιδιωτικό: δεκτό, το κλειδί σβήνεται', 'http://10.0.0.7:8080' === $p['settings']['crowdsec_url'] && '' === $p['settings']['crowdsec_key'] );
// Επαναφορά παλιάς έκδοσης με άλλη διεύθυνση: το τωρινό κλειδί δεν πηγαίνει εκεί.
$restored = PNCP_Settings_Io::restored( PNCP_Options::stored(), array( 'crowdsec_url' => 'https://old.example.net' ) );
t( 'B restore παλιάς έκδοσης με άλλον host: το κλειδί κενό', '' === $restored['crowdsec_key'] && 'https://old.example.net' === $restored['crowdsec_url'] );
$restored = PNCP_Settings_Io::restored( PNCP_Options::stored(), array( 'crowdsec_url' => 'http://127.0.0.1:8080/' ) );
t( 'B restore με τον ίδιο host: το κλειδί μένει', 'secret-key-1' === $restored['crowdsec_key'] );
// WP-CLI settings set (το ίδιο prepare(), σε άλλη διεργασία).
$cli = (string) getenv( 'WP_CLI' );
if ( '' !== $cli ) {
	settings(
		array(
			'crowdsec_url' => 'https://lapi.example.com:8080',
			'crowdsec_key' => 'secret-key-1',
		)
	);
	$out = (string) shell_exec( $cli . ' scrapelock settings set crowdsec_url https://cli.example.net 2>&1' );
	wp_cache_flush();
	PNCP_Options::flush();
	$now = PNCP_Options::stored();
	t( 'B wp scrapelock settings set crowdsec_url <άλλος host>: το κλειδί σβήνεται, με το μήνυμα', 'https://cli.example.net' === $now['crowdsec_url'] && '' === $now['crowdsec_key'] && false !== strpos( $out, 'cleared' ), $out . ' ' . $now['crowdsec_url'] );
	$out = (string) shell_exec( $cli . ' scrapelock settings set crowdsec_url http://public.example.net 2>&1' );
	wp_cache_flush();
	PNCP_Options::flush();
	t( 'B wp scrapelock settings set crowdsec_url http://<δημόσιος>: δεν αποθηκεύεται', 'https://cli.example.net' === PNCP_Options::stored()['crowdsec_url'], $out );
} else {
	echo "SKIP B WP-CLI (χωρίς WP_CLI)\n";
}
settings(
	array(
		'crowdsec_mode' => 'off',
		'crowdsec_url'  => '',
		'crowdsec_key'  => '',
	)
);

/* ---------- C. Παγίδα / probe: <img> παλιού browser δεν μετράει, curl ναι ---------- */
$trap = new ReflectionMethod( 'PNCP_Bots', 'trap_should_ban' );
$trap->setAccessible( true );
$series = static function ( $ip, $ua, $headers ) use ( $trap ) {
	$out = array();
	for ( $i = 0; $i < 3; $i++ ) {
		as_request( $ip, $ua, $headers, '/.env' );
		$out[] = $trap->invoke( null, $ip ) ? 'ban' : '-';
	}
	return implode( ',', $out );
};
$lang = array( 'HTTP_ACCEPT_LANGUAGE' => 'en-US,en;q=0.9' ); // Ένας browser το στέλνει σε κάθε αίτημα.
$got  = $series( rand_ip(), $safari15, array( 'HTTP_ACCEPT' => $img_accept ) + $lang );
t( 'C Safari 15 χωρίς Sec-Fetch, <img> (Accept: image/…) ×3: κανένα ban', '-,-,-' === $got, $got );
$got = $series( rand_ip(), $safari15, array( 'HTTP_ACCEPT' => '*/*' ) + $lang );
t( 'C Safari 15 χωρίς Sec-Fetch, <script> (Accept: */*) ×3: κανένα ban', '-,-,-' === $got, $got );
$got = $series( rand_ip(), $safari15, array( 'HTTP_ACCEPT' => '*/*' ) );
t( 'C «Safari» με Accept: */* (curl) χωρίς Accept-Language: μετράει, το 3ο', '-,-,ban' === $got, $got );
$got = $series( rand_ip(), $safari15, array( 'HTTP_ACCEPT' => $doc_accept ) + $lang );
t( 'C Safari 15 χωρίς Sec-Fetch, navigation (text/html): όπως πριν, το 3ο', '-,-,ban' === $got, $got );
$got = $series( rand_ip(), $safari15, array() );
t( 'C «Mozilla/» χωρίς Accept (κανένας browser): μετράει, το 3ο', '-,-,ban' === $got, $got );
$ip = rand_ip();
as_request( $ip, 'curl/8.5.0', array( 'HTTP_ACCEPT' => '*/*' ), '/.env' );
t( 'C curl (Accept: */*): αμέσως', $trap->invoke( null, $ip ) );
as_request( $ip, 'python-requests/2.32.3', array( 'HTTP_ACCEPT' => '*/*' ), '/.env' );
t( 'C python-requests (Accept: */*): αμέσως', $trap->invoke( null, $ip ) );
as_request( $ip, $safari15, array( 'HTTP_ACCEPT' => $img_accept, 'HTTP_SEC_FETCH_SITE' => 'cross-site', 'HTTP_SEC_FETCH_DEST' => 'image' ) );
t( 'C νέος browser με Sec-Fetch cross-site: όπως πριν, όχι', ! $trap->invoke( null, $ip ) );

// Μέσω HTTP: «Ban scanners on their first probe» στο /.env.
settings( array( 'probe_ban' => 1, 'trap_enabled' => 1 ) );
$is_banned = static function ( $ip ) {
	wp_cache_flush();
	PNCP_Log::reset_cache();
	return PNCP_Log::is_banned( $ip );
};
$victim = rand_ip();
$codes  = array();
for ( $i = 0; $i < 3; $i++ ) {
	list( $codes[] ) = http( '/.env', $victim, $safari15, array( 'Accept: ' . $img_accept, 'Accept-Language: en-US,en;q=0.9' ) );
}
t( 'C HTTP: 3 × <img src=/.env> από Safari 15 (άλλο site): ο επισκέπτης δεν αποκλείεται', ! $is_banned( $victim ), wp_json_encode( $codes ) );
$scanner = rand_ip();
list( $code ) = http( '/.env', $scanner, 'curl/8.5.0', array( 'Accept: */*' ) );
t( 'C HTTP: curl στο /.env: 403 και ban από το πρώτο', 403 === $code && $is_banned( $scanner ), (string) $code );
$fake = rand_ip();
for ( $i = 0; $i < 3; $i++ ) {
	list( $code ) = http( '/.env', $fake, $safari15, array( 'Accept: ' . $doc_accept, 'Accept-Language: en-US,en;q=0.9' ) );
}
t( 'C HTTP: «Safari» που ζητά HTML χωρίς Sec-Fetch, 3 φορές: ban (όπως πριν)', $is_banned( $fake ) );
foreach ( array( $victim, $scanner, $fake ) as $ip ) {
	PNCP_Log::unban( $ip );
}
settings( array( 'probe_ban' => 0 ) );

/* ---------- D. Σύνδεση: ένα email ανά 6 ώρες, ο σύνδεσμος μένει έγκυρος ---------- */
$login = 'pncp-31214-' . wp_rand( 1000, 9999 );
$uid   = wp_create_user( $login, wp_generate_password( 24 ), $login . '@example.com' );
$user  = get_user_by( 'id', $uid );
settings( array( 'login_user_email' => 1 ) );
$mails = array();
$catch = static function ( $pre, $atts ) use ( &$mails ) {
	$mails[] = $atts;
	return true;
};
add_filter( 'pre_wp_mail', $catch, 10, 2 );
$lock = new ReflectionMethod( 'PNCP_Login', 'lock_user' );
$lock->setAccessible( true );
$lock->invoke( null, 'id:' . $uid, $login, $user, time() + 15 * MINUTE_IN_SECONDS );
$meta1  = get_user_meta( $uid, PNCP_Login::UNLOCK_META, true );
$token1 = isset( $mails[0]['message'] ) && preg_match( '/pncp_unlock=([A-Za-z0-9]+)/', $mails[0]['message'], $m ) ? $m[1] : '';
t( 'D πρώτο κλείδωμα: ένα email με σύνδεσμο, «sent» στο meta', 1 === count( $mails ) && '' !== $token1 && is_array( $meta1 ) && isset( $meta1['sent'] ), wp_json_encode( $meta1 ) );
PNCP_Login::unlock_user( 'id:' . $uid );
$lock->invoke( null, 'id:' . $uid, $login, $user, time() + 15 * MINUTE_IN_SECONDS );
$meta2 = get_user_meta( $uid, PNCP_Login::UNLOCK_META, true );
t( 'D δεύτερο κλείδωμα μετά από 15 λεπτά (εδώ: αμέσως): κανένα νέο email', 1 === count( $mails ), (string) count( $mails ) );
t( 'D ... το token δεν αλλάζει', is_array( $meta2 ) && $meta1['hash'] === $meta2['hash'] );
for ( $i = 0; $i < 5; $i++ ) {
	PNCP_Login::unlock_user( 'id:' . $uid );
	$lock->invoke( null, 'id:' . $uid, $login, $user, time() + 15 * MINUTE_IN_SECONDS );
}
t( 'D άλλα 5 κλειδώματα: ακόμα ένα email συνολικά', 1 === count( $mails ), (string) count( $mails ) );
$_COOKIE = array();
t( 'D ο σύνδεσμος του πρώτου email δουλεύει ακόμα (και λύνει το τωρινό κλείδωμα)', PNCP_Login::redeem( $uid, $token1 ) && ! isset( PNCP_Login::locks()[ 'id:' . $uid ] ) );
$lock->invoke( null, 'id:' . $uid, $login, $user, time() + 15 * MINUTE_IN_SECONDS );
t( 'D μετά τη χρήση του συνδέσμου: νέο κλείδωμα → νέο email', 2 === count( $mails ), (string) count( $mails ) );
$meta         = (array) get_user_meta( $uid, PNCP_Login::UNLOCK_META, true );
$meta['sent'] = time() - 7 * HOUR_IN_SECONDS;
update_user_meta( $uid, PNCP_Login::UNLOCK_META, $meta );
PNCP_Login::unlock_user( 'id:' . $uid );
$lock->invoke( null, 'id:' . $uid, $login, $user, time() + 15 * MINUTE_IN_SECONDS );
$meta3 = get_user_meta( $uid, PNCP_Login::UNLOCK_META, true );
$meta3 = (array) $meta3;
t( 'D το προηγούμενο email πριν από 7 ώρες: νέο email, νέο token', 3 === count( $mails ) && isset( $meta3['hash'], $meta['hash'] ) && $meta3['hash'] !== $meta['hash'], (string) count( $mails ) );
$meta3['until'] = time() - 1;
update_user_meta( $uid, PNCP_Login::UNLOCK_META, $meta3 );
PNCP_Login::unlock_user( 'id:' . $uid );
$lock->invoke( null, 'id:' . $uid, $login, $user, time() + 15 * MINUTE_IN_SECONDS );
t( 'D ο σύνδεσμος έληξε (μέσα στις 6 ώρες): νέο email', 4 === count( $mails ), (string) count( $mails ) );
remove_filter( 'pre_wp_mail', $catch, 10 );
$fail_mail = static function () {
	return false;
};
add_filter( 'pre_wp_mail', $fail_mail );
delete_user_meta( $uid, PNCP_Login::UNLOCK_META );
PNCP_Login::unlock_user( 'id:' . $uid );
$lock->invoke( null, 'id:' . $uid, $login, $user, time() + 15 * MINUTE_IN_SECONDS );
$meta4 = get_user_meta( $uid, PNCP_Login::UNLOCK_META, true );
t( 'D email που δεν στάλθηκε: χωρίς «sent», το επόμενο κλείδωμα ξαναδοκιμάζει', is_array( $meta4 ) && ! isset( $meta4['sent'] ), wp_json_encode( $meta4 ) );
remove_filter( 'pre_wp_mail', $fail_mail );
PNCP_Login::unlock_user( 'id:' . $uid );
wp_delete_user( $uid );

/* ---------- E. DNS: εξαντλημένος προϋπολογισμός ---------- */
$applebot = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)';
settings(
	array(
		'block_fake_crawlers'   => 1,
		'human_check'           => 1,
		'rate_limit'            => 2,
		'rate_limit_unverified' => 1,
		'ban_strikes'           => 1,
	)
);
$no_budget = static function () {
	return 0;
};
add_filter( 'pncp_dns_lookups_per_minute', $no_budget );
$real = rand_ip();
$v    = array();
for ( $i = 0; $i < 9; $i++ ) {
	as_request( $real, $applebot, array( 'HTTP_ACCEPT' => '*/*' ) );
	$v[] = verdict( true );
}
t( 'E εξαντλημένος προϋπολογισμός: Applebot (όχι επαληθεύσιμος τώρα) περνά 8 φορές = 4 × όριο 2, όχι το «unverified» 1', 8 === count( array_keys( array_slice( $v, 0, 8 ), 'pass', true ) ), implode( ',', $v ) );
t( 'E ... το 9ο: 429 rate_page', '429 rate_page' === $v[8], $v[8] );
t( 'E ... χωρίς παράβαση: δεν αποκλείστηκε (ban_strikes 1)', ! PNCP_Log::is_banned( $real ) );
remove_filter( 'pncp_dns_lookups_per_minute', $no_budget );
$fake = rand_ip();
as_request( $fake, $applebot, array( 'HTTP_ACCEPT' => '*/*', 'HTTP_X_TEST_RDNS' => 'nxdomain' ) );
t( 'E με προϋπολογισμό: ψεύτικος Applebot χωρίς PTR: 403 fake_crawler', '403 fake_crawler' === verdict( true ), verdict() );
PNCP_Log::unban( $fake );
// Ανά /24 πρώτα: με όριο 4 το λεπτό, κάθε δίκτυο έχει 1.
$four = static function () {
	return 4;
};
add_filter( 'pncp_dns_lookups_per_minute', $four );
// Με το YandexBot: ο προϋπολογισμός της οικογένειάς του (ανά λεπτό) δεν έχει χρησιμοποιηθεί παραπάνω.
$yandex = 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)';
if ( (int) gmdate( 's' ) > 50 || (int) PNCP_Log::cache_get( 'pncp_dns_yandex_' . (int) floor( time() / MINUTE_IN_SECONDS ) ) > 0 ) {
	sleep( 61 - (int) gmdate( 's' ) ); // Ένα νέο λεπτό: ο μετρητής από την αρχή.
}
$net   = '45.' . wp_rand( 1, 250 ) . '.' . wp_rand( 1, 250 );
$other = '46.' . wp_rand( 1, 250 ) . '.' . wp_rand( 1, 250 );
$res   = array();
foreach ( array( $net . '.1', $net . '.2', $net . '.3', $other . '.1' ) as $ip ) {
	as_request( $ip, $yandex, array( 'HTTP_ACCEPT' => '*/*', 'HTTP_X_TEST_RDNS' => 'nxdomain' ) );
	$res[] = verdict( true );
	PNCP_Log::unban( $ip );
}
t( 'E ανά /24: 1ο του δικτύου ελέγχεται (403 fake_crawler), 2ο και 3ο χωρίς έλεγχο (με το όριο crawler), άλλο δίκτυο ελέγχεται', array( '403 fake_crawler', 'pass', 'pass', '403 fake_crawler' ) === $res, implode( ',', $res ) );
remove_filter( 'pncp_dns_lookups_per_minute', $four );

/* ---------- Επαναφορά ---------- */
update_option( PNCP_OPTION, $saved_settings );
PNCP_Options::flush();
if ( null === $saved_self ) {
	delete_option( PNCP_Server_Ips::OPTION );
} else {
	update_option( PNCP_Server_Ips::OPTION, $saved_self, true );
}
if ( false === $saved_out ) {
	delete_transient( PNCP_Server_Ips::OUTBOUND );
} else {
	set_transient( PNCP_Server_Ips::OUTBOUND, $saved_out, PNCP_Server_Ips::OUTBOUND_KEEP );
}
PNCP_Precheck::refresh();
PNCP_Log::clear();

echo $fails ? "\n$fails FAIL\n" : "\nOK\n";
exit( $fails ? 1 : 0 );

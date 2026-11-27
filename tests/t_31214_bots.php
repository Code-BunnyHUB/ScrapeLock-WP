<?php
/**
 * ScrapeLock 3.13.0 — how bots are blocked, after a measured review:
 *  A  payment gateway callbacks (?wc-api=, /wc-api/, REST webhooks) never refused, also with "Browsers only" and in
 *     Emergency Mode: WordPress, the early check, the pre-cache check and the Nginx / Apache rules;
 *  B  a fake Googlebot on a cached page: 403 with the official list loaded and fresh, "unverified" (counted) without;
 *     the Nginx geo of the official ranges;
 *  C  browser headers that do not fit the User-Agent (header_mismatch(), the same in both checks): the stricter
 *     limit, not a 403 (a 403 only with another bad sign); HeadlessChrome on a cached page: 403;
 *  D  the network limit (IPv4 /24, IPv6 /48): human-check cookie holders and signed-in users exempt;
 *  E  the human check: difficulty per client, signed into the challenge; shorter cookie; cookies per network;
 *  F  an "always allowed" User-Agent without an address that confirms it: the stricter limit and the header checks;
 *     a link preview from its operator's network: exempt, as before;
 *  G  excerpts in lists and hidden author archives for new installs only; the presets;
 *  H  the new AI names;
 *  I  the sliding window (WordPress and the pre-cache check);
 *  J  /author/<slug>/ with "Hide the author archives too";
 *  K  "refuse full-size originals requested without a Referer" in the hotlink rules.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_31214_bots.php
 *
 * Only on a test WordPress: settings, lists, wp-config.php, advanced-cache.php and a mu-plugin of its own are put back
 * or removed at the end.
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( '' !== (string) $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/** A request with curl: [code, lowercase headers, body]. */
function req( $path, $headers = array(), $method = 'GET', $cookie = '', $body = null ) {
	global $base;
	$ch = curl_init( $base . $path );
	$h  = array();
	foreach ( $headers as $k => $v ) {
		$h[] = $k . ': ' . $v;
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_HTTPHEADER     => $h,
		CURLOPT_CUSTOMREQUEST  => $method,
		CURLOPT_TIMEOUT        => 60,
	);
	if ( 'HEAD' === $method ) {
		$opts[ CURLOPT_NOBODY ] = true;
	}
	if ( null !== $body ) {
		$opts[ CURLOPT_POSTFIELDS ] = $body;
	}
	if ( '' !== $cookie ) {
		$opts[ CURLOPT_COOKIE ] = $cookie;
	}
	curl_setopt_array( $ch, $opts );
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	return array( $code, strtolower( substr( $out, 0, $hs ) ), substr( $out, $hs ) );
}

/** The status codes of $n requests. */
function codes( $path, $headers, $n, $method = 'GET', $cookie = '' ) {
	$out = array();
	for ( $i = 0; $i < $n; $i++ ) {
		$out[] = req( $path, $headers, $method, $cookie )[0];
	}
	return $out;
}

const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36';

/** A real Chrome 142 on Windows over HTTPS, from $ip (the headers it always sends). */
function chrome( $ip, $extra = array() ) {
	return array_merge(
		array(
			'X-Real-IP'          => $ip,
			'X-Test-IP'          => $ip,
			'X-Test-HTTPS'       => '1',
			'User-Agent'         => CHROME,
			'Accept'             => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
			'Accept-Language'    => 'en-US,en;q=0.9',
			'Sec-CH-UA'          => '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
			'Sec-CH-UA-Mobile'   => '?0',
			'Sec-CH-UA-Platform' => '"Windows"',
			'Sec-Fetch-Site'     => 'none',
			'Sec-Fetch-Mode'     => 'navigate',
			'Sec-Fetch-Dest'     => 'document',
			'Sec-Fetch-User'     => '?1',
		),
		$extra
	);
}

/** A client that sends only these headers (plus the test IP). */
function client( $ip, $ua, $extra = array() ) {
	return array_merge(
		array(
			'X-Real-IP'  => $ip,
			'X-Test-IP'  => $ip,
			'User-Agent' => $ua,
		),
		$extra
	);
}

function settings( $changes, $wait = true ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Ip::reset();
	if ( $wait ) {
		sleep( 3 ); // OPcache revalidates the pre-cache check's files after 2 s.
	}
}

/** Waits for the next minute when fewer than $need seconds are left in this one (the counters are per minute). */
function same_minute( $need = 25 ) {
	$left = 60 - time() % 60;
	if ( $left < $need ) {
		sleep( $left + 1 );
	}
}

function fresh() {
	global $wpdb;
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_%pncp\_%' OR option_name LIKE '\_transient\_timeout\_%pncp\_%'" );
	PNCP_Log::unban_all();
	PNCP_Log::clear();
	wp_cache_flush();
	PNCP_Log::reset_cache();
	if ( PNCP_Precheck::dir() && is_dir( PNCP_Precheck::dir() . '/hits' ) ) {
		PNCP_Precheck_Runtime::cleanup( PNCP_Precheck::dir() . '/hits', PHP_INT_MAX, 0 );
	}
}

/** The last event of the pre-cache check for an IP: its code and reason ('' = none). */
function pc_event( $ip ) {
	$log = (string) @file_get_contents( PNCP_Precheck::dir() . '/events.log' );
	$out = '';
	foreach ( explode( "\n", $log ) as $line ) {
		$f = explode( "\t", $line );
		if ( isset( $f[3] ) && $f[3] === $ip ) {
			$out = $f[1] . ' ' . $f[2];
		}
	}
	return $out;
}

/** Turns the pre-cache check on or off (its line in wp-config.php), as the settings page does. */
function precheck( $on ) {
	settings( array( 'precheck' => $on ? 1 : 0 ), false );
	PNCP_Precheck::maybe_sync();
	sleep( 3 );
}

/** The reason of the latest log row of an IP ('' = none). */
function wp_reason( $ip ) {
	PNCP_Log::reset_cache();
	foreach ( PNCP_Log::recent( 200 ) as $row ) {
		if ( isset( $row['ip'] ) && $ip === (string) $row['ip'] ) {
			return (string) $row['reason'];
		}
	}
	return '';
}

/* ---------- Setup: a page cache for /cached-page/ (as t_precheck.php), the test mu-plugin, settings ---------- */

$config_file = PNCP_Precheck::config_path();
$cache_file  = WP_CONTENT_DIR . '/advanced-cache.php';
$mu_file     = WP_CONTENT_DIR . '/mu-plugins/pncp-t31214.php';
$original    = (string) file_get_contents( $config_file );
$had_cache   = file_exists( $cache_file ) ? (string) file_get_contents( $cache_file ) : null;
$keep        = PNCP_Options::stored();
$keep_lists  = array();
foreach ( array( 'google', 'bing', 'dc_aws' ) as $list ) {
	$keep_lists[ $list ] = get_option( PNCP_Ip::LISTS_OPTION . '_' . $list, null );
}
$keep_updated = get_option( PNCP_Ip::LISTS_OPTION . '_updated', null );
$keep_users   = array();
register_shutdown_function(
	static function () use ( $config_file, $original, $cache_file, $had_cache, $keep, $mu_file, $keep_lists, $keep_updated, &$keep_users ) {
		file_put_contents( $config_file, $original );
		if ( null === $had_cache ) {
			@unlink( $cache_file );
		} else {
			file_put_contents( $cache_file, $had_cache );
		}
		@unlink( $mu_file );
		foreach ( $keep_lists as $list => $value ) {
			if ( null === $value ) {
				delete_option( PNCP_Ip::LISTS_OPTION . '_' . $list );
			} else {
				update_option( PNCP_Ip::LISTS_OPTION . '_' . $list, $value );
			}
		}
		if ( null === $keep_updated ) {
			delete_option( PNCP_Ip::LISTS_OPTION . '_updated' );
		} else {
			update_option( PNCP_Ip::LISTS_OPTION . '_updated', $keep_updated );
		}
		PNCP_Ip::store_list( 'dc_aws', is_array( $keep_lists['dc_aws'] ) ? $keep_lists['dc_aws'] : array() );
		if ( null === $keep_lists['dc_aws'] ) {
			delete_option( PNCP_Ip::LISTS_OPTION . '_dc_aws' );
		}
		require_once ABSPATH . 'wp-admin/includes/user.php';
		foreach ( $keep_users as $id ) {
			wp_delete_user( $id );
		}
		update_option( PNCP_OPTION, $keep );
		update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
		PNCP_Options::flush();
		PNCP_Precheck::sync();
		PNCP_Log::unban_all();
	}
);

// The test mu-plugin: X-Test-Woo = WooCommerce counts as active for the payment callbacks (in every layer, also
// the early check, which loads after it); X-Test-Hv-Cap = the cap on human-check cookies per network.
file_put_contents(
	$mu_file,
	"<?php\nif ( isset( \$_SERVER['HTTP_X_TEST_WOO'] ) ) { add_filter( 'pncp_payment_webhooks_active', '__return_true' ); }\n" .
	"if ( isset( \$_SERVER['HTTP_X_TEST_NET_MIN'] ) ) { add_filter( 'pncp_network_limit_min', function () { return (int) \$_SERVER['HTTP_X_TEST_NET_MIN']; } ); }\n" .
	"if ( isset( \$_SERVER['HTTP_X_TEST_HV_CAP'] ) ) { add_filter( 'pncp_human_cookies_per_network', function () { return (int) \$_SERVER['HTTP_X_TEST_HV_CAP']; } ); }\n"
);
file_put_contents( $config_file, "<?php\ndefine( 'WP_CACHE', true ); // test cache\n" . substr( $original, 6 ) );
file_put_contents( $cache_file, "<?php\nif ( isset( \$_SERVER['REQUEST_URI'] ) && 0 === strpos( \$_SERVER['REQUEST_URI'], '/cached-page/' ) ) {\n\theader( 'X-Test-Cache: HIT' );\n\techo 'CACHED PAGE';\n\texit;\n}\n" );

update_option( PNCP_Options::EMERGENCY_OPTION, 0 );
$base_settings = array(
	'enabled'                 => 1,
	'monitor_mode'            => 0,
	'monitor_until'           => 0,
	'precheck'                => 1,
	'early_mode'              => 0,
	'rate_limit'              => 60,
	'ban_strikes'             => 0,
	'ip_header'               => 'x_real_ip',
	'block_bots'              => 1,
	'block_http_libs'         => 1,
	'block_empty_ua'          => 1,
	'block_fake_crawlers'     => 1,
	'require_browser_headers' => 0,
	'block_headless'          => 0,
	'human_check'             => 0,
	'rate_limit_unverified'   => 20,
	'rate_limit_datacenter'   => 0,
	'rate_limit_lowrep'       => 0,
	'reputation'              => 0,
	'trap_enabled'            => 0,
	'probe_ban'               => 0,
	'block_ip_host'           => 0,
	'auto_emergency'          => 0,
	'ipv6_wide'               => 0,
	'allow_ips'               => '',
	'allow_list'              => PNCP_Options::default_allow_list(), // An earlier test may have left its own.
	'trust_any_proxy'         => 0,
	'block_ips'               => '',
	'block_user_enum'         => 1,
	'block_author_archives'   => 0,
	'hotlink_originals' => 0,
);
settings( $base_settings, false );
PNCP_Precheck::load_runtime();
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
WP_Screen::get( 'settings_page_scrapelock' )->set_current_screen();
PNCP_Precheck::maybe_sync();
sleep( 3 );
t( 'setup: the pre-cache check runs (wp-config.php line, loader)', PNCP_Precheck::active() );
fresh();
// A page of the site (not cached): the pre-cache check counts it too, so the WordPress parts below turn it off.
$posts = get_posts(
	array(
		'numberposts' => 1,
		'post_status' => 'publish',
		'post_type'   => 'post',
	)
);
$page  = $posts ? (string) wp_parse_url( get_permalink( $posts[0] ), PHP_URL_PATH ) : '/';

/* ---------- A. Payment gateway callbacks ---------- */

$stripe = 'Stripe/1.0 (+https://stripe.com/docs/webhooks)';
$java   = 'Java/1.8.0_351';
settings( array( 'require_browser_headers' => 1, 'block_headless' => 1 ) );
// WordPress (explain(): the same check()).
$e = PNCP_Bots::explain( '203.0.113.21', $stripe, home_url( '/?wc-api=wc_stripe' ) );
t( 'A1 without WooCommerce, ?wc-api= is an ordinary page: "Browsers only" refuses a Stripe callback (no_browser)', 403 === $e['code'] && 'no_browser' === $e['reason'], $e['reason'] );
add_filter( 'pncp_payment_webhooks_active', '__return_true' );
$e = PNCP_Bots::explain( '203.0.113.21', $stripe, home_url( '/?wc-api=wc_stripe' ) );
t( 'A1 WooCommerce active: POST /?wc-api=wc_stripe passes "Browsers only" (pass webhook)', 0 === $e['code'] && 'webhook' === $e['pass'], $e['code'] . ' ' . $e['reason'] . $e['pass'] );
$e = PNCP_Bots::explain( '203.0.113.21', $java, home_url( '/wc-api/WC_Gateway_Paypal/' ) );
t( 'A1 /wc-api/ path with a Java User-Agent (http libraries blocked): passes', 0 === $e['code'] && 'webhook' === $e['pass'], $e['reason'] . $e['pass'] );
$e = PNCP_Bots::explain( '203.0.113.21', 'PayPal/AUHD-214.0-56789', home_url( '/wp-json/paypal/v1/incoming' ) );
t( 'A1 REST webhook (PayPal Payments) passes', 0 === $e['code'] && 'webhook' === $e['pass'], $e['context'] . ' ' . $e['reason'] . $e['pass'] );
$e = PNCP_Bots::explain( '203.0.113.21', $stripe, home_url( '/?wc-api=' ) );
t( 'A1 an empty ?wc-api= is not a callback: refused as before', 403 === $e['code'], $e['reason'] );
$e = PNCP_Bots::explain( '203.0.113.21', $stripe, home_url( '/my-wc-api-guide/' ) );
t( 'A1 a page whose slug merely contains "wc-api": refused as before', 403 === $e['code'], $e['reason'] );
PNCP_Options::set_emergency( 1, false );
PNCP_Options::flush();
$e = PNCP_Bots::explain( '203.0.113.21', $stripe, home_url( '/?wc-api=wc_stripe' ) );
t( 'A1 Emergency Mode: the callback still passes', 0 === $e['code'] && 'webhook' === $e['pass'], $e['reason'] );
$e = PNCP_Bots::explain( '203.0.113.21', $stripe, home_url( $page ) );
t( 'A1 Emergency Mode: the same client on a page is refused (no_browser)', 403 === $e['code'] && 'no_browser' === $e['reason'], $e['reason'] );
PNCP_Options::set_emergency( 0, false );
PNCP_Options::flush();
// Over HTTP (the server sees WooCommerce as active through X-Test-Woo).
$woo = array( 'X-Test-Woo' => '1' );
list( $code ) = req( '/?wc-api=wc_stripe', client( '203.0.113.22', $stripe, $woo ), 'POST', '', '{"id":"evt_1"}' );
t( 'A2 HTTP POST /?wc-api=wc_stripe (Stripe, no browser headers): not refused', 403 !== $code && 429 !== $code, (string) $code );
list( $code ) = req( '/?wc-api=wc_stripe', client( '203.0.113.22', $stripe ), 'POST', '', '{"id":"evt_1"}' );
t( 'A2 ... without WooCommerce: 403 as before', 403 === $code, (string) $code );
PNCP_Options::set_emergency( 1, false );
sleep( 3 );
list( $code ) = req( '/?wc-api=WC_Gateway_Paypal', client( '203.0.113.23', 'PayPal IPN ( https://www.paypal.com/ipn )', $woo ), 'POST', '', 'txn_id=1' );
t( 'A2 Emergency Mode: PayPal IPN POST not refused', 403 !== $code && 429 !== $code, (string) $code );
$c = codes( '/?wc-api=wc_stripe', client( '203.0.113.24', $stripe, $woo ), 25 );
t( 'A2 Emergency Mode: 25 callbacks of one gateway in a minute (page limit 20): none refused, also by the pre-cache check', ! array_intersect( array( 403, 429 ), $c ), implode( ',', array_count_values( array_map( 'strval', $c ) ) ? array_map( 'strval', $c ) : array() ) );
PNCP_Options::set_emergency( 0, false );
// The early check (GET, before the other plugins): a callback with a Java User-Agent.
settings( array( 'early_mode' => 1 ) );
list( $code ) = req( '/?wc-api=wc_gateway_bank', client( '203.0.113.25', $java, $woo ) );
t( 'A3 early check: GET /?wc-api= with a Java User-Agent not refused', 403 !== $code, (string) $code );
list( $code, $h ) = req( $page, client( '203.0.113.25', $java, $woo ) );
t( 'A3 early check: the same client on a page is refused', 403 === $code, (string) $code );
settings( array( 'early_mode' => 0 ) );
// The pre-cache check: its configuration has the markers while WooCommerce is active.
PNCP_Precheck::sync();
$pc = json_decode( (string) file_get_contents( PNCP_Precheck::config_file() ), true );
t( 'A4 pre-cache configuration: the callback markers while WooCommerce is active', isset( $pc['webhooks']['query'] ) && in_array( 'wc-api', $pc['webhooks']['query'], true ), wp_json_encode( isset( $pc['webhooks'] ) ? $pc['webhooks'] : null ) );
settings( array( 'rate_limit' => 3, 'require_browser_headers' => 1 ) );
same_minute();
$c = codes( '/cached-page/?wc-api=wc_stripe', client( '203.0.113.26', $stripe ), 6 );
t( 'A4 pre-cache check: 6 callbacks with page limit 3: never 429', ! in_array( 429, $c, true ), implode( ',', $c ) );
$c = codes( '/cached-page/', client( '203.0.113.26', $stripe ), 4 );
t( 'A4 ... while the same IP on a cached page is limited as before', in_array( 429, $c, true ), implode( ',', $c ) );
// The server rules.
settings( array( 'rate_limit' => 60, 'require_browser_headers' => 1, 'block_headless' => 1 ), false );
$r = PNCP_Rules::evaluate( array( 'ua' => $java, 'path' => '/?wc-api=wc_gateway_bank' ) );
t( 'A5 Nginx rules (evaluate()): a Java callback to /?wc-api= is not refused', null === $r, wp_json_encode( $r ) );
$r = PNCP_Rules::evaluate( array( 'ua' => $java, 'path' => '/wc-api/wc_gateway_bank/' ) );
t( 'A5 ... nor to /wc-api/…', null === $r, wp_json_encode( $r ) );
$r = PNCP_Rules::evaluate( array( 'ua' => $java, 'path' => $page ) );
t( 'A5 ... the same User-Agent on a page: the bot list', is_array( $r ) && 'bad_bot' === $r['rule'], wp_json_encode( $r ) );
$http = PNCP_Rules::nginx_http();
t( 'A5 Nginx part 1: a webhook map, the default of the open-path map', false !== strpos( $http, 'map $request_uri $' ) && (bool) preg_match( '/\$pncp_open_path_\S+ \{\n    default \$pncp_webhook_/', $http ) );
$apache = PNCP_Rules::apache();
t( 'A5 Apache: the bot and fake-browser rules leave out ?wc-api= and /wc-api/', false !== strpos( $apache, 'RewriteCond %{QUERY_STRING} !(?:^|&)wc\-api=[^&] [NC]' ) && false !== strpos( $apache, '/wc\-api/' ) );
remove_filter( 'pncp_payment_webhooks_active', '__return_true' );
t( 'A5 without WooCommerce: no webhook lines in the rules', false === strpos( PNCP_Rules::nginx_http(), '$request_uri' ) && false === strpos( PNCP_Rules::apache(), 'wc\-api' ) );
settings( $base_settings );
fresh();

/* ---------- B. Fake Googlebot on cached pages; the Nginx geo ---------- */

$gbot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
delete_option( PNCP_Ip::LISTS_OPTION . '_google' );
delete_option( PNCP_Ip::LISTS_OPTION . '_bing' );
settings( array( 'rate_limit' => 5 ) );
PNCP_Precheck::sync();
sleep( 3 );
same_minute();
list( $code, $h, $body ) = req( '/cached-page/', client( '203.0.113.31', $gbot ) );
t( 'B1 no Google list loaded: a "Googlebot" on a cached page is counted, not refused (unverified)', 200 === $code && 'CACHED PAGE' === $body, (string) $code );
PNCP_Ip::store_list( 'google', array( '66.249.64.0/19', '2001:4860:4801::/48' ) );
PNCP_Ip::store_list( 'bing', array( '157.55.39.0/24' ) );
PNCP_Ip::reset();
PNCP_Precheck::sync();
sleep( 3 );
list( $code, $h, $body ) = req( '/cached-page/', client( '203.0.113.32', $gbot ) );
t( 'B2 list loaded: a fake Googlebot on a cached page gets 403 from the pre-cache check', 403 === $code && 'Access denied.' === $body, $code . ' ' . substr( $body, 0, 40 ) );
t( 'B2 ... logged as fake_crawler', '403 fake_crawler' === pc_event( '203.0.113.32' ), pc_event( '203.0.113.32' ) );
list( $code, $h, $body ) = req( '/cached-page/', client( '66.249.66.1', $gbot ) );
t( 'B2 the real Googlebot (address on the list): the cached page', 200 === $code && 'CACHED PAGE' === $body, (string) $code );
list( $code ) = req( '/cached-page/', client( '203.0.113.33', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' ) );
t( 'B2 a fake Bingbot: 403', 403 === $code, (string) $code );
settings( array( 'block_fake_crawlers' => 0 ) );
list( $code ) = req( '/cached-page/', client( '203.0.113.34', $gbot ) );
t( 'B2 "Block fake search engines" off: counted, not refused', 200 === $code, (string) $code );
settings( array( 'block_fake_crawlers' => 1 ) );
$updated           = (array) get_option( PNCP_Ip::LISTS_OPTION . '_updated', array() );
$updated['google'] = time() - 8 * DAY_IN_SECONDS;
update_option( PNCP_Ip::LISTS_OPTION . '_updated', $updated );
PNCP_Precheck::sync();
sleep( 3 );
list( $code ) = req( '/cached-page/', client( '203.0.113.35', $gbot ) );
t( 'B3 a Google list not refreshed for 8 days: not refused here (WordPress decides with the DNS)', 200 === $code, (string) $code );
$updated['google'] = time();
update_option( PNCP_Ip::LISTS_OPTION . '_updated', $updated );
PNCP_Precheck::sync();
// Nginx.
$http = PNCP_Rules::nginx_http();
t( 'B4 Nginx part 1: a geo of the official ranges (Google g, Bing b)', false !== strpos( $http, "    66.249.64.0/19 g;\n" ) && false !== strpos( $http, "    157.55.39.0/24 b;\n" ) && false !== strpos( $http, '$time_iso8601' ), substr( $http, 0, 200 ) );
$r = PNCP_Rules::evaluate( array( 'ua' => $gbot, 'path' => '/', 'remote' => '203.0.113.36' ) );
t( 'B4 Nginx: a fake Googlebot straight from the visitor: refused (fake_crawler)', is_array( $r ) && 'fake_crawler' === $r['rule'], wp_json_encode( $r ) );
$r = PNCP_Rules::evaluate( array( 'ua' => $gbot, 'path' => '/', 'remote' => '66.249.66.1' ) );
t( 'B4 Nginx: the real Googlebot passes', null === $r, wp_json_encode( $r ) );
$r = PNCP_Rules::evaluate(
	array(
		'ua'      => $gbot,
		'path'    => '/',
		'remote'  => '203.0.113.36',
		'headers' => array( 'X-Forwarded-For' => '66.249.66.1' ),
	)
);
t( 'B4 Nginx: through a proxy (X-Forwarded-For) never refused there ($remote_addr may not be the visitor)', null === $r, wp_json_encode( $r ) );
$before = PNCP_Rules::nginx_fingerprint();
PNCP_Ip::store_list( 'google', array( '66.249.64.0/19', '2001:4860:4801::/48', '192.178.5.0/27' ) );
PNCP_Ip::reset();
t( 'B4 Nginx: a new range in the list does not make the rules "out of date" (the geo is outside the fingerprint)', PNCP_Rules::nginx_fingerprint() === $before );
t( 'B4 Nginx: the rules stay a reasonable size', strlen( PNCP_Rules::nginx_http() ) < 60000, (string) strlen( PNCP_Rules::nginx_http() ) );
settings( array( 'block_fake_crawlers' => 0 ), false );
t( 'B4 Nginx: no geo with "Block fake search engines" off', false === strpos( PNCP_Rules::nginx_http(), 'crawler_ip' ) );
settings( $base_settings );
fresh();

/* ---------- C. Browser headers that do not fit the User-Agent ---------- */

$hd = static function ( $hints, $platform = '"Windows"', $fetch = true ) {
	$h = array(
		'sec-ch-ua'          => $hints,
		'sec-ch-ua-platform' => $platform,
	);
	if ( $fetch ) {
		$h += array(
			'sec-fetch-site' => 'none',
			'sec-fetch-mode' => 'navigate',
			'sec-fetch-dest' => 'document',
		);
	}
	return $h;
};
$c142    = '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"';
$android = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36';
$desk    = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36';
$ff      = 'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0';
$safari  = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15';
$cases   = array(
	'real Chrome on Windows'                              => array( CHROME, $hd( $c142 ), true, '' ),
	'Playwright: Chrome 131 with the User-Agent of 142'   => array( CHROME, $hd( '"Chromium";v="131", "Not_A Brand";v="24"', '"Linux"' ), true, 'version' ),
	'platform Linux, User-Agent Windows'                  => array( CHROME, $hd( $c142, '"Linux"' ), true, 'platform' ),
	'Chrome for Android, "Desktop site" (Linux UA)'       => array( $desk, $hd( $c142, '"Android"' ), true, '' ),
	'Chrome for Android'                                  => array( $android, $hd( $c142, '"Android"' ), true, '' ),
	'Edge'                                                => array( CHROME . ' Edg/142.0.0.0', $hd( '"Microsoft Edge";v="142", "Chromium";v="142", "Not_A Brand";v="99"' ), true, '' ),
	'Opera (Chromium 141, Opera 125)'                     => array( str_replace( '142.0.0.0', '141.0.0.0', CHROME ) . ' OPR/125.0.0.0', $hd( '"Opera";v="125", "Chromium";v="141", "Not_A Brand";v="24"' ), true, '' ),
	'Chrome, Sec-Fetch-Mode but no Sec-CH-UA'             => array( CHROME, array( 'sec-fetch-mode' => 'navigate', 'sec-fetch-site' => 'none', 'sec-fetch-dest' => 'document' ), true, 'missing' ),
	'Chrome, hints but no Sec-Fetch-*'                    => array( CHROME, $hd( $c142, '"Windows"', false ), true, 'missing' ),
	'Chrome, Sec-Fetch-Mode "x"'                          => array( CHROME, array_merge( $hd( $c142 ), array( 'sec-fetch-mode' => 'x' ) ), true, 'implausible' ),
	'Chrome, only GREASE in Sec-CH-UA'                    => array( CHROME, $hd( '"Not_A Brand";v="99"' ), true, 'implausible' ),
	'Firefox with Sec-Fetch-*'                            => array( $ff, $hd( '', '' ), true, '' ),
	'Firefox without Sec-Fetch-Site'                      => array( $ff, array( 'sec-fetch-mode' => 'navigate' ), true, 'missing' ),
	'Firefox UA with Sec-CH-UA (a switcher in Chrome)'    => array( $ff, $hd( $c142 ), true, 'engine' ),
	'Safari 18 without Sec-Fetch-*'                       => array( $safari, array(), true, 'missing' ),
	'Safari 18 with Sec-Fetch-*'                          => array( $safari, $hd( '', '' ), true, '' ),
	'Safari 16.3 (before Sec-Fetch)'                      => array( str_replace( 'Version/18.1', 'Version/16.3', $safari ), array(), true, '' ),
	'plain HTTP: nothing checked'                         => array( CHROME, array(), false, '' ),
	'Android WebView: nothing checked'                    => array( 'Mozilla/5.0 (Linux; Android 14; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/142.0.0.0 Mobile Safari/537.36', array(), true, '' ),
	'Chrome 89: nothing checked'                          => array( str_replace( '142.0.0.0', '89.0.4389.90', CHROME ), array(), true, '' ),
);
foreach ( $cases as $label => $case ) {
	$wp = PNCP_Bots::header_mismatch( $case[0], $case[1], $case[2] );
	$pc = PNCP_Precheck_Runtime::header_mismatch( $case[0], $case[1], $case[2] );
	t( "C1 $label: '" . $case[3] . "' in WordPress and in the pre-cache check", $case[3] === $wp && $wp === $pc, "wp=$wp pc=$pc" );
}
// WordPress: a mismatch gets the stricter limit, not a 403.
precheck( false );
settings( array( 'block_headless' => 1, 'rate_limit_unverified' => 3 ) );
same_minute();
$pw = chrome( '203.0.113.41', array( 'Sec-CH-UA' => '"Chromium";v="131", "Not_A Brand";v="24"', 'Sec-CH-UA-Platform' => '"Linux"' ) );
$c  = codes( $page, $pw, 5 );
t( 'C2 WordPress: a Chrome whose Sec-CH-UA does not fit its User-Agent: 3 pages, then 429 (not 403)', array( 200, 200, 200, 429, 429 ) === $c, implode( ',', $c ) );
t( 'C2 ... logged as rate_mismatch, no violation', 'rate_mismatch' === wp_reason( '203.0.113.41' ) && ! PNCP_Log::is_banned( '203.0.113.41' ), wp_reason( '203.0.113.41' ) );
$c = codes( $page, chrome( '203.0.113.42' ), 5 );
t( 'C2 a real Chrome with the same settings: 5 pages, no limit', array( 200, 200, 200, 200, 200 ) === $c, implode( ',', $c ) );
PNCP_Ip::store_list( 'dc_aws', array( '198.18.250.0/24' ) );
PNCP_Ip::reset();
list( $code ) = req( $page, array_merge( $pw, array( 'X-Real-IP' => '198.18.250.7', 'X-Test-IP' => '198.18.250.7' ) ) );
t( 'C2 a mismatch from a data center: 403 fake_browser (two bad signs)', 403 === $code && 'fake_browser' === wp_reason( '198.18.250.7' ), $code . ' ' . wp_reason( '198.18.250.7' ) );
list( $code ) = req( $page, chrome( '198.18.250.8' ) );
t( 'C2 a real Chrome from the same data center: 200', 200 === $code, (string) $code );
PNCP_Ip::store_list( 'dc_aws', array() );
// The pre-cache check: the same.
precheck( true );
$c = codes( '/cached-page/', chrome( '203.0.113.43', array( 'Sec-CH-UA' => '"Chromium";v="131", "Not_A Brand";v="24"', 'Sec-CH-UA-Platform' => '"Linux"' ) ), 5 );
t( 'C3 pre-cache check: the mismatch on a cached page: 3 pages, then 429 (not 403)', array( 200, 200, 200, 429, 429 ) === $c, implode( ',', $c ) );
t( 'C3 ... reason rate_mismatch', '429 rate_mismatch' === pc_event( '203.0.113.43' ), pc_event( '203.0.113.43' ) );
list( $code ) = req( '/cached-page/', chrome( '203.0.113.44', array( 'Sec-CH-UA' => '"HeadlessChrome";v="142", "Chromium";v="142"' ) ) );
t( 'C3 pre-cache check: HeadlessChrome in Sec-CH-UA: 403 (before: the cached page)', 403 === $code && '403 headless' === pc_event( '203.0.113.44' ), $code . ' ' . pc_event( '203.0.113.44' ) );
list( $code ) = req( '/cached-page/', client( '203.0.113.45', CHROME, array( 'X-Test-HTTPS' => '1', 'Accept-Language' => 'en' ) ) );
t( 'C3 pre-cache check: a Chrome User-Agent over HTTPS without any browser header: 403 fake_browser', 403 === $code && '403 fake_browser' === pc_event( '203.0.113.45' ), $code . ' ' . pc_event( '203.0.113.45' ) );
$c = codes( '/cached-page/', chrome( '203.0.113.46' ), 5 );
t( 'C3 pre-cache check: a real Chrome: 5 cached pages', array( 200, 200, 200, 200, 200 ) === $c, implode( ',', $c ) );
list( $code ) = req( '/cached-page/', client( '203.0.113.47', CHROME, array( 'Accept-Language' => 'en' ) ) );
t( 'C3 pre-cache check: plain HTTP is not checked', 200 === $code, (string) $code );
settings( array( 'block_headless' => 0 ) );
list( $code ) = req( '/cached-page/', chrome( '203.0.113.48', array( 'Sec-CH-UA' => '"HeadlessChrome";v="142"' ) ) );
t( 'C3 "Block headless browsers" off: nothing refused for the headers', 200 === $code, (string) $code );
settings( $base_settings );
fresh();

/* ---------- D. The network limit (IPv4 /24, IPv6 /48) ---------- */

// The network limit is never below 100 pages a minute (NETWORK_MIN): 0 here, so 4 × 5 = 20 can be tested.
t( 'D0 the network limit: 5 × the page limit, at least 100', 300 === PNCP_Bots::network_limit( 60 ) && 100 === PNCP_Bots::network_limit( 4 ) && 0 === PNCP_Bots::network_limit( 0 ) );
add_filter( 'pncp_network_limit_min', '__return_zero' );
$nmin = array( 'X-Test-Net-Min' => '0' );
precheck( false );
settings( array( 'rate_limit' => 4 ) );
same_minute( 40 );
$c = array();
for ( $i = 1; $i <= 24; $i++ ) {
	$c[] = req( $page, chrome( '198.51.77.' . $i, $nmin ) )[0];
}
t( 'D1 WordPress: 24 addresses of one /24, one page each (limit 4 → network 20): 20 pages, then 429', 20 === count( array_keys( $c, 200, true ) ) && 429 === $c[20], implode( ',', $c ) );
t( 'D1 ... reason rate_net, no ban', 'rate_net' === wp_reason( '198.51.77.24' ) && ! PNCP_Log::is_banned( '198.51.77.24' ), wp_reason( '198.51.77.24' ) );
// A human-check cookie holder of the same /24 is not counted.
$_SERVER['HTTP_USER_AGENT'] = CHROME;
$hv                         = PNCP_Human::COOKIE . '=' . PNCP_Human::cookie_value( '198.51.77.30' ) . '; ' . PNCP_Human::PC_COOKIE . '=' . PNCP_Human::pc_value( '198.51.77.30' );
list( $code ) = req( $page, chrome( '198.51.77.30', $nmin ), 'GET', $hv );
t( 'D1 a visitor of that /24 with the human-check cookie: 200', 200 === $code, (string) $code );
list( $code ) = req( $page, chrome( '198.51.77.31', $nmin ) );
t( 'D1 ... one without it: 429', 429 === $code, (string) $code );
// A signed-in member.
$uid          = wp_insert_user(
	array(
		'user_login' => 't31214_member',
		'user_pass'  => wp_generate_password(),
		'role'       => 'subscriber',
	)
);
$keep_users[] = $uid;
$logged       = LOGGED_IN_COOKIE . '=' . rawurlencode( wp_generate_auth_cookie( $uid, time() + HOUR_IN_SECONDS, 'logged_in' ) );
list( $code ) = req( $page, chrome( '198.51.77.32', $nmin ), 'GET', $logged );
t( 'D1 a signed-in member of that /24: 200', 200 === $code, (string) $code );
// IPv6: one /48, a new /56 each time.
$c = array();
for ( $i = 1; $i <= 24; $i++ ) {
	$c[] = req( $page, chrome( sprintf( '2001:db8:77:%x00::1', $i ), $nmin ) )[0];
}
t( 'D2 WordPress: IPv6, 24 new /56 networks of one /48: 20 pages, then 429', 20 === count( array_keys( $c, 200, true ) ) && 429 === $c[20], implode( ',', $c ) );
// The pre-cache check.
precheck( true );
$c = array();
for ( $i = 1; $i <= 24; $i++ ) {
	$c[] = req( '/cached-page/', chrome( '198.51.78.' . $i ) )[0];
}
t( 'D3 pre-cache check: 24 addresses of one /24 on a cached page: 20, then 429', 20 === count( array_keys( $c, 200, true ) ) && 429 === $c[20], implode( ',', $c ) );
t( 'D3 ... reason rate_net', '429 rate_net' === pc_event( '198.51.78.24' ), pc_event( '198.51.78.24' ) );
add_filter( 'pncp_network_limit_factor', '__return_zero' );
PNCP_Precheck::sync();
remove_filter( 'pncp_network_limit_factor', '__return_zero' );
sleep( 3 );
list( $code ) = req( '/cached-page/', chrome( '198.51.78.30' ) );
t( 'D3 filter pncp_network_limit_factor 0: no network limit', 200 === $code, (string) $code );
remove_filter( 'pncp_network_limit_min', '__return_zero' );
PNCP_Precheck::sync();
settings( $base_settings );
fresh();

/* ---------- E. The human check ---------- */

settings( array( 'human_check' => 1, 'reputation' => 1 ) );
$_SERVER['HTTP_USER_AGENT'] = CHROME;
foreach ( array( 'HTTP_SEC_CH_UA', 'HTTP_SEC_CH_UA_PLATFORM', 'HTTP_SEC_FETCH_SITE', 'HTTP_SEC_FETCH_MODE', 'HTTP_SEC_FETCH_DEST' ) as $key ) {
	unset( $_SERVER[ $key ] );
}
$_SERVER['HTTP_SEC_CH_UA']          = '"Chromium";v="142", "Not_A Brand";v="99"';
$_SERVER['HTTP_SEC_CH_UA_PLATFORM'] = '"Windows"';
$_SERVER['HTTP_SEC_FETCH_SITE']     = 'same-origin';
$_SERVER['HTTP_SEC_FETCH_MODE']     = 'cors';
$_SERVER['HTTP_SEC_FETCH_DEST']     = 'empty';
$_SERVER['HTTPS']                   = 'on';
t( 'E1 a normal browser at home: difficulty 3 (unchanged), cookie for 7 days', 3 === PNCP_Human::difficulty( '203.0.113.51' ) && 7 * DAY_IN_SECONDS === PNCP_Human::cookie_seconds( '203.0.113.51' ), PNCP_Human::difficulty( '203.0.113.51' ) );
PNCP_Ip::store_list( 'dc_aws', array( '198.18.251.0/24' ) );
PNCP_Ip::reset();
t( 'E1 from a data center: difficulty 4, cookie for 4 hours', 4 === PNCP_Human::difficulty( '198.18.251.9' ) && 4 * HOUR_IN_SECONDS === PNCP_Human::cookie_seconds( '198.18.251.9' ), PNCP_Human::difficulty( '198.18.251.9' ) . ' ' . PNCP_Human::cookie_seconds( '198.18.251.9' ) );
$_SERVER['HTTP_SEC_CH_UA_PLATFORM'] = '"Linux"';
t( 'E1 data center + headers that do not fit: difficulty 5', 5 === PNCP_Human::difficulty( '198.18.251.9' ) );
t( 'E1 headers that do not fit alone: difficulty 4', 4 === PNCP_Human::difficulty( '203.0.113.51' ) );
$_SERVER['HTTP_SEC_CH_UA_PLATFORM'] = '"Windows"';
PNCP_Ip::store_list( 'dc_aws', array() );
PNCP_Ip::reset();
$chal  = PNCP_Human::challenge( '203.0.113.52', 4 );
$parts = explode( '.', $chal );
t( 'E2 a challenge carries its difficulty, signed: time.difficulty.random.signature', 4 === count( $parts ) && '4' === $parts[1] );
$n = 0;
while ( 0 !== strpos( hash( 'sha256', $chal . $n ), '000' ) ) {
	++$n;
}
$four = 0 === strpos( hash( 'sha256', $chal . $n ), '0000' );
t( 'E2 an answer with 3 zeros to a difficulty-4 challenge is refused (unless it happens to have 4)', $four === PNCP_Human::check_answer( $chal, (string) $n, '203.0.113.52' ) );
$m = 0;
while ( 0 !== strpos( hash( 'sha256', $chal . $m ), '0000' ) ) {
	++$m;
}
t( 'E2 the right answer to the difficulty-4 challenge is accepted', PNCP_Human::check_answer( $chal, (string) $m, '203.0.113.52' ) );
$forged    = $parts;
$forged[1] = '1';
t( 'E2 a challenge whose difficulty was lowered by the client: refused (signature)', ! PNCP_Human::check_answer( implode( '.', $forged ), '0', '203.0.113.52' ) );
// The cap on cookies per network (lowered to 3 for the test through X-Test-Hv-Cap).
$got = array();
for ( $i = 1; $i <= 4; $i++ ) {
	$ip  = '198.51.79.' . $i;
	$h   = chrome( $ip, array( 'X-Test-Hv-Cap' => '3' ) );
	$res = req( '/wp-admin/admin-ajax.php?action=pncp_hv', $h );
	$j   = json_decode( $res[2], true );
	$ch  = isset( $j['data']['c'] ) ? (string) $j['data']['c'] : '';
	$d   = isset( $j['data']['d'] ) ? (int) $j['data']['d'] : 3;
	$n   = 0;
	while ( '' !== $ch && 0 !== strpos( hash( 'sha256', $ch . $n ), str_repeat( '0', $d ) ) ) {
		++$n;
	}
	$res   = req( '/wp-admin/admin-ajax.php', array_merge( $h, array( 'Content-Type' => 'application/x-www-form-urlencoded' ) ), 'POST', '', http_build_query( array( 'action' => 'pncp_hv', 'c' => $ch, 'n' => $n ) ) );
	$got[] = $res[0] . ( false !== strpos( $res[1], 'set-cookie: pncp_hv=' ) ? '+cookie' : '' );
}
t( 'E3 4 addresses of one /24 solve the proof of work (cap 3 an hour): 3 cookies, then 429 without one', array( '200+cookie', '200+cookie', '200+cookie', '429' ) === $got, implode( ',', $got ) );
list( $code, $h ) = req( '/wp-admin/admin-ajax.php?action=pncp_hv', chrome( '198.51.80.1' ) );
$j = json_decode( req( '/wp-admin/admin-ajax.php?action=pncp_hv', chrome( '198.51.80.2' ) )[2], true );
t( 'E3 a normal browser asks for a challenge: difficulty 3', isset( $j['data']['d'] ) && 3 === (int) $j['data']['d'], wp_json_encode( $j ) );
$j = json_decode( req( '/wp-admin/admin-ajax.php?action=pncp_hv', chrome( '198.51.80.3', array( 'Sec-CH-UA-Platform' => '"Linux"' ) ) )[2], true );
t( 'E3 a browser whose headers do not fit: difficulty 4', isset( $j['data']['d'] ) && 4 === (int) $j['data']['d'], wp_json_encode( $j ) );
unset( $_SERVER['HTTPS'] );
settings( $base_settings );
fresh();

/* ---------- F. "Always allowed" User-Agents without an address that confirms them ---------- */

precheck( false );
settings( array( 'human_check' => 1, 'rate_limit_unverified' => 2, 'block_headless' => 1 ) );
same_minute();
$fb = 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)';
$c  = codes( $page, client( '203.0.113.61', $fb ), 4 );
t( 'F1 a "facebookexternalhit" from a stranger\'s address: the stricter limit of the human check (2, then 429)', array( 200, 200, 429, 429 ) === $c, implode( ',', $c ) );
$c = codes( $page, client( '69.171.250.1', $fb ), 4 );
t( 'F1 the real one, from Meta\'s network: never the stricter limit', array( 200, 200, 200, 200 ) === $c, implode( ',', $c ) );
precheck( true );
$c = codes( '/cached-page/', client( '203.0.113.62', $fb ), 4 );
t( 'F1 pre-cache check: the same (2, then 429)', array( 200, 200, 429, 429 ) === $c, implode( ',', $c ) );
$c = codes( '/cached-page/', client( '69.171.250.2', $fb ), 4 );
t( 'F1 pre-cache check: from Meta\'s network: 4 pages', array( 200, 200, 200, 200 ) === $c, implode( ',', $c ) );
$spoof = CHROME . ' facebookexternalhit/1.1';
list( $code ) = req( $page, client( '203.0.113.63', $spoof, array( 'X-Test-HTTPS' => '1', 'Accept-Language' => 'en' ) ) );
t( 'F2 a Chrome User-Agent with "facebookexternalhit" added and no browser header: 403 fake_browser (before: passed)', 403 === $code, (string) $code );
list( $code ) = req( '/cached-page/', client( '203.0.113.64', $spoof, array( 'X-Test-HTTPS' => '1', 'Accept-Language' => 'en' ) ) );
t( 'F2 ... also on a cached page', 403 === $code, (string) $code );
list( $code ) = req( $page, client( '69.171.250.3', $spoof, array( 'X-Test-HTTPS' => '1', 'Accept-Language' => 'en' ) ) );
t( 'F2 ... from Meta\'s network: passes', 200 === $code, (string) $code );
settings( array( 'require_browser_headers' => 1, 'human_check' => 0 ) );
list( $code ) = req( $page, client( '203.0.113.65', 'Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)' ) );
t( 'F3 "Browsers only" on: an uptime monitor of the "Always allowed" list still gets the page', 200 === $code, (string) $code );
list( $code ) = req( $page, client( '203.0.113.66', 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)' ) );
t( 'F3 ... and Slackbot (not pinned: a normal visitor, not refused)', 200 === $code, (string) $code );
t( 'F4 the networks of the link previews (Meta, X, LinkedIn) are built in; Slack is not pinned', PNCP_Bots::preview_pinned( 'Twitterbot/1.0', '199.16.156.10' ) && PNCP_Bots::preview_pinned( 'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)', '108.174.2.9' ) && ! PNCP_Bots::preview_pinned( 'Twitterbot/1.0', '203.0.113.9' ) && ! PNCP_Bots::preview_pinned( 'Slackbot 1.0', '3.3.3.3' ) );
settings( $base_settings );
fresh();

/* ---------- G. New-install defaults, presets ---------- */

$new = array_merge( PNCP_Options::defaults(), PNCP_Options::new_install() );
t( 'G1 a new install: excerpts in lists and hidden author archives on', 1 === (int) $new['list_excerpts'] && 1 === (int) $new['block_author_archives'] );
t( 'G1 an existing site (settings stored before, without the keys): both stay off', 0 === (int) PNCP_Options::defaults()['list_excerpts'] && 0 === (int) PNCP_Options::defaults()['block_author_archives'] );
$stored = get_option( PNCP_OPTION );
unset( $stored['list_excerpts'], $stored['block_author_archives'] );
update_option( PNCP_OPTION, $stored );
PNCP_Options::flush();
t( 'G1 ... read back (stored()): off', 0 === (int) PNCP_Options::stored()['list_excerpts'] && 0 === (int) PNCP_Options::stored()['block_author_archives'] );
$profiles = PNCP_Options::profiles();
t( 'G2 the Balanced, Strict and Maximum presets turn excerpts in lists on', 1 === $profiles['balanced']['list_excerpts'] && 1 === $profiles['strict']['list_excerpts'] && 1 === $profiles['maximum']['list_excerpts'] );
$up = PNCP_Options::upgrade_values();
t( 'G2 the settings page says sites installed before 3.13.0 have them off', isset( $up['list_excerpts'], $up['block_author_archives'] ) && '3.13.0' === $up['list_excerpts']['since'] && 0 === (int) $up['list_excerpts']['value'], wp_json_encode( isset( $up['list_excerpts'] ) ? $up['list_excerpts'] : null ) );
settings( $base_settings, false );

/* ---------- H. New AI names ---------- */

$agents = PNCP_Options::blocked_agents( PNCP_Options::get() );
foreach ( array( 'ProRataInc', 'Novellum', 'wpbot', 'magpie-crawler', 'YisouSpider' ) as $name ) {
	$e = PNCP_Bots::explain( '203.0.113.71', 'Mozilla/5.0 (compatible; ' . $name . '/1.0; +https://example.com/bot)', home_url( '/' ) );
	t( "H1 $name: blocked by name (bot_ua) and asked in robots.txt", 403 === $e['code'] && 'bot_ua' === $e['reason'] && in_array( strtolower( $name ), array_map( 'strtolower', PNCP_Bots::robots_agents() ), true ), $e['reason'] );
}

/* ---------- I. Sliding window ---------- */

/** Codes of 5 requests at second 56 of a minute and of 5 more at second 2 of the next one. */
function across_minute( $path, $headers ) {
	sleep( ( 56 - time() % 60 + 60 ) % 60 );
	$before = codes( $path, $headers, 5 );
	sleep( ( 62 - time() % 60 ) % 60 );
	return array( $before, codes( $path, $headers, 5 ) );
}
settings( array( 'rate_limit' => 5 ) );
precheck( false );
fresh();
list( $before, $after ) = across_minute( $page, chrome( '203.0.113.81' ) );
t( 'I1 WordPress: 5 pages just before the minute turns (limit 5), then 5 just after: at most 1 more passes (before: 5)', array( 200, 200, 200, 200, 200 ) === $before && count( array_keys( $after, 200, true ) ) <= 1, implode( ',', $before ) . ' | ' . implode( ',', $after ) );
precheck( true );
list( $before, $after ) = across_minute( '/cached-page/', chrome( '203.0.113.82' ) );
t( 'I1 pre-cache check: the same on a cached page', array( 200, 200, 200, 200, 200 ) === $before && count( array_keys( $after, 200, true ) ) <= 1, implode( ',', $before ) . ' | ' . implode( ',', $after ) );
settings( $base_settings, false );
fresh();

/* ---------- J. /author/<slug>/ ---------- */

$admin = get_user_by( 'id', 1 );
$slug  = $admin ? $admin->user_nicename : 'admin';
list( $code, $h, $body ) = req( '/author/' . $slug . '/', chrome( '203.0.113.91' ) );
t( 'J1 "Hide the author archives too" off (existing sites): /author/' . $slug . '/ as before (200)', 200 === $code, (string) $code );
settings( array( 'block_author_archives' => 1 ) );
list( $code, $h, $body ) = req( '/author/' . $slug . '/', chrome( '203.0.113.92' ) );
t( 'J2 on: /author/' . $slug . '/ is "page not found" (404), the slug is not in the page', 404 === $code && false === strpos( $body, 'author-' . $slug ), (string) $code );
list( $code, $h, $body ) = req( '/author/nobody-' . wp_rand() . '/', chrome( '203.0.113.93' ) );
t( 'J2 ... like an author that does not exist (no way to tell them apart)', 404 === $code, (string) $code );
list( $code, $h, $body ) = req( $page, chrome( '203.0.113.94' ) );
t( 'J2 a post: no link to /author/' . $slug . '/', 200 === $code && false === strpos( $body, '/author/' . $slug . '/' ), (string) $code );
settings( array( 'block_user_enum' => 0 ) );
list( $code ) = req( '/author/' . $slug . '/', chrome( '203.0.113.95' ) );
t( 'J3 only with "Hide usernames": off, the archive is back', 200 === $code, (string) $code );
settings( $base_settings, false );

/* ---------- K. Hotlink: full-size originals without a Referer ---------- */

$up_path = (string) wp_parse_url( wp_upload_dir( null, false )['baseurl'], PHP_URL_PATH );
$orig    = $up_path . '/2026/11/photo.jpg';
$sized   = $up_path . '/2026/11/photo-300x200.jpg';
$r       = PNCP_Rules::evaluate( array( 'path' => $orig, 'ua' => CHROME ) );
t( 'K1 option off (the default): an original without a Referer passes, as before', null === $r, wp_json_encode( $r ) );
settings( array( 'hotlink_originals' => 1 ), false );
$r = PNCP_Rules::evaluate( array( 'path' => $orig, 'ua' => CHROME ) );
t( 'K2 on: an original without a Referer: 403 (hotlink_original)', is_array( $r ) && 'hotlink_original' === $r['rule'] && 403 === $r['code'], wp_json_encode( $r ) );
$r = PNCP_Rules::evaluate( array( 'path' => $sized, 'ua' => CHROME ) );
t( 'K2 ... a smaller size (-300x200) without a Referer still loads', null === $r, wp_json_encode( $r ) );
$r = PNCP_Rules::evaluate(
	array(
		'path'    => $orig,
		'ua'      => CHROME,
		'headers' => array( 'Referer' => home_url( '/a-post/' ) ),
	)
);
t( 'K2 ... the original from a page of the site loads', null === $r, wp_json_encode( $r ) );
$r = PNCP_Rules::evaluate(
	array(
		'path'    => $orig,
		'ua'      => CHROME,
		'headers' => array( 'Referer' => 'https://leech.example/page' ),
	)
);
t( 'K2 ... from another site: 403 as before', is_array( $r ) && 403 === $r['code'], wp_json_encode( $r ) );
$nginx  = PNCP_Rules::nginx_server();
$apache = PNCP_Rules::apache();
t( 'K3 Nginx: a location for the originals with valid_referers without "none", above the hotlink one', false !== strpos( $nginx, 'valid_referers blocked server_names' ) && strpos( $nginx, 'valid_referers blocked server_names' ) < strpos( $nginx, 'valid_referers none blocked' ) );
t( 'K3 Apache: a rule for the originals without the empty-Referer exception', false !== strpos( $apache, '# Image hotlinking, full-size originals' ) );
settings( array( 'hotlink_originals' => 0 ), false );
t( 'K3 off: neither', false === strpos( PNCP_Rules::nginx_server(), 'valid_referers blocked server_names' ) && false === strpos( PNCP_Rules::apache(), 'full-size originals' ) );

/* ---------- Labels ---------- */

$labels = PNCP_Log::reasons();
t( 'L1 the new refusals have labels (rate_net, rate_mismatch)', isset( $labels['rate_net'], $labels['rate_mismatch'] ) );
t( 'L1 the new pass has a label on the card (webhook)', isset( PNCP_Tester::pass_reasons()['webhook'] ) );
t( 'L1 the new settings have labels', '' !== PNCP_Setting_Labels::label( 'block_author_archives' ) && '' !== PNCP_Setting_Labels::label( 'hotlink_originals' ) );

echo $fails ? "\n$fails FAILED\n" : "\nALL PASSED\n";
exit( $fails ? 1 : 0 );

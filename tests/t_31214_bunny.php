<?php
/**
 * ScrapeLock 3.13.0 — the Bunny CDN integration after a review, with a stand-in Bunny API (as t_bunny_rules.php:
 * it refuses a trigger with more than 5 patterns with HTTP 400, like the real API). Never calls the real API.
 *
 *  1. The login lock's own exception: "*action=postpass*" let wp-login.php?action=login&z=action=postpass through
 *     the edge. Now the exact address only, the record (classify()) wants action=postpass and no other action,
 *     and WordPress refuses wp-login.php from other IPs while the lock blocks (also over HTTP).
 *  2. "Only through the CDN" in the Nginx / Apache server rules (before the fastcgi cache and static files).
 *  3. sync_rules() with a pull zone answer without EdgeRules keeps every lock.
 *  4. The log parser with "|" in the Referer and the User-Agent, and malformed lines.
 *  5. A Bunny edge not in the list: unreliable (no strike, no ban), a forged mark grants no trust, the CDN secret
 *     does; the edge list is asked for again at most once an hour. Same in the pre-cache check.
 *  6. The query and encoded variants of the lock patterns, within Bunny's limits.
 *  7. The administrator's exact IP in the login lock, next to its range, also after a cron run.
 *  8. The import: request IDs seen twice counted once, how far behind it is, static files skipped when far
 *     behind, lines skipped after a long pause noted.
 *  9. Site Health: an import that never ran, or not for an hour.
 * 10. The time of a log download within the run's budget, https for the API address, the addresses left out of
 *     "too fast at the CDN".
 *  A. The lock of AI crawlers by User-Agent: patterns from the settings, plan, rollback, Monitor only, sync.
 *  B. The Edge Rule that sends the CDN secret: idempotent, follows the secret, removable, the secret never stored.
 *  C. Bunny's cache purged after Stealth / watermark changes: rate-limited, never in a visitor's request.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 [WP_CLI="wp --path=…"] php t_31214_bunny.php
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );

// The stand-in API as a temporary mu-plugin (WP-CLI and the web server talk to it too), only while the option
// pncp_test_bunny_31214 exists; removed at the end.
$pncp_mock = $wp_dir . '/wp-content/mu-plugins/pncp-test-bunny-31214.php';
file_put_contents(
	$pncp_mock,
	<<<'PHP'
<?php
// TESTS ONLY: written and removed by tests/t_31214_bunny.php. A stand-in Bunny API.
if ( is_array( get_option( 'pncp_test_bunny_31214' ) ) ) {
	add_filter( 'pncp_bunny_api_base', static function () { return 'https://bunny-31214.mock.test'; } );
	add_filter( 'pncp_bunny_log_base', static function () { return 'https://bunny-31214-log.mock.test'; } );
	add_filter( 'pncp_bunny_call_budget', static function () { return 100000; } );
	add_filter(
		'pre_http_request',
		static function ( $pre, $args, $url ) {
			if ( 0 !== strpos( $url, 'https://bunny-31214' ) ) {
				return $pre;
			}
			wp_cache_delete( 'pncp_test_bunny_31214', 'options' );
			$db      = get_option( 'pncp_test_bunny_31214' ) + array( 'rules' => array(), 'calls' => array(), 'fail' => array(), 'posts' => 0, 'no_edgerules' => false, 'log' => array(), 'timeouts' => array(), 'purges' => 0 );
			$method  = isset( $args['method'] ) ? $args['method'] : 'GET';
			$body    = isset( $args['body'] ) ? json_decode( (string) $args['body'], true ) : null;
			$headers = isset( $args['headers'] ) ? $args['headers'] : array();
			$reply   = static function ( $code, $data = null, $raw = null ) {
				return array( 'headers' => array( 'content-type' => null === $raw ? 'application/json' : 'text/plain' ), 'body' => null !== $raw ? $raw : ( null === $data ? '' : wp_json_encode( $data ) ), 'response' => array( 'code' => $code, 'message' => '' ), 'cookies' => array(), 'filename' => null );
			};
			$save = static function () use ( &$db ) {
				update_option( 'pncp_test_bunny_31214', $db, false );
			};
			if ( ! isset( $headers['AccessKey'] ) || 'bunny-31214-key-1234567890' !== $headers['AccessKey'] ) {
				$save();
				return $reply( 401, array( 'Message' => 'The request authorization failed' ) );
			}
			if ( 0 === strpos( $url, 'https://bunny-31214-log.mock.test/' ) ) {
				// The log: lines from the test, start / end as Bunny reads them.
				$db['timeouts'][] = isset( $args['timeout'] ) ? (int) $args['timeout'] : 0;
				parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $q );
				$start = isset( $q['start'] ) ? (int) $q['start'] : 0;
				$end   = isset( $q['end'] ) ? (int) $q['end'] : count( $db['log'] );
				$part  = array_slice( (array) $db['log'], $start, max( 0, $end - $start ) );
				$save();
				return $reply( 200, null, $part ? implode( "\n", $part ) . "\n" : '' );
			}
			$base = 'https://bunny-31214.mock.test/pullzone/';
			if ( 0 === strpos( $url, 'https://bunny-31214.mock.test/purge?' ) ) {
				$db['calls'][] = 'POST purge';
				$save();
				return $reply( 200 );
			}
			if ( 0 !== strpos( $url, $base . '777' ) ) {
				$save();
				return $reply( 404, array( 'Message' => 'Pull zone not found' ) );
			}
			$rest          = (string) substr( $url, strlen( $base ) + 3 );
			$db['calls'][] = $method . ' ' . $rest;
			if ( '' === $rest && 'GET' === $method ) {
				$save();
				$zone = array( 'Id' => 777, 'Name' => 'mock', 'EnableLogging' => true, 'LoggingIPAnonymizationEnabled' => false );
				if ( empty( $db['no_edgerules'] ) ) {
					$zone['EdgeRules'] = array_values( $db['rules'] );
				}
				return $reply( 200, $zone );
			}
			if ( '/purgeCache' === $rest && 'POST' === $method ) {
				++$db['purges'];
				$save();
				return $reply( 204 );
			}
			if ( '/edgerules/addOrUpdate' === $rest && 'POST' === $method ) {
				++$db['posts'];
				if ( isset( $db['fail'][ $db['posts'] ] ) ) {
					$save();
					return $reply( (int) $db['fail'][ $db['posts'] ], array( 'ErrorKey' => 'mock', 'Message' => 'Injected failure' ) );
				}
				foreach ( isset( $body['Triggers'] ) ? (array) $body['Triggers'] : array() as $trigger ) {
					if ( isset( $trigger['PatternMatches'] ) && count( (array) $trigger['PatternMatches'] ) > 5 ) {
						$save();
						return $reply( 400, array( 'ErrorKey' => 'pullzone.edgerule_validation', 'Field' => 'Triggers', 'Message' => 'Maximum 5 triggers are allowed per condition.' ) );
					}
				}
				if ( ! empty( $body['Guid'] ) ) {
					if ( ! isset( $db['rules'][ $body['Guid'] ] ) ) {
						$save();
						return $reply( 404, array( 'Message' => 'The requested edge rule was not found' ) );
					}
					$db['rules'][ $body['Guid'] ] = $body;
					$save();
					return $reply( 200 );
				}
				$guid                 = wp_generate_uuid4();
				$body                 = array( 'Guid' => $guid ) + $body;
				$db['rules'][ $guid ] = $body;
				$save();
				return $reply( 200, $body );
			}
			if ( 0 === strpos( $rest, '/edgerules/' ) && 'DELETE' === $method ) {
				$guid = substr( $rest, 11 );
				if ( ! isset( $db['rules'][ $guid ] ) ) {
					$save();
					return $reply( 404, array( 'Message' => 'The requested edge rule was not found' ) );
				}
				unset( $db['rules'][ $guid ] );
				$save();
				return $reply( 204 );
			}
			$save();
			return $reply( 404, array( 'Message' => 'nf' ) );
		},
		10,
		3
	);
}
PHP
);
register_shutdown_function(
	static function () use ( $pncp_mock ) {
		if ( is_file( $pncp_mock ) ) {
			unlink( $pncp_mock );
		}
	}
);

define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

const B4_ZONE = '777';
const B4_KEY  = 'bunny-31214-key-1234567890';

function mock() {
	wp_cache_delete( 'pncp_test_bunny_31214', 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	$db = get_option( 'pncp_test_bunny_31214' );
	return ( is_array( $db ) ? $db : array() ) + array( 'rules' => array(), 'calls' => array(), 'fail' => array(), 'posts' => 0, 'no_edgerules' => false, 'log' => array(), 'timeouts' => array(), 'purges' => 0 );
}
function mock_set( $changes ) {
	update_option( 'pncp_test_bunny_31214', array_merge( mock(), $changes ), false );
}
function mock_reset( $changes = array() ) {
	update_option( 'pncp_test_bunny_31214', array_merge( array( 'rules' => array(), 'calls' => array(), 'fail' => array(), 'posts' => 0, 'no_edgerules' => false, 'log' => array(), 'timeouts' => array(), 'purges' => 0 ), $changes ), false );
}
function at_bunny( $needle ) {
	$out = array();
	foreach ( mock()['rules'] as $guid => $rule ) {
		if ( false !== strpos( (string) $rule['Description'], $needle ) ) {
			$out[ $guid ] = $rule;
		}
	}
	return $out;
}
function within_limit( $rules ) {
	foreach ( $rules as $rule ) {
		foreach ( $rule['Triggers'] as $trigger ) {
			if ( count( $trigger['PatternMatches'] ) > 5 ) {
				return false;
			}
		}
	}
	return true;
}
function stored( $id ) {
	wp_cache_delete( PNCP_Bunny::RULES, 'options' );
	wp_cache_delete( 'alloptions', 'options' );
	$rules = get_option( PNCP_Bunny::RULES, array() );
	return isset( $rules[ $id ] ) ? $rules[ $id ] : null;
}
function settings( $changes ) {
	update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), $changes ) );
	PNCP_Options::flush();
	PNCP_Ip::reset();
	PNCP_Bunny::reset();
}
function pattern_hit( $pattern, $subject ) {
	return 1 === preg_match( '#^' . str_replace( '\*', '.*', preg_quote( $pattern, '#' ) ) . '$#i', $subject );
}
/** Would these Edge Rules block a request (URL, IP, User-Agent)? As Bunny evaluates the triggers. */
function blocks( $rules, $url, $ip, $ua = 'Mozilla/5.0' ) {
	foreach ( $rules as $rule ) {
		if ( 4 !== (int) $rule['ActionType'] ) {
			continue;
		}
		$results = array();
		foreach ( $rule['Triggers'] as $tr ) {
			$any = false;
			foreach ( $tr['PatternMatches'] as $p ) {
				if ( 5 === (int) $tr['Type'] ) {
					$any = $any || PNCP_Ip::in_any( $ip, array( $p ) );
				} elseif ( 1 === (int) $tr['Type'] ) {
					$any = $any || ( 'User-Agent' === $tr['Parameter1'] && pattern_hit( $p, $ua ) );
				} else {
					$any = $any || pattern_hit( $p, $url );
				}
			}
			$results[] = 2 === (int) $tr['PatternMatchingType'] ? ! $any : $any;
		}
		$m  = (int) $rule['TriggerMatchingType'];
		$on = 0 === $m ? in_array( true, $results, true ) : ( 1 === $m ? ! in_array( false, $results, true ) : ! in_array( true, $results, true ) );
		if ( $on && ! empty( $rule['Enabled'] ) ) {
			return true;
		}
	}
	return false;
}
/** A Bunny log line. */
function line( $url, $ip = '45.159.10.5', $referer = '-', $ua = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0 Safari/537.36', $id = '', $status = 200, $ts = null, $cache = 'HIT' ) {
	$ts = null === $ts ? (int) round( microtime( true ) * 1000 ) : $ts;
	$id = '' !== $id ? $id : md5( $url . $ip . $ts . wp_rand() );
	return implode( '|', array( $cache, $status, $ts, 1234, '777', $ip, $referer, $url, 'DE', $ua, $id, 'GR' ) );
}
/** Sets $_SERVER for an in-process "request" and forgets the IP of the last one. */
function req( $server ) {
	foreach ( array( 'REMOTE_ADDR', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_VIA', 'HTTP_CDN_SERVERID', 'HTTP_X_SCRAPELOCK_CDN', 'REQUEST_URI', 'QUERY_STRING' ) as $k ) {
		unset( $_SERVER[ $k ] );
	}
	$_SERVER['REQUEST_URI'] = '/';
	foreach ( $server as $k => $v ) {
		$_SERVER[ $k ] = $v;
	}
	PNCP_Ip::reset();
}

/* ---------- Clean start ---------- */
$saved_settings = PNCP_Options::stored();
$saved_server   = $_SERVER;
settings( array( 'enabled' => 1, 'monitor_mode' => 0, 'monitor_until' => 0, 'bunny_login_allow' => '', 'cdn_only' => 0, 'cdn_secret' => '', 'ip_header' => 'remote_addr', 'trust_bunny' => 1, 'bunny_import' => 0 ) );
foreach ( array( PNCP_Bunny::RULES, PNCP_Bunny::CALLS, PNCP_Bunny::LOGIN_STRICT, PNCP_Bunny::LOGIN_ADMIN_IP, PNCP_Bunny::STATE, PNCP_Bunny::PURGE, 'pncp_bunny_import_on' ) as $pncp_o ) {
	delete_option( $pncp_o );
}
wp_clear_scheduled_hook( PNCP_Bunny::PURGE_EVENT );
delete_option( PNCP_Edge::CONFIG );
mock_reset();
if ( ! has_filter( 'pncp_bunny_api_base' ) ) {
	include $pncp_mock;
}
update_option( PNCP_Bunny::CONFIG, array( 'zone' => B4_ZONE, 'token' => B4_KEY ), false );
PNCP_Bunny::reset();
t( 'connected to the stand-in Bunny API', PNCP_Bunny::edge_available() && B4_ZONE === PNCP_Bunny::credentials()['zone'] && 'https://bunny-31214.mock.test' === PNCP_Bunny::base( 'api' ) );
$presets = PNCP_Bunny::presets();

/* ---------- 1. The login lock's exception ---------- */
t( '1: the login exception is the exact address of the password form, no trailing *', array( '*/wp-login.php?action=postpass' ) === $presets['login']['except'] );
// A lock made since 3.9 (the explicit list), so the runs below keep 198.51.100.1 whatever IPs other tests left.
settings( array( 'bunny_login_allow' => '198.51.100.1' ) );
update_option( PNCP_Bunny::LOGIN_STRICT, time(), false );
$r     = PNCP_Bunny::edge_block( 'preset_login', $presets['login']['patterns'], $presets['login']['label'], array( 'allow' => array( '198.51.100.1' ), 'except' => $presets['login']['except'] ) );
$login = at_bunny( '[preset_login]' );
t( '1: login locked at the stand-in Bunny, within the limits', true === $r && 1 === count( $login ) && within_limit( $login ), is_wp_error( $r ) ? $r->get_error_message() : '' );
t( '1: the bypass wp-login.php?action=login&z=action=postpass is blocked at the edge now', blocks( $login, 'https://example.com/wp-login.php?action=login&z=action=postpass', '203.0.113.9' ) );
t( '1: …and so are ?action=postpass&action=login, ?redirect_to=…action=postpass and wp-login%2ephp', blocks( $login, 'https://example.com/wp-login.php?action=postpass&action=login', '203.0.113.9' ) && blocks( $login, 'https://example.com/wp-login.php?redirect_to=/?action=postpass', '203.0.113.9' ) && blocks( $login, 'https://example.com/wp-login%2ephp', '203.0.113.9' ) && blocks( $login, 'https://example.com/wp-login%2Ephp?action=postpass', '203.0.113.9' ) );
t( '1: the password form itself (wp-login.php?action=postpass) and the allowed IP still pass', ! blocks( $login, 'https://example.com/wp-login.php?action=postpass', '203.0.113.9' ) && ! blocks( $login, 'https://example.com/wp-login.php?action=login', '198.51.100.1' ) );
$row = PNCP_Bunny::parse_line( line( 'https://example.com/wp-login.php?action=login&z=action=postpass', '203.0.113.9', '-', 'Mozilla/5.0', '', 403, null, 'MISS' ) );
t( '1: classify(): the bypass is an attack on wp-login.php (it was left out of the record)', is_array( $row ) && 'wp-login.php' === PNCP_Bunny::classify( $row ) );
$ok = true;
foreach ( array( 'action=postpass' => '', 'action=postpass&action=login' => 'wp-login.php', 'action[]=postpass&action=postpass' => 'wp-login.php', 'z=action%3Dpostpass' => 'wp-login.php', 'ACTION=postpass' => '', 'action=postpassx' => 'wp-login.php' ) as $q => $want ) {
	$rw = PNCP_Bunny::parse_line( line( 'https://example.com/wp-login.php?' . $q ) );
	$ok = $ok && $want === PNCP_Bunny::classify( $rw );
}
t( '1: classify(): only exactly one action, "postpass", is the password form', $ok );
// The origin: while the lock blocks, wp-login.php from IPs it does not let through is refused, unless it is the form.
$verdict = static function ( $get, $post, $ip ) {
	req( array( 'REMOTE_ADDR' => $ip, 'REQUEST_URI' => '/wp-login.php?' . http_build_query( $get ), 'QUERY_STRING' => http_build_query( $get ) ) );
	$_GET     = $get;
	$_POST    = $post;
	$_REQUEST = array_merge( $get, $post );
	$v        = PNCP_Bunny::origin_login_verdict();
	$_GET     = array();
	$_POST    = array();
	$_REQUEST = array();
	return $v;
};
t( '1: origin: wp-login.php?action=login&z=action=postpass from a stranger is refused', 'refused' === $verdict( array( 'action' => 'login', 'z' => 'action=postpass' ), array(), '203.0.113.9' ) );
t( '1: origin: ?action=postpass with a POSTed action=login (what WordPress would do) is refused', 'refused' === $verdict( array( 'action' => 'postpass' ), array( 'action' => 'login', 'log' => 'admin' ), '203.0.113.9' ) );
t( '1: origin: the password form (GET and POST postpass) passes, and so does the allowed IP', '' === $verdict( array( 'action' => 'postpass' ), array( 'post_password' => 'x' ), '203.0.113.9' ) && '' === $verdict( array(), array( 'log' => 'admin' ), '198.51.100.1' ) );
settings( array( 'monitor_mode' => 1 ) );
PNCP_Bunny::sync_rules();
t( '1: origin: in Monitor only (rule switched off) nothing is refused', '' === $verdict( array( 'action' => 'login' ), array(), '203.0.113.9' ) );
settings( array( 'monitor_mode' => 0 ) );
PNCP_Bunny::sync_rules();
// Over HTTP: the built-in server is 127.0.0.1, which X-Forwarded-For (trusted from the local proxy) names a visitor.
settings( array( 'ip_header' => 'x_forwarded_for' ) );
$forget_learned = static function () {
	$st = get_option( PNCP_Server_Ips::OPTION, array() );
	if ( is_array( $st ) && isset( $st['learned'] ) && is_array( $st['learned'] ) ) {
		unset( $st['learned']['203.0.113.77'], $st['learned']['198.51.100.1'] );
		update_option( PNCP_Server_Ips::OPTION, $st, true );
	}
	$out = get_transient( PNCP_Server_Ips::OUTBOUND );
	if ( is_array( $out ) ) {
		unset( $out['203.0.113.77'], $out['198.51.100.1'] );
		set_transient( PNCP_Server_Ips::OUTBOUND, $out, DAY_IN_SECONDS );
	}
};
$forget_learned(); // Addresses a signed request of the site taught as its own would pass as the server.

// Not through WordPress's HTTP API: it signs the site's requests to itself (X-ScrapeLock-Sig), which pass every check.
$http = static function ( $path, $ip, $post = null ) use ( $base ) {
	$headers = array( 'X-Forwarded-For: ' . $ip, 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', 'Accept: text/html', 'Accept-Language: en', 'Sec-Fetch-Mode: navigate', 'Sec-CH-UA: "Chromium";v="130"', 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' );
	$opts    = array(
		'http' => array(
			'method'          => null === $post ? 'GET' : 'POST',
			'header'          => implode( "\r\n", array_merge( $headers, null === $post ? array() : array( 'Content-Type: application/x-www-form-urlencoded' ) ) ),
			'content'         => null === $post ? '' : http_build_query( $post ),
			'follow_location' => 0,
			'ignore_errors'   => true,
			'timeout'         => 15,
		),
	);
	$body = (string) @file_get_contents( $base . $path, false, stream_context_create( $opts ) );
	$head = isset( $http_response_header ) ? $http_response_header : array();
	$code = isset( $head[0] ) && preg_match( '#\s(\d{3})\s#', $head[0] . ' ', $m ) ? (int) $m[1] : 0;
	return array(
		'code'    => $code,
		'cookies' => implode( ' ', preg_grep( '/^set-cookie:/i', $head ) ),
		'body'    => $body,
	);
};
$res = $http( '/wp-login.php?action=login&z=action=postpass', '203.0.113.77', array( 'log' => 'admin', 'pwd' => 'admin' ) );
t( '1: HTTP: POST wp-login.php?action=login&z=action=postpass from a stranger = 403, no sign-in cookie', 403 === $res['code'] && false === strpos( $res['cookies'], 'wordpress_logged_in' ) && false !== strpos( $res['body'], 'Access denied.' ), $res['code'] . ' ' . substr( $res['body'], 0, 80 ) );
$res = $http( '/wp-login.php?action=postpass', '203.0.113.77', array( 'post_password' => 'x' ) );
t( '1: HTTP: the password form from the same IP still works (its cookie is set, not 403)', 403 !== $res['code'] && false !== strpos( $res['cookies'], 'wp-postpass_' ), $res['code'] . ' ' . $res['cookies'] );
$res = $http( '/wp-login.php', '198.51.100.1' );
t( '1: HTTP: the allowed IP gets the login page', 200 === $res['code'] && false !== strpos( $res['body'], 'user_login' ), (string) $res['code'] );
settings( array( 'ip_header' => 'remote_addr' ) );
$forget_learned();
// A lock stored with the old exception is sent again with the new one by the next run.
$rules                            = get_option( PNCP_Bunny::RULES );
$rules['preset_login']['except'] = array( '*action=postpass*' );
update_option( PNCP_Bunny::RULES, $rules, false );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
$login = at_bunny( '[preset_login]' );
t( '1: a lock of 3.12.13 ("*action=postpass*") is sent again with the exact exception, in place', array( '*/wp-login.php?action=postpass' ) === stored( 'preset_login' )['except'] && 1 === count( $login ) && blocks( $login, 'https://example.com/wp-login.php?action=login&z=action=postpass', '203.0.113.9' ) );
PNCP_Bunny::edge_unblock( 'preset_login' );
delete_option( PNCP_Bunny::LOGIN_STRICT );
settings( array( 'bunny_login_allow' => '' ) );

/* ---------- 3. sync_rules() and an answer without EdgeRules ---------- */
mock_reset();
PNCP_Bunny::lock_preset( 'probes' );
$before = stored( 'preset_probes' );
$n      = PNCP_Bunny::sync_rules( array( 'Id' => 777, 'Name' => 'mock' ) );
t( '3: a pull zone answer without EdgeRules: no lock forgotten, nothing sent', 0 === $n && $before && stored( 'preset_probes' ) == $before && 1 === count( at_bunny( '[preset_probes]' ) ) );
t( '3: …noted for the card, and the card says it', (int) PNCP_Bunny::state()['sync_skipped'] > time() - 60 );
mock_set( array( 'no_edgerules' => true ) );
PNCP_Bunny::run();
t( '3: a whole run with such an answer keeps the lock too', null !== stored( 'preset_probes' ) && 1 === count( at_bunny( '[preset_probes]' ) ) );
$n = PNCP_Bunny::sync_rules( array( 'EdgeRules' => 'oops' ) );
t( '3: EdgeRules that is not a list: kept as well', 0 === $n && null !== stored( 'preset_probes' ) );
mock_set( array( 'no_edgerules' => false ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array() ) );
t( '3: an answer that lists no rules (removed in the dashboard): forgotten, as before', null === stored( 'preset_probes' ) );
mock_reset();

/* ---------- 4. The log parser ---------- */
$url = 'https://example.com/wp-login.php';
$r1  = PNCP_Bunny::parse_line( line( $url, '45.159.10.5', 'https://x.example/?a=1|https://example.com/innocent/', 'Mozilla/5.0', 'id-1' ) );
t( '4: "|" in the Referer: the URL is wp-login.php, the Referer whole, UA, ID and country in place', is_array( $r1 ) && $url === $r1['url'] && '/wp-login.php' === $r1['path'] && 'https://x.example/?a=1|https://example.com/innocent/' === $r1['referer'] && 'Mozilla/5.0' === $r1['ua'] && 'id-1' === $r1['id'] && 'GR' === $r1['country'] && 'DE' === $r1['edge'], wp_json_encode( $r1 ) );
t( '4: …and it is recorded as an attack on wp-login.php', 'wp-login.php' === PNCP_Bunny::classify( $r1 ) );
$r2 = PNCP_Bunny::parse_line( line( 'https://example.com/shop/', '45.159.10.5', '-', 'Evil|Bot|1.0', 'id-2' ) );
t( '4: "|" in the User-Agent: joined again, the URL in place', is_array( $r2 ) && '/shop/' === $r2['path'] && 'Evil|Bot|1.0' === $r2['ua'] && 'id-2' === $r2['id'] && 'GR' === $r2['country'] );
$r3 = PNCP_Bunny::parse_line( line( $url, '45.159.10.5', 'a|b', 'c|d|e', 'id-3' ) );
t( '4: "|" in both', is_array( $r3 ) && '/wp-login.php' === $r3['path'] && 'a|b' === $r3['referer'] && 'c|d|e' === $r3['ua'] && 'id-3' === $r3['id'] );
$r4 = PNCP_Bunny::parse_line( line( $url, '45.159.10.5', 'x|https://example.com/innocent/|DE', 'Mozilla/5.0', 'id-4' ) );
t( '4: a Referer that imitates "URL|edge" cannot hide the attack: the worst reading counts', is_array( $r4 ) && 'wp-login.php' === PNCP_Bunny::classify( $r4 ), wp_json_encode( $r4 ) );
$r5 = PNCP_Bunny::parse_line( line( 'https://example.com/blog/', '45.159.10.5', '-', 'x|https://example.com/wp-login.php|DE|y', 'id-5' ) );
t( '4: a User-Agent with a fake URL makes the line count as the attack it names (never less)', is_array( $r5 ) && '/blog/' === $r5['path'] && 'wp-login.php' === PNCP_Bunny::classify( $r5 ) );
t( '4: malformed: too few fields, no URL, a bad IP, an empty line', null === PNCP_Bunny::parse_line( 'HIT|200|1' ) && null === PNCP_Bunny::parse_line( 'HIT|200|1|2|777|1.2.3.4|ref|nourl|DE|ua|id|GR|x|y' ) && null === PNCP_Bunny::parse_line( 'HIT|200|1|2|777|not-an-ip|-|https://example.com/|DE|ua|id|GR' ) && null === PNCP_Bunny::parse_line( '' ) );
$r6 = PNCP_Bunny::parse_line( 'MISS|404|1732099200000|0|777|45.159.10.6|-|https://example.com/a' );
t( '4: a line without the last fields still parses (as before)', is_array( $r6 ) && '/a' === $r6['path'] && '' === $r6['ua'] && '' === $r6['id'] );

/* ---------- 5. A Bunny edge not in the list ---------- */
$saved_bunny = get_option( 'pncp_ip_lists_bunny', null );
PNCP_Ip::store_list( 'bunny', array( '185.93.1.10', '185.93.1.11' ) );
settings( array( 'ip_header' => 'x_real_ip', 'trust_bunny' => 1, 'cdn_secret' => '' ) );
req( array( 'REMOTE_ADDR' => '185.93.1.10', 'HTTP_X_REAL_IP' => '203.0.113.20', 'HTTP_VIA' => '1.1 BunnyCDN-DE1-123', 'HTTP_CDN_SERVERID' => '123' ) );
t( '5: a listed edge without the secret: X-Real-IP read, unreliable (as since 3.4.3)', '203.0.113.20' === PNCP_Ip::client_ip() && ! PNCP_Ip::reliable() );
req( array( 'REMOTE_ADDR' => '45.159.10.20', 'HTTP_X_REAL_IP' => '203.0.113.20', 'HTTP_VIA' => '1.1 BunnyCDN-DE1-777', 'HTTP_CDN_SERVERID' => '777' ) );
$ip = PNCP_Ip::client_ip();
t( '5: an edge not in the list yet: its own address, unreliable, seen as an unlisted edge', '45.159.10.20' === $ip && ! PNCP_Ip::reliable() && PNCP_Ip::from_unlisted_edge() );
t( '5: …so no strike and no trust for the forged X-Real-IP', false === PNCP_Log::strike( $ip, 'rate' ) && ! PNCP_Ip::is_trusted_proxy( '45.159.10.20', PNCP_Options::get(), 'x_real_ip' ) );
settings( array( 'allow_ips' => "45.159.10.20\n203.0.113.20" ) );
req( array( 'REMOTE_ADDR' => '45.159.10.20', 'HTTP_X_REAL_IP' => '203.0.113.20', 'HTTP_VIA' => '1.1 BunnyCDN' ) );
$allowed = PNCP_Ip::reliable() && PNCP_Ip::in_any( PNCP_Ip::client_ip(), PNCP_Options::parse_list( PNCP_Options::get()['allow_ips'] ) );
t( '5: a forged mark from an address on the always-allowed list does not unlock it (unreliable)', ! $allowed );
settings( array( 'allow_ips' => '' ) );
req( array( 'REMOTE_ADDR' => '45.159.10.20', 'HTTP_X_REAL_IP' => '203.0.113.20' ) );
t( '5: the same address without the marks: a normal visitor (reliable, the header not read)', '45.159.10.20' === PNCP_Ip::client_ip() && PNCP_Ip::reliable() && ! PNCP_Ip::from_unlisted_edge() );
req( array( 'REMOTE_ADDR' => '203.0.113.20', 'HTTP_X_REAL_IP' => '203.0.113.20', 'HTTP_X_FORWARDED_FOR' => '203.0.113.20, 185.93.1.10', 'HTTP_VIA' => '1.1 BunnyCDN' ) );
t( '5: a server that put the visitor in REMOTE_ADDR itself (Nginx real_ip): Bunny\'s marks change nothing, reliable', '203.0.113.20' === PNCP_Ip::client_ip() && PNCP_Ip::reliable() && ! PNCP_Ip::from_unlisted_edge() );
wp_clear_scheduled_hook( PNCP_Ip::BUNNY_REFRESH );
PNCP_Log::cache_delete( 'pncp_bunny_edges_try' );
$first  = PNCP_Ip::schedule_bunny_refresh();
wp_clear_scheduled_hook( PNCP_Ip::BUNNY_REFRESH );
$second = PNCP_Ip::schedule_bunny_refresh();
t( '5: the edge list is asked for again, at most once an hour', $first && ! $second );
wp_clear_scheduled_hook( PNCP_Ip::BUNNY_REFRESH );
PNCP_Log::cache_delete( 'pncp_bunny_edges_try' );
settings( array( 'cdn_secret' => 'Sec-31214-abcdef' ) );
req( array( 'REMOTE_ADDR' => '45.159.10.20', 'HTTP_X_REAL_IP' => '203.0.113.20', 'HTTP_VIA' => '1.1 BunnyCDN', 'HTTP_X_SCRAPELOCK_CDN' => 'Sec-31214-abcdef' ) );
t( '5: with the CDN secret, the new edge is trusted as Bunny: X-Real-IP read, reliable', '203.0.113.20' === PNCP_Ip::client_ip() && PNCP_Ip::reliable() );
req( array( 'REMOTE_ADDR' => '45.159.10.20', 'HTTP_X_REAL_IP' => '203.0.113.20', 'HTTP_VIA' => '1.1 BunnyCDN', 'HTTP_X_SCRAPELOCK_CDN' => 'wrong' ) );
t( '5: a wrong secret: not trusted, unreliable', '45.159.10.20' === PNCP_Ip::client_ip() && ! PNCP_Ip::reliable() );
// The pre-cache check, with its own copy of the rules.
$c = array(
	'format'          => 3,
	'header'          => 'HTTP_X_REAL_IP',
	'proxies'         => array( array(), array() ),
	'proxies_cdn'     => array( 'bunny' => 1, 'cf' => 0 ),
	'cdn_bunny'       => array( array( '185.93.1.10' => true ), array() ),
	'cdn_cf'          => array( array(), array() ),
	'private'         => 1,
	'cdn_secret_hash' => '',
	'trust_any'       => 0,
);
req( array( 'REMOTE_ADDR' => '45.159.10.20', 'HTTP_X_REAL_IP' => '203.0.113.20', 'HTTP_VIA' => '1.1 BunnyCDN' ) );
$rel = true;
$pip = PNCP_Precheck_Runtime::client_ip( $c, $rel );
t( '5: pre-cache check: an unlisted edge with the marks is unreliable, its header not read', '45.159.10.20' === $pip && false === $rel );
req( array( 'REMOTE_ADDR' => '45.159.10.20' ) );
$rel = true;
PNCP_Precheck_Runtime::client_ip( $c, $rel );
t( '5: pre-cache check: without the marks, reliable', true === $rel );
req( array( 'REMOTE_ADDR' => '203.0.113.20', 'HTTP_X_REAL_IP' => '203.0.113.20', 'HTTP_VIA' => '1.1 BunnyCDN' ) );
$rel = true;
PNCP_Precheck_Runtime::client_ip( $c, $rel );
t( '5: pre-cache check: REMOTE_ADDR already the visitor (real_ip): reliable', true === $rel );
$c['cdn_secret_hash'] = hash( 'sha256', 'Sec-31214-abcdef' );
req( array( 'REMOTE_ADDR' => '45.159.10.20', 'HTTP_X_REAL_IP' => '203.0.113.20', 'HTTP_VIA' => '1.1 BunnyCDN', 'HTTP_X_SCRAPELOCK_CDN' => 'Sec-31214-abcdef' ) );
$rel = true;
$pip = PNCP_Precheck_Runtime::client_ip( $c, $rel );
t( '5: pre-cache check: with the secret, the new edge is trusted (X-Real-IP)', '203.0.113.20' === $pip && true === $rel );
req( array( 'REMOTE_ADDR' => '127.0.0.1' ) );
if ( null === $saved_bunny ) {
	delete_option( 'pncp_ip_lists_bunny' );
} else {
	update_option( 'pncp_ip_lists_bunny', $saved_bunny );
}
delete_option( PNCP_Ip::BUNNY_SUM );
settings( array( 'ip_header' => 'remote_addr', 'cdn_secret' => '' ) );

/* ---------- 6. Query and encoded variants ---------- */
$probes = $presets['probes']['patterns'];
t( '6: "Secret files" holds *.sql?*, *.sql.gz?* and the encoded .env', in_array( '*.sql?*', $probes, true ) && in_array( '*.sql.gz?*', $probes, true ) && in_array( '*/%2eenv*', $probes, true ) && in_array( '*/%2Eenv*', $probes, true ) );
$plan = PNCP_Bunny::plan( array( 'patterns' => $probes ) );
t( '6: …still one Edge Rule of 5 conditions of at most 5 patterns', ! is_wp_error( $plan ) && 1 === count( $plan ) && 5 === count( $plan[0]['triggers'] ) );
PNCP_Bunny::lock_preset( 'probes' );
$there = at_bunny( '[preset_probes]' );
t( '6: blocks /dump.sql?x=1, /db.sql.gz?dl=1, /%2eenv, and not /shop/?q=sql', within_limit( $there ) && blocks( $there, 'https://example.com/dump.sql?x=1', '1.2.3.4' ) && blocks( $there, 'https://example.com/db.sql.gz?dl=1', '1.2.3.4' ) && blocks( $there, 'https://example.com/%2eenv', '1.2.3.4' ) && ! blocks( $there, 'https://example.com/shop/?q=sql', '1.2.3.4' ) );
PNCP_Bunny::unlock_preset( 'probes' );
t( '6: wp-login.php and xmlrpc.php with %2e / %2E', in_array( '*/wp-login%2ephp*', $presets['login']['patterns'], true ) && in_array( '*/wp-login%2Ephp*', $presets['login']['patterns'], true ) && in_array( '*/xmlrpc%2ephp*', $presets['xmlrpc']['patterns'], true ) && in_array( '*/xmlrpc%2Ephp*', PNCP_Hardening::point( 'xmlrpc' )['edge'], true ) );
t( '6: the login page still lets 15 IPs through next to its patterns', 15 === PNCP_Bunny::login_allow_max() );

/* ---------- 7. The administrator's exact IP in the login lock ---------- */
mock_reset();
settings( array( 'bunny_login_allow' => '2001:db8:1:2::/64' ) );
req( array( 'REMOTE_ADDR' => '2001:db8:1:2::5' ) );
wp_set_current_user( 1 );
$r     = PNCP_Bunny::lock_preset( 'login' );
$login = at_bunny( '[preset_login]' );
$ips   = array();
foreach ( $login ? reset( $login )['Triggers'] : array() as $tr ) {
	if ( 5 === (int) $tr['Type'] ) {
		$ips = array_merge( $ips, $tr['PatternMatches'] );
	}
}
t( '7: locked from 2001:db8:1:2::5 with the list "2001:db8:1:2::/64": the rule carries the exact IP and the range', true === $r && in_array( '2001:db8:1:2::5', $ips, true ) && in_array( '2001:db8:1:2::/64', $ips, true ), is_wp_error( $r ) ? $r->get_error_message() : wp_json_encode( $ips ) );
wp_set_current_user( 0 );
req( array( 'REMOTE_ADDR' => '127.0.0.1' ) );
settings( array( 'monitor_mode' => 0 ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
t( '7: a run from cron (no administrator) keeps the exact IP in the rule', in_array( '2001:db8:1:2::5', (array) stored( 'preset_login' )['allow'], true ) && in_array( '2001:db8:1:2::5', PNCP_Bunny::login_rule_admins(), true ) );
t( '7: the preview shows the exact IP too', ( static function () {
	wp_set_current_user( 1 );
	req( array( 'REMOTE_ADDR' => '2001:db8:1:2::5' ) );
	$p = PNCP_Bunny::lock_preview( 'preset', 'login' );
	wp_set_current_user( 0 );
	return in_array( '2001:db8:1:2::5', (array) $p['allow'], true );
} )() );
PNCP_Bunny::edge_unblock( 'preset_login' );
delete_option( PNCP_Bunny::LOGIN_STRICT );
delete_option( PNCP_Bunny::LOGIN_ADMIN_IP );
$full = array( '2001:db8:1:2::/64' );
for ( $i = 1; $i < 15; $i++ ) {
	$full[] = '192.0.2.' . $i;
}
settings( array( 'bunny_login_allow' => implode( "\n", $full ) ) );
wp_set_current_user( 1 );
req( array( 'REMOTE_ADDR' => '2001:db8:1:2::5' ) );
t( '7: a full list (15) that holds the IP only as a range: the lock asks for room for the exact IP', (bool) preg_grep( '/only as part of a range/', PNCP_Bunny::login_lock_blockers() ) );
wp_set_current_user( 0 );
req( array( 'REMOTE_ADDR' => '127.0.0.1' ) );
settings( array( 'bunny_login_allow' => '' ) );
mock_reset();

/* ---------- 8. The import ---------- */
settings( array( 'bunny_import' => 1, 'bunny_strikes' => 0 ) );
delete_option( PNCP_Bunny::STATE );
$now   = (int) round( microtime( true ) * 1000 );
$lines = array();
for ( $i = 0; $i < 10; $i++ ) {
	$lines[] = line( 'https://example.com/.env', '45.159.10.' . ( 30 + $i ), '-', 'Mozilla/5.0', 'dup-' . $i, 404, $now - 1000 * $i, 'MISS' );
}
mock_set( array( 'log' => $lines ) );
$c   = PNCP_Bunny::credentials();
$res = PNCP_Bunny::import( $c, microtime( true ) + 15 );
t( '8: first import: 10 lines', '' === $res['error'] && 10 === $res['lines'] && 0 === (int) PNCP_Bunny::state()['dupes'], wp_json_encode( $res ) );
$state           = PNCP_Bunny::state();
$state['offset'] = 4; // As if Bunny sent lines 5-10 again (start/end ignored, a run cut short).
update_option( PNCP_Bunny::STATE, $state, false );
$more    = $lines;
$more[]  = line( 'https://example.com/.git/config', '45.159.10.50', '-', 'Mozilla/5.0', 'new-1', 404, $now, 'MISS' );
mock_set( array( 'log' => $more ) );
$res = PNCP_Bunny::import( $c, microtime( true ) + 15 );
t( '8: the same lines read again are counted once (6 skipped by request ID, 1 new)', 1 === $res['lines'] && 6 === (int) PNCP_Bunny::state()['dupes'], wp_json_encode( $res ) . ' dupes=' . PNCP_Bunny::state()['dupes'] );
t( '8: the request IDs kept are bounded (at most 4000)', count( PNCP_Bunny::state()['seen_ids'] ) <= 4000 && count( PNCP_Bunny::state()['seen_ids'] ) >= 11 );
// Far behind: more lines than a run reads, two hours old.
add_filter( 'pncp_bunny_lines_per_request', static function () { return 100; } );
$old  = $now - 2 * HOUR_IN_SECONDS * 1000;
$back = array();
for ( $i = 0; $i < 1000; $i++ ) {
	$back[] = line( 'https://example.com/wp-content/uploads/p' . $i . '.jpg', '45.159.11.' . ( $i % 200 ), '-', 'Mozilla/5.0', 'b-' . $i, 200, $old + $i, 'HIT' );
}
mock_set( array( 'log' => $back ) );
delete_option( PNCP_Bunny::STATE );
$state          = PNCP_Bunny::state();
$state['zone']  = B4_ZONE;
$state['day']   = PNCP_Bunny::log_day( time() );
$state['floor'] = 0;
update_option( PNCP_Bunny::STATE, $state, false );
PNCP_Bunny::import( $c, microtime( true ) + 15 );
$st = PNCP_Bunny::state();
t( '8: a run that stops before the end notes how far behind it is (about 2 hours)', (int) $st['behind'] > HOUR_IN_SECONDS && (int) $st['behind'] < 3 * HOUR_IN_SECONDS && 400 === (int) $st['offset'], 'behind=' . $st['behind'] . ' offset=' . $st['offset'] );
t( '8: …shown as a warning (card, Site Health)', false !== strpos( PNCP_Bunny::import_stale( $st ), 'behind' ) );
PNCP_Bunny::import( $c, microtime( true ) + 15 );
$st = PNCP_Bunny::state();
t( '8: while far behind, the next run reads more (8 downloads) and skips static files', 1000 === (int) $st['offset'] && (int) $st['static_skip'] > 0 && 0 === (int) $st['behind'], 'offset=' . $st['offset'] . ' static=' . $st['static_skip'] . ' behind=' . $st['behind'] );
remove_all_filters( 'pncp_bunny_lines_per_request' );
// A pause of more than a day: the cursor moves to today, and that is noted.
$state            = PNCP_Bunny::state();
$state['day']     = PNCP_Bunny::log_day( time() - 3 * DAY_IN_SECONDS );
$state['last_ok'] = time() - 3 * DAY_IN_SECONDS;
$state['lost']    = array();
update_option( PNCP_Bunny::STATE, $state, false );
mock_set( array( 'log' => array() ) );
PNCP_Bunny::import( $c, microtime( true ) + 15 );
$st = PNCP_Bunny::state();
t( '8: after a pause of 3 days the skipped lines are noted, not silently passed over', ! empty( $st['lost']['time'] ) && $state['day'] === $st['lost']['from'] && false !== strpos( PNCP_Bunny::import_stale( $st ), 'did not run' ) );
// 10: the download's timeout stays within the run's budget.
mock_set( array( 'log' => $lines, 'timeouts' => array() ) );
delete_option( PNCP_Bunny::STATE );
PNCP_Bunny::import( $c, microtime( true ) + 2 );
$to = mock()['timeouts'];
t( '10: "Import now": a log download may take at most the time left + 5 s (here ≤ 7 s, not 20)', $to && max( $to ) <= 7, wp_json_encode( $to ) );

/* ---------- 9. Site Health ---------- */
$st             = PNCP_Bunny::state();
$st['last_run'] = time() - 2 * HOUR_IN_SECONDS;
$st['last_ok']  = time() - 2 * HOUR_IN_SECONDS;
$st['behind']   = 0;
$st['lost']     = array();
$st['logging']  = array( 'status' => 'on' );
update_option( PNCP_Bunny::STATE, $st, false );
$h = PNCP_Bunny::health_test();
t( '9: last run 2 hours ago: "recommended", with the advice of a real system cron', 'recommended' === $h['status'] && false !== strpos( $h['description'], 'DISABLE_WP_CRON' ) && false !== strpos( $h['description'], 'wp cron event run' ), wp_json_encode( $h ) );
$st['last_run'] = 0;
update_option( PNCP_Bunny::STATE, $st, false );
update_option( 'pncp_bunny_import_on', time() - 2 * HOUR_IN_SECONDS, false );
$h = PNCP_Bunny::health_test();
t( '9: turned on 2 hours ago and never run: "recommended"', 'recommended' === $h['status'] && false !== strpos( $h['description'], 'has not run yet' ) );
$st['last_run'] = time() - 60;
$st['error']    = '';
update_option( PNCP_Bunny::STATE, $st, false );
t( '9: run a minute ago: good', 'good' === PNCP_Bunny::health_test()['status'] );
wp_set_current_user( 1 );
ob_start();
PNCP_Bunny::render_card();
$card = (string) ob_get_clean();
wp_set_current_user( 0 );
t( 'D: the card advises against caching error responses at Bunny', false !== strpos( $card, 'does not cache error responses' ) );
settings( array( 'bunny_import' => 0 ) );

/* ---------- 10. https for the API address; "too fast" exclusions ---------- */
$f = static function () {
	return 'http://api.example.com/v1';
};
remove_all_filters( 'pncp_bunny_api_base' );
add_filter( 'pncp_bunny_api_base', $f );
$https = PNCP_Bunny::base( 'api' );
remove_filter( 'pncp_bunny_api_base', $f );
$g = static function () {
	return 'http://bunny.local.test:8080';
};
add_filter( 'pncp_bunny_api_base', $g );
$test = PNCP_Bunny::base( 'api' );
remove_filter( 'pncp_bunny_api_base', $g );
add_filter( 'pncp_bunny_api_base', static function () { return 'https://bunny-31214.mock.test'; } );
t( '10: an http:// API address from the filter is used over https; a *.test host keeps http', 'https://api.example.com/v1' === $https && 'http://bunny.local.test:8080' === $test, $https . ' ' . $test );
$ok = PNCP_Bunny::fast_exempt( '/', 'wc-ajax=get_refreshed_fragments' ) && PNCP_Bunny::fast_exempt( '/wp-admin/admin-ajax.php', 'action=heartbeat' ) && PNCP_Bunny::fast_exempt( '/wp-cron.php', 'doing_wp_cron=1' ) && PNCP_Bunny::fast_exempt( '/wp-json/wc/store/v1/cart', '' ) && PNCP_Bunny::fast_exempt( '/', 'rest_route=/wc/store/v1/batch' ) && PNCP_Bunny::fast_exempt( '/wp-admin/admin-ajax.php', 'action=rest-nonce' );
t( '10: wc-ajax, admin-ajax (heartbeat, rest-nonce), wp-cron, the Store API: never "too fast"', $ok );
t( '10: a page, a search, wp-login.php still count', ! PNCP_Bunny::fast_exempt( '/shop/', '' ) && ! PNCP_Bunny::fast_exempt( '/', 's=x' ) && ! PNCP_Bunny::fast_exempt( '/wp-login.php', '' ) );
$a = ( static function () {
	$m = new ReflectionMethod( 'PNCP_Bunny', 'new_analysis' );
	$m->setAccessible( true );
	return $m->invoke( null );
} )();
for ( $i = 0; $i < 50; $i++ ) {
	PNCP_Bunny::analyse( $a, PNCP_Bunny::parse_line( line( 'https://example.com/?wc-ajax=get_refreshed_fragments', '45.159.12.1' ) ) );
	PNCP_Bunny::analyse( $a, PNCP_Bunny::parse_line( line( 'https://example.com/shop/p' . $i . '/', '45.159.12.2' ) ) );
}
$per = array();
foreach ( $a['minutes'] as $mk => $n ) {
	$k         = explode( '|', $mk )[0];
	$per[ $k ] = ( isset( $per[ $k ] ) ? $per[ $k ] : 0 ) + $n;
}
t( '10: the analysis counts the pages of one IP, not the wc-ajax refreshes of another', ! isset( $per['45.159.12.1'] ) && 50 === $per['45.159.12.2'], wp_json_encode( $per ) );

/* ---------- A. AI crawlers by User-Agent ---------- */
settings( array( 'allow_ai_search' => 1, 'allow_list' => PNCP_Options::default_allow_list(), 'bot_list' => PNCP_Options::default_bot_list(), 'block_bots' => 1 ) );
$ua = PNCP_Bunny::ua_lock_patterns();
t( 'A: the patterns name the training crawlers (GPTBot, CCBot, ClaudeBot, Bytespider) and a site copier', in_array( '*GPTBot*', $ua, true ) && in_array( '*CCBot*', $ua, true ) && in_array( '*ClaudeBot*', $ua, true ) && in_array( '*Bytespider*', $ua, true ) && in_array( '*HTTrack*', $ua, true ), implode( ' ', array_slice( $ua, 0, 12 ) ) );
$never = true;
foreach ( $ua as $p ) {
	foreach ( array( 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'Mozilla/5.0 (compatible; bingbot/2.0)', 'facebookexternalhit/1.1', 'Mozilla/5.0 (compatible; OAI-SearchBot/1.0)', 'Mozilla/5.0 AppleWebKit/537.36; compatible; ChatGPT-User/1.0', 'Mozilla/5.0+(compatible; UptimeRobot/2.0)', 'Stripe/1.0 (+https://stripe.com/docs/webhooks)', 'WordPress/6.9; https://example.com', 'curl/8.5.0', 'WP Rocket/Preload', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36' ) as $good ) {
		if ( pattern_hit( $p, $good ) ) {
			$never = false;
			echo "    ($p hits $good)\n";
		}
	}
}
t( 'A: never a search engine, an allowed AI search bot, a link preview, a monitor, a payment webhook, WordPress, curl or a browser', $never );
t( 'A: within the most patterns (75: 3 Edge Rules)', count( $ua ) <= 75 && count( $ua ) >= 20 );
settings( array( 'allow_ai_search' => 0 ) );
t( 'A: with "Allow AI search" off, the AI search bots are locked too', in_array( '*OAI-SearchBot*', PNCP_Bunny::ua_lock_patterns(), true ) );
settings( array( 'allow_ai_search' => 1, 'allow_list' => PNCP_Options::default_allow_list() . "\nGPTBot" ) );
t( 'A: an always-allowed User-Agent is left out (GPTBot on the allow list)', ! in_array( '*GPTBot*', PNCP_Bunny::ua_lock_patterns(), true ) );
settings( array( 'allow_list' => PNCP_Options::default_allow_list() ) );
$presets = PNCP_Bunny::presets();
t( 'A: offered as a preset, off until locked', isset( $presets['ai_bots'] ) && 'ua' === $presets['ai_bots']['trigger'] && ! PNCP_Bunny::preset_locked( 'ai_bots' ) );
$preview = PNCP_Bunny::lock_preview( 'preset', 'ai_bots' );
t( 'A: the preview: User-Agent patterns, Edge Rules within the limits, no blocker', ! is_wp_error( $preview ) && 'ua' === $preview['trigger'] && $preview['bunny_rules'] === (int) ceil( count( $ua ) / 25 ) && ! $preview['blockers'], is_wp_error( $preview ) ? $preview->get_error_message() : wp_json_encode( array( $preview['bunny_rules'], $preview['blockers'] ) ) );
mock_reset();
$r     = PNCP_Bunny::lock_preset( 'ai_bots' );
$there = at_bunny( '[preset_ai_bots]' );
$types = array();
foreach ( $there as $rule ) {
	foreach ( $rule['Triggers'] as $tr ) {
		$types[ $tr['Type'] . '|' . $tr['Parameter1'] ] = true;
	}
}
t( 'A: locked: BlockRequest rules with "Request Header" User-Agent triggers only, within the limits', true === $r && count( $there ) === (int) ceil( count( $ua ) / 25 ) && within_limit( $there ) && array( PNCP_Bunny::TRIGGER_HEADER . '|User-Agent' ) === array_keys( $types ) && 4 === (int) reset( $there )['ActionType'], is_wp_error( $r ) ? $r->get_error_message() : wp_json_encode( array_keys( $types ) ) );
t( 'A: it refuses GPTBot and Bytespider on any address, not a browser or Googlebot', blocks( $there, 'https://example.com/', '1.2.3.4', 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)' ) && blocks( $there, 'https://example.com/p/', '1.2.3.4', 'Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)' ) && ! blocks( $there, 'https://example.com/', '1.2.3.4' ) && ! blocks( $there, 'https://example.com/', '66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' ) );
t( 'A: stored as one lock of kind "ua"', 'ua' === stored( 'preset_ai_bots' )['kind'] && PNCP_Bunny::preset_locked( 'ai_bots' ) );
$a = ( static function () {
	$m = new ReflectionMethod( 'PNCP_Bunny', 'new_analysis' );
	$m->setAccessible( true );
	return $m->invoke( null );
} )();
t( 'A: the log import knows a 403 of GPTBot as "blocked at Bunny" by this lock, and its patterns are not URL patterns', ( static function () use ( $a ) {
	foreach ( $a['ua_rules'] as $regex => $label ) {
		if ( preg_match( $regex, 'Mozilla/5.0 (compatible; GPTBot/1.2)' ) ) {
			foreach ( array_keys( $a['rules'] ) as $url_regex ) {
				if ( preg_match( $url_regex, 'https://example.com/GPTBot' ) ) {
					return false;
				}
			}
			return true;
		}
	}
	return false;
} )() );
settings( array( 'monitor_mode' => 1 ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
$off = true;
foreach ( at_bunny( '[preset_ai_bots]' ) as $rule ) {
	$off = $off && empty( $rule['Enabled'] );
}
t( 'A: Monitor only: switched off at Bunny', $off && false === stored( 'preset_ai_bots' )['enabled'] );
settings( array( 'monitor_mode' => 0 ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
t( 'A: blocking again: switched on', true === stored( 'preset_ai_bots' )['enabled'] );
settings( array( 'allow_ai_search' => 0 ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
$all = array();
foreach ( at_bunny( '[preset_ai_bots]' ) as $rule ) {
	$all = array_merge( $all, ...array_column( $rule['Triggers'], 'PatternMatches' ) );
}
t( 'A: the rule follows the settings ("Allow AI search" off: OAI-SearchBot added by the next run)', in_array( '*OAI-SearchBot*', $all, true ) && in_array( '*OAI-SearchBot*', stored( 'preset_ai_bots' )['patterns'], true ) );
settings( array( 'allow_ai_search' => 1 ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
$before = stored( 'preset_ai_bots' );
mock_set( array( 'fail' => array( mock()['posts'] + 2 => 400 ) ) );
settings( array( 'allow_list' => PNCP_Options::default_allow_list() . "\nBytespider" ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
t( 'A: a refused update (HTTP 400 on rule 2): rolled back, the lock stays as it was', stored( 'preset_ai_bots' )['guids'] === $before['guids'] && stored( 'preset_ai_bots' )['patterns'] === $before['patterns'] && count( at_bunny( '[preset_ai_bots]' ) ) === count( $before['guids'] ) );
settings( array( 'allow_list' => PNCP_Options::default_allow_list() ) );
mock_set( array( 'fail' => array() ) );
$r = PNCP_Bunny::unlock_preset( 'ai_bots' );
t( 'A: Remove: gone at Bunny and here', true === $r && ! at_bunny( '[preset_ai_bots]' ) && null === stored( 'preset_ai_bots' ) );
mock_reset( array( 'fail' => array( 2 => 429 ) ) );
$r = PNCP_Bunny::lock_preset( 'ai_bots' );
t( 'A: a lock refused halfway leaves nothing at Bunny', is_wp_error( $r ) && ! at_bunny( '[preset_ai_bots]' ) && null === stored( 'preset_ai_bots' ) );

/* ---------- B. The CDN secret, sent by Bunny ---------- */
mock_reset();
settings( array( 'cdn_secret' => '' ) );
$r = PNCP_Bunny::secret_rule_on();
t( 'B: without a secret: refused with a clear message', is_wp_error( $r ) && 'pncp_no_secret' === $r->get_error_code() && ! mock()['rules'] );
$secret = 'Sec-31214-' . wp_generate_password( 16, false );
settings( array( 'cdn_secret' => $secret ) );
$r    = PNCP_Bunny::secret_rule_on();
$rule = mock()['rules'] ? reset( mock()['rules'] ) : array();
t( 'B: one Edge Rule "Set Request Header" X-ScrapeLock-CDN = the secret, for every request, switched on', true === $r && 1 === count( mock()['rules'] ) && PNCP_Bunny::ACTION_SET_HEADER === (int) $rule['ActionType'] && 'X-ScrapeLock-CDN' === $rule['ActionParameter1'] && $secret === $rule['ActionParameter2'] && array( '*' ) === $rule['Triggers'][0]['PatternMatches'] && ! empty( $rule['Enabled'] ), is_wp_error( $r ) ? $r->get_error_message() : wp_json_encode( $rule ) );
t( 'B: the secret is not stored with the rule (only a hash), and the state is "on"', false === strpos( serialize( get_option( PNCP_Bunny::RULES ) ), $secret ) && 'on' === PNCP_Bunny::secret_rule_state() );
$guid = stored( PNCP_Bunny::SECRET_RULE )['guids'];
PNCP_Bunny::secret_rule_on();
t( 'B: idempotent: sent again, the same rule (same GUID), still one', $guid === stored( PNCP_Bunny::SECRET_RULE )['guids'] && 1 === count( mock()['rules'] ) );
settings( array( 'monitor_mode' => 1 ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
t( 'B: Monitor only does not switch it off (it blocks nothing)', ! empty( reset( mock()['rules'] )['Enabled'] ) && true === stored( PNCP_Bunny::SECRET_RULE )['enabled'] );
settings( array( 'monitor_mode' => 0, 'cdn_secret' => $secret . 'X' ) );
t( 'B: a new secret: "stale" until the next run', 'stale' === PNCP_Bunny::secret_rule_state() );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
t( 'B: the next run sends the new secret, in place', $secret . 'X' === reset( mock()['rules'] )['ActionParameter2'] && $guid === stored( PNCP_Bunny::SECRET_RULE )['guids'] && 'on' === PNCP_Bunny::secret_rule_state() );
wp_set_current_user( 1 );
ob_start();
PNCP_Bunny::render_card();
$card = (string) ob_get_clean();
wp_set_current_user( 0 );
t( 'B: the card shows it (on), never the secret, and not among the locks', false !== strpos( $card, 'Send the CDN secret from Bunny' ) && false !== strpos( $card, 'pncp-bunny-secret-on' ) && false === strpos( $card, $secret ) && false === strpos( $card, 'value="' . PNCP_Bunny::SECRET_RULE . '"' ) );
settings( array( 'cdn_secret' => '' ) );
PNCP_Bunny::sync_rules( array( 'EdgeRules' => array_values( mock()['rules'] ) ) );
t( 'B: the secret cleared: the rule is removed by the next run', ! mock()['rules'] && 'off' === PNCP_Bunny::secret_rule_state() );
settings( array( 'cdn_secret' => $secret ) );
PNCP_Bunny::secret_rule_on();
PNCP_Bunny::lock_preset( 'probes' );
PNCP_Bunny::deactivate();
t( 'B: deactivation removes the locks but keeps the rule that sends the secret (server rules may need it)', 1 === count( mock()['rules'] ) && null !== stored( PNCP_Bunny::SECRET_RULE ) && PNCP_Bunny::ACTION_SET_HEADER === (int) reset( mock()['rules'] )['ActionType'] );
$r = PNCP_Bunny::secret_rule_off();
t( 'B: Remove: gone at Bunny and here', true === $r && ! mock()['rules'] && null === stored( PNCP_Bunny::SECRET_RULE ) );

/* ---------- 2. "Only through the CDN" in the server rules ---------- */
settings( array( 'cdn_secret' => $secret, 'cdn_only' => 1 ) );
$http1 = PNCP_Rules::nginx_http();
$srv   = PNCP_Rules::nginx_server();
$id    = PNCP_Rules::nginx_id();
t( '2: Nginx part 1: a map of the secret (placeholder, never the secret itself), open paths, allowed IPs', false !== strpos( $http1, 'map $http_x_scrapelock_cdn $pncp_cdn_ok_' . $id . ' { default 0; "YOUR_CDN_SECRET" 1; }' ) && false !== strpos( $http1, 'acme-challenge' ) && false !== strpos( $http1, 'wp-cron' ) && false !== strpos( $http1, '$pncp_not_cdn_' . $id ) && false === strpos( $http1 . $srv, $secret ) );
$pos_if  = strpos( $srv, 'if ($pncp_not_cdn_' . $id . ') { return 403; }' );
$pos_loc = preg_match( '/^location /m', $srv, $mloc, PREG_OFFSET_CAPTURE ) ? $mloc[0][1] : false;
t( '2: Nginx part 2: "if ($pncp_not_cdn_…) { return 403; }" before every location (before cache and static files)', false !== $pos_if && false !== $pos_loc && $pos_if < $pos_loc );
$apache = PNCP_Rules::apache();
t( '2: Apache: the same check in .htaccess', false !== strpos( $apache, 'RewriteCond %{HTTP:X-ScrapeLock-CDN} !=YOUR_CDN_SECRET' ) && false !== strpos( $apache, 'acme-challenge' ) && false === strpos( $apache, $secret ) );
// The map's logic, as Nginx reads "<secret><open><allowed>:<self><forwarded>".
$map = '';
foreach ( explode( "\n", $http1 ) as $l ) {
	if ( false !== strpos( $l, '$pncp_not_cdn_' . $id . ' {' ) ) {
		$map = $l;
	}
}
preg_match_all( '/"(~[^"]+)" 0;/', $map, $mm );
$let = static function ( $key ) use ( $mm ) {
	foreach ( $mm[1] as $re ) {
		if ( preg_match( '#' . substr( $re, 1 ) . '#', $key ) ) {
			return true;
		}
	}
	return false;
};
t( '2: map: with the secret, on an open path, from an allowed IP or the server itself: let through; anyone else: 403', $let( '100:01' ) && $let( '010:01' ) && $let( '001:01' ) && $let( '000:11' ) && $let( '000:20' ) && ! $let( '000:01' ) && ! $let( '000:21' ) && ! $let( '000:00' ) );
$nginx = trim( (string) shell_exec( 'command -v nginx 2>/dev/null' ) );
if ( '' !== $nginx ) {
	$dir = sys_get_temp_dir() . '/pncp-31214-nginx-' . getmypid();
	@mkdir( $dir . '/logs', 0700, true );
	file_put_contents( $dir . '/nginx.conf', "error_log $dir/logs/e.log;\npid $dir/n.pid;\nevents {}\nhttp {\naccess_log off;\nclient_body_temp_path $dir/logs;\nproxy_temp_path $dir/logs;\nfastcgi_temp_path $dir/logs;\nuwsgi_temp_path $dir/logs;\nscgi_temp_path $dir/logs;\n" . str_replace( 'YOUR_CDN_SECRET', 'abc', $http1 ) . "\nserver {\nlisten 127.0.0.1:64999;\n" . $srv . "\n}\n}\n" );
	exec( escapeshellarg( $nginx ) . ' -t -p ' . escapeshellarg( $dir ) . ' -c ' . escapeshellarg( $dir . '/nginx.conf' ) . ' 2>&1', $out, $rc );
	t( '2: nginx -t accepts both parts with the check', 0 === $rc, implode( ' ', $out ) );
	exec( 'rm -rf ' . escapeshellarg( $dir ) );
} else {
	echo "SKIP nginx -t (no nginx here)\n";
}
if ( '' !== $wp_cli ) {
	$dir = sys_get_temp_dir() . '/pncp-31214-rules-' . getmypid();
	@mkdir( $dir, 0700, true );
	// The token of the static private feeds, when other tests left them on: the command keeps the installed one.
	file_put_contents( $dir . '/scrapelock.conf', "map x \$y {\n    \"~^tok31214abcdef:\" 1;\n}\n" );
	exec( $wp_cli . ' scrapelock rules install --nginx-http=' . escapeshellarg( $dir . '/scrapelock.conf' ) . ' --dry-run 2>&1', $out2, $rc2 );
	$txt = implode( "\n", $out2 );
	t( '2: rules install --dry-run: the secret written in place of the placeholder, never printed', false !== strpos( $txt, '"[secret]" 1;' ) && false === strpos( $txt, $secret ) && false === strpos( $txt, 'YOUR_CDN_SECRET" 1' ), substr( $txt, 0, 400 ) );
	exec( 'rm -rf ' . escapeshellarg( $dir ) );
}
settings( array( 'cdn_only' => 0 ) );
t( '2: without "Only through the CDN", no such lines', false === strpos( PNCP_Rules::nginx_http() . PNCP_Rules::nginx_server() . PNCP_Rules::apache(), 'not_cdn' ) && false === strpos( PNCP_Rules::apache(), 'X-ScrapeLock-CDN' ) );
settings( array( 'cdn_secret' => '' ) );

/* ---------- C. Purging Bunny's cache after a change of the content ---------- */
mock_reset();
wp_clear_scheduled_hook( PNCP_Bunny::PURGE_EVENT );
delete_option( PNCP_Bunny::PURGE );
t( 'C: never in a visitor\'s request', false === PNCP_Bunny::queue_purge( 'stealth' ) && ! wp_next_scheduled( PNCP_Bunny::PURGE_EVENT ) );
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
require_once ABSPATH . 'wp-admin/includes/screen.php';
WP_Screen::get( 'dashboard' )->set_current_screen();
$old = PNCP_Options::stored();
update_option( PNCP_OPTION, array_merge( $old, array( 'watermark_opacity' => 37 === (int) $old['watermark_opacity'] ? 38 : 37 ) ) );
PNCP_Options::flush();
t( 'C: a watermark setting changed (from wp-admin): a purge is waiting, in about a minute', (int) wp_next_scheduled( PNCP_Bunny::PURGE_EVENT ) > time() && (int) wp_next_scheduled( PNCP_Bunny::PURGE_EVENT ) <= time() + 70 );
$r = PNCP_Bunny::run_purge();
t( 'C: the event purges the pull zone once (POST /pullzone/777/purgeCache)', is_array( $r ) && 'ok' === $r['status'] && 1 === (int) mock()['purges'] );
wp_clear_scheduled_hook( PNCP_Bunny::PURGE_EVENT );
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'stealth_sitemap' => empty( $old['stealth_sitemap'] ) ? 1 : 0 ) ) );
PNCP_Options::flush();
$at = (int) wp_next_scheduled( PNCP_Bunny::PURGE_EVENT );
t( 'C: a Stealth change right after: waits until 10 minutes after the last purge', $at >= time() + PNCP_Bunny::PURGE_GAP - 70 );
t( 'C: an early run of the event does not purge again', null === PNCP_Bunny::run_purge() && 1 === (int) mock()['purges'] );
wp_clear_scheduled_hook( PNCP_Bunny::PURGE_EVENT );
delete_option( PNCP_Bunny::PURGE );
do_action( 'pncp_watermark_file_changed', '/tmp/x.jpg' );
do_action( 'pncp_watermark_file_changed', '/tmp/y.jpg' );
t( 'C: an image rewritten by the watermark: one purge waiting (once per request)', (int) wp_next_scheduled( PNCP_Bunny::PURGE_EVENT ) > 0 && 1 === count( array_filter( _get_cron_array(), static function ( $e ) { return isset( $e[ PNCP_Bunny::PURGE_EVENT ] ); } ) ) );
do_action( 'pncp_bunny_queue_purge', 'stealth' );
t( 'C: the hook for other parts (Stealth\'s new map) queues it too', (int) wp_next_scheduled( PNCP_Bunny::PURGE_EVENT ) > 0 && 'stealth' === get_option( PNCP_Bunny::PURGE )['why'] );
update_option( PNCP_OPTION, $old );
PNCP_Options::flush();
wp_clear_scheduled_hook( PNCP_Bunny::PURGE_EVENT );
$GLOBALS['current_screen'] = null;

/* ---------- Clean up ---------- */
$_SERVER = $saved_server;
foreach ( array( PNCP_Bunny::RULES, PNCP_Bunny::CALLS, PNCP_Bunny::LOGIN_STRICT, PNCP_Bunny::LOGIN_ADMIN_IP, PNCP_Bunny::CONFIG, PNCP_Bunny::STATE, PNCP_Bunny::PURGE, 'pncp_bunny_import_on', 'pncp_test_bunny_31214' ) as $pncp_o ) {
	delete_option( $pncp_o );
}
update_option( PNCP_OPTION, $saved_settings );
PNCP_Options::flush();
wp_clear_scheduled_hook( PNCP_Bunny::CRON );
wp_clear_scheduled_hook( PNCP_Bunny::PURGE_EVENT );
wp_clear_scheduled_hook( PNCP_Ip::BUNNY_REFRESH );
global $wpdb;
$wpdb->query( 'DELETE FROM ' . PNCP_Log::table() . " WHERE ip IN ('203.0.113.77', '203.0.113.9')" ); // phpcs:ignore

echo $fails ? "\n$fails FAILED\n" : "\nALL PASSED\n";
exit( $fails ? 1 : 0 );

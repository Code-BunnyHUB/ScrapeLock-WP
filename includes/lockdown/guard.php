<?php
/**
 * Plugin Name: ScrapeLock Lockdown guard
 * Description: Part of the ScrapeLock plugin (Lockdown). While the site is locked it keeps ScrapeLock active and keeps the active plugins and the theme as they were when the site was locked, from the start of every request. It reads the signed state of the lock from scrapelock-lockdown-data/guard.json next to it. ScrapeLock removes this file when the site is unlocked or ScrapeLock is deactivated. To turn it off by hand: add define( 'SCRAPELOCK_UNLOCK', true ); to wp-config.php, or delete this file.
 * Author: ScrapeLock
 * Version: 3
 *
 * 3.12.11: this file is the same on every site, a copy of wp-content/plugins/scrapelock/includes/lockdown/guard.php
 * (its hash does not change with the site or the lock). What belongs to this site and lock is in
 * scrapelock-lockdown-data/guard.json, plain JSON:
 *
 *   {"about": "...", "data": {"beacon": {...}, "own": "scrapelock/scrapelock.php", "multisite": false}, "sig": "..."}
 *
 * - "beacon": whether the site is locked, until when it is unlocked for a while, and the generations of the lock,
 *   signed with the key of Lockdown (ScrapeLock checks that signature itself).
 * - "sig": an HMAC-SHA256 of "data" with a key made from SCRAPELOCK_KEY, or else AUTH_KEY and AUTH_SALT, of
 *   wp-config.php (never from the database). A guard.json that does not match it is not followed: then only
 *   ScrapeLock itself is kept active on a single site, nothing else.
 *
 * 3.13.0: the active plugins and the theme as they were when the site was locked ("values"; multisite: per site in
 * "sites", and the plugins of the whole network in "network") are in guard-values.json in the private folder next
 * to guard.json ("data-" and 20 hex digits made from the same key, so it cannot be guessed on a server that ignores
 * the folder's deny rules), signed the same way, with the generations of the record in guard.json ("gen", "snap"):
 * the guard only follows the file of the same lock. A guard.json of 3.12.11 to 3.12.13 that still holds them is
 * followed as before until ScrapeLock writes it again (PNCP_LOCKDOWN_GUARD_INLINE tells it so).
 *
 * The file is never run, only read, and holds nothing secret. Without guard.json this file does nothing. Nothing is
 * kept while the site is unlocked for a while, with SCRAPELOCK_UNLOCK in wp-config.php, or when ScrapeLock's own
 * files are gone.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

// Which guard ran on this request (3.12.10 and older wrote the data into this file itself).
defined( 'PNCP_LOCKDOWN_GUARD' ) || define( 'PNCP_LOCKDOWN_GUARD', 3 );

( static function () {
	$file = __DIR__ . '/scrapelock-lockdown-data/guard.json';
	if ( ! is_file( $file ) ) {
		return;
	}
	$text = @file_get_contents( $file, false, null, 0, 4194304 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Before WordPress has loaded; unreadable = no data.
	$json = is_string( $text ) ? json_decode( $text, true ) : null;
	if ( ! is_array( $json ) || ! isset( $json['data'], $json['sig'] ) || ! is_array( $json['data'] ) || ! is_string( $json['sig'] ) ) {
		return;
	}
	$data = $json['data'];

	// The key: from wp-config.php only (WordPress's own wp_salt() is not loaded yet, and may read the database).
	if ( defined( 'SCRAPELOCK_KEY' ) && is_string( SCRAPELOCK_KEY ) && strlen( SCRAPELOCK_KEY ) >= 32 ) {
		$material = 'scrapelock|' . SCRAPELOCK_KEY;
	} elseif ( defined( 'AUTH_KEY' ) && defined( 'AUTH_SALT' ) ) {
		$material = (string) AUTH_KEY . (string) AUTH_SALT;
	} else {
		$material = '';
	}
	// The same data always gives the same text: keys sorted at every level.
	$canon = static function ( $value ) use ( &$canon ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}
		ksort( $value );
		foreach ( $value as $key => $item ) {
			$value[ $key ] = $canon( $item );
		}
		return $value;
	};
	$signed  = json_encode( $canon( $data ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Before WordPress has loaded.
	$genuine = is_string( $signed ) && hash_equals( hash_hmac( 'sha256', $signed, hash( 'sha256', $material . '|pncp_lockdown_guard', true ) ), $json['sig'] );

	// Values that are not valid UTF-8 are written as {"~pncp": "hex", "v": "..."} (arrays that have a "~pncp" key
	// themselves as {"~pncp": "array", "v": {...}}).
	$unpack = static function ( $value ) use ( &$unpack ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}
		if ( isset( $value['~pncp'] ) && array_key_exists( 'v', $value ) && 2 === count( $value ) ) {
			if ( 'hex' === $value['~pncp'] && is_string( $value['v'] ) && preg_match( '/^(?:[0-9a-f]{2})*$/', $value['v'] ) ) {
				return (string) hex2bin( $value['v'] );
			}
			if ( 'array' === $value['~pncp'] && is_array( $value['v'] ) ) {
				$value = $value['v'];
			} else {
				return null;
			}
		}
		foreach ( $value as $key => $item ) {
			$value[ $key ] = $unpack( $item );
		}
		return $value;
	};

	if ( $genuine && array_intersect( array( 'values', 'sites', 'network', 'network_own' ), array_keys( $data ) ) ) {
		defined( 'PNCP_LOCKDOWN_GUARD_INLINE' ) || define( 'PNCP_LOCKDOWN_GUARD_INLINE', true ); // Written again by ScrapeLock.
	} elseif ( $genuine && isset( $data['beacon']['gen'], $data['beacon']['snap'] ) ) {
		// 3.13.0: the plugins and the theme, from the private folder.
		$dir   = 'data-' . substr( hash_hmac( 'sha256', 'pncp_lockdown_private_dir', hash( 'sha256', $material . '|pncp_lockdown_sig', true ) ), 0, 20 );
		$vtext = @file_get_contents( __DIR__ . '/scrapelock-lockdown-data/' . $dir . '/guard-values.json', false, null, 0, 4194304 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Before WordPress has loaded; unreadable = no lists.
		$vjson = is_string( $vtext ) ? json_decode( $vtext, true ) : null;
		if ( is_array( $vjson ) && isset( $vjson['data'], $vjson['sig'] ) && is_array( $vjson['data'] ) && is_string( $vjson['sig'] ) ) {
			$vdata   = $vjson['data'];
			$vsigned = json_encode( $canon( $vdata ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Before WordPress has loaded.
			$vok     = is_string( $vsigned ) && hash_equals( hash_hmac( 'sha256', $vsigned, hash( 'sha256', $material . '|pncp_lockdown_guard', true ) ), $vjson['sig'] );
			if ( $vok && isset( $vdata['kind'], $vdata['gen'], $vdata['snap'] ) && 'values' === $vdata['kind'] && (int) $vdata['gen'] === (int) $data['beacon']['gen'] && (int) $vdata['snap'] === (int) $data['beacon']['snap'] ) {
				foreach ( array( 'values', 'sites', 'network', 'network_own' ) as $key ) {
					if ( array_key_exists( $key, $vdata ) ) {
						$data[ $key ] = $vdata[ $key ];
					}
				}
			}
		}
	}

	if ( $genuine && isset( $data['beacon'] ) && is_array( $data['beacon'] ) ) {
		// ScrapeLock reads the lock from here (and checks its own signature on it).
		defined( 'PNCP_LOCKDOWN_BEACON' ) || define( 'PNCP_LOCKDOWN_BEACON', (string) json_encode( $data['beacon'] ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Before WordPress has loaded.
	}

	// ScrapeLock's main file (folder/file.php). Not followed for data that does not match its signature unless it
	// is a plugin's scrapelock.php.
	$own = isset( $data['own'] ) && is_string( $data['own'] ) ? $data['own'] : '';
	$ok  = (bool) preg_match( $genuine ? '#^[^/\\\\]+/[^/\\\\]+\.php$#' : '#^[^/\\\\]+/scrapelock\.php$#', $own ) && false === strpos( $own, '..' );
	if ( ! $ok || ! defined( 'WP_PLUGIN_DIR' ) || ! is_readable( WP_PLUGIN_DIR . '/' . $own ) ) {
		return; // ScrapeLock's files are gone: nothing is kept.
	}
	if ( defined( 'SCRAPELOCK_UNLOCK' ) && true === SCRAPELOCK_UNLOCK ) {
		return;
	}
	$multisite = is_multisite();
	if ( $genuine ) {
		$beacon = isset( $data['beacon'] ) && is_array( $data['beacon'] ) ? $data['beacon'] : array();
		if ( empty( $beacon['locked'] ) || time() < ( isset( $beacon['until'] ) ? (int) $beacon['until'] : 0 ) ) {
			return; // Not locked, or unlocked for a while.
		}
		if ( ! empty( $data['multisite'] ) !== $multisite ) {
			return; // Written for another kind of site.
		}
	} elseif ( $multisite ) {
		return; // Data that does not match its signature: on multisite nothing is kept.
	}

	// The values as they were when the site was locked. ScrapeLock reads the stored values (to put them back) with
	// 'pass' set, and changes the values when it writes guard.json again on the same request.
	if ( ! $multisite ) {
		$GLOBALS['pncp_lockdown_guard'] = array(
			'own'    => $own,
			'values' => $genuine && isset( $data['values'] ) && is_array( $data['values'] ) ? $unpack( $data['values'] ) : array(),
			'pass'   => false,
		);
		$filter = static function ( $value, $option ) {
			$guard = isset( $GLOBALS['pncp_lockdown_guard'] ) && is_array( $GLOBALS['pncp_lockdown_guard'] ) ? $GLOBALS['pncp_lockdown_guard'] : array();
			if ( ! empty( $guard['pass'] ) || ! isset( $guard['own'] ) ) {
				return $value;
			}
			if ( isset( $guard['values'] ) && is_array( $guard['values'] ) && array_key_exists( $option, $guard['values'] ) ) {
				$value = $guard['values'][ $option ];
			}
			if ( 'active_plugins' === $option ) {
				$value = is_array( $value ) ? array_values( $value ) : array();
				if ( ! in_array( $guard['own'], $value, true ) ) {
					$value[] = $guard['own'];
				}
			}
			return $value;
		};
		foreach ( array( 'active_plugins', 'template', 'stylesheet' ) as $option ) {
			add_filter( 'option_' . $option, $filter, 1, 2 );
			add_filter( 'default_option_' . $option, $filter, 1, 2 );
		}
		return;
	}

	// Multisite: per site ID ('sites') and for the whole network ('network').
	$GLOBALS['pncp_lockdown_guard'] = array(
		'own'         => $own,
		'values'      => array(),
		'sites'       => isset( $data['sites'] ) && is_array( $data['sites'] ) ? $unpack( $data['sites'] ) : array(),
		'network'     => isset( $data['network'] ) && is_array( $data['network'] ) ? $unpack( $data['network'] ) : array(),
		'network_own' => ! empty( $data['network_own'] ),
		'pass'        => false,
	);
	$read    = static function () {
		return isset( $GLOBALS['pncp_lockdown_guard'] ) && is_array( $GLOBALS['pncp_lockdown_guard'] ) ? $GLOBALS['pncp_lockdown_guard'] : array();
	};
	$filter  = static function ( $value, $option ) use ( $read ) {
		$guard = $read();
		$id    = get_current_blog_id();
		if ( empty( $guard['pass'] ) && isset( $guard['sites'][ $id ] ) && is_array( $guard['sites'][ $id ] ) && array_key_exists( $option, $guard['sites'][ $id ] ) ) {
			$value = $guard['sites'][ $id ][ $option ];
		}
		return $value;
	};
	$network = static function ( $value, $option ) use ( $read ) {
		$guard = $read();
		if ( ! empty( $guard['pass'] ) || ! isset( $guard['own'] ) ) {
			return $value;
		}
		if ( isset( $guard['network'] ) && is_array( $guard['network'] ) && array_key_exists( $option, $guard['network'] ) ) {
			$value = $guard['network'][ $option ];
		}
		if ( ! empty( $guard['network_own'] ) ) {
			$value = is_array( $value ) ? $value : array();
			if ( ! isset( $value[ $guard['own'] ] ) ) {
				$value[ $guard['own'] ] = 1;
			}
		}
		return $value;
	};
	foreach ( array( 'active_plugins', 'template', 'stylesheet' ) as $option ) {
		add_filter( 'option_' . $option, $filter, 1, 2 );
		add_filter( 'default_option_' . $option, $filter, 1, 2 );
	}
	add_filter( 'site_option_active_sitewide_plugins', $network, 1, 2 );
	add_filter( 'default_site_option_active_sitewide_plugins', $network, 1, 2 );
} )();

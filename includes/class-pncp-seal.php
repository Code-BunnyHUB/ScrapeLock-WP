<?php
/**
 * Lockdown seal: keeps the lock honest against someone who can write to the database directly (for example
 * through SQL injection in another plugin) but not to the files.
 *
 * - The lock state and the file fingerprint are signed (HMAC) with a key derived from the keys in
 *   wp-config.php, which are not in the database. A changed or forged value no longer matches its signature.
 * - A small must-use plugin (the "guard") holds a signed copy of "locked / until when" and of the generation
 *   of the lock state (a number that goes up with every save). It is a file, so deleting the state in the
 *   database, or putting back an older copy of it from a backup, cannot unlock the site or bring back an old
 *   app secret or old recovery codes. While locked the guard also keeps the list of active plugins and the
 *   theme as they were when the site was locked, before any other plugin loads, and keeps ScrapeLock loaded.
 *   3.12.11: the guard is a fixed file shipped with the plugin (includes/lockdown/guard.php, the same on every
 *   site); it reads the signed data of the lock from plain JSON files next to it. No file Lockdown writes is PHP
 *   with data in it, and nothing is base64 or serialize(): see DATA_DIR and migrate_files().
 * - When the site is locked, the protected options are saved (signed) and put back if they change behind
 *   WordPress's back, and the accounts that could administer the site are noted: another account that gains
 *   such rights while locked cannot sign in.
 * - 3.4, multisite: the lock covers the whole network. The network options (network plugins, super admins) are
 *   saved in a signed snapshot of the network, which also notes the fingerprints and administrators of every
 *   site; each site checks its own snapshot against it, and the guard keeps the plugins and themes per site.
 *
 * Someone who can change the files themselves (or wp-config.php) can still do anything; that is what the file
 * integrity check, "No PHP in uploads" and the server's own security are for.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * Signatures, the guard file, the snapshot of protected options and of the administrators.
 */
final class PNCP_Seal {

	/**
	 * Snapshot of the protected options and the administrators, taken when the site is locked (per site).
	 */
	const SNAP = 'pncp_lockdown_snap';

	/**
	 * The fingerprints of the same options, signed and autoloaded: what every request compares, without reading
	 * the (larger, not autoloaded) snapshot itself unless something changed.
	 */
	const DIGESTS = 'pncp_lockdown_digests';

	/**
	 * Seconds after the lock during which a missing snapshot of that lock is not an alarm yet: the lock is saved
	 * a moment before its snapshot is taken (snapshot_pending()).
	 */
	const SNAPSHOT_GRACE = 60;

	/**
	 * 3.4: what the administrator who unlocked for a while changed through WordPress meanwhile (signed, per site,
	 * not autoloaded): kept when the site locks again by itself (accept_window()).
	 */
	const WINDOW = 'pncp_lockdown_window';

	/**
	 * The guard (must-use plugin).
	 */
	const FILE   = 'scrapelock-lockdown-guard.php';
	const MARKER = 'ScrapeLock Lockdown guard';

	/**
	 * The options the guard keeps as they were when the site was locked, from the very start of every request:
	 * other plugins are loaded from the list of active plugins, so putting it back later (verify_options(), on
	 * plugins_loaded) would be too late for a plugin added to it in the database.
	 */
	const GUARDED = array( 'active_plugins', 'template', 'stylesheet' );

	/**
	 * 3.4 to 3.12.10: the constant the guard file defined with a signed copy of the whole snapshot (single site), as
	 * base64 of serialize(). Read once more by migrate_files(); since 3.12.11 the copy is snapshot.json in the
	 * private folder next to the guard (plain JSON). Someone who can only change the database can delete or change
	 * the snapshot there, but not this copy: the changed settings are still put back from it, and the snapshot in
	 * the database is put back too.
	 */
	const COPY = 'PNCP_LOCKDOWN_SNAP_COPY';

	/**
	 * 3.12.11: the data files of Lockdown. Next to the guard, in the folder DATA_DIR of the must-use plugins folder:
	 * GUARD_DATA (what the guard reads: the signed record, nothing secret; 3.13.0: not the plugins and the theme it
	 * keeps, which are in GUARD_VALUES in the private folder), and in the private folder (private_name(), made from the keys) SNAP_FILE (the signed copy of the snapshot) and
	 * FAILS_FILE (the copy of the wrong-code counters). Without the guard, LOCK_FILE and FAILS_FILE in the private
	 * folder of the first of BEACON_DIRS that PHP can write to. All plain JSON (see pack()), never run: no file
	 * Lockdown writes is PHP, except the guard, which is the same shipped file on every site.
	 */
	const DATA_DIR   = 'scrapelock-lockdown-data';
	const GUARD_DATA = 'guard.json';
	const SNAP_FILE  = 'snapshot.json';
	const LOCK_FILE  = 'lock.json';
	const FAILS_FILE = 'fails.json';

	/**
	 * 3.13.0: the plugins and the theme the guard keeps while locked (multisite: of every site and of the network),
	 * signed like guard.json, in the guard's private folder (guard_private_dir_for_guard()). guard.json, whose name is
	 * fixed and which a server that ignores .htaccess (Nginx) shows to anyone, holds only the signed record and
	 * ScrapeLock's own file: the list of active plugins tells an attacker which vulnerabilities to try.
	 */
	const GUARD_VALUES = 'guard-values.json';

	/**
	 * 3.12.11: the first key of each data file: what it is.
	 */
	const ABOUT_GUARD = 'ScrapeLock Lockdown: the signed state of the lock (nothing else), read by wp-content/mu-plugins/scrapelock-lockdown-guard.php. Written and removed by ScrapeLock, never run. To unlock from the server, set SCRAPELOCK_UNLOCK to true in wp-config.php.';
	const ABOUT_SNAP  = 'ScrapeLock Lockdown: the signed copy of the protected settings, kept while the site is locked. Written and removed by ScrapeLock, never run.';
	const ABOUT_VALUES = 'ScrapeLock Lockdown: the active plugins and the theme kept while the site is locked, read by wp-content/mu-plugins/scrapelock-lockdown-guard.php. Written and removed by ScrapeLock, never run.';
	const ABOUT_LOCK  = 'ScrapeLock Lockdown: the signed lock file, written when the guard file could not be. Written and removed by ScrapeLock, never run.';

	/**
	 * 3.4.1: the lock file, written when the guard cannot be written (the owner locked with "Lock without the guard
	 * file"): a signed copy of the lock outside the database, in the first of these folders of wp-content that PHP
	 * can write to (BEACON_DIRS). 3.12.11: lock.json in the folder's private folder. 3.4.1 to 3.12.10 wrote
	 * lock-<hex>.php there, starting with BEACON_HEAD, then the JSON: read once more and replaced
	 * (migrate_files()).
	 */
	const BEACON_DIRS = array( 'uploads/scrapelock-lockdown', 'scrapelock-lockdown' );
	const BEACON_HEAD = "<?php exit; ?>\n";

	/**
	 * The .htaccess of Lockdown's data folders (no access on Apache) and, 3.12.11, their index.html (no folder
	 * listing). BEACON_INDEX: the index.php of 3.4.1 to 3.12.10, removed once an index.html is there.
	 */
	const BEACON_INDEX    = "<?php\n// Silence is golden.\n";
	const BEACON_HTACCESS = "# ScrapeLock Lockdown\n<IfModule mod_authz_core.c>\n\tRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n\tOrder allow,deny\n\tDeny from all\n</IfModule>\n";
	const DIR_INDEX       = "<!-- Silence is golden. -->\n";

	/**
	 * The lock file keeps the signed copy of the snapshot (as the guard does) only up to this size.
	 */
	const BEACON_MAX_COPY = 1048576;

	/**
	 * 3.4.2: the lock line, a constant the owner adds to wp-config.php by hand: define( 'SCRAPELOCK_LOCKED',
	 * '<token>' );. Offered when no file of the lock can be written (neither the guard nor the lock file: PHP
	 * cannot write to any of their folders), and as an optional second copy outside the database next to them.
	 * The token is signed with the keys (key()), so it only counts on this site, and names the generation of
	 * the lock (the state saved when the site was locked, "lgen") and the address alerts go to. While it is
	 * there, a lock state that is missing, does not match its signature or is older than that generation (put
	 * back from a copy) counts as "locked", as with the guard file. A newer genuine state is followed as usual:
	 * an unlock for a while, or an unlock for good (the owner is then told to remove the line). Multisite: one
	 * line for the whole network (one wp-config.php, one lock, the same keys). ScrapeLock never writes
	 * wp-config.php itself.
	 */
	const CONFIG        = 'SCRAPELOCK_LOCKED';
	const CONFIG_PREFIX = 'sl1';

	/**
	 * 3.4, multisite: the snapshot of the whole network, taken when the network is locked (a network option,
	 * signed, not read on every request): the network options below, the super admins, the application
	 * passwords, and for every site where ScrapeLock is active the fingerprints of its protected options, its
	 * administrators and the generation of its own snapshot. Each site keeps its own snapshot as well (SNAP and
	 * DIGESTS above, per site), and checks it against this one.
	 */
	const NET_SNAP = 'pncp_lockdown_net_snap';

	/**
	 * 3.4, multisite: the fingerprints of the network options and the generation of every site's snapshot,
	 * signed: what every request on every site compares (small, without the values themselves).
	 */
	const NET_DIGESTS = 'pncp_lockdown_net_digests';

	/**
	 * 3.4, multisite: what the administrator who unlocked for a while changed in the network options meanwhile
	 * (signed). The changes on each site are noted in that site's own WINDOW.
	 */
	const NET_WINDOW = 'pncp_lockdown_net_window';

	/**
	 * 3.4, multisite: the network options kept while locked and put back if they change behind WordPress's
	 * back: the plugins active on the whole network, the super admins, the network admin email and who may
	 * register accounts and sites.
	 */
	const NETWORK_OPTIONS = array( 'active_sitewide_plugins', 'site_admins', 'admin_email', 'registration' );

	/**
	 * The signed fingerprints of the network (NET_DIGESTS) as read on this request: null = not read yet, false =
	 * missing or not matching their signature.
	 *
	 * @var array<string, mixed>|false|null
	 */
	private static $net_digests = null;

	/**
	 * The guard's record as written on this request (the constant from the guard file is from the start of
	 * the request).
	 *
	 * @var array{locked:bool, until:int, gen?:int, snap?:int}|null
	 */
	private static $current = null;

	/**
	 * 3.4: the signed copy of the snapshot that the guard holds on this request (null: as the guard file defined
	 * it at the start of the request; false: none). Changed when the guard is written again on this request.
	 *
	 * @var array<string, mixed>|false|null
	 */
	private static $copy = null;

	/**
	 * 3.4: did snapshot() on this request return the copy from the guard file, because the snapshot in the
	 * database is missing, changed or older?
	 *
	 * @var bool
	 */
	private static $from_copy = false;

	/**
	 * 3.4.1: the lock file as read on this request (see beacon_file()): null = not read yet, false = none.
	 *
	 * @var array<string, mixed>|false|null
	 */
	private static $file = null;

	/**
	 * 3.4.1: was there a lock file when it was first read on this request?
	 *
	 * @var bool
	 */
	private static $file_at_start = false;

	/**
	 * 3.4.2: the lock line in wp-config.php (see CONFIG) as read on this request: null = not read yet, false =
	 * none, or not matching this site's keys.
	 *
	 * @var array{g:int, m:string}|false|null
	 */
	private static $config = null;

	/**
	 * 3.4.2: the lock line is not followed for the rest of this request (a new app is being connected with
	 * SCRAPELOCK_UNLOCK: the lock it named is over, as when the guard file is removed then).
	 *
	 * @var bool
	 */
	private static $config_off = false;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		// Early: right after the plugins have loaded, before themes, REST and the admin.
		add_action( 'plugins_loaded', array( __CLASS__, 'verify_options' ), 1 );
		add_filter( 'authenticate', array( __CLASS__, 'authenticate' ), 100 );
		// 3.4: a password WordPress itself changes is noted in the snapshot (see password_changed()).
		add_action( 'wp_set_password', array( __CLASS__, 'on_set_password' ), 10, 3 );
		add_action( 'profile_update', array( __CLASS__, 'on_profile_update' ), 10, 2 );
		// 3.12.11: the files of the lock written by 3.12.10 are moved into the new ones on the first page of wp-admin.
		add_action( 'admin_init', array( __CLASS__, 'maybe_migrate' ), 1 );
	}

	/**
	 * WordPress set a new password (wp_set_password()), for example when it stores the hash again in a newer
	 * format as the owner signs in.
	 *
	 * @param string       $password Password (not used).
	 * @param int          $user_id  User.
	 * @param WP_User|null $old      The user before the change.
	 */
	public static function on_set_password( $password, $user_id, $old = null ) {
		if ( $old instanceof WP_User ) {
			self::password_changed( (int) $user_id, (string) $old->user_pass );
		}
	}

	/**
	 * WordPress updated an account (wp_update_user()), perhaps its password.
	 *
	 * @param int          $user_id User.
	 * @param WP_User|null $old     The user before the change.
	 */
	public static function on_profile_update( $user_id, $old = null ) {
		if ( $old instanceof WP_User ) {
			self::password_changed( (int) $user_id, (string) $old->user_pass );
		}
	}

	/* ---------- Signatures ---------- */

	/**
	 * The signing key: from the keys in wp-config.php (AUTH_KEY / AUTH_SALT), never stored.
	 *
	 * @return string
	 */
	private static function key() {
		return hash( 'sha256', self::key_material() . '|pncp_lockdown_sig', true );
	}

	/**
	 * 3.4.3: a Lockdown option as it is in the database now. With a persistent object cache (Redis, Memcached)
	 * get_option() answers from the cache, which keeps an option with no expiry: a row changed or deleted
	 * with SQL went unseen, the tamper checks passed and a later write compared against the stale copy (and
	 * changed nothing). The row is read directly, and the cache is brought in line with it. Without an
	 * object cache this is get_option() / get_site_option() as before.
	 *
	 * @param string $name    Option.
	 * @param bool   $network A site option (network option on multisite).
	 * @param mixed  $default Value when the row is not there.
	 * @return mixed
	 */
	public static function fresh_option( $name, $network = false, $default = false ) {
		$net = $network && is_multisite();
		// 3.12.9: not in a visitor's request (PNCP_Defer::active()): there every option comes from the object cache,
		// as WordPress itself reads them, never from the database (the request must not wait on a disk that stalls).
		// A row changed behind WordPress's back is not in effect for visitors either while the cache holds the old
		// one; wp-admin, cron and WP-CLI still compare the row itself.
		if ( ! wp_using_ext_object_cache() || PNCP_Defer::active() ) {
			return $net ? get_site_option( $name, $default ) : get_option( $name, $default );
		}
		global $wpdb;
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- The row itself, not the cached copy (see above).
		if ( $net ) {
			$raw = $wpdb->get_var( $wpdb->prepare( "SELECT meta_value FROM {$wpdb->sitemeta} WHERE meta_key = %s AND site_id = %d LIMIT 1", $name, get_current_network_id() ) );
		} else {
			$raw = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s LIMIT 1", $name ) );
		}
		// phpcs:enable
		$value = null === $raw ? null : ( is_serialized( $raw ) ? @unserialize( trim( $raw ), array( 'allowed_classes' => false ) ) : $raw ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize -- Data only, no objects.
		if ( $net ) {
			$key = get_current_network_id() . ':' . $name;
			if ( null === $raw ) {
				wp_cache_delete( $key, 'site-options' );
			} else {
				wp_cache_set( $key, $value, 'site-options' );
			}
		} else {
			// The cache holds the stored text (get_option() unserializes it): in "alloptions" for an autoloaded
			// option, under its own name otherwise.
			// 3.6: written back only when the row differs from the cached copy. Before, the whole "alloptions" entry
			// (often hundreds of KB) was rewritten on every request, from this request's copy, which could also
			// overwrite a newer one written meanwhile by another request.
			$all = wp_cache_get( 'alloptions', 'options' );
			if ( is_array( $all ) && array_key_exists( $name, $all ) ) {
				if ( null === $raw ) {
					unset( $all[ $name ] );
					wp_cache_set( 'alloptions', $all, 'options' );
				} elseif ( $all[ $name ] !== $raw ) {
					$all[ $name ] = $raw;
					wp_cache_set( 'alloptions', $all, 'options' );
				}
			}
			if ( null === $raw ) {
				wp_cache_delete( $name, 'options' );
			} elseif ( ( ! is_array( $all ) || ! array_key_exists( $name, $all ) ) && wp_cache_get( $name, 'options' ) !== $raw ) {
				wp_cache_set( $name, $raw, 'options' );
			}
			if ( null !== $raw ) {
				$not = wp_cache_get( 'notoptions', 'options' );
				if ( is_array( $not ) && isset( $not[ $name ] ) ) {
					unset( $not[ $name ] );
					wp_cache_set( 'notoptions', $not, 'options' );
				}
			}
		}
		return null === $raw ? $default : $value;
	}

	/**
	 * What the keys of Lockdown are made from: SCRAPELOCK_KEY when wp-config.php defines it, otherwise the
	 * WordPress keys (AUTH_KEY / AUTH_SALT). Security plugins and hosts sometimes change the WordPress keys
	 * on their own; a key of ScrapeLock's own is not touched by that.
	 *
	 * @return string
	 */
	public static function key_material() {
		if ( defined( 'SCRAPELOCK_KEY' ) && is_string( SCRAPELOCK_KEY ) && strlen( SCRAPELOCK_KEY ) >= 32 ) {
			return 'scrapelock|' . SCRAPELOCK_KEY;
		}
		return wp_salt( 'auth' );
	}

	/**
	 * The same data always gives the same text (keys sorted at every level).
	 *
	 * @param mixed $data Data.
	 * @return mixed
	 */
	private static function canonical( $data ) {
		if ( ! is_array( $data ) ) {
			return $data;
		}
		ksort( $data );
		foreach ( $data as $key => $value ) {
			$data[ $key ] = self::canonical( $value );
		}
		return $data;
	}

	/**
	 * The signature of some data.
	 *
	 * @param mixed $data Data.
	 * @return string
	 */
	public static function sign( $data ) {
		return hash_hmac( 'sha256', (string) wp_json_encode( self::canonical( $data ) ), self::key() );
	}

	/**
	 * Does the signature match the data?
	 *
	 * @param mixed $data Data.
	 * @param mixed $sig  Signature.
	 * @return bool
	 */
	public static function valid( $data, $sig ) {
		return is_string( $sig ) && 64 === strlen( $sig ) && hash_equals( self::sign( $data ), $sig );
	}

	/**
	 * Data stored before 3.3, which had no signatures yet: accepted until the upgrade signs it.
	 *
	 * The version stored in the database is not enough on its own: someone who can write to the database could
	 * set it back to "3.2.0" and then strip the signatures, or make the upgrade sign their own values. So the
	 * data counts as "from before 3.3" only when nothing that 3.3 and later write is there: no guard file, no
	 * signature and no "sealed" marker in the lock state, no snapshot of the protected options, no signed
	 * fingerprint of the files.
	 *
	 * @return bool
	 */
	public static function legacy() {
		// The guard file only exists since 3.3: with it in place, unsigned data is never accepted, whatever the
		// version stored in the database says.
		if ( self::guard_installed() || '' !== self::beacon_path() || null !== self::config_lock() ) {
			return false; // 3.4.1: the same for the lock file written when the guard could not be (3.4.2: and the lock line).
		}
		$from = (string) get_option( 'pncp_version', '' );
		if ( '' === $from || version_compare( $from, '3.3.0', '>=' ) ) {
			return false;
		}
		return ! self::sealed_before();
	}

	/**
	 * Has a version with signatures (3.3 or later) already written Lockdown data on this site? Only looks at
	 * whether the data is there, not at the signatures: anything a newer version wrote means that unsigned data
	 * next to it was not written by an older version.
	 *
	 * @return bool
	 */
	public static function sealed_before() {
		$state = self::fresh_option( PNCP_Lockdown::OPTION, true, array() );
		if ( is_array( $state ) && ( isset( $state['sig'] ) || ! empty( $state['sealed'] ) ) ) {
			return true;
		}
		if ( false !== get_option( self::DIGESTS, false ) || false !== get_option( self::SNAP, false ) ) {
			return true;
		}
		if ( is_multisite() && ( false !== get_site_option( self::NET_DIGESTS, false ) || false !== get_site_option( self::NET_SNAP, false ) ) ) {
			return true;
		}
		return PNCP_Integrity::fingerprint_signed();
	}

	/**
	 * Is there signed data that only exists while the site is locked? Used when the lock state is missing, does
	 * not match its signature, or says "not locked": if the snapshot of the protected options (or a current
	 * fingerprint of the files) is there and genuine, the site was locked and the state was deleted, forged or
	 * put back from an older copy behind WordPress's back.
	 *
	 * @param bool     $full  Also read the snapshot and the fingerprint (not autoloaded: only when something is
	 *                        already wrong). Otherwise only the autoloaded fingerprints of the options, which cost
	 *                        no query.
	 * @param int|null $since The lock time ("since") of a state that is genuine but says "not locked": only
	 *                        fingerprints noted for another lock count then. Null: any genuine fingerprints count.
	 * @param int|null $snap  The generation of the snapshot that state names (3.4): only fingerprints of a
	 *                        newer snapshot count then. Null or 0: a state from before 3.4 (the lock time counts).
	 * @return bool
	 */
	public static function lock_evidence( $full, $since = null, $snap = null ) {
		$record = self::digests_record( ! $full );
		if ( null !== $record ) {
			if ( null === $since ) {
				return true;
			}
			if ( $snap && isset( $record['gen'] ) ) {
				// Fingerprints newer than the snapshot the state knows: they were stored after that state was saved,
				// so the state was put back from an older copy. Older ones (an old copy put back) are no evidence.
				if ( (int) $record['gen'] > (int) $snap ) {
					return true;
				}
			} elseif ( isset( $record['since'] ) && (int) $record['since'] !== (int) $since ) {
				// A genuine unlock keeps the lock time in the state, and the fingerprints of that lock are deleted
				// right after it: the same lock time is the normal case (or the moment in between), never an alarm.
				return true;
			}
		}
		if ( ! $full ) {
			return false;
		}
		if ( is_multisite() && ( null !== self::net_record( self::NET_DIGESTS ) || null !== self::net_record( self::NET_SNAP ) ) ) {
			return true; // The signed snapshot of a network lock.
		}
		return null !== self::snapshot_record() || PNCP_Integrity::fingerprint_while_locked();
	}

	/**
	 * Has the owner just locked the site, and is the snapshot of this lock not stored yet? The lock is saved a
	 * moment before its snapshot is taken (in the same request): a request in between, such as the background
	 * request the lock starts for the official checksums, finds no snapshot of this lock. That is no alarm for
	 * SNAPSHOT_GRACE seconds after the (signed) lock time, as long as no snapshot of this lock is there yet.
	 *
	 * @param array<string, mixed>|null $record The signed snapshot record that is there now, if any.
	 * @return bool
	 */
	private static function snapshot_pending( $record ) {
		if ( '' !== PNCP_Lockdown::tampered() ) {
			return false;
		}
		$state = PNCP_Lockdown::state();
		$since = (int) $state['since'];
		if ( $since <= 0 || $since > time() + 5 || $since < time() - self::SNAPSHOT_GRACE ) {
			return false;
		}
		// 3.4: the snapshot of this lock was stored already, so a missing one was deleted: the state notes the
		// lock time of the snapshot it names, and the fingerprints of this lock are stored right after it.
		$digests = self::digests_record();
		if ( ( isset( $state['snapped'] ) && (int) $state['snapped'] === $since ) || ( null !== $digests && isset( $digests['since'] ) && (int) $digests['since'] === $since ) ) {
			return false;
		}
		return null === $record || ! isset( $record['since'] ) || (int) $record['since'] !== $since;
	}

	/**
	 * Is the signed snapshot of a lock still there while the state says the site is not locked (or is gone)?
	 * The same rules as for the fingerprints in lock_evidence(): a snapshot newer than the one the state
	 * knows, or one of another lock, shows that the state was put back from an older copy (or changed); the
	 * snapshot of the lock the state itself ended is the moment between a genuine unlock and the deletion of
	 * its snapshot, never an alarm. Used on sites without the guard file (PNCP_Lockdown::seal_check()).
	 *
	 * @param int|null $since The lock time in the state (null: there is no state).
	 * @param int|null $snap  The generation of the snapshot the state knows.
	 * @return bool
	 */
	public static function snapshot_evidence( $since = null, $snap = null ) {
		$record = self::snapshot_record();
		if ( null === $record ) {
			return false;
		}
		if ( null === $since ) {
			return true;
		}
		if ( $snap && isset( $record['gen'] ) ) {
			return (int) $record['gen'] > (int) $snap;
		}
		return isset( $record['since'] ) && (int) $record['since'] !== (int) $since;
	}

	/**
	 * Are the keys the signatures rely on in wp-config.php? Otherwise WordPress keeps them in the database,
	 * where someone who can change the database can also read them.
	 *
	 * @return bool
	 */
	public static function keys_in_config() {
		if ( defined( 'SCRAPELOCK_KEY' ) && is_string( SCRAPELOCK_KEY ) && strlen( SCRAPELOCK_KEY ) >= 32 ) {
			return true; // The keys are made from ScrapeLock's own key then (see key_material()), not from AUTH_KEY / AUTH_SALT.
		}
		// 3.4.3: as wp_salt() decides: a value used by more than one of the keys (or the sample phrase, also
		// translated) is ignored by WordPress, which then makes one and keeps it in the database.
		$count = array();
		foreach ( array( 'AUTH', 'SECURE_AUTH', 'LOGGED_IN', 'NONCE', 'SECRET' ) as $first ) {
			foreach ( array( 'KEY', 'SALT' ) as $second ) {
				if ( defined( "{$first}_{$second}" ) ) {
					$value           = (string) constant( "{$first}_{$second}" );
					$count[ $value ] = isset( $count[ $value ] ) ? $count[ $value ] + 1 : 1;
				}
			}
		}
		$sample = array( 'put your unique phrase here', __( 'put your unique phrase here' ) ); // phpcs:ignore WordPress.WP.I18n.MissingArgDomain -- WordPress's own string, as wp_salt() reads it.
		foreach ( array( 'AUTH_KEY', 'AUTH_SALT' ) as $name ) {
			if ( ! defined( $name ) ) {
				return false;
			}
			$value = (string) constant( $name );
			if ( '' === $value || in_array( $value, $sample, true ) || 1 !== $count[ $value ] ) {
				return false;
			}
		}
		return true;
	}

	/* ---------- The guard (must-use plugin) ---------- */

	/**
	 * Path of the guard.
	 *
	 * @return string
	 */
	public static function path() {
		return PNCP_Paths::mu_plugins() . '/' . self::FILE;
	}

	/**
	 * 3.12.11: the guard as ScrapeLock ships it. It is copied to the must-use plugins folder as it is, so it is the
	 * same file on every site (a host can allow it by its hash); what belongs to this site and lock is in guard.json
	 * (guard_data()).
	 *
	 * @return string
	 */
	public static function guard_template() {
		return PNCP_DIR . 'includes/lockdown/guard.php';
	}

	/**
	 * The guard's code: since 3.12.11 the shipped file (guard_template()), whatever the site and the lock ('' when
	 * it cannot be read).
	 *
	 * @return string
	 */
	public static function code() {
		static $code = null;
		if ( null === $code ) {
			$file = self::guard_template();
			$code = is_readable( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		}
		return $code;
	}

	/**
	 * 3.12.11: the guard's data folder, next to it: wp-content/mu-plugins/scrapelock-lockdown-data (WordPress only
	 * loads the PHP files directly in the must-use plugins folder, nothing in its sub-folders). It holds guard.json
	 * (nothing secret in it), an index.html, an .htaccess that denies access, and the private folder
	 * (guard_private_dir()).
	 *
	 * @return string
	 */
	public static function data_dir() {
		return PNCP_Paths::mu_plugins() . '/' . self::DATA_DIR;
	}

	/**
	 * 3.12.11: the file the guard reads its state from.
	 *
	 * @return string
	 */
	public static function guard_data_path() {
		return self::data_dir() . '/' . self::GUARD_DATA;
	}

	/**
	 * 3.12.11: the name of the private folder ("data-" and 20 hex digits), made from the keys, so it cannot be
	 * guessed: on a server that ignores .htaccess (Nginx) nobody finds the files in it, as with the data folder of
	 * the pre-cache check. It holds what must not be shown to anyone: the copy of the protected settings, the
	 * address alerts go to and the counters of wrong codes.
	 *
	 * @return string
	 */
	public static function private_name() {
		return 'data-' . substr( hash_hmac( 'sha256', 'pncp_lockdown_private_dir', self::key() ), 0, 20 );
	}

	/**
	 * 3.12.11: the private folder next to the guard (see private_name()).
	 *
	 * @return string
	 */
	public static function guard_private_dir() {
		return self::data_dir() . '/' . self::private_name();
	}

	/**
	 * 3.12.11: the signed copy of the snapshot of the protected settings next to the guard (single site).
	 *
	 * @return string
	 */
	public static function snapshot_copy_path() {
		return self::guard_private_dir() . '/' . self::SNAP_FILE;
	}

	/**
	 * 3.13.0: the private folder the guard itself can find before WordPress has loaded: named like private_name(),
	 * but from the keys in wp-config.php only (guard_key_material(); WordPress's wp_salt() is not loaded yet when the
	 * guard runs). With the keys in wp-config.php it is the same folder as guard_private_dir().
	 *
	 * @return string
	 */
	public static function guard_values_dir() {
		$key = hash( 'sha256', self::guard_key_material() . '|pncp_lockdown_sig', true );
		return self::data_dir() . '/data-' . substr( hash_hmac( 'sha256', 'pncp_lockdown_private_dir', $key ), 0, 20 );
	}

	/**
	 * 3.13.0: the file with the plugins and the theme the guard keeps (GUARD_VALUES).
	 *
	 * @return string
	 */
	public static function guard_values_path() {
		return self::guard_values_dir() . '/' . self::GUARD_VALUES;
	}

	/**
	 * 3.12.11: what the key of guard.json is made from, exactly as the guard makes it (includes/lockdown/guard.php):
	 * SCRAPELOCK_KEY, or else AUTH_KEY and AUTH_SALT. Only from wp-config.php: the guard runs before WordPress has
	 * loaded wp_salt(), which can also read keys from the database.
	 *
	 * @return string
	 */
	public static function guard_key_material() {
		if ( defined( 'SCRAPELOCK_KEY' ) && is_string( SCRAPELOCK_KEY ) && strlen( SCRAPELOCK_KEY ) >= 32 ) {
			return 'scrapelock|' . SCRAPELOCK_KEY;
		}
		if ( defined( 'AUTH_KEY' ) && defined( 'AUTH_SALT' ) ) {
			return (string) AUTH_KEY . (string) AUTH_SALT;
		}
		return '';
	}

	/**
	 * 3.12.11: the signature of guard.json's "data" (HMAC-SHA256, keys sorted at every level, as the guard checks it).
	 *
	 * @param array<string, mixed> $data Data, as written to the file (pack()).
	 * @return string
	 */
	public static function guard_sign( $data ) {
		$key = hash( 'sha256', self::guard_key_material() . '|pncp_lockdown_guard', true );
		return hash_hmac( 'sha256', (string) json_encode( self::canonical( $data ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ), $key ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- The exact encoding the guard uses (it runs before WordPress).
	}

	/**
	 * 3.12.11: a value as plain JSON keeps it exactly (types included: the fingerprints compare serialized values,
	 * and the signatures must match after reading it back). Text, numbers, true/false, null and arrays are JSON as
	 * they are. Only what JSON cannot hold becomes a small marked object: text that is not valid UTF-8 as its
	 * bytes in hex ({"~pncp": "hex", "v": "..."}), INF / NAN, an object (its properties), an array with keys that
	 * are not valid UTF-8 (as pairs), and an array that itself has a "~pncp" key.
	 *
	 * @param mixed $value Value.
	 * @return mixed
	 */
	public static function pack( $value ) {
		if ( is_string( $value ) ) {
			return preg_match( '//u', $value ) ? $value : array(
				'~pncp' => 'hex',
				'v'     => bin2hex( $value ),
			);
		}
		if ( is_float( $value ) && ! is_finite( $value ) ) {
			return array(
				'~pncp' => 'float',
				'v'     => is_nan( $value ) ? 'NAN' : ( $value > 0 ? 'INF' : '-INF' ),
			);
		}
		if ( is_object( $value ) ) {
			return array(
				'~pncp' => 'object',
				'v'     => self::pack( get_object_vars( $value ) ),
			);
		}
		if ( ! is_array( $value ) ) {
			return is_scalar( $value ) ? $value : null;
		}
		$pairs = false;
		foreach ( array_keys( $value ) as $key ) {
			if ( is_string( $key ) && ! preg_match( '//u', $key ) ) {
				$pairs = true;
				break;
			}
		}
		$out = array();
		foreach ( $value as $key => $item ) {
			if ( $pairs ) {
				$out[] = array( self::pack( $key ), self::pack( $item ) );
			} else {
				$out[ $key ] = self::pack( $item );
			}
		}
		if ( $pairs ) {
			return array(
				'~pncp' => 'pairs',
				'v'     => $out,
			);
		}
		return array_key_exists( '~pncp', $value ) ? array(
			'~pncp' => 'array',
			'v'     => $out,
		) : $out;
	}

	/**
	 * 3.12.11: the value pack() was given, back from JSON.
	 *
	 * @param mixed $value Value read from JSON.
	 * @return mixed
	 */
	public static function unpack( $value ) {
		if ( ! is_array( $value ) ) {
			return $value;
		}
		if ( isset( $value['~pncp'] ) && is_string( $value['~pncp'] ) && array_key_exists( 'v', $value ) && 2 === count( $value ) ) {
			$inner = $value['v'];
			switch ( $value['~pncp'] ) {
				case 'hex':
					return is_string( $inner ) && preg_match( '/^(?:[0-9a-f]{2})*$/', $inner ) ? (string) hex2bin( $inner ) : null;
				case 'float':
					return 'NAN' === $inner ? NAN : ( '-INF' === $inner ? -INF : INF );
				case 'object':
					return (object) ( is_array( $inner ) ? self::unpack( $inner ) : array() );
				case 'pairs':
					$out = array();
					foreach ( is_array( $inner ) ? $inner : array() as $pair ) {
						if ( is_array( $pair ) && array_key_exists( 0, $pair ) && array_key_exists( 1, $pair ) ) {
							$key = self::unpack( $pair[0] );
							if ( is_int( $key ) || is_string( $key ) ) {
								$out[ $key ] = self::unpack( $pair[1] );
							}
						}
					}
					return $out;
				case 'array':
					$value = is_array( $inner ) ? $inner : array();
					break;
				default:
					return null;
			}
		}
		foreach ( $value as $key => $item ) {
			$value[ $key ] = self::unpack( $item );
		}
		return $value;
	}

	/**
	 * 3.12.11: the text of a data file of Lockdown: readable JSON (one key per line), "<" and ">" and "&" escaped.
	 *
	 * @param array<string, mixed> $data Data (already packed).
	 * @return string '' when it cannot be encoded.
	 */
	public static function json_text( $data ) {
		$text = json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_HEX_TAG | JSON_HEX_AMP ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Exact flags (packed data is always valid UTF-8).
		return is_string( $text ) ? $text . "\n" : '';
	}

	/**
	 * 3.12.11: what guard.json holds for a lock: the signed record (as the guard file defined it before) and
	 * ScrapeLock's main file. 3.13.0: nothing else. The plugins and the theme the guard keeps are in the private
	 * folder (guard_values_data()): the guard's folder may be reachable from the web on a server that ignores
	 * .htaccess, and guard.json has a fixed name.
	 *
	 * @param bool $locked Locked.
	 * @param int  $until  Unlocked for a while until (0 = not).
	 * @param int  $gen    Generation of the state.
	 * @param int  $snap   Generation of the snapshot.
	 * @return array<string, mixed>
	 */
	private static function guard_data( $locked, $until, $gen, $snap ) {
		$record = self::record( $locked, $until, $gen, $snap );
		return array(
			'beacon'    => array_merge( $record, array( 'sig' => self::sign( $record ) ) ),
			'own'       => plugin_basename( PNCP_FILE ),
			'multisite' => is_multisite(),
		);
	}

	/**
	 * 3.13.0: what guard-values.json holds for a lock: the generations of the record in guard.json (the guard only
	 * follows the file of the same lock), and while locked the active plugins and the theme as they were when the
	 * site was locked (multisite: per site and for the whole network, see guard_payload()).
	 *
	 * @param bool $locked Locked.
	 * @param int  $gen    Generation of the state.
	 * @param int  $snap   Generation of the snapshot.
	 * @return array<string, mixed>
	 */
	private static function guard_values_data( $locked, $gen, $snap ) {
		$data = array(
			'kind'      => 'values',
			'gen'       => (int) $gen,
			'snap'      => (int) $snap,
			'multisite' => is_multisite(),
		);
		if ( is_multisite() ) {
			$payload             = $locked ? self::guard_payload( (int) $snap ) : array(
				'network'     => array(),
				'sites'       => array(),
				'network_own' => false,
			);
			$data['network']     = self::pack( $payload['network'] );
			$data['sites']       = self::pack( $payload['sites'] );
			$data['network_own'] = (bool) $payload['network_own'];
		} else {
			$data['values'] = self::pack( $locked ? self::guarded_values( (int) $snap ) : array() );
		}
		return $data;
	}

	/**
	 * 3.13.0: guard-values.json for some data, signed as guard.json is (guard_sign()).
	 *
	 * @param array<string, mixed> $data Data (guard_values_data()).
	 * @return string
	 */
	private static function guard_values_text( $data ) {
		return self::json_text(
			array(
				'about' => self::ABOUT_VALUES,
				'data'  => $data,
				'sig'   => self::guard_sign( $data ),
			)
		);
	}

	/**
	 * 3.13.0: the version of the guard that ran on this request (0: none). The guard on disk may be an older copy
	 * than includes/lockdown/guard.php until it is written again.
	 *
	 * @return int
	 */
	private static function guard_version_ran() {
		return defined( 'PNCP_LOCKDOWN_GUARD' ) ? (int) constant( 'PNCP_LOCKDOWN_GUARD' ) : 0;
	}

	/**
	 * 3.13.0: guard.json still holds the plugins and the theme (written by 3.12.11 to 3.12.13), or the guard of
	 * 3.12.13 or older ran on this request: guard.json and the guard are written again, the lists in the private
	 * folder. Only for a genuine record of a lock (nothing else is written while the site is not locked).
	 *
	 * @return bool Whether they were written again.
	 */
	public static function migrate_guard_values() {
		if ( '' !== self::legacy_guard_code() ) {
			return false; // The guard of 3.12.10: migrate_files() moves it.
		}
		$data = self::read_guard_data();
		if ( null === $data || ! isset( $data['beacon'] ) || ! is_array( $data['beacon'] ) ) {
			return false;
		}
		$inline = array_intersect( array( 'values', 'sites', 'network', 'network_own' ), array_keys( $data ) );
		$ran    = self::guard_version_ran();
		$old    = $ran > 0 && $ran < 3 && self::ours( self::path() );
		if ( ! $inline && ! $old ) {
			return false;
		}
		$record = self::guard_record( (string) json_encode( $data['beacon'] ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- As the guard encodes it.
		if ( null === $record || ! $record['locked'] || ! isset( $record['gen'], $record['snap'] ) ) {
			return false;
		}
		return self::write_guard( true, (int) $record['until'], (int) $record['gen'], (int) $record['snap'] );
	}

	/**
	 * 3.12.11: guard.json for some data: what it is, the data and its signature (guard_sign()).
	 *
	 * @param array<string, mixed> $data Data (guard_data()).
	 * @return string
	 */
	private static function guard_file_text( $data ) {
		return self::json_text(
			array(
				'about' => self::ABOUT_GUARD,
				'data'  => $data,
				'sig'   => self::guard_sign( $data ),
			)
		);
	}

	/**
	 * 3.12.11: guard.json's data as it is on disk now, if it matches its signature (otherwise null).
	 *
	 * @return array<string, mixed>|null
	 */
	public static function read_guard_data() {
		$json = self::read_json( self::guard_data_path(), 4 * self::BEACON_MAX_COPY );
		if ( null === $json || ! isset( $json['data'], $json['sig'] ) || ! is_array( $json['data'] ) || ! is_string( $json['sig'] ) ) {
			return null;
		}
		return hash_equals( self::guard_sign( $json['data'] ), $json['sig'] ) ? $json['data'] : null;
	}

	/**
	 * 3.12.11: a JSON file as an array (null: missing, unreadable, too large or not a JSON object).
	 *
	 * @param string $path File.
	 * @param int    $max  Bytes read at most.
	 * @return array<mixed>|null
	 */
	private static function read_json( $path, $max ) {
		clearstatcache( true, $path );
		if ( ! is_file( $path ) ) {
			return null;
		}
		$text = @file_get_contents( $path, false, null, 0, $max ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file; unreadable = none.
		$data = is_string( $text ) ? json_decode( $text, true ) : null;
		return is_array( $data ) ? $data : null;
	}

	/**
	 * The guard's signed record, as the guard defined it on this request: [locked, until, gen, snap], or null when
	 * there is no guard (or it does not match the keys in wp-config.php). A guard written before 3.4 has no
	 * generations ("gen" and "snap" are missing then). 3.12.11: the guard reads it from guard.json and defines
	 * PNCP_LOCKDOWN_BEACON with it, as the guard of 3.12.10 and older did from its own code.
	 *
	 * @return array{locked:bool, until:int, gen?:int, snap?:int}|null
	 */
	public static function beacon() {
		if ( null !== self::$current ) {
			return self::$current['locked'] ? self::$current : null;
		}
		if ( ! defined( 'PNCP_LOCKDOWN_BEACON' ) ) {
			// 3.4.1: no guard file. The lock file, if the guard could not be written (see write_beacon()).
			$file = self::beacon_file();
			return null === $file ? null : $file['record'];
		}
		return self::guard_record( (string) PNCP_LOCKDOWN_BEACON );
	}

	/**
	 * Reads the guard again, when the record defined at the start of this request no longer matches the
	 * database: another request may have written the guard and the state in between (they are written a moment
	 * apart). Only a record that matches its signature counts; a guard that is gone now counts as "not locked",
	 * since only ScrapeLock removes it.
	 *
	 * @return bool Whether the guard changed since the start of the request.
	 */
	public static function refresh_beacon() {
		if ( null !== self::$current ) {
			return false; // Written on this request (so it is current).
		}
		if ( ! defined( 'PNCP_LOCKDOWN_BEACON' ) ) {
			return self::refresh_beacon_file();
		}
		clearstatcache( true, self::path() );
		if ( ! self::ours( self::path() ) ) {
			self::$current = self::record( false, 0 );
			return true;
		}
		$json = self::guard_json();
		if ( null === $json || (string) PNCP_LOCKDOWN_BEACON === $json ) {
			return false;
		}
		$record = self::guard_record( $json );
		if ( null === $record ) {
			return false;
		}
		self::$current = $record;
		self::$copy    = null; // The copy next to it may be newer too.
		return true;
	}

	/**
	 * The signed text of the guard's record on disk now (what the guard defines as PNCP_LOCKDOWN_BEACON), or null.
	 * 3.12.11: from guard.json; from the guard file itself while it is still one of 3.12.10 or older (until
	 * migrate_files() has run).
	 *
	 * @return string|null
	 */
	private static function guard_json() {
		$legacy = self::legacy_guard_code();
		if ( '' !== $legacy ) {
			return self::legacy_guard_json( $legacy );
		}
		$data = self::read_guard_data();
		return null === $data || ! isset( $data['beacon'] ) || ! is_array( $data['beacon'] ) ? null : (string) json_encode( $data['beacon'] ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- As the guard encodes it.
	}

	/**
	 * The record in a guard's signed text, if it matches its signature (otherwise null).
	 *
	 * @param string $json The signed text.
	 * @return array{locked:bool, until:int, gen?:int, snap?:int}|null
	 */
	private static function guard_record( $json ) {
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || ! isset( $data['locked'], $data['until'], $data['sig'] ) ) {
			return null;
		}
		$record = self::record( $data['locked'], $data['until'], isset( $data['gen'] ) ? $data['gen'] : null, isset( $data['snap'] ) ? $data['snap'] : null );
		return self::valid( $record, $data['sig'] ) ? $record : null;
	}

	/**
	 * 3.4.1: removes a guard file and a lock file that are older than the last unlock for good (put back from a
	 * backup, see PNCP_Lockdown::seal_check()). Each is read again from disk first and only removed while it
	 * still names a generation lower than that unlock: a file written by a lock since then stays.
	 *
	 * @param int $gen   The generation of the old file found on this request.
	 * @param int $freed The generation of the unlock for good (signed in the state).
	 * @return string[] The files removed.
	 */
	public static function remove_stale( $gen, $freed ) {
		$removed = array();
		if ( (int) $gen >= (int) $freed ) {
			return $removed;
		}
		$path = self::path();
		clearstatcache( true, $path );
		if ( self::ours( $path ) ) {
			$json   = self::guard_json();
			$record = null === $json ? null : self::guard_record( $json );
			if ( null !== $record && $record['locked'] && isset( $record['gen'] ) && $record['gen'] < (int) $freed ) {
				PNCP_Lockdown::fails_remove(); // The copy of the counters goes with the guard.
				self::delete_guard_file();
				self::remove_guard_data();
				clearstatcache( true, $path );
				if ( ! file_exists( $path ) ) {
					$removed[] = $path;
				}
			}
		}
		clearstatcache();
		$file = self::read_beacon_file();
		if ( false !== $file && $file['record']['locked'] && isset( $file['record']['gen'] ) && $file['record']['gen'] < (int) $freed ) {
			self::remove_beacon();
			$removed[] = $file['path'];
		}
		self::$file          = null;
		self::$file_at_start = false;
		self::beacon_file();
		if ( $removed && ! self::ours( $path ) ) {
			self::$copy    = false;
			self::$current = self::record( false, 0 );
			self::guard_now( false, 0 );
		}
		return $removed;
	}

	/**
	 * The record the guard signs.
	 *
	 * 3.4: also the generation of the lock state ("gen", one more on every save) and the generation of the
	 * snapshot of the protected options ("snap"). A signed state, snapshot or set of fingerprints from an older
	 * copy of the database has a lower generation than the guard, so it is no longer accepted.
	 *
	 * @param bool     $locked Locked.
	 * @param int      $until  Unlocked for a while until (0 = not).
	 * @param int|null $gen    Generation of the state (null: a guard from before 3.4).
	 * @param int|null $snap   Generation of the snapshot (null: a guard from before 3.4).
	 * @return array{locked:bool, until:int, gen?:int, snap?:int}
	 */
	private static function record( $locked, $until, $gen = null, $snap = null ) {
		$record = array(
			'locked' => (bool) $locked,
			'until'  => (int) $until,
		);
		if ( null !== $gen ) {
			$record['gen']  = (int) $gen;
			$record['snap'] = (int) $snap;
		}
		return $record;
	}

	/**
	 * What the guard keeps on multisite (see the guard's code), from the genuine snapshot of the network for this
	 * lock: 'network' (the plugins active on the whole network), 'sites' (site ID => active plugins and theme) and
	 * 'network_own' (keep ScrapeLock active on the whole network). A site that is not listed (added after the
	 * lock, or beyond the number of sites the guard holds) keeps its stored values. Without a genuine snapshot of
	 * the network (missing, changed, from an older lock, or a network locked before 3.4) only ScrapeLock is kept,
	 * in the plugins of the whole network if it is active there now.
	 *
	 * @param int $snap The generation of the snapshot the state names.
	 * @return array{network:array<string, mixed>, sites:array<int, array<string, mixed>>, network_own:bool}
	 */
	private static function guard_payload( $snap ) {
		$out = array(
			'network'     => array(),
			'sites'       => array(),
			'network_own' => false,
		);
		$own = plugin_basename( PNCP_FILE );
		$net = self::net_record( self::NET_SNAP );
		if ( null !== $net && self::generation_ok( $net, $snap ) && isset( $net['values'], $net['sites'] ) && is_array( $net['values'] ) && is_array( $net['sites'] ) ) {
			$plugins = isset( $net['values']['active_sitewide_plugins'] ) ? $net['values']['active_sitewide_plugins'] : false;
			if ( is_array( $plugins ) ) {
				$list = array();
				foreach ( $plugins as $file => $time ) {
					if ( is_string( $file ) && '' !== $file ) {
						$list[ $file ] = (int) $time;
					}
				}
				ksort( $list );
				$out['network']['active_sitewide_plugins'] = $list;
				$out['network_own']                        = isset( $list[ $own ] );
			}
			foreach ( $net['sites'] as $id => $entry ) {
				if ( is_array( $entry ) && isset( $entry['guard'] ) && is_array( $entry['guard'] ) && $entry['guard'] ) {
					$out['sites'][ (int) $id ] = $entry['guard'];
				}
			}
			ksort( $out['sites'] );
			return $out;
		}
		$stored             = self::stored_site_option( 'active_sitewide_plugins' );
		$out['network_own'] = is_array( $stored ) && isset( $stored[ $own ] );
		return $out;
	}

	/**
	 * The values of the guarded options (active plugins, theme) that the guard keeps for one site, from the
	 * values read for a snapshot: lists of plugin files, and non-empty names of themes.
	 *
	 * @param array<string, mixed> $values Option => value.
	 * @return array<string, mixed>
	 */
	private static function guard_subset( $values ) {
		$out = array();
		foreach ( self::GUARDED as $option ) {
			if ( ! array_key_exists( $option, $values ) ) {
				continue;
			}
			$value = $values[ $option ];
			if ( 'active_plugins' === $option && is_array( $value ) ) {
				$out[ $option ] = array_values( array_filter( array_map( 'strval', $value ), 'strlen' ) );
			} elseif ( 'active_plugins' !== $option && is_string( $value ) && '' !== $value ) {
				$out[ $option ] = $value;
			}
		}
		return $out;
	}

	/**
	 * A value as PHP code, on one line: text, numbers, true/false and lists of them.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	public static function php_value( $value ) {
		if ( ! is_array( $value ) ) {
			return var_export( is_scalar( $value ) ? $value : null, true ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Writes a value as PHP code (quotes escaped).
		}
		if ( ! $value ) {
			return 'array()';
		}
		$list  = array_keys( $value ) === range( 0, count( $value ) - 1 );
		$items = array();
		foreach ( $value as $key => $item ) {
			$items[] = ( $list ? '' : self::php_value( $key ) . ' => ' ) . self::php_value( $item );
		}
		return 'array( ' . implode( ', ', $items ) . ' )';
	}

	/**
	 * The values the guard keeps (active plugins, theme), from the genuine snapshot of this lock. Empty without
	 * one (missing, changed, or from an older lock), and on multisite, where the guard keeps the values per site
	 * instead (guard_payload()).
	 *
	 * @param int $snap The generation of the snapshot the state names.
	 * @return array<string, mixed>
	 */
	private static function guarded_values( $snap ) {
		if ( is_multisite() ) {
			return array();
		}
		$record = self::snapshot_source( $snap );
		return null === $record ? array() : self::guard_subset( $record['values'] );
	}

	/**
	 * Single site: the signed snapshot of this lock (with its signature) that the guard keeps a copy of: the one in
	 * the database, or else the copy kept next to the guard now (the one in the database was deleted, changed or
	 * set back to an older one). Null without either for this generation.
	 *
	 * @param int $snap The generation of the snapshot the state names.
	 * @return array<string, mixed>|null
	 */
	private static function snapshot_source( $snap ) {
		$record = self::snapshot_record();
		if ( null !== $record && self::generation_ok( $record, $snap ) ) {
			$record['sig'] = self::sign( $record );
			return $record;
		}
		$copy = self::guard_copy();
		if ( null !== $copy && self::generation_ok( $copy, $snap ) ) {
			$copy['sig'] = self::sign( $copy );
			return $copy;
		}
		return null;
	}

	/**
	 * The signed copy of the snapshot kept outside the database, without its signature, if it matches it. 3.12.11:
	 * next to the guard, snapshot.json in the private folder (read when first needed on a request, not on every
	 * request); without a guard, in the lock file. A guard of 3.12.10 still defines it (COPY) until it is migrated.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function guard_copy() {
		if ( null === self::$copy ) {
			self::$copy = false;
			$data       = null;
			if ( defined( self::COPY ) ) {
				$data = self::legacy_copy( (string) constant( self::COPY ) );
			} elseif ( defined( 'PNCP_LOCKDOWN_BEACON' ) ) {
				$data = self::read_snapshot_copy();
			} else {
				// 3.4.1: no guard file: the copy in the lock file, if there is one (see write_beacon()).
				$file = self::beacon_file();
				$data = null === $file ? null : $file['copy'];
			}
			self::$copy = is_array( $data ) ? $data : false;
		}
		$copy = self::$copy;
		if ( ! is_array( $copy ) || ! isset( $copy['sig'], $copy['values'], $copy['admins'], $copy['time'] ) || ! is_array( $copy['values'] ) || ! is_array( $copy['admins'] ) ) {
			return null;
		}
		$sig = $copy['sig'];
		unset( $copy['sig'] );
		return self::valid( $copy, $sig ) ? $copy : null;
	}

	/**
	 * 3.12.11: the copy of the snapshot next to the guard, as it is on disk (signature not checked here), or null.
	 *
	 * @return array<string, mixed>|null
	 */
	private static function read_snapshot_copy() {
		$json = self::read_json( self::snapshot_copy_path(), 16 * self::BEACON_MAX_COPY );
		if ( null === $json || ! isset( $json['snapshot'] ) || ! is_array( $json['snapshot'] ) ) {
			return null;
		}
		return self::open_copy( $json['snapshot'] );
	}

	/**
	 * 3.12.11: the key that encrypts the protected settings in the copy of the snapshot (made from the keys of
	 * Lockdown, key(), with its own label; never stored).
	 *
	 * @return string 32 bytes.
	 */
	private static function box_key() {
		return hash_hmac( 'sha256', 'pncp_lockdown_values_box', self::key(), true );
	}

	/**
	 * 3.12.11: the copy of the snapshot as it is written to snapshot.json and to lock.json: JSON (pack()), with the
	 * values of the protected settings (which can hold API keys and payment settings) encrypted with
	 * sodium_crypto_secretbox (XSalsa20-Poly1305, a random nonce on every write), stored as hex:
	 * "values": {"~pncp": "box", "v": ["<nonce and ciphertext in hex, 128 digits a line>", ...]} (short lines: no
	 * long encoded-looking string in the file). The rest (time, generations, account IDs,
	 * keyed fingerprints, the signature) stays readable. The files are only read by ScrapeLock once WordPress has
	 * loaded, which brings sodium_compat when PHP's sodium extension is missing. Null when neither is there: then
	 * no copy is written, never the values in clear text.
	 *
	 * @param array<string, mixed> $copy The signed copy (with "sig").
	 * @return array<string, mixed>|null
	 */
	private static function seal_copy( $copy ) {
		if ( ! function_exists( 'sodium_crypto_secretbox' ) || ! isset( $copy['values'] ) ) {
			return null;
		}
		$plain = json_encode( self::pack( $copy['values'] ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- Exact flags (packed data is always valid UTF-8).
		if ( ! is_string( $plain ) ) {
			return null;
		}
		try {
			$nonce = random_bytes( 24 );
			$box   = sodium_crypto_secretbox( $plain, $nonce, self::box_key() );
		} catch ( Throwable $e ) {
			return null;
		}
		$out           = self::pack( $copy );
		$out['values'] = array(
			'~pncp' => 'box',
			'v'     => str_split( bin2hex( $nonce . $box ), 128 ),
		);
		return $out;
	}

	/**
	 * 3.12.11: the copy back from seal_copy()'s form: null when the values cannot be decrypted (changed, other keys,
	 * or no sodium); its signature is then checked as before (guard_copy()).
	 *
	 * @param array<string, mixed> $data The copy as read from JSON.
	 * @return array<string, mixed>|null
	 */
	private static function open_copy( $data ) {
		$box = isset( $data['values'] ) && is_array( $data['values'] ) ? $data['values'] : null;
		if ( null === $box || ! isset( $box['~pncp'], $box['v'] ) || 'box' !== $box['~pncp'] || ! is_array( $box['v'] ) || ! function_exists( 'sodium_crypto_secretbox_open' ) ) {
			return null;
		}
		$hex = '';
		foreach ( $box['v'] as $line ) {
			if ( ! is_string( $line ) || ! preg_match( '/^[0-9a-f]{1,128}$/', $line ) ) {
				return null;
			}
			$hex .= $line;
		}
		if ( ! preg_match( '/^(?:[0-9a-f]{2}){41,}$/', $hex ) ) {
			return null; // Odd length, or shorter than a nonce and a tag.
		}
		$raw = (string) hex2bin( $hex );
		try {
			$plain = sodium_crypto_secretbox_open( substr( $raw, 24 ), substr( $raw, 0, 24 ), self::box_key() );
		} catch ( Throwable $e ) {
			return null;
		}
		$values = is_string( $plain ) ? json_decode( $plain, true ) : null;
		if ( ! is_array( $values ) ) {
			return null;
		}
		$data['values'] = null; // Keeps its place among the keys.
		$copy = self::unpack( $data );
		if ( ! is_array( $copy ) ) {
			return null;
		}
		$copy['values'] = self::unpack( $values );
		return $copy;
	}

	/**
	 * Reads an option as it is stored, without the values the guard keeps on this request (the seal compares
	 * the stored value with the snapshot and puts it back).
	 *
	 * @param string $option Option.
	 * @return mixed
	 */
	public static function stored_option( $option ) {
		return self::unguarded(
			static function () use ( $option ) {
				return get_option( $option );
			}
		);
	}

	/**
	 * Reads a network option (multisite) as it is stored, without the values the guard keeps on this request.
	 *
	 * @param string $option Option.
	 * @return mixed
	 */
	public static function stored_site_option( $option ) {
		return self::unguarded(
			static function () use ( $option ) {
				return get_site_option( $option );
			}
		);
	}

	/**
	 * Runs something with the guard's values switched off for this request (reading or writing the stored
	 * value: update_option() would otherwise see the guard's value and think nothing changed).
	 *
	 * @param callable $callback What to run.
	 * @return mixed What it returns.
	 */
	public static function unguarded( $callback ) {
		if ( ! isset( $GLOBALS['pncp_lockdown_guard'] ) || ! is_array( $GLOBALS['pncp_lockdown_guard'] ) ) {
			return $callback();
		}
		$before = ! empty( $GLOBALS['pncp_lockdown_guard']['pass'] );
		// Put back afterwards, also when the callback throws.
		$GLOBALS['pncp_lockdown_guard']['pass'] = true;
		try {
			return $callback();
		} finally {
			$GLOBALS['pncp_lockdown_guard']['pass'] = $before;
		}
	}

	/**
	 * Writes the guard for this state (removes it when not locked). Only with direct file access; without it
	 * the lock works as before, without the copy outside the database.
	 *
	 * 3.12.11: three files, the data before the code: the copy of the snapshot (private folder, see
	 * private_name()), guard.json, and then the guard itself, the shipped file as it is (code()). A request that
	 * runs in between reads either the guard as it was (3.12.10's guard does not read the new files) or the new
	 * guard with its data already in place: the lock is kept all the time. Each file is written to a temporary
	 * file next to it ("<name>.tmp-<random>", never a name that ends in .php, so WordPress never loads it) and then
	 * renamed over it; it keeps its owner, group and mode (3.12.10), a new one gets 0644 (the guard WordPress's
	 * file mode) and, written as root, the owner of the WordPress folder.
	 *
	 * @param bool     $locked Locked.
	 * @param int      $until  Until.
	 * @param int|null $gen    Generation of the state (null: the one stored now).
	 * @param int|null $snap   Generation of the snapshot (null: the one stored now).
	 * @return bool Whether the guard is now as it should be.
	 */
	public static function write_guard( $locked, $until, $gen = null, $snap = null ) {
		if ( ! $locked ) {
			self::remove_guard(); // With the lock file (3.4.1), if there is one.
			$ok = ! file_exists( self::path() ) && '' === self::beacon_path();
			if ( $ok ) {
				self::$copy    = false;
				self::$current = array(
					'locked' => false,
					'until'  => 0,
				);
				self::guard_now( false, 0 );
			}
			return $ok;
		}
		if ( null === $gen || null === $snap ) {
			$state = PNCP_Lockdown::state();
			$gen   = null === $gen ? (int) $state['gen'] : $gen;
			$snap  = null === $snap ? (int) $state['snap'] : $snap;
		}
		$path = self::path();
		$code = self::code();
		if ( '' === $code ) {
			return false; // The plugin's own copy of the guard is missing.
		}
		$record = self::record( true, $until, $gen, $snap );
		$text   = self::guard_file_text( self::guard_data( true, (int) $until, (int) $gen, (int) $snap ) );
		$copy   = ! is_multisite() ? self::snapshot_source( (int) $snap ) : null;
		$sealed = null === $copy ? null : self::seal_copy( $copy );
		if ( null === $sealed ) {
			$copy = null; // 3.12.11: no copy rather than the protected values in clear text (no sodium).
		}
		$ctext = null === $sealed ? '' : self::json_text(
			array(
				'about'    => self::ABOUT_SNAP,
				'snapshot' => $sealed,
			)
		);
		$cpath = self::snapshot_copy_path();
		// 3.13.0: the plugins and the theme in the private folder, not in guard.json.
		$vtext = self::guard_values_text( self::guard_values_data( true, (int) $gen, (int) $snap ) );
		$vpath = self::guard_values_path();
		if ( '' === $text || '' === $vtext || ( null !== $copy && '' === $ctext ) ) {
			return false;
		}
		// The copy is encrypted with a new nonce on every write: the one on disk counts as the same when it opens to
		// the same snapshot.
		$csame = null !== $copy && is_file( $cpath ) && self::read_snapshot_copy() === $copy;
		if ( self::file_is( $path, $code ) && self::file_is( self::guard_data_path(), $text ) && self::file_is( $vpath, $vtext ) && ( null === $copy ? ! file_exists( $cpath ) : $csame ) ) {
			self::$current = $record;
			self::guard_now( time() >= (int) $until, (int) $snap );
			return true;
		}
		$filesystem = self::filesystem();
		if ( ! $filesystem ) {
			return false;
		}
		if ( ! PNCP_Early::make_dir() ) { // 3.4.3: recorded when ScrapeLock creates the folder.
			return false;
		}
		if ( $filesystem->exists( $path ) && ! self::ours( $path ) ) {
			return false; // Someone else's file with the same name: never overwritten.
		}
		if ( ! self::ensure_dir( self::data_dir(), true ) ) {
			return false;
		}
		if ( '' !== $ctext ) {
			if ( ! self::ensure_dir( self::guard_private_dir(), false ) || ( ! $csame && ! self::put_file( $cpath, $ctext ) ) ) {
				return false;
			}
		} elseif ( file_exists( $cpath ) ) {
			wp_delete_file( $cpath ); // Of an older snapshot: no copy for this one.
		}
		// The lists first: the guard follows them only with a guard.json of the same generation.
		if ( ! self::ensure_dir( dirname( $vpath ), false ) || ( ! self::file_is( $vpath, $vtext ) && ! self::put_file( $vpath, $vtext ) ) ) {
			return false;
		}
		if ( ! self::file_is( self::guard_data_path(), $text ) && ! self::put_file( self::guard_data_path(), $text ) ) {
			return false;
		}
		$ok = self::file_is( $path, $code ) || self::put_file( $path, $code, defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644 );
		if ( ! $ok ) {
			// A folder PHP cannot create files in (only change them): the guard is written in place, as before.
			$meta = PNCP_File_Owner::capture( $path );
			$ok   = $filesystem->put_contents( $path, $code, null !== $meta ? $meta['mode'] : ( defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644 ) );
			if ( $ok ) {
				PNCP_File_Owner::restore( $path, $meta );
			}
		}
		clearstatcache( true, $path );
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $path, true );
		}
		if ( $ok ) {
			self::$copy    = null === $copy ? false : $copy;
			self::$current = $record;
			self::guard_now( time() >= (int) $until, (int) $snap );
			self::remove_legacy_leftovers();
		}
		return (bool) $ok;
	}

	/**
	 * 3.12.11: does a file hold exactly this text?
	 *
	 * @param string $path File.
	 * @param string $text Text.
	 * @return bool
	 */
	private static function file_is( $path, $text ) {
		clearstatcache( true, $path );
		return is_file( $path ) && is_readable( $path ) && (string) file_get_contents( $path ) === $text; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
	}

	/**
	 * 3.12.11: writes a file of Lockdown whole: into "<name>.tmp-<random>" next to it (never hidden, never a name
	 * that ends in .php), then renamed over it, so a reader gets the old or the new content, never half a file.
	 * 3.12.10: an existing file keeps its owner, group and mode; a new one gets $mode and, written as root, the
	 * owner of the WordPress folder (set on the temporary file before the rename).
	 *
	 * @param string $path File.
	 * @param string $text Content.
	 * @param int    $mode Mode of a new file.
	 * @return bool
	 */
	private static function put_file( $path, $text, $mode = 0644 ) {
		// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions -- Direct writes on purpose (WP_Filesystem may need FTP); a failure is the answer.
		$meta = PNCP_File_Owner::capture( $path );
		$name = basename( $path );
		$tmp  = dirname( $path ) . '/' . ( '.php' === substr( $name, -4 ) ? substr( $name, 0, -4 ) : $name ) . '.tmp-' . wp_generate_password( 10, false );
		if ( strlen( $text ) !== @file_put_contents( $tmp, $text, LOCK_EX ) ) {
			@unlink( $tmp );
			return false;
		}
		@chmod( $tmp, null !== $meta ? $meta['mode'] : $mode );
		PNCP_File_Owner::restore( $tmp, $meta );
		if ( ! @rename( $tmp, $path ) ) {
			@unlink( $tmp );
			return false;
		}
		PNCP_File_Owner::restore( $path, $meta );
		// phpcs:enable
		clearstatcache( true, $path );
		return true;
	}

	/**
	 * 3.12.11: makes a data folder of Lockdown (only inside a folder that is there already) with an
	 * index.html (no folder listing) and, with $deny, an .htaccess that denies all access (Apache). A private
	 * folder gets no .htaccess of its own (the one of the folder above covers it). 3.12.10: 0755, and created as
	 * root, the owner of the WordPress folder.
	 *
	 * @param string $dir  Folder.
	 * @param bool   $deny With the .htaccess.
	 * @return bool Whether the folder is there and PHP can write to it.
	 */
	public static function ensure_dir( $dir, $deny ) {
		// phpcs:disable WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions -- Direct writes on purpose (WP_Filesystem may need FTP); a failure is the answer.
		if ( file_exists( $dir ) && ! is_dir( $dir ) ) {
			return false; // A file of that name: not ours, never replaced.
		}
		if ( ! is_dir( $dir ) ) {
			$parent = dirname( $dir );
			if ( ! is_dir( $parent ) || ! wp_is_writable( $parent ) || ! @mkdir( $dir, 0755 ) ) {
				return false;
			}
			@chmod( $dir, 0755 ); // Whatever the umask (root's 077 gave 0700).
			PNCP_File_Owner::restore( $dir, null );
		}
		if ( ! wp_is_writable( $dir ) ) {
			return false;
		}
		$files = array( 'index.html' => self::DIR_INDEX );
		if ( $deny ) {
			$files['.htaccess'] = self::BEACON_HTACCESS;
		}
		foreach ( $files as $file => $content ) {
			if ( ! file_exists( $dir . '/' . $file ) && false !== @file_put_contents( $dir . '/' . $file, $content ) ) {
				@chmod( $dir . '/' . $file, 0644 );
				PNCP_File_Owner::restore( $dir . '/' . $file, null );
			}
		}
		// phpcs:enable
		return true;
	}

	/**
	 * 3.12.11: removes a folder of Lockdown when nothing else is in it: its index.html, .htaccess and the index.php of
	 * 3.12.10 go only when they are exactly ScrapeLock's, and the folder only when it is empty then.
	 *
	 * @param string $dir Folder.
	 */
	private static function tidy_dir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$ours  = array(
			'index.html' => self::DIR_INDEX,
			'.htaccess'  => self::BEACON_HTACCESS,
			'index.php'  => self::BEACON_INDEX,
		);
		$names = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable = kept.
		if ( false === $names || array() !== array_diff( $names, array( '.', '..' ), array_keys( $ours ) ) ) {
			return;
		}
		foreach ( $ours as $file => $content ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
			if ( is_file( $dir . '/' . $file ) && @file_get_contents( $dir . '/' . $file ) === $content ) {
				wp_delete_file( $dir . '/' . $file );
			}
		}
		@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- Only succeeds when empty (nothing of someone else is removed).
		clearstatcache();
	}

	/**
	 * 3.12.11: the private folders ("data-" and 20 hex digits) in a folder of Lockdown, whatever the keys they were
	 * made with (so they can be removed after the keys changed).
	 *
	 * @param string $dir Folder.
	 * @return string[]
	 */
	private static function private_dirs( $dir ) {
		$out = array();
		foreach ( (array) glob( $dir . '/data-*', GLOB_ONLYDIR ) as $sub ) {
			if ( is_string( $sub ) && preg_match( '/^data-[0-9a-f]{20}$/', basename( $sub ) ) ) {
				$out[] = $sub;
			}
		}
		return $out;
	}

	/**
	 * 3.12.11: removes the files of a private folder (only the names ScrapeLock writes, and its temporary files),
	 * and the folder when it is empty then.
	 *
	 * @param string   $dir   Private folder.
	 * @param string[] $names The file names.
	 */
	private static function remove_private( $dir, $names ) {
		foreach ( $names as $name ) {
			if ( is_file( $dir . '/' . $name ) ) {
				wp_delete_file( $dir . '/' . $name );
			}
		}
		foreach ( (array) glob( $dir . '/*.json.tmp-*' ) as $file ) {
			if ( is_string( $file ) ) {
				wp_delete_file( $file );
			}
		}
		self::tidy_dir( $dir );
	}

	/**
	 * 3.12.11: removes guard.json, the copy of the snapshot (in every private folder, whatever the keys), their
	 * temporary files and, when nothing else is left in it, the data folder. The counters are removed by
	 * PNCP_Lockdown::fails_remove().
	 */
	private static function remove_guard_data() {
		$dir = self::data_dir();
		if ( ! is_dir( $dir ) ) {
			return;
		}
		if ( is_file( self::guard_data_path() ) ) {
			wp_delete_file( self::guard_data_path() );
		}
		foreach ( (array) glob( $dir . '/*.json.tmp-*' ) as $file ) {
			if ( is_string( $file ) ) {
				wp_delete_file( $file );
			}
		}
		foreach ( self::private_dirs( $dir ) as $sub ) {
			self::remove_private( $sub, array( self::SNAP_FILE, self::GUARD_VALUES ) );
		}
		self::tidy_dir( $dir );
	}

	/**
	 * Removes the guard file, only if it is ours (not its data).
	 */
	private static function delete_guard_file() {
		$path = self::path();
		if ( file_exists( $path ) && self::ours( $path ) ) {
			wp_delete_file( $path );
			if ( function_exists( 'opcache_invalidate' ) ) {
				opcache_invalidate( $path, true );
			}
		}
	}

	/**
	 * 3.12.11: the temporary files of the guard file: "scrapelock-lockdown-guard.tmp-<random>", and the hidden
	 * ".scrapelock-lockdown-guard.php.<random>.tmp" of 3.12.10 and older (left only if a write was cut off).
	 */
	private static function remove_legacy_leftovers() {
		$mu = PNCP_Paths::mu_plugins();
		foreach ( array_merge( (array) glob( $mu . '/scrapelock-lockdown-guard.tmp-*' ), (array) glob( $mu . '/.' . self::FILE . '.*.tmp' ) ) as $file ) {
			if ( is_string( $file ) && is_file( $file ) ) {
				wp_delete_file( $file );
			}
		}
		// 3.12.10's index.php of the data folder: an index.html is there now.
		$dir = self::data_dir();
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( is_file( $dir . '/index.html' ) && is_file( $dir . '/index.php' ) && self::BEACON_INDEX === @file_get_contents( $dir . '/index.php' ) ) {
			wp_delete_file( $dir . '/index.php' );
		}
	}

	/**
	 * The guard file was written again on this request: the values it keeps change now too, not only from the
	 * next request on (for example after unlocking, or after the quarantine deactivated a plugin).
	 *
	 * @param bool $active Whether the guard keeps values now (locked, not unlocked for a while).
	 * @param int  $snap   The generation of the snapshot the state names.
	 */
	private static function guard_now( $active, $snap ) {
		if ( ! isset( $GLOBALS['pncp_lockdown_guard'] ) || ! is_array( $GLOBALS['pncp_lockdown_guard'] ) ) {
			return;
		}
		if ( ! is_multisite() ) {
			$GLOBALS['pncp_lockdown_guard']['values'] = $active ? self::guarded_values( (int) $snap ) : array();
			return;
		}
		$payload = $active ? self::guard_payload( (int) $snap ) : array(
			'network'     => array(),
			'sites'       => array(),
			'network_own' => false,
		);
		foreach ( $payload as $key => $value ) {
			$GLOBALS['pncp_lockdown_guard'][ $key ] = $value;
		}
	}

	/**
	 * Removes the guard, only if it is ours, with its data (guard.json, the copy of the snapshot, the counters)
	 * and the lock file (3.4.1). 3.12.11: also the files of 3.12.10 (the guard with its data inside, fails.php,
	 * index.php). The guard first, so it never runs without its data.
	 */
	public static function remove_guard() {
		self::delete_guard_file();
		PNCP_Lockdown::fails_remove(); // The copy of the wrong-code counters goes with the guard.
		self::remove_beacon(); // 3.4.1: and the lock file written when the guard could not be.
		self::remove_guard_data();
		self::remove_legacy_leftovers();
		self::tidy_dir( self::data_dir() );
		PNCP_Early::remove_dir(); // 3.4.3: and the mu-plugins folder, if ScrapeLock created it and it is now empty.
	}

	/**
	 * Is the guard exactly the file ScrapeLock ships, with guard.json for the lock as it is stored now (nothing
	 * changed or added by hand)? Used by the file integrity check.
	 *
	 * @return bool
	 */
	public static function guard_genuine() {
		$path = self::path();
		if ( ! self::ours( $path ) || '' !== PNCP_Lockdown::tampered() ) {
			return false;
		}
		$state = PNCP_Lockdown::state();
		if ( empty( $state['locked'] ) || ! self::file_is( $path, self::code() ) ) {
			return false;
		}
		$data = self::read_guard_data();
		if ( null === $data || ! isset( $data['beacon'] ) || ! is_array( $data['beacon'] ) ) {
			return false;
		}
		$record = self::guard_record( (string) json_encode( $data['beacon'] ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- As the guard encodes it.
		return self::record( true, (int) $state['until'], (int) $state['gen'], (int) $state['snap'] ) === $record;
	}

	/**
	 * Is the guard in place?
	 *
	 * @return bool
	 */
	public static function guard_installed() {
		return self::ours( self::path() );
	}

	/**
	 * Can the guard be written on this site (direct file access to wp-content/mu-plugins, and no file of
	 * someone else under its name)? Checked before locking: without the guard, someone who can change the
	 * database directly could open the lock.
	 *
	 * @return bool
	 */
	public static function can_write_guard() {
		$path = self::path();
		if ( self::ours( $path ) && wp_is_writable( $path ) && ( ! is_dir( self::data_dir() ) || wp_is_writable( self::data_dir() ) ) ) {
			return true;
		}
		if ( file_exists( $path ) && ! self::ours( $path ) ) {
			return false;
		}
		$filesystem = self::filesystem();
		if ( ! $filesystem ) {
			return false;
		}
		$dir = PNCP_Paths::mu_plugins();
		return $filesystem->is_dir( $dir ) ? $filesystem->is_writable( $dir ) : $filesystem->is_writable( dirname( $dir ) );
	}

	/**
	 * Was the file written by ScrapeLock?
	 *
	 * @param string $path Path.
	 * @return bool
	 */
	private static function ours( $path ) {
		if ( ! is_readable( $path ) ) {
			return false;
		}
		$head = (string) file_get_contents( $path, false, null, 0, 200 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		return false !== strpos( $head, 'Plugin Name: ' . self::MARKER );
	}

	/* ---------- 3.12.11: the files of 3.12.10 and older, read once more and replaced ---------- */

	/**
	 * 3.12.11: the guard file on disk when it is one of 3.12.10 or older (its data written into the PHP code
	 * itself), otherwise ''.
	 *
	 * @return string
	 */
	private static function legacy_guard_code() {
		$path = self::path();
		if ( ! self::ours( $path ) ) {
			return '';
		}
		$code = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		return false !== strpos( $code, "define( 'PNCP_LOCKDOWN_BEACON', '" ) ? $code : '';
	}

	/**
	 * 3.12.11: the signed record in a guard file of 3.12.10 or older (as var_export() wrote it), or null.
	 *
	 * @param string $code The guard file.
	 * @return string|null
	 */
	private static function legacy_guard_json( $code ) {
		if ( ! preg_match( "/define\\( 'PNCP_LOCKDOWN_BEACON', '((?:[^'\\\\]|\\\\.)*)' \\);/", $code, $match ) ) {
			return null;
		}
		return strtr(
			$match[1],
			array(
				'\\\\' => '\\',
				"\\'"  => "'",
			)
		);
	}

	/**
	 * 3.12.11: the copy of the snapshot in the format of 3.12.10 and older (the guard's constant COPY, the "copy" of
	 * the lock file): base64 of serialize(). Read only to move it into the new files, as data only (no objects);
	 * the caller checks its signature.
	 *
	 * @param string $encoded The encoded copy.
	 * @return array<string, mixed>|null
	 */
	private static function legacy_copy( $encoded ) {
		if ( '' === $encoded ) {
			return null;
		}
		$raw  = base64_decode( $encoded, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Reads the format of 3.12.10 once, to replace it.
		$data = is_string( $raw ) ? @unserialize( $raw, array( 'allowed_classes' => false ) ) : false; // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize, WordPress.PHP.NoSilencedErrors.Discouraged -- Our own signed data of 3.12.10, no objects.
		return is_array( $data ) ? $data : null;
	}

	/**
	 * 3.12.11: moves the files of the lock written by 3.12.10 and older into the new ones, without unlocking the site
	 * for a moment: on the upgrade, in the hourly check and on the first page of wp-admin that finds them.
	 *
	 * - The guard with its data inside (PHP code generated per site, the copy of the snapshot as base64 of
	 *   serialize()): its signed record is read from the file itself (never from the database, which may have been
	 *   changed) and written again with write_guard(): snapshot.json and guard.json first, then the shipped guard
	 *   over the old one. A guard whose record does not match the keys is left as it is (and is reported as before).
	 * - The lock file lock-<hex>.php ("<?php exit; ?>" and JSON, with the copy as base64 of serialize()): written
	 *   again as lock.json in the private folder with the same record, address and lock time, then removed. Next to a
	 *   guard (which replaces it) it is only removed.
	 * - The copies of the wrong-code counters fails.php and fails-<hex>.php: moved into fails.json, then removed.
	 * - The index.php of those folders (an index.html is written instead) and temporary files of a cut-off write.
	 *
	 * @return string[] The new files written for the lock.
	 */
	public static function migrate_files() {
		$done   = array();
		$legacy = self::legacy_guard_code();
		if ( '' !== $legacy ) {
			$json   = self::legacy_guard_json( $legacy );
			$record = null === $json ? null : self::guard_record( $json );
			if ( null !== $record && $record['locked'] && isset( $record['gen'], $record['snap'] ) ) {
				if ( ! defined( self::COPY ) && ( null === self::$copy || false === self::$copy ) && preg_match( "/define\\( '" . self::COPY . "', '([A-Za-z0-9+\\/=]+)' \\);/", $legacy, $match ) ) {
					// This request did not load that guard (the copy is in the file only).
					$copy       = self::legacy_copy( $match[1] );
					self::$copy = null === $copy ? false : $copy;
				}
				if ( self::write_guard( true, (int) $record['until'], (int) $record['gen'], (int) $record['snap'] ) ) {
					$done[] = self::path();
				}
			}
		}
		clearstatcache();
		$file = self::read_beacon_file();
		if ( false !== $file && ! empty( $file['legacy'] ) && $file['record']['locked'] ) {
			if ( self::guard_installed() ) {
				// The guard keeps the lock (write_lock_files() removes a lock file once the guard is written).
				if ( '' === self::legacy_guard_code() && null !== self::read_guard_data() ) {
					self::remove_beacon();
				}
			} else {
				$rec                 = $file['record'];
				self::$file          = $file;
				self::$file_at_start = true;
				self::$copy          = null;
				$copy                = is_multisite() || ! isset( $rec['snap'] ) ? null : self::snapshot_source( (int) $rec['snap'] );
				if ( self::write_beacon_record( $rec, (string) $file['mail'], (int) $file['since'], $copy ) ) {
					$done[] = self::beacon_path();
				}
			}
		}
		PNCP_Lockdown::fails_migrate();
		if ( '' === self::legacy_guard_code() ) {
			self::remove_legacy_leftovers();
		}
		foreach ( self::beacon_dirs() as $dir ) {
			foreach ( (array) glob( $dir . '/.lock-*.tmp' ) as $tmp ) {
				if ( is_string( $tmp ) ) {
					wp_delete_file( $tmp );
				}
			}
		}
		return $done;
	}

	/**
	 * 3.12.11: on a page of wp-admin, moves the files of 3.12.10 (migrate_files()) as soon as they are found: the
	 * guard of 3.12.10 ran on this request (it defines the copy, or its record without PNCP_LOCKDOWN_GUARD), or the
	 * lock file or the counters are still in the old format. Costs nothing once they are moved.
	 */
	public static function maybe_migrate() {
		if ( defined( self::COPY ) || ( defined( 'PNCP_LOCKDOWN_BEACON' ) && ! defined( 'PNCP_LOCKDOWN_GUARD' ) ) ) {
			self::migrate_files();
			return;
		}
		// 3.13.0: the guard of 3.12.11 to 3.12.13 ran (version 2), or guard.json still lists the plugins and the
		// theme (the guard says so with PNCP_LOCKDOWN_GUARD_INLINE): written again with the lists in the private folder.
		$ran = self::guard_version_ran();
		if ( ( $ran > 0 && $ran < 3 ) || defined( 'PNCP_LOCKDOWN_GUARD_INLINE' ) ) {
			self::migrate_guard_values();
		}
		$file = self::beacon_file();
		if ( ( null !== $file && ! empty( $file['legacy'] ) ) || file_exists( PNCP_Lockdown::fails_file_legacy_php() ) ) {
			self::migrate_files();
		}
	}

	/* ---------- 3.4.1: the lock file, when the guard cannot be written ---------- */

	/**
	 * Writes the guard for this state or, when the guard cannot be written (and is not there), the lock file
	 * (write_beacon()). The guard, once written, replaces a lock file.
	 *
	 * @param bool     $locked Locked.
	 * @param int      $until  Until.
	 * @param int|null $gen    Generation of the state (null: the one stored now).
	 * @param int|null $snap   Generation of the snapshot (null: the one stored now).
	 * @return bool Whether the guard, or else the lock file, is now as it should be.
	 */
	public static function write_lock_files( $locked, $until, $gen = null, $snap = null ) {
		if ( self::write_guard( $locked, $until, $gen, $snap ) ) {
			if ( $locked && '' !== self::beacon_path() ) {
				self::remove_beacon();
			}
			return true;
		}
		if ( ! $locked || self::guard_installed() ) {
			return false;
		}
		return self::write_beacon( true, $until, $gen, $snap );
	}

	/**
	 * The folders the lock file may be written to, in order: wp-content/uploads/scrapelock-lockdown, then
	 * wp-content/scrapelock-lockdown. Always from WP_CONTENT_DIR (wp-config.php), never from a setting in the
	 * database (such as the uploads path), so the database cannot make ScrapeLock look elsewhere. 3.12.11: the lock
	 * file and its counters are in the private folder of the first one (beacon_private()).
	 *
	 * @return string[] Without a trailing slash.
	 */
	public static function beacon_dirs() {
		$content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
		$dirs    = array();
		foreach ( self::BEACON_DIRS as $dir ) {
			$dirs[] = $content . '/' . $dir;
		}
		return $dirs;
	}

	/**
	 * A path as shown to the owner: relative to the WordPress folder when it is inside it.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function short_path( $path ) {
		$path = wp_normalize_path( (string) $path );
		$core = trailingslashit( wp_normalize_path( ABSPATH ) );
		return 0 === strpos( $path, $core ) ? substr( $path, strlen( $core ) ) : $path;
	}

	/**
	 * 3.12.11: the private folder in one of the lock file's folders (see private_name()).
	 *
	 * @param string $dir One of beacon_dirs().
	 * @return string
	 */
	public static function beacon_private( $dir ) {
		return $dir . '/' . self::private_name();
	}

	/**
	 * 3.12.11: the folder of the lock file as shown to the owner (the private folder's name is not shown).
	 *
	 * @return string '' when there is no lock file.
	 */
	public static function beacon_folder() {
		$path = self::beacon_path();
		if ( '' === $path ) {
			return '';
		}
		$dir = dirname( $path );
		return in_array( $dir, self::beacon_dirs(), true ) ? $dir : dirname( $dir );
	}

	/**
	 * 3.4.1 to 3.12.10: the name of the lock file (lock-<hex>.php), made from the keys. Read once more and replaced
	 * (migrate_files()).
	 *
	 * @return string
	 */
	private static function legacy_beacon_name() {
		return 'lock-' . substr( hash_hmac( 'sha256', 'pncp_lockdown_beacon_name', self::key() ), 0, 20 ) . '.php';
	}

	/**
	 * 3.4.1 to 3.12.10: the name of the copy of the wrong-code counters next to the lock file (fails-<hex>.php).
	 *
	 * @return string
	 */
	private static function legacy_fails_name() {
		return 'fails-' . substr( hash_hmac( 'sha256', 'pncp_lockdown_beacon_fails', self::key() ), 0, 20 ) . '.php';
	}

	/**
	 * 3.4.1: where the copy of the wrong-code counters goes while the lock is kept by the lock file instead of
	 * the guard: next to the lock file, fails.json in the private folder ('' when there is no lock file).
	 *
	 * @return string
	 */
	public static function beacon_fails_path() {
		$folder = self::beacon_folder();
		return '' === $folder ? '' : self::beacon_private( $folder ) . '/' . self::FAILS_FILE;
	}

	/**
	 * 3.4.1: every place a copy of the counters next to a lock file may be (in each folder of beacon_dirs(), and
	 * 3.12.11: the fails-<hex>.php of 3.12.10 there).
	 *
	 * @return string[]
	 */
	public static function beacon_fails_paths() {
		$paths = array();
		foreach ( self::beacon_dirs() as $dir ) {
			$paths[] = self::beacon_private( $dir ) . '/' . self::FAILS_FILE;
			$paths[] = $dir . '/' . self::legacy_fails_name();
		}
		return $paths;
	}

	/**
	 * The folder the lock file can be written to now ('' when none can): the first of beacon_dirs() that PHP can
	 * write to directly, or create.
	 *
	 * @return string
	 */
	public static function beacon_writable_dir() {
		foreach ( self::beacon_dirs() as $dir ) {
			if ( is_dir( $dir ) ) {
				if ( wp_is_writable( $dir ) ) {
					return $dir;
				}
				continue;
			}
			if ( file_exists( $dir ) ) {
				continue; // A file of that name: not ours, never replaced.
			}
			$parent = dirname( $dir );
			if ( is_dir( $parent ) && wp_is_writable( $parent ) ) {
				return $dir;
			}
		}
		return '';
	}

	/**
	 * The lock file as read on this request (only read the first time it is needed, on a site without the
	 * guard file: one check per folder while there is none), or null when there is none or it does not match
	 * its signature.
	 *
	 * @return array{record: array{locked:bool, until:int, gen?:int, snap?:int}, mail: string, since: int, copy: array<string, mixed>|null, path: string, legacy: bool}|null
	 */
	private static function beacon_file() {
		if ( null === self::$file ) {
			self::$file          = self::kept_beacon_file();
			self::$file_at_start = false !== self::$file;
		}
		return false === self::$file ? null : self::$file;
	}

	/**
	 * 3.12.9: the lock file as read_beacon_file() finds it, kept for 5 minutes in a persistent object cache or
	 * APCu (PNCP_Defer): a visitor's request reads the copy, never the disk (one check per folder on every page,
	 * where the disk may stall). Written and removed only by ScrapeLock, which refreshes the copy (forget_beacon()).
	 * Every other request (wp-admin, cron, WP-CLI) reads the disk and refreshes it.
	 *
	 * @return array<string, mixed>|false
	 */
	private static function kept_beacon_file() {
		$key = self::beacon_cache_key();
		if ( PNCP_Defer::active() ) {
			$kept = PNCP_Defer::get( $key );
			if ( is_array( $kept ) || 0 === $kept ) {
				return is_array( $kept ) ? $kept : false;
			}
		}
		$file = self::read_beacon_file();
		if ( '' !== PNCP_Defer::store() ) {
			PNCP_Defer::set( $key, false === $file ? 0 : $file, 5 * MINUTE_IN_SECONDS );
		}
		return $file;
	}

	/**
	 * 3.12.11: the name of the copy kept for visitors' requests (another one than 3.12.10's, whose copy of the
	 * snapshot was a text).
	 *
	 * @return string
	 */
	private static function beacon_cache_key() {
		return 'pncp_beacon2_' . md5( self::private_name() );
	}

	/**
	 * 3.12.9: the lock file was written or removed: the copy kept for visitors' requests goes (kept_beacon_file()).
	 */
	private static function forget_beacon() {
		PNCP_Defer::delete( self::beacon_cache_key() );
	}

	/**
	 * Path of the lock file that is there now and matches its signature ('' when none is).
	 *
	 * @return string
	 */
	public static function beacon_path() {
		$file = self::beacon_file();
		return null === $file ? '' : $file['path'];
	}

	/**
	 * Reads the lock file from the first folder that has a genuine one. 3.12.11: lock.json in the private folder, or
	 * else the lock-<hex>.php of 3.12.10 and older (until migrate_files() has replaced it).
	 *
	 * @return array<string, mixed>|false
	 */
	private static function read_beacon_file() {
		foreach ( self::beacon_dirs() as $dir ) {
			$path = self::beacon_private( $dir ) . '/' . self::LOCK_FILE;
			if ( is_file( $path ) ) {
				$data = self::parse_beacon( $path );
				if ( null !== $data ) {
					return $data;
				}
			}
			$old = $dir . '/' . self::legacy_beacon_name();
			if ( is_file( $old ) ) {
				$data = self::parse_legacy_beacon( $old );
				if ( null !== $data ) {
					return $data;
				}
			}
		}
		return false;
	}

	/**
	 * 3.12.11: the signed content of a lock file (lock.json), or null.
	 *
	 * @param string $path File.
	 * @return array<string, mixed>|null
	 */
	private static function parse_beacon( $path ) {
		$data = self::read_json( $path, 4 * self::BEACON_MAX_COPY );
		if ( null === $data || ! isset( $data['beacon'], $data['mail'], $data['since'], $data['xsig'] ) || ! is_array( $data['beacon'] ) ) {
			return null;
		}
		$copy = isset( $data['copy'] ) && is_array( $data['copy'] ) ? self::open_copy( $data['copy'] ) : null;
		return self::beacon_entry( $data['beacon'], $data['mail'], $data['since'], $data['xsig'], $copy, $path, false );
	}

	/**
	 * 3.4.1 to 3.12.10: the signed content of a lock file lock-<hex>.php (BEACON_HEAD, then JSON with the record as
	 * text and the copy as base64 of serialize()), or null.
	 *
	 * @param string $path File.
	 * @return array<string, mixed>|null
	 */
	private static function parse_legacy_beacon( $path ) {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file; unreadable = none.
		$text = @file_get_contents( $path, false, null, 0, 2 * self::BEACON_MAX_COPY );
		if ( ! is_string( $text ) || 0 !== strpos( $text, self::BEACON_HEAD ) ) {
			return null;
		}
		$data = json_decode( substr( $text, strlen( self::BEACON_HEAD ) ), true );
		if ( ! is_array( $data ) || ! isset( $data['beacon'], $data['mail'], $data['since'], $data['xsig'] ) || ! is_string( $data['beacon'] ) ) {
			return null;
		}
		$beacon = json_decode( $data['beacon'], true );
		if ( ! is_array( $beacon ) ) {
			return null;
		}
		$copy = isset( $data['copy'] ) && is_string( $data['copy'] ) ? self::legacy_copy( $data['copy'] ) : null;
		return self::beacon_entry( $beacon, $data['mail'], $data['since'], $data['xsig'], $copy, $path, true );
	}

	/**
	 * The lock file's content, if its record and the record with the address and the lock time match their
	 * signatures (otherwise null).
	 *
	 * @param array<string, mixed>      $beacon The signed record.
	 * @param mixed                     $mail   The address alerts go to.
	 * @param mixed                     $since  The lock time.
	 * @param mixed                     $xsig   The signature of the record with the address and the lock time.
	 * @param array<string, mixed>|null $copy   The copy of the snapshot (its signature is checked when used).
	 * @param string                    $path   File.
	 * @param bool                      $legacy Written by 3.12.10 or older.
	 * @return array<string, mixed>|null
	 */
	private static function beacon_entry( $beacon, $mail, $since, $xsig, $copy, $path, $legacy ) {
		if ( ! isset( $beacon['locked'], $beacon['until'], $beacon['sig'] ) || ! is_scalar( $mail ) || ! is_scalar( $since ) ) {
			return null;
		}
		$record = self::record( $beacon['locked'], $beacon['until'], isset( $beacon['gen'] ) ? $beacon['gen'] : null, isset( $beacon['snap'] ) ? $beacon['snap'] : null );
		$mail   = (string) $mail;
		$since  = (int) $since;
		if ( ! self::valid( $record, $beacon['sig'] ) || ! self::valid( array( 'pncp_lockdown_beacon', $record, $mail, $since ), $xsig ) ) {
			return null;
		}
		return array(
			'record' => $record,
			'mail'   => $mail,
			'since'  => $since,
			'copy'   => $copy,
			'path'   => $path,
			'legacy' => (bool) $legacy,
		);
	}

	/**
	 * Reads the lock file again (see refresh_beacon()): another request may have written it since the start
	 * of this one. A lock file that is gone now counts as "not locked", since only ScrapeLock removes it.
	 *
	 * @return bool Whether it changed since it was first read on this request.
	 */
	private static function refresh_beacon_file() {
		if ( ! self::$file_at_start ) {
			return false; // There was none when this request first looked.
		}
		$before = self::beacon_file();
		clearstatcache();
		$now        = self::read_beacon_file();
		self::$file = $now;
		self::$copy = null;
		$record     = false === $now ? self::record( false, 0 ) : $now['record'];
		if ( null !== $before && $before['record'] === $record ) {
			return false;
		}
		self::$current = $record;
		return true;
	}

	/**
	 * The administration address the lock file signs: alerts go there while locked. When the site is locked
	 * now, the one signed when it was locked (snapshot, its copy, the lock file or the state); only the address
	 * stored now when the site is being locked.
	 *
	 * @return string
	 */
	private static function beacon_mail() {
		$state  = PNCP_Lockdown::state();
		$tamper = PNCP_Lockdown::tampered();
		if ( '' === $tamper && empty( $state['locked'] ) ) {
			$mail = (string) ( is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' ) );
		} else {
			$mail = self::alert_address();
			if ( '' === $mail && '' === $tamper && is_email( $state['mail'] ) ) {
				$mail = (string) $state['mail'];
			}
		}
		return is_email( $mail ) ? $mail : '';
	}

	/**
	 * Writes the lock file (removes it when not locked): used when the guard file cannot be written (the owner
	 * locked with "Lock without the guard file"). A signed copy of the lock outside the database: the lock
	 * flag, the generation of the state and of the snapshot, the lock time, the address alerts go to and, when
	 * it is not too large, the signed copy of the snapshot (as next to the guard). While it is there, a site
	 * whose Lockdown data was deleted or changed in the database stays locked, and its protected settings are
	 * put back from the copy. Written directly by PHP (not through WP_Filesystem, which may need FTP), to a
	 * temporary file first and then renamed, so a request never reads half a file. 3.12.11: lock.json (plain
	 * JSON) in the private folder of the first folder of beacon_dirs() that can be written.
	 *
	 * @param bool     $locked Locked.
	 * @param int      $until  Until.
	 * @param int|null $gen    Generation of the state (null: the one stored now).
	 * @param int|null $snap   Generation of the snapshot (null: the one stored now).
	 * @return bool Whether the lock file is now as it should be.
	 */
	public static function write_beacon( $locked, $until, $gen = null, $snap = null ) {
		if ( ! $locked ) {
			self::remove_beacon();
			return '' === self::beacon_path();
		}
		$state = PNCP_Lockdown::state();
		$gen   = null === $gen ? (int) $state['gen'] : (int) $gen;
		$snap  = null === $snap ? (int) $state['snap'] : (int) $snap;
		$old   = self::beacon_file();
		$since = '' === PNCP_Lockdown::tampered() ? (int) $state['since'] : ( null === $old ? 0 : (int) $old['since'] );
		$copy  = is_multisite() ? null : self::snapshot_source( $snap );
		return self::write_beacon_record( self::record( true, $until, $gen, $snap ), self::beacon_mail(), $since, $copy );
	}

	/**
	 * 3.12.11: writes lock.json for a record (see write_beacon()), into the first folder that can be written; the
	 * lock files in the other folders, and those of 3.12.10 in this one, are removed once it is written.
	 *
	 * @param array{locked:bool, until:int, gen?:int, snap?:int} $rec   The record.
	 * @param string                                             $mail  The address alerts go to.
	 * @param int                                                $since The lock time.
	 * @param array<string, mixed>|null                          $copy  The signed copy of the snapshot, or null.
	 * @return bool
	 */
	private static function write_beacon_record( $rec, $mail, $since, $copy ) {
		$data = array(
			'about'  => self::ABOUT_LOCK,
			'beacon' => array_merge( $rec, array( 'sig' => self::sign( $rec ) ) ),
			'mail'   => $mail,
			'since'  => $since,
			'xsig'   => self::sign( array( 'pncp_lockdown_beacon', $rec, $mail, $since ) ),
		);
		if ( null !== $copy ) {
			$packed = self::seal_copy( $copy );
			if ( null !== $packed && strlen( self::json_text( array( 'copy' => $packed ) ) ) <= self::BEACON_MAX_COPY ) {
				$data['copy'] = $packed;
			} else {
				$copy = null;
			}
		}
		$text = self::json_text( $data );
		if ( '' === $text ) {
			return false;
		}
		$written = '';
		foreach ( self::beacon_dirs() as $dir ) {
			if ( self::beacon_put( $dir, $text ) ) {
				$written = $dir;
				break;
			}
		}
		if ( '' === $written ) {
			return false;
		}
		foreach ( self::beacon_dirs() as $dir ) {
			if ( $dir !== $written ) {
				self::remove_beacon_in( $dir ); // Only the file just written counts.
			}
		}
		self::$file          = array(
			'record' => $rec,
			'mail'   => $mail,
			'since'  => $since,
			'copy'   => $copy,
			'path'   => self::beacon_private( $written ) . '/' . self::LOCK_FILE,
			'legacy' => false,
		);
		self::$file_at_start = true;
		self::$copy          = null === $copy ? false : $copy;
		self::$current       = $rec;
		self::forget_beacon();
		// 3.12.11: the counters of 3.12.10 next to an old lock file are moved first, then its files go.
		PNCP_Lockdown::fails_migrate();
		self::remove_legacy_beacon_in( $written );
		return true;
	}

	/**
	 * Writes the lock file into one folder: the folder (with an index.html and an .htaccess that denies access),
	 * its private folder (with an index.html), and lock.json in it.
	 *
	 * @param string $dir  One of beacon_dirs().
	 * @param string $text Content.
	 * @return bool Whether the file holds exactly this content now.
	 */
	private static function beacon_put( $dir, $text ) {
		$private = self::beacon_private( $dir );
		if ( ! self::ensure_dir( $dir, true ) || ! self::ensure_dir( $private, false ) ) {
			return false;
		}
		$path = $private . '/' . self::LOCK_FILE;
		if ( self::file_is( $path, $text ) ) {
			return true;
		}
		return self::put_file( $path, $text ) && self::file_is( $path, $text );
	}

	/**
	 * Removes the lock file from every folder (on a full unlock, when the app is removed, on deactivation and
	 * when the guard replaces it).
	 */
	public static function remove_beacon() {
		foreach ( self::beacon_dirs() as $dir ) {
			self::remove_beacon_in( $dir );
		}
		self::forget_beacon();
		self::$file          = null;
		self::$file_at_start = false;
		self::beacon_file();
	}

	/**
	 * Removes ScrapeLock's lock files from one folder (also ones written with other keys, and those of 3.12.10),
	 * with the copy of the counters next to them, the index.html and .htaccess when they are exactly ScrapeLock's,
	 * and the folders when they are empty then.
	 *
	 * @param string $dir Folder.
	 */
	private static function remove_beacon_in( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		self::remove_legacy_beacon_in( $dir );
		foreach ( self::private_dirs( $dir ) as $sub ) {
			self::remove_private( $sub, array( self::LOCK_FILE, self::FAILS_FILE ) );
		}
		self::tidy_dir( $dir );
	}

	/**
	 * 3.12.11: removes the files of 3.12.10 and older from one of the lock file's folders: lock-<hex>.php and
	 * fails-<hex>.php (only ScrapeLock's, whatever the keys), their hidden temporary files, and the index.php (when an
	 * index.html is there, or nothing else is).
	 *
	 * @param string $dir Folder.
	 */
	private static function remove_legacy_beacon_in( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		foreach ( (array) glob( $dir . '/lock-*.php' ) as $file ) {
			if ( is_string( $file ) && self::beacon_ours( $file ) ) {
				wp_delete_file( $file );
			}
		}
		foreach ( (array) glob( $dir . '/.lock-*.tmp' ) as $file ) {
			if ( is_string( $file ) ) {
				wp_delete_file( $file );
			}
		}
		foreach ( (array) glob( $dir . '/fails-*.php' ) as $file ) {
			if ( is_string( $file ) && 0 === strpos( (string) @file_get_contents( $file, false, null, 0, 64 ), self::BEACON_HEAD . '{"rows":' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
				wp_delete_file( $file );
			}
		}
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		if ( is_file( $dir . '/index.html' ) && is_file( $dir . '/index.php' ) && self::BEACON_INDEX === @file_get_contents( $dir . '/index.php' ) ) {
			wp_delete_file( $dir . '/index.php' );
		}
		clearstatcache();
	}

	/**
	 * Was this file written by ScrapeLock as a lock file of 3.4.1 to 3.12.10 (whatever the keys)?
	 *
	 * @param string $path File.
	 * @return bool
	 */
	private static function beacon_ours( $path ) {
		$head = (string) @file_get_contents( $path, false, null, 0, 64 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file.
		return 0 === strpos( $head, self::BEACON_HEAD . '{"beacon":' );
	}

	/**
	 * Is this a file of the lock file's folder exactly as ScrapeLock writes it, which cannot run any code? The file
	 * integrity check only looks at files that can run code: there, the .htaccess, and until migrate_files() has run
	 * the files of 3.12.10 (index.php, lock-<hex>.php and fails-<hex>.php: BEACON_HEAD and then text without "<").
	 * The data itself (3.12.11) is JSON, which never runs. A file there with anything else in it is checked like any
	 * other.
	 *
	 * @param string $path File.
	 * @return bool
	 */
	public static function beacon_inert( $path ) {
		$path = wp_normalize_path( (string) $path );
		if ( ! in_array( dirname( $path ), self::beacon_dirs(), true ) || ! is_readable( $path ) ) {
			return false;
		}
		$name = basename( $path );
		clearstatcache( true, $path );
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Unreadable = checked.
		if ( false === $size || $size > 3 * self::BEACON_MAX_COPY ) {
			return false;
		}
		$data = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file; unreadable = checked.
		if ( ! is_string( $data ) ) {
			return false;
		}
		if ( 'index.php' === $name ) {
			return self::BEACON_INDEX === $data;
		}
		if ( '.htaccess' === $name ) {
			return self::BEACON_HTACCESS === $data;
		}
		// 3.4.1: also the copy of the wrong-code counters next to the lock file (the same first line, then JSON).
		return (bool) preg_match( '/^(?:lock|fails)-[0-9a-f]{20}\.php$/', $name ) && 0 === strpos( $data, self::BEACON_HEAD ) && false === strpos( substr( $data, strlen( self::BEACON_HEAD ) ), '<' );
	}

	/* ---------- 3.4.2: the lock line in wp-config.php ---------- */

	/**
	 * The address alerts go to that is signed for a lock being saved now (as in the lock file).
	 *
	 * @return string
	 */
	public static function lock_mail() {
		return self::beacon_mail();
	}

	/**
	 * What the token of the lock line signs.
	 *
	 * @param int    $gen  The generation of the lock.
	 * @param string $mail The address alerts go to.
	 * @return array{g:int, m:string}
	 */
	private static function config_data( $gen, $mail ) {
		return array(
			'g' => (int) $gen,
			'm' => is_string( $mail ) && is_email( $mail ) ? $mail : '',
		);
	}

	/**
	 * The token of the lock line for a lock: "sl1.", the generation and the address (JSON, base64url), ".", and
	 * their signature. Only letters, digits, "-", "_" and ".", so it can be copied into wp-config.php as it is.
	 *
	 * @param int    $gen  The generation of the lock (the state saved when the site was locked).
	 * @param string $mail The address alerts go to.
	 * @return string
	 */
	public static function config_token( $gen, $mail ) {
		$data = self::config_data( $gen, $mail );
		$body = rtrim( strtr( base64_encode( (string) wp_json_encode( $data ) ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- A signed token, not obfuscation.
		return self::CONFIG_PREFIX . '.' . $body . '.' . self::sign( array( 'pncp_lockdown_config', $data ) );
	}

	/**
	 * The whole line for wp-config.php.
	 *
	 * @param int    $gen  The generation of the lock.
	 * @param string $mail The address alerts go to.
	 * @return string
	 */
	public static function config_line( $gen, $mail ) {
		return "define( '" . self::CONFIG . "', '" . self::config_token( $gen, $mail ) . "' );";
	}

	/**
	 * The lock line as wp-config.php defines it, if its signature matches this site's keys.
	 *
	 * @return array{g:int, m:string}|false
	 */
	private static function config_read() {
		if ( null !== self::$config ) {
			return self::$config;
		}
		self::$config = false;
		$value        = defined( self::CONFIG ) ? constant( self::CONFIG ) : null;
		if ( ! is_string( $value ) || strlen( $value ) > 2000 ) {
			return false;
		}
		$parts = explode( '.', trim( $value ) );
		if ( 3 !== count( $parts ) || self::CONFIG_PREFIX !== $parts[0] || ! preg_match( '/^[A-Za-z0-9_-]+$/', $parts[1] ) ) {
			return false;
		}
		$json = base64_decode( strtr( $parts[1], '-_', '+/' ), true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- See config_token().
		$data = is_string( $json ) ? json_decode( $json, true ) : null;
		if ( ! is_array( $data ) || ! isset( $data['g'], $data['m'] ) || ! is_int( $data['g'] ) || $data['g'] < 1 || ! is_string( $data['m'] ) ) {
			return false;
		}
		$data = self::config_data( $data['g'], $data['m'] );
		if ( ! self::valid( array( 'pncp_lockdown_config', $data ), $parts[2] ) ) {
			return false;
		}
		self::$config = $data;
		return $data;
	}

	/**
	 * The lock the line in wp-config.php names (null: no line, a line of another site or changed by hand, or
	 * not followed on this request): its generation and the address alerts go to.
	 *
	 * @return array{gen:int, mail:string}|null
	 */
	public static function config_lock() {
		if ( self::$config_off ) {
			return null;
		}
		$data = self::config_read();
		return false === $data ? null : array(
			'gen'  => $data['g'],
			'mail' => $data['m'],
		);
	}

	/**
	 * The generation the lock line names (0: none). Also while it is not followed: a new state is always saved
	 * with a higher one, so the line no longer holds it once the owner has dealt with the lock.
	 *
	 * @return int
	 */
	public static function config_gen() {
		$data = self::config_read();
		return false === $data ? 0 : (int) $data['g'];
	}

	/**
	 * The lock line is not followed for the rest of this request (see $config_off).
	 */
	public static function config_off() {
		self::$config_off = true;
	}

	/**
	 * Is SCRAPELOCK_LOCKED defined in wp-config.php at all (valid or not)?
	 *
	 * @return bool
	 */
	public static function config_defined() {
		return defined( self::CONFIG );
	}

	/**
	 * What the lock line in wp-config.php means for the lock as it is now: 'none' (no line), 'invalid' (the
	 * signature does not match this site's keys: the line of another site, changed by hand, or the keys
	 * changed since; it is not followed), 'current' (it names the current lock, or holds it: the site stays
	 * locked whatever the database says), 'old' (the site was locked again since: the line names an earlier
	 * lock, replace it) or 'stale' (the site is not locked: remove the line).
	 *
	 * @return string
	 */
	public static function config_status() {
		if ( ! defined( self::CONFIG ) ) {
			return 'none';
		}
		$data = self::config_read();
		if ( false === $data ) {
			return 'invalid';
		}
		if ( '' !== PNCP_Lockdown::tampered() ) {
			return 'current';
		}
		$state = PNCP_Lockdown::state();
		if ( empty( $state['locked'] ) ) {
			return 'stale';
		}
		return (int) $data['g'] >= (int) $state['lgen'] ? 'current' : 'old';
	}

	/**
	 * The lock line for the current lock ('' when the site is not locked, or its data cannot be trusted).
	 *
	 * @return string
	 */
	public static function current_config_line() {
		if ( '' !== PNCP_Lockdown::tampered() ) {
			return '';
		}
		$state = PNCP_Lockdown::state();
		if ( empty( $state['locked'] ) ) {
			return '';
		}
		$gen  = (int) $state['lgen'] > 0 ? (int) $state['lgen'] : (int) $state['gen'];
		$mail = is_email( $state['lmail'] ) ? (string) $state['lmail'] : (string) $state['mail'];
		return self::config_line( $gen, $mail );
	}

	/**
	 * Is the lock kept by nothing outside the database but the lock line (no guard file, no lock file)?
	 *
	 * @return bool
	 */
	public static function needs_config() {
		return ! self::guard_installed() && '' === self::beacon_path();
	}

	/**
	 * WP_Filesystem with direct access, or null (never asks for FTP details).
	 *
	 * @return WP_Filesystem_Base|null
	 */
	private static function filesystem() {
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		// The check writes a test file in the folder it is given: for a mu-plugins folder that does not exist yet
		// (most sites) it would always fail and the file would never be written. Then wp-content is asked.
		$mu      = PNCP_Paths::mu_plugins();
		$context = is_dir( $mu ) ? $mu : dirname( $mu );
		if ( 'direct' !== get_filesystem_method( array(), $context ) || ! WP_Filesystem() ) {
			return null;
		}
		global $wp_filesystem;
		return $wp_filesystem instanceof WP_Filesystem_Base ? $wp_filesystem : null;
	}

	/* ---------- Protected options and administrators ---------- */

	/**
	 * The accounts that could administer the site (any capability that can take it over).
	 *
	 * @return int[]
	 */
	public static function admin_ids() {
		// The upgrade runs on plugins_loaded, before WordPress sets up the roles: get_users() needs them.
		wp_roles();
		$ids = get_users(
			array(
				'capability__in' => PNCP_Lockdown::control_caps(),
				'fields'         => 'ID',
				'number'         => 500,
			)
		);
		$ids = array_map( 'intval', (array) $ids );
		sort( $ids );
		return $ids;
	}

	/**
	 * Fingerprint of an option's value.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	private static function digest( $value ) {
		return md5( maybe_serialize( $value ) );
	}

	/**
	 * The fingerprints of some values.
	 *
	 * @param array<string, mixed> $values Option => value.
	 * @return array<string, string>
	 */
	private static function digests_of( $values ) {
		$digests = array();
		foreach ( $values as $option => $value ) {
			$digests[ (string) $option ] = self::digest( $value );
		}
		return $digests;
	}

	/**
	 * Takes the snapshot when the site is locked (and again when the site is locked again after a temporary
	 * unlock). Signed. Only ever called right after the owner locked the site with the app code: the values and
	 * the administrators as they are now become the ones that count, so it never runs on its own (an upgrade, a
	 * scheduled event), where it would make values changed behind WordPress's back look genuine.
	 */
	public static function take_snapshot() {
		if ( is_multisite() ) {
			self::take_network_snapshot();
			return;
		}
		self::take_site_snapshot();
	}

	/**
	 * Takes the snapshot of this site only (see take_snapshot()). On multisite only for a lock taken before 3.3
	 * (the upgrade to 3.3): a lock taken since then takes the snapshot of the whole network.
	 */
	public static function take_site_snapshot() {
		$admins = self::admin_ids();
		self::store_snapshot( self::site_values(), $admins, null, self::staff_apps(), true, is_multisite() ? null : self::passwords_of( $admins ) );
	}

	/**
	 * 3.4, single site: keyed fingerprints of the stored password hashes of some accounts (user => fingerprint).
	 * A password hash needs no secret, so someone who can change the database could set one for an
	 * administrator and sign in with it; while locked, an account whose hash no longer matches the snapshot
	 * cannot sign in (authenticate()).
	 *
	 * @param int[] $ids Users.
	 * @return array<int, string>
	 */
	private static function passwords_of( $ids ) {
		global $wpdb;
		$ids = array_values( array_filter( array_map( 'intval', $ids ) ) );
		$out = array();
		if ( ! $ids ) {
			return $out;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- One query for all of them, as stored now; the placeholders are built from the count.
		$rows = (array) $wpdb->get_results( $wpdb->prepare( 'SELECT ID, user_pass FROM %i WHERE ID IN (' . implode( ',', array_fill( 0, count( $ids ), '%d' ) ) . ')', $wpdb->users, ...$ids ) );
		foreach ( $rows as $row ) {
			if ( '' !== (string) $row->user_pass ) {
				$out[ (int) $row->ID ] = self::pass_print( (string) $row->user_pass );
			}
		}
		ksort( $out );
		return $out;
	}

	/**
	 * The password hash of an account as it is in the database now (never a cached copy).
	 *
	 * @param int $id User.
	 * @return string
	 */
	private static function stored_pass( $id ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Compared with the snapshot: the value as stored now, not a cached one.
		return (string) $wpdb->get_var( $wpdb->prepare( 'SELECT user_pass FROM %i WHERE ID = %d', $wpdb->users, (int) $id ) );
	}

	/**
	 * The keyed fingerprint of a password hash (never the hash itself in the snapshot).
	 *
	 * @param string $hash Password hash.
	 * @return string
	 */
	private static function pass_print( $hash ) {
		return substr( hash_hmac( 'sha256', 'pass|' . $hash, self::key() ), 0, 32 );
	}

	/**
	 * 3.4, single site: WordPress itself changed the password of an account the snapshot has a fingerprint for
	 * (during an unlock for a while, or when it stores the hash again in a newer format as the owner signs in).
	 * The snapshot gets the new fingerprint, but only if the hash before the change was the one in the snapshot:
	 * a hash written in the database first is never taken over this way.
	 *
	 * @param int    $user_id  User.
	 * @param string $old_hash The hash before the change.
	 */
	public static function password_changed( $user_id, $old_hash ) {
		if ( is_multisite() ) {
			return;
		}
		$snap = self::snapshot();
		$id   = (int) $user_id;
		if ( null === $snap || ! isset( $snap['pass'] ) || ! is_array( $snap['pass'] ) || ! isset( $snap['pass'][ $id ] ) ) {
			return;
		}
		$now = self::stored_pass( $id );
		if ( '' === $now || ! hash_equals( (string) $snap['pass'][ $id ], self::pass_print( (string) $old_hash ) ) || hash_equals( (string) $snap['pass'][ $id ], self::pass_print( $now ) ) ) {
			return;
		}
		$snap['pass'][ $id ] = self::pass_print( $now );
		self::store_snapshot( $snap['values'], $snap['admins'], isset( $snap['since'] ) ? (int) $snap['since'] : null, isset( $snap['apps'] ) ? $snap['apps'] : null, true, $snap['pass'] );
	}

	/**
	 * Does the stored password hash of an account still match the snapshot? True when the snapshot has no
	 * fingerprint for it (an account added later, or a snapshot from before this check).
	 *
	 * @param array<string, mixed> $snap Snapshot.
	 * @param int                  $id   User.
	 * @return bool
	 */
	private static function password_ok( $snap, $id ) {
		if ( ! isset( $snap['pass'] ) || ! is_array( $snap['pass'] ) || ! isset( $snap['pass'][ $id ] ) ) {
			return true;
		}
		return hash_equals( (string) $snap['pass'][ $id ], self::pass_print( self::stored_pass( $id ) ) );
	}

	/**
	 * The protected options of the current site, as stored.
	 *
	 * @return array<string, mixed>
	 */
	private static function site_values() {
		$values = array();
		foreach ( PNCP_Lockdown::sealed_options() as $option ) {
			$values[ $option ] = self::stored_option( $option );
		}
		return $values;
	}

	/**
	 * The application passwords of the staff accounts (see PNCP_Lockdown::is_staff()): user => UUIDs, sorted.
	 * Every staff account is listed, also without application passwords, so a password added later to any of
	 * them is noticed.
	 *
	 * @return array<int, string[]>
	 */
	public static function staff_apps() {
		$apps = array();
		foreach ( self::staff_ids() as $id ) {
			$apps[ $id ] = self::user_apps( $id );
		}
		return $apps;
	}

	/**
	 * The UUIDs of a user's application passwords, sorted.
	 *
	 * @param int $id User.
	 * @return string[]
	 */
	private static function user_apps( $id ) {
		$uuids = array();
		foreach ( WP_Application_Passwords::get_user_application_passwords( (int) $id ) as $item ) {
			if ( isset( $item['uuid'] ) ) {
				$uuids[] = (string) $item['uuid'];
			}
		}
		sort( $uuids );
		return $uuids;
	}

	/**
	 * The staff accounts of the current site (frozen roles and the roles that keep their work while locked),
	 * and everyone with application passwords who is staff here, sorted.
	 *
	 * @return int[]
	 */
	private static function staff_ids() {
		wp_roles();
		$ids    = array();
		$frozen = array_merge( PNCP_Lockdown::frozen_roles(), PNCP_Lockdown::limited_roles() );
		if ( $frozen ) {
			$ids = get_users(
				array(
					'role__in' => $frozen,
					'fields'   => 'ID',
					'number'   => 2000,
				)
			);
		}
		// Also everyone who has application passwords: staff through a capability of their own, network admins.
		$with = get_users(
			array(
				'blog_id'      => 0,
				'meta_key'     => WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Only on lock and in the hourly check.
				'meta_compare' => 'EXISTS',
				'fields'       => 'ID',
				'number'       => 2000,
			)
		);
		$out  = array();
		foreach ( array_unique( array_map( 'intval', array_merge( (array) $ids, (array) $with ) ) ) as $id ) {
			if ( PNCP_Lockdown::is_staff( $id ) ) {
				$out[] = $id;
			}
		}
		sort( $out );
		return $out;
	}

	/**
	 * Was this application password of a staff account added after the site was locked? Staff cannot add one
	 * while locked (or unlocked for a while), so it was added in the database. False without a snapshot that
	 * lists the application passwords (not locked, or a snapshot from before 3.4).
	 *
	 * @param int    $user_id User.
	 * @param string $uuid    The application password.
	 * @return bool
	 */
	public static function app_password_new( $user_id, $uuid ) {
		$snap = self::current_snapshot();
		if ( null === $snap || ! isset( $snap['apps'] ) || ! is_array( $snap['apps'] ) || ! PNCP_Lockdown::is_staff( (int) $user_id ) ) {
			return false;
		}
		$known = isset( $snap['apps'][ (int) $user_id ] ) ? (array) $snap['apps'][ (int) $user_id ] : array();
		return ! in_array( (string) $uuid, $known, true );
	}

	/**
	 * Removes the application passwords that were added to staff accounts after the snapshot was taken, and
	 * reports them. Run hourly while locked, and before the snapshot is replaced or removed (locked again after
	 * a while, unlocked for good, app removed), because from then on they would count as genuine.
	 *
	 * @param bool $known_only Only the accounts the snapshot lists: after a temporary unlock, an account may have
	 *                         become staff in the meantime (with application passwords made before).
	 * @param bool $alert      Report them (false: the caller reports, see check_apps_all()).
	 * @return string[] The accounts concerned.
	 */
	public static function check_apps( $known_only = false, $alert = true ) {
		$snap = self::current_snapshot();
		if ( null === $snap || ! isset( $snap['apps'] ) || ! is_array( $snap['apps'] ) ) {
			return array();
		}
		$found = array();
		foreach ( self::staff_apps() as $id => $uuids ) {
			if ( $known_only && ! isset( $snap['apps'][ $id ] ) ) {
				continue;
			}
			$known = isset( $snap['apps'][ $id ] ) ? (array) $snap['apps'][ $id ] : array();
			$new   = array_diff( $uuids, $known );
			if ( ! $new ) {
				continue;
			}
			foreach ( $new as $uuid ) {
				WP_Application_Passwords::delete_application_password( $id, $uuid );
			}
			$user    = get_userdata( $id );
			$found[] = ( $user ? $user->user_login . ' (#' . $id . ')' : '#' . $id ) . ': ' . count( $new );
		}
		if ( $found && $alert ) {
			PNCP_Lockdown::tamper_alert( 'apps', implode( ', ', array_slice( $found, 0, 10 ) ) );
		}
		return $found;
	}

	/**
	 * Updates one value in the snapshot (and its fingerprint), keeping everything else as it was signed: for a
	 * change ScrapeLock itself makes while locked (the quarantine deactivating a plugin). Nothing is signed when
	 * there is no genuine snapshot to update.
	 *
	 * @param string $option Option.
	 * @return bool Whether the snapshot was updated.
	 */
	public static function update_snapshot( $option ) {
		if ( is_multisite() && self::network_mode() ) {
			self::ensure_site_snapshot();
		}
		$snap = self::snapshot();
		if ( null === $snap || ! array_key_exists( (string) $option, $snap['values'] ) ) {
			return false;
		}
		$snap['values'][ (string) $option ] = self::stored_option( (string) $option );
		self::store_snapshot( $snap['values'], $snap['admins'], isset( $snap['since'] ) ? (int) $snap['since'] : null, isset( $snap['apps'] ) ? $snap['apps'] : null, true, isset( $snap['pass'] ) ? $snap['pass'] : null );
		return true;
	}

	/**
	 * Signs and stores the snapshot and the fingerprints of its values.
	 *
	 * @param array<string, mixed>      $values Option => value.
	 * @param int[]                     $admins The accounts that could administer the site.
	 * @param int|null                  $since  The lock time it belongs to (null: the lock time in the state now).
	 * @param array<int, string[]>|null $apps   The application passwords of the staff accounts (null: not kept,
	 *                                          a snapshot from before 3.4).
	 * @param bool                      $note   Note its generation in the state now (false: the caller saves the
	 *                                          state itself, in the same write as its other changes).
	 * @param array<int, string>|null   $pass   Single site, 3.4: the fingerprints of the password hashes of the
	 *                                          administrators (null: not kept).
	 * @return int The generation of the snapshot.
	 */
	private static function store_snapshot( $values, $admins, $since = null, $apps = null, $note = true, $pass = null ) {
		$since = null === $since ? (int) PNCP_Lockdown::state()['since'] : (int) $since;
		// 3.4: a generation higher than any before it. The state (and the guard) note it, so a snapshot or set of
		// fingerprints put back from an older copy of the database is no longer accepted.
		$gen = PNCP_Lockdown::next_generation();
		self::write_site_snapshot( $values, $admins, $since, $gen, $apps, false, $pass );
		if ( is_multisite() && self::network_mode() ) {
			// Multisite: the snapshot of the network names the generation of each site's snapshot. Only this site's
			// entry changes; the other sites keep theirs (and their own, older generation).
			$net = self::net_snapshot();
			if ( null !== $net ) {
				$id                  = get_current_blog_id();
				$old                 = isset( $net['sites'][ $id ] ) && is_array( $net['sites'][ $id ] ) ? $net['sites'][ $id ] : array();
				$net['sites'][ $id ] = self::site_entry( $values, $admins, $gen, true, isset( $old['guard'] ) );
				$net['gen']          = $gen;
				self::store_network( $net );
			}
		}
		// Snapshot first, then the state and the guard: a request in between sees a snapshot newer than the one
		// the state names, which is accepted (only older ones are not).
		if ( $note ) {
			PNCP_Lockdown::note_snapshot( $gen );
		}
		return $gen;
	}

	/**
	 * Signs and stores the snapshot of the current site and the fingerprints of its values, with a generation
	 * given by the caller.
	 *
	 * @param array<string, mixed>      $values Option => value.
	 * @param int[]                     $admins The accounts that could administer the site.
	 * @param int                       $since  The lock time it belongs to.
	 * @param int                       $gen    The generation.
	 * @param array<int, string[]>|null $apps   The application passwords of the staff accounts (null: not kept).
	 * @param bool                      $lazy   Multisite: only the fingerprints (marked "lazy"); the snapshot itself
	 *                                          is taken on the first request to the site (ensure_site_snapshot()).
	 * @param array<int, string>|null   $pass   The fingerprints of the administrators' password hashes (null: not
	 *                                          kept).
	 */
	private static function write_site_snapshot( $values, $admins, $since, $gen, $apps = null, $lazy = false, $pass = null ) {
		if ( $lazy ) {
			self::save_digests( $values, $since, $gen, true );
			return;
		}
		$snap = array(
			'time'   => time(),
			'values' => $values,
			'admins' => array_values( array_map( 'intval', $admins ) ),
			// 3.4: the lock it belongs to. A lock state put back from before this lock no longer matches it.
			'since'  => $since,
			'gen'    => $gen,
		);
		if ( is_array( $apps ) ) {
			// 3.4: the application passwords of the staff accounts (check_apps()).
			$snap['apps'] = $apps;
		}
		if ( is_array( $pass ) ) {
			// 3.4: the administrators' password hashes, as keyed fingerprints (see passwords_of()).
			$snap['pass'] = $pass;
		}
		$snap['sig'] = self::sign( $snap );
		update_option( self::SNAP, $snap, false );
		wp_cache_delete( self::SNAP, 'options' );
		self::save_digests( $values, $since, $gen );
	}

	/**
	 * The upgrade to 3.4: gives the genuine snapshot of the current lock a generation (the same values,
	 * administrators and application passwords as signed when the site was locked, never the options as they
	 * are now). Nothing happens without a genuine snapshot.
	 */
	public static function upgrade_snapshot() {
		$snap = self::snapshot();
		if ( null === $snap || isset( $snap['gen'] ) ) {
			return;
		}
		self::store_snapshot( $snap['values'], $snap['admins'], isset( $snap['since'] ) ? (int) $snap['since'] : null, isset( $snap['apps'] ) ? $snap['apps'] : null, true, isset( $snap['pass'] ) ? $snap['pass'] : null );
	}

	/**
	 * Stores the signed fingerprints of the protected options (autoloaded).
	 *
	 * @param array<string, mixed> $values Option => value.
	 * @param int                  $since  The lock time they belong to.
	 * @param int                  $gen    The generation of the snapshot they belong to (0: a snapshot from
	 *                                     before 3.4).
	 * @param bool                 $lazy   Multisite: the snapshot itself is not taken yet (see
	 *                                     write_site_snapshot()).
	 */
	private static function save_digests( $values, $since, $gen = 0, $lazy = false ) {
		$record = array(
			'digests' => self::digests_of( $values ),
			'since'   => (int) $since,
		);
		if ( $gen ) {
			$record['gen'] = (int) $gen;
		}
		if ( $lazy ) {
			$record['lazy'] = true;
		}
		$record['sig'] = self::sign( $record );
		update_option( self::DIGESTS, $record, true );
	}

	/**
	 * The signed fingerprints of the current snapshot, or null (missing, not matching their signature, or from
	 * an older snapshot than the one the state and the guard name).
	 *
	 * @return array<string, string>|null
	 */
	private static function digests() {
		$record = self::digests_record();
		$want   = self::wanted_site_snap();
		if ( -1 === $want ) {
			return null;
		}
		if ( null !== $record && ! self::generation_ok( $record, $want ) ) {
			// The fingerprints are autoloaded: read at the start of this request, perhaps a moment before another
			// request stored newer ones with a new snapshot (for example when an unlock for a while has just
			// ended), while the state was read later. Read once more from the database before calling it old.
			wp_cache_delete( 'alloptions', 'options' );
			wp_cache_delete( self::DIGESTS, 'options' );
			$record = self::digests_record();
		}
		return null !== $record && self::generation_ok( $record, $want ) ? $record['digests'] : null;
	}

	/**
	 * The generation of the snapshot that counts now: the one the guard names (a file, so it cannot be set back
	 * in the database), or the one the genuine state names. 0: no generations yet (data from before 3.4).
	 *
	 * @return int
	 */
	public static function wanted_snap() {
		$want   = '' === PNCP_Lockdown::tampered() ? (int) PNCP_Lockdown::state()['snap'] : 0;
		$beacon = self::beacon();
		if ( $beacon && isset( $beacon['snap'] ) ) {
			$want = max( $want, (int) $beacon['snap'] );
		}
		// 3.4.2: the snapshots of the lock the line in wp-config.php names are taken after it was locked, so they
		// have a higher generation: an older one (of an earlier lock, put back from a copy) does not count.
		$config = self::config_lock();
		if ( null !== $config ) {
			$want = max( $want, (int) $config['gen'] );
		}
		return $want;
	}

	/**
	 * The generation of this site's snapshot that counts now. On a single site the one of the lock
	 * (wanted_snap()). On a multisite network locked with 3.4 or later the one the signed snapshot of the network
	 * names for this site: each site's snapshot changes on its own (the quarantine, an unlock for a while), so
	 * the generation of the lock is often newer than a site's own. -1: the network's snapshot does not list this
	 * site (added after the lock, or ScrapeLock was not active on it): there is nothing to compare with.
	 * 0 when the network's fingerprints cannot be read (missing or changed, reported by verify_network()): any
	 * genuine snapshot of this lock is accepted then.
	 *
	 * @return int
	 */
	private static function wanted_site_snap() {
		if ( ! is_multisite() || ! self::network_mode() ) {
			return self::wanted_snap();
		}
		$net = self::net_digests();
		if ( null === $net ) {
			return 0;
		}
		$id = get_current_blog_id();
		return isset( $net['sites'][ $id ] ) ? max( 1, (int) $net['sites'][ $id ] ) : -1;
	}

	/**
	 * Is a signed snapshot (or set of fingerprints) the current one? It must be at least as new as the generation
	 * that counts now: an older one was put back from a copy of the database. A newer one is fine (the snapshot
	 * is stored a moment before the state notes it).
	 *
	 * @param array<string, mixed> $record Snapshot or fingerprints (signature already checked).
	 * @param int                  $want   The generation that counts now (0: none, everything from before 3.4).
	 * @return bool
	 */
	private static function generation_ok( $record, $want ) {
		if ( (int) $want <= 0 ) {
			return true;
		}
		return isset( $record['gen'] ) && (int) $record['gen'] >= (int) $want;
	}

	/**
	 * The record of the signed fingerprints (without its signature), or null.
	 *
	 * @param bool $loaded_only Only if WordPress already loaded it with the autoloaded options: a site that never
	 *                          locked costs no extra query on every request.
	 * @return array{digests:array<string, string>, since?:int, gen?:int}|null
	 */
	private static function digests_record( $loaded_only = false ) {
		if ( $loaded_only ) {
			$all = wp_load_alloptions();
			if ( ! isset( $all[ self::DIGESTS ] ) ) {
				return null;
			}
		}
		$record = self::fresh_option( self::DIGESTS ); // 3.4.3: the row, not a cached copy (see fresh_option()).
		if ( ! is_array( $record ) || ! isset( $record['digests'], $record['sig'] ) || ! is_array( $record['digests'] ) ) {
			return null;
		}
		$sig = $record['sig'];
		unset( $record['sig'] );
		return self::valid( $record, $sig ) ? $record : null;
	}

	/**
	 * The snapshot of the current lock, if its signature matches and it is not older than the generation that
	 * counts now: [time, values, admins], or null.
	 *
	 * @return array{time:int, values:array<string, mixed>, admins:int[]}|null
	 */
	public static function snapshot() {
		self::$from_copy = false;
		$snap            = self::snapshot_record();
		if ( null === $snap && ( is_multisite() || null === self::guard_copy() ) ) {
			return null;
		}
		$want = self::wanted_site_snap();
		if ( -1 === $want ) {
			return null;
		}
		if ( ! is_multisite() && ( null === $snap || ! self::generation_ok( $snap, $want ) ) ) {
			// 3.4: the snapshot in the database is missing, changed or older than this lock: the signed copy in the
			// guard file counts instead (verify_options() puts it back in the database).
			$copy = self::guard_copy();
			if ( null !== $copy && self::generation_ok( $copy, $want ) ) {
				self::$from_copy = true;
				return $copy;
			}
		}
		if ( null === $snap ) {
			return null;
		}
		if ( is_multisite() && self::network_mode() && ( ! isset( $snap['since'] ) || self::lock_since() !== (int) $snap['since'] ) ) {
			return null; // From another lock (each site's snapshot is checked against the lock of the network).
		}
		return self::generation_ok( $snap, $want ) ? $snap : null;
	}

	/**
	 * The snapshot if its signature matches, whatever its generation (also an older one put back from a copy of
	 * the database): only as evidence that the site was locked, and to tell an older copy from a changed one.
	 *
	 * @return array{time:int, values:array<string, mixed>, admins:int[]}|null
	 */
	private static function snapshot_record() {
		$snap = self::fresh_option( self::SNAP ); // 3.4.3: the row, not a cached copy.
		if ( ! is_array( $snap ) || ! isset( $snap['sig'], $snap['values'], $snap['admins'], $snap['time'] ) ) {
			return null;
		}
		$sig = $snap['sig'];
		unset( $snap['sig'] );
		return self::valid( $snap, $sig ) && is_array( $snap['values'] ) && is_array( $snap['admins'] ) ? $snap : null;
	}

	/* ---------- Multisite: the snapshot of the whole network ---------- */

	/**
	 * Was this network locked with a snapshot of the whole network (3.4 or later)? The (signed) state says so;
	 * genuine fingerprints of the network count too, so a state that cannot be trusted does not switch it off. A
	 * network locked with an earlier version has a snapshot of one site only (the one where it was locked).
	 *
	 * @return bool
	 */
	public static function network_mode() {
		if ( ! is_multisite() ) {
			return false;
		}
		return ! empty( PNCP_Lockdown::state()['net'] ) || null !== self::net_record( self::NET_DIGESTS );
	}

	/**
	 * A signed network record (NET_SNAP or NET_DIGESTS) without its signature, whatever its generation, or null
	 * (missing, or not matching its signature). The fingerprints are read once per request.
	 *
	 * @param string $name NET_SNAP or NET_DIGESTS.
	 * @return array<string, mixed>|null
	 */
	private static function net_record( $name ) {
		if ( self::NET_DIGESTS === $name && null !== self::$net_digests ) {
			return false === self::$net_digests ? null : self::$net_digests;
		}
		$stored = self::fresh_option( $name, true ); // 3.4.3: the row, not a cached copy.
		$record = null;
		if ( is_array( $stored ) && isset( $stored['sig'], $stored['sites'], $stored['since'], $stored['gen'] ) && is_array( $stored['sites'] ) ) {
			$sig = $stored['sig'];
			unset( $stored['sig'] );
			$keys = self::NET_SNAP === $name ? array( 'values', 'super', 'apps' ) : array( 'digests' );
			$ok   = self::valid( $stored, $sig );
			foreach ( $keys as $key ) {
				$ok = $ok && isset( $stored[ $key ] ) && is_array( $stored[ $key ] );
			}
			$record = $ok ? $stored : null;
		}
		if ( self::NET_DIGESTS === $name ) {
			self::$net_digests = null === $record ? false : $record;
		}
		return $record;
	}

	/**
	 * Forgets the network's fingerprints read on this request (the next read comes from the database).
	 */
	private static function forget_net_cache() {
		self::$net_digests = null;
		wp_cache_delete( get_current_network_id() . ':' . self::NET_DIGESTS, 'site-options' );
		wp_cache_delete( get_current_network_id() . ':' . self::NET_SNAP, 'site-options' );
		wp_cache_delete( get_current_network_id() . ':notoptions', 'site-options' );
	}

	/**
	 * The signed fingerprints of the network for the current lock, or null (missing, changed, or older than the
	 * generation that counts now). Like the fingerprints of a site, read once more from the database before an
	 * older one is called old: another request may have stored newer ones a moment ago.
	 *
	 * @return array{digests:array<string, string>, sites:array<int, int>, since:int, gen:int}|null
	 */
	private static function net_digests() {
		static $reread = false;

		$record = self::net_record( self::NET_DIGESTS );
		$want   = self::wanted_snap();
		if ( ( null === $record || ! self::generation_ok( $record, $want ) ) && ! $reread ) {
			$reread = true;
			self::forget_net_cache();
			$record = self::net_record( self::NET_DIGESTS );
		}
		return null !== $record && self::generation_ok( $record, $want ) ? $record : null;
	}

	/**
	 * The snapshot of the network for the current lock, if its signature matches and it is not older than the
	 * generation that counts now, or null.
	 *
	 * @return array<string, mixed>|null
	 */
	public static function net_snapshot() {
		$net = self::net_record( self::NET_SNAP );
		return null !== $net && self::generation_ok( $net, self::wanted_snap() ) ? $net : null;
	}

	/**
	 * The lock time the snapshots belong to: from the network's signed fingerprints when they can be read (the
	 * state itself may have been changed), otherwise from the state.
	 *
	 * @return int
	 */
	private static function lock_since() {
		$net = is_multisite() ? self::net_digests() : null;
		return null !== $net ? (int) $net['since'] : (int) PNCP_Lockdown::state()['since'];
	}

	/**
	 * Signs and stores the snapshot of the network and its fingerprints (the generation of every site's
	 * snapshot with them).
	 *
	 * @param array<string, mixed> $net The snapshot of the network.
	 */
	private static function store_network( $net ) {
		unset( $net['sig'] );
		ksort( $net['sites'] );
		$stored        = $net;
		$stored['sig'] = self::sign( $net );
		update_site_option( self::NET_SNAP, $stored );
		$sites = array();
		foreach ( $net['sites'] as $id => $entry ) {
			$sites[ (int) $id ] = (int) $entry['gen'];
		}
		$digests        = array(
			'digests' => self::digests_of( $net['values'] ),
			'sites'   => $sites,
			'since'   => (int) $net['since'],
			'gen'     => (int) $net['gen'],
		);
		$digests['sig'] = self::sign( $digests );
		update_site_option( self::NET_DIGESTS, $digests );
		self::forget_net_cache();
	}

	/**
	 * What the snapshot of the network keeps of one site: the generation of its own snapshot, the fingerprints
	 * of its protected options, its administrators, whether its snapshot was taken at once ("taken"; otherwise
	 * on its first request) and, for the first sites, the active plugins and the theme the guard keeps.
	 *
	 * @param array<string, mixed> $values Option => value.
	 * @param int[]                $admins The accounts that could administer the site.
	 * @param int                  $gen    The generation of its snapshot.
	 * @param bool                 $taken  The snapshot itself was stored.
	 * @param bool                 $guard  Also the values the guard keeps.
	 * @return array<string, mixed>
	 */
	private static function site_entry( $values, $admins, $gen, $taken, $guard ) {
		$admins = array_values( array_unique( array_map( 'intval', $admins ) ) );
		sort( $admins );
		$entry = array(
			'gen'     => (int) $gen,
			'digests' => self::digests_of( $values ),
			'admins'  => $admins,
			'taken'   => (bool) $taken,
		);
		if ( $guard ) {
			$entry['guard'] = self::guard_subset( $values );
		}
		return $entry;
	}

	/**
	 * Multisite: how many sites the lock of a network covers ('sites', filter pncp_lockdown_network_sites,
	 * 1000), how many of them get their full snapshot at once when the network is locked ('now', filter
	 * pncp_lockdown_network_snapshots, 50; the others on their first request), and for how many the guard keeps
	 * the active plugins and the theme ('guard', filter pncp_lockdown_guard_sites, 100: the guard file is read on
	 * every request).
	 *
	 * @return array{sites:int, now:int, guard:int}
	 */
	public static function network_limits() {
		return array(
			'sites' => max( 1, (int) apply_filters( 'pncp_lockdown_network_sites', 1000 ) ),
			'now'   => max( 1, (int) apply_filters( 'pncp_lockdown_network_snapshots', 50 ) ),
			'guard' => max( 0, (int) apply_filters( 'pncp_lockdown_guard_sites', 100 ) ),
		);
	}

	/**
	 * Multisite: how many sites the snapshot of the network covers, and how many sites the network had when it
	 * was locked (for the Lockdown tab). Null without a genuine snapshot of the network.
	 *
	 * @return array{covered:int, total:int}|null
	 */
	public static function network_coverage() {
		$net = is_multisite() ? self::net_snapshot() : null;
		if ( null === $net ) {
			return null;
		}
		return array(
			'covered' => count( $net['sites'] ),
			'total'   => isset( $net['total'] ) ? (int) $net['total'] : count( $net['sites'] ),
		);
	}

	/**
	 * The sites the lock of a network covers: up to 1000 (filter pncp_lockdown_network_sites), the current site
	 * first.
	 *
	 * @return int[]
	 */
	public static function network_site_ids() {
		$limit   = self::network_limits()['sites'];
		$ids     = array_map(
			'intval',
			(array) get_sites(
				array(
					'fields'                 => 'ids',
					'number'                 => $limit,
					'network_id'             => get_current_network_id(),
					'orderby'                => 'id',
					'order'                  => 'ASC',
					'update_site_meta_cache' => false,
				)
			)
		);
		$current = get_current_blog_id();
		$ids     = array_values( array_diff( $ids, array( $current ) ) );
		array_unshift( $ids, $current );
		return array_slice( $ids, 0, max( $limit, 1 ) );
	}

	/**
	 * The IDs of the super admins (from a list of logins, or the ones WordPress knows now).
	 *
	 * @param mixed $logins Logins (null: get_super_admins()).
	 * @return int[]
	 */
	private static function super_ids( $logins = null ) {
		$ids = array();
		foreach ( (array) ( null === $logins ? get_super_admins() : $logins ) as $login ) {
			$user = is_string( $login ) ? get_user_by( 'login', $login ) : false;
			if ( $user ) {
				$ids[] = (int) $user->ID;
			}
		}
		$ids = array_values( array_unique( $ids ) );
		sort( $ids );
		return $ids;
	}

	/**
	 * Everyone with application passwords on the network: user => UUIDs (for the snapshot of a site taken on
	 * its first request after the lock).
	 *
	 * @return array<int, string[]>
	 */
	private static function network_apps() {
		$with = get_users(
			array(
				'blog_id'      => 0,
				'meta_key'     => WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Only when the network is locked.
				'meta_compare' => 'EXISTS',
				'fields'       => 'ID',
				'number'       => 2000,
			)
		);
		$apps = array();
		foreach ( array_map( 'intval', (array) $with ) as $id ) {
			$apps[ $id ] = self::user_apps( $id );
		}
		ksort( $apps );
		return $apps;
	}

	/**
	 * Multisite: takes the snapshot of the whole network when it is locked (only ever right after the owner
	 * locked it with the app code, like take_snapshot()).
	 *
	 * The network options, the super admins and the application passwords go in the snapshot of the network.
	 * Every site where ScrapeLock is active (up to network_site_ids()) gets the signed fingerprints of its
	 * protected options and its administrators, noted in the snapshot of the network too. The first 50 sites
	 * (filter pncp_lockdown_network_snapshots) get their full snapshot at once; the others on their first request
	 * (ensure_site_snapshot()), from the values that still match the fingerprints taken now, so a large network
	 * does not wait for every copy. The guard keeps the active plugins and the theme of the first 100 sites
	 * (filter pncp_lockdown_guard_sites).
	 */
	private static function take_network_snapshot() {
		$since  = (int) PNCP_Lockdown::state()['since'];
		$gen    = PNCP_Lockdown::next_generation();
		$own    = plugin_basename( PNCP_FILE );
		$values = array();
		foreach ( self::NETWORK_OPTIONS as $option ) {
			$values[ $option ] = self::stored_site_option( $option );
		}
		$network_active = is_array( $values['active_sitewide_plugins'] ) && isset( $values['active_sitewide_plugins'][ $own ] );
		$limits         = self::network_limits();
		$now            = $limits['now'];
		$guard          = $limits['guard'];
		$sites          = array();
		$taken          = 0;
		foreach ( self::network_site_ids() as $id ) {
			switch_to_blog( $id );
			try {
				$site = self::site_values();
				if ( ! $network_active && ! ( is_array( $site['active_plugins'] ) && in_array( $own, $site['active_plugins'], true ) ) ) {
					// ScrapeLock does not run on this site, so nothing there would check a snapshot. One left from an
					// earlier lock goes.
					delete_option( self::SNAP );
					delete_option( self::DIGESTS );
					continue;
				}
				$admins = self::admin_ids();
				$eager  = $taken < $now;
				if ( $eager ) {
					self::write_site_snapshot( $site, $admins, $since, $gen, self::staff_apps() );
					++$taken;
				} else {
					delete_option( self::SNAP ); // One left from an earlier lock.
					self::write_site_snapshot( $site, $admins, $since, $gen, null, true );
				}
				$sites[ $id ] = self::site_entry( $site, $admins, $gen, $eager, count( $sites ) < $guard );
			} finally {
				restore_current_blog();
			}
		}
		self::store_network(
			array(
				'time'   => time(),
				'since'  => $since,
				'gen'    => $gen,
				'values' => $values,
				'super'  => self::super_ids(),
				'apps'   => self::network_apps(),
				'sites'  => $sites,
				'total'  => (int) get_sites(
					array(
						'count'      => true,
						'orderby'    => 'none',
						'network_id' => get_current_network_id(),
					)
				),
			)
		);
		PNCP_Lockdown::note_snapshot( $gen, true );
	}

	/**
	 * Multisite: a site whose snapshot was not taken at once (or whose snapshot is missing, changed or older than
	 * the snapshot of the network names) gets it now, from the values that still match the fingerprints the
	 * snapshot of the network took when the network was locked. Those are exactly the values of the lock, so
	 * nothing changed behind WordPress's back is ever taken as genuine. A value that no longer matches cannot be
	 * known any more: the active plugins and the theme come from the snapshot of the network when it holds them
	 * (and are put back), anything else is reported.
	 */
	private static function ensure_site_snapshot() {
		if ( null !== self::snapshot() ) {
			return;
		}
		$net = self::net_snapshot();
		$id  = get_current_blog_id();
		if ( null === $net || ! isset( $net['sites'][ $id ] ) || ! is_array( $net['sites'][ $id ] ) ) {
			return;
		}
		$entry  = $net['sites'][ $id ];
		$old    = self::snapshot_record();
		$stored = false !== get_option( self::SNAP, false );
		$values = array();
		$lost   = array();
		foreach ( isset( $entry['digests'] ) ? (array) $entry['digests'] : array() as $option => $digest ) {
			$option = (string) $option;
			$now    = self::stored_option( $option );
			if ( self::digest( $now ) === $digest ) {
				$values[ $option ] = $now;
			} elseif ( isset( $entry['guard'] ) && is_array( $entry['guard'] ) && array_key_exists( $option, $entry['guard'] ) ) {
				$values[ $option ] = $entry['guard'][ $option ]; // As the guard keeps it; put back by restore().
			} else {
				$lost[] = $option;
			}
		}
		$apps = array();
		foreach ( self::staff_ids() as $user ) {
			$apps[ $user ] = isset( $net['apps'][ $user ] ) ? array_values( array_map( 'strval', (array) $net['apps'][ $user ] ) ) : array();
		}
		self::write_site_snapshot( $values, isset( $entry['admins'] ) ? (array) $entry['admins'] : array(), (int) $net['since'], (int) $entry['gen'], $apps );
		// A snapshot taken at once that is gone, changed, or older than the one the network names was changed in
		// the database. A snapshot of an earlier lock, left on a site whose snapshot is taken now, was not.
		$tampered = ! empty( $entry['taken'] ) || ( $stored && ( null === $old || ( isset( $old['since'] ) && (int) $old['since'] === (int) $net['since'] ) ) );
		if ( $tampered || $lost ) {
			$detail = self::site_label( $id ) . ( $lost ? ': ' . implode( ', ', $lost ) : '' );
			PNCP_Lockdown::tamper_alert( null !== $old && ! $lost ? 'replay' : 'snapshot', $detail );
		}
	}

	/**
	 * Multisite: puts back the network options that changed behind WordPress's back, compared with the signed
	 * snapshot of the network (the fingerprints first, on every request). Returns the network's fingerprints
	 * for the per-site checks, or null when they cannot be read (reported).
	 *
	 * @return array{digests:array<string, string>, sites:array<int, int>, since:int, gen:int}|null
	 */
	private static function verify_network() {
		$record  = self::net_digests();
		$pending = PNCP_Lockdown::reseal_pending();
		if ( null !== $record && ! $pending ) {
			$same = true;
			foreach ( $record['digests'] as $option => $digest ) {
				if ( self::digest( self::stored_site_option( (string) $option ) ) !== $digest ) {
					$same = false;
					break;
				}
			}
			if ( $same ) {
				return $record;
			}
		}
		$net = self::current_network_snapshot();
		if ( null === $net ) {
			if ( self::snapshot_pending( self::net_record( self::NET_SNAP ) ) ) {
				return $record; // Just locked: the snapshot of the network is being taken (see snapshot_pending()).
			}
			PNCP_Lockdown::tamper_alert( null !== self::net_record( self::NET_SNAP ) ? 'replay' : 'snapshot', 'network' );
			return $record;
		}
		$restored = array();
		foreach ( $net['values'] as $option => $value ) {
			if ( self::digest( self::stored_site_option( (string) $option ) ) !== self::digest( $value ) ) {
				PNCP_Lockdown::write_protected_site( (string) $option, $value );
				$restored[] = (string) $option;
			}
		}
		if ( $restored ) {
			PNCP_Lockdown::tamper_alert( 'options', 'network: ' . implode( ', ', $restored ) );
		}
		if ( null === $record ) {
			if ( null !== self::net_record( self::NET_DIGESTS ) ) {
				PNCP_Lockdown::tamper_alert( 'replay', 'network' );
			}
			// The fingerprints again, from the signed snapshot of the network (never from the values as they are).
			$genuine = self::net_snapshot();
			if ( null !== $genuine ) {
				self::store_network( $genuine );
			}
			$record = self::net_digests();
		}
		return $record;
	}

	/**
	 * Multisite: the snapshot of the network that counts now: with the changes the owner made to the network
	 * options during an unlock for a while that has just ended (see current_snapshot()).
	 *
	 * @return array<string, mixed>|null
	 */
	public static function current_network_snapshot() {
		$net = self::net_snapshot();
		if ( null === $net || ! PNCP_Lockdown::reseal_pending() ) {
			return $net;
		}
		$record = self::window_record( false, true );
		if ( null === $record ) {
			return $net;
		}
		foreach ( $record['values'] as $option => $value ) {
			if ( array_key_exists( (string) $option, $net['values'] ) ) {
				$net['values'][ (string) $option ] = $value;
			}
		}
		if ( array_key_exists( 'site_admins', $record['values'] ) ) {
			// The super admins the owner added (or removed) meanwhile, by their login, as WordPress keeps them.
			$net['super'] = self::super_ids( (array) $net['values']['site_admins'] );
		}
		return $net;
	}

	/**
	 * Multisite: one network option changed by ScrapeLock itself while locked (the quarantine deactivating a
	 * plugin active on the whole network): only that value changes in the snapshot of the network.
	 *
	 * @param string $option Network option.
	 * @return bool Whether the snapshot of the network was updated.
	 */
	public static function update_network_value( $option ) {
		if ( ! is_multisite() || ! self::network_mode() ) {
			return false;
		}
		$net = self::net_snapshot();
		if ( null === $net || ! array_key_exists( (string) $option, $net['values'] ) ) {
			return false;
		}
		$gen                               = PNCP_Lockdown::next_generation();
		$net['values'][ (string) $option ] = self::stored_site_option( (string) $option );
		$net['gen']                        = $gen;
		self::store_network( $net );
		PNCP_Lockdown::note_snapshot( $gen );
		return true;
	}

	/**
	 * 3.4: the administration address as signed when the site (or the network) was locked: from the snapshot,
	 * or from its copy in the guard file. Empty without a genuine one. Alerts go there while locked
	 * (PNCP_Lockdown::alert_to()), so someone who changed the address in the database does not get them.
	 *
	 * @return string
	 */
	public static function alert_address() {
		if ( is_multisite() && self::network_mode() ) {
			$net  = self::net_snapshot();
			$mail = null !== $net && isset( $net['values']['admin_email'] ) ? $net['values']['admin_email'] : '';
		} else {
			$snap = self::snapshot();
			$mail = null !== $snap && isset( $snap['values']['admin_email'] ) ? $snap['values']['admin_email'] : '';
		}
		if ( ! is_string( $mail ) || ! is_email( $mail ) ) {
			// 3.4.1: without a snapshot (or its copy), the address signed in the lock file, if there is one.
			$file = defined( 'PNCP_LOCKDOWN_BEACON' ) ? null : self::beacon_file();
			$mail = null === $file ? '' : $file['mail'];
		}
		if ( ! is_string( $mail ) || ! is_email( $mail ) ) {
			// 3.4.2: or the one signed in the lock line in wp-config.php.
			$config = self::config_lock();
			$mail   = null === $config ? '' : $config['mail'];
		}
		return is_string( $mail ) && is_email( $mail ) ? $mail : '';
	}

	/**
	 * Deletes the snapshots when the lock ends for good (unlocked "until I lock it again", the app removed, or a
	 * new app connected): of this site, and on multisite of every site and of the network.
	 */
	public static function forget_snapshots() {
		delete_option( self::SNAP );
		delete_option( self::DIGESTS );
		if ( ! is_multisite() ) {
			return;
		}
		foreach ( self::network_site_ids() as $id ) {
			if ( get_current_blog_id() !== $id ) {
				delete_blog_option( $id, self::SNAP );
				delete_blog_option( $id, self::DIGESTS );
			}
		}
		delete_site_option( self::NET_SNAP );
		delete_site_option( self::NET_DIGESTS );
		self::forget_net_cache();
	}

	/**
	 * Runs check_apps() on every site the lock of the network covers (multisite), or on this site.
	 *
	 * @param bool $known_only See check_apps().
	 * @return string[] The accounts concerned.
	 */
	public static function check_apps_all( $known_only = false ) {
		if ( ! is_multisite() || ! self::network_mode() ) {
			return self::check_apps( $known_only );
		}
		$net   = self::net_snapshot();
		$ids   = null !== $net ? array_map( 'intval', array_keys( $net['sites'] ) ) : array( get_current_blog_id() );
		$found = array();
		foreach ( $ids as $id ) {
			switch_to_blog( $id );
			try {
				foreach ( self::check_apps( $known_only, false ) as $line ) {
					$found[] = self::site_label( $id ) . ' ' . $line;
				}
			} finally {
				restore_current_blog();
			}
		}
		if ( $found ) {
			PNCP_Lockdown::tamper_alert( 'apps', implode( ', ', array_slice( $found, 0, 10 ) ) );
		}
		return $found;
	}

	/**
	 * A site, for an alert and the lockdown log. Like the names of the options in the same messages, it is not
	 * translated: some of them are written before WordPress loads translations (the seal runs on
	 * plugins_loaded).
	 *
	 * @param int $id Site ID.
	 * @return string
	 */
	private static function site_label( $id ) {
		return 'site ' . (int) $id;
	}

	/**
	 * A user's login and ID, for an alert.
	 *
	 * @param int $id User.
	 * @return string
	 */
	private static function user_label( $id ) {
		$user = get_userdata( (int) $id );
		return $user ? $user->user_login . ' (#' . (int) $id . ')' : '#' . (int) $id;
	}

	/* ---------- Unlocked for a while: what is kept when it locks again by itself ---------- */

	/**
	 * Notes a change of a protected option made through WordPress while the site is unlocked for a while, by the
	 * administrator who unlocked, in the browser session that unlocked (PNCP_Lockdown::window_session()). Only
	 * the change itself is noted, against the signed snapshot: what this write added, changed or removed
	 * compared with the value it replaced. A value changed directly in the database (now or before) that a
	 * WordPress screen then saves again unchanged is not part of the change, so it is still put back.
	 *
	 * @param string $option Option.
	 * @param mixed  $before The value it replaced (null: not known, e.g. the option was deleted).
	 * @param mixed  $after  The new value (false: deleted).
	 */
	public static function window_note( $option, $before, $after ) {
		if ( is_multisite() && self::network_mode() ) {
			self::ensure_site_snapshot(); // A site whose snapshot is taken on its first request.
		}
		$snap = self::snapshot();
		if ( null === $snap || ! array_key_exists( (string) $option, $snap['values'] ) ) {
			return;
		}
		$record = self::window_record( true );
		if ( null === $record ) {
			return;
		}
		$option = (string) $option;
		$base   = array_key_exists( $option, $record['values'] ) ? $record['values'][ $option ] : $snap['values'][ $option ];

		$record['values'][ $option ] = self::merge_change( $base, $before, $after );
		self::save_window( $record );
	}

	/**
	 * Multisite: the same for a network option (see window_note()), against the snapshot of the network.
	 *
	 * @param string $option Network option.
	 * @param mixed  $before The value it replaced (null: not known).
	 * @param mixed  $after  The new value (false: deleted).
	 */
	public static function window_note_network( $option, $before, $after ) {
		$net = is_multisite() ? self::net_snapshot() : null;
		if ( null === $net || ! array_key_exists( (string) $option, $net['values'] ) ) {
			return;
		}
		$record = self::window_record( true, true );
		if ( null === $record ) {
			return;
		}
		$option = (string) $option;
		$base   = array_key_exists( $option, $record['values'] ) ? $record['values'][ $option ] : $net['values'][ $option ];

		$record['values'][ $option ] = self::merge_change( $base, $before, $after );
		self::save_window( $record, true );
	}

	/**
	 * Notes that the administrator who unlocked changed the role of an account meanwhile: 2 = it can administer
	 * the site now (and could not before this change), 1 = staff, 0 = neither. Only an account noted with 2 is
	 * added to the administrators of the snapshot when the site locks again by itself.
	 *
	 * @param int $user_id User.
	 * @param int $kind    2, 1 or 0.
	 */
	public static function window_note_user( $user_id, $kind ) {
		if ( null === self::snapshot() ) {
			return;
		}
		$record = self::window_record( true );
		if ( null === $record ) {
			return;
		}
		$record['users'][ (int) $user_id ] = (int) $kind;
		self::save_window( $record );
	}

	/**
	 * Applies one change (from $old to $new) to a value of the snapshot. Lists (such as the active plugins) are
	 * treated as sets: what the change added is added, what it removed is removed. Lists of settings (keys and
	 * values) are compared key by key, at every level: only the keys the change touched take the new value.
	 * Anything else (text, numbers, a value of another kind) takes the new value.
	 *
	 * @param mixed $base   The value of the snapshot (or as already changed during this unlock).
	 * @param mixed $before The value before the change.
	 * @param mixed $after  The value after it.
	 * @return mixed
	 */
	private static function merge_change( $base, $before, $after ) {
		if ( $before === $after ) {
			return $base;
		}
		if ( ! is_array( $base ) || ! is_array( $before ) || ! is_array( $after ) ) {
			return $after;
		}
		if ( self::is_list( $before ) && self::is_list( $after ) && self::is_list( $base ) && self::scalars( $before ) && self::scalars( $after ) && self::scalars( $base ) ) {
			$added   = array_diff( $after, $before );
			$removed = array_diff( $before, $after );
			$out     = array_values( array_diff( $base, $removed ) );
			foreach ( $added as $item ) {
				if ( ! in_array( $item, $out, true ) ) {
					$out[] = $item;
				}
			}
			$sorted = $after;
			sort( $sorted );
			if ( $sorted === $after ) {
				sort( $out ); // WordPress keeps the active plugins sorted.
			}
			return $out;
		}
		$out = $base;
		foreach ( array_keys( $before + $after ) as $key ) {
			if ( ! array_key_exists( $key, $after ) ) {
				unset( $out[ $key ] );
			} elseif ( ! array_key_exists( $key, $before ) || ! array_key_exists( $key, $base ) ) {
				if ( ! array_key_exists( $key, $before ) || $before[ $key ] !== $after[ $key ] ) {
					$out[ $key ] = $after[ $key ];
				}
			} elseif ( $before[ $key ] !== $after[ $key ] ) {
				$out[ $key ] = self::merge_change( $base[ $key ], $before[ $key ], $after[ $key ] );
			}
		}
		return $out;
	}

	/**
	 * Is it a plain list (keys 0, 1, 2…)? The empty array counts as one.
	 *
	 * @param array<mixed> $value Value.
	 * @return bool
	 */
	private static function is_list( $value ) {
		$i = 0;
		foreach ( array_keys( $value ) as $key ) {
			if ( $key !== $i++ ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Does the list hold only text and numbers?
	 *
	 * @param array<mixed> $value Value.
	 * @return bool
	 */
	private static function scalars( $value ) {
		foreach ( $value as $item ) {
			if ( ! is_scalar( $item ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The signed record of the changes made during the current unlock, or null: missing, not matching its
	 * signature, or from another unlock (each one has its own lock time, end time and snapshot). With $fresh, an
	 * empty record for the current unlock instead of null (null only when the site is not unlocked for a while
	 * now, or the state cannot be trusted).
	 *
	 * @param bool $fresh   An empty record when there is none for this unlock.
	 * @param bool $network Multisite: the record of the network options (NET_WINDOW) instead of this site's.
	 * @return array{since:int, until:int, snap:int, values:array<string, mixed>, users:array<int, int>}|null
	 */
	private static function window_record( $fresh = false, $network = false ) {
		if ( '' !== PNCP_Lockdown::tampered() ) {
			return null;
		}
		$state = PNCP_Lockdown::state();
		if ( empty( $state['locked'] ) || (int) $state['until'] <= 0 ) {
			return null;
		}
		$id = array(
			'since' => (int) $state['since'],
			'until' => (int) $state['until'],
			'snap'  => (int) $state['snap'],
		);
		// Read from the database, not from this request's cache: another request of the same session may have
		// noted a change a moment ago.
		if ( $network ) {
			wp_cache_delete( get_current_network_id() . ':' . self::NET_WINDOW, 'site-options' );
			$stored = get_site_option( self::NET_WINDOW );
		} else {
			wp_cache_delete( self::WINDOW, 'options' );
			$stored = get_option( self::WINDOW );
		}
		if ( is_array( $stored ) && isset( $stored['sig'], $stored['values'], $stored['users'] ) && is_array( $stored['values'] ) && is_array( $stored['users'] ) ) {
			$sig = $stored['sig'];
			unset( $stored['sig'] );
			if ( self::valid( $stored, $sig ) && isset( $stored['since'], $stored['until'], $stored['snap'] ) && (int) $stored['since'] === $id['since'] && (int) $stored['until'] === $id['until'] && (int) $stored['snap'] === $id['snap'] ) {
				return $stored;
			}
		}
		return $fresh ? $id + array(
			'values' => array(),
			'users'  => array(),
		) : null;
	}

	/**
	 * Signs and stores the record of the changes made during the current unlock (not autoloaded).
	 *
	 * @param array<string, mixed> $record  Record.
	 * @param bool                 $network Multisite: the record of the network options.
	 */
	private static function save_window( $record, $network = false ) {
		unset( $record['sig'] );
		$record['sig'] = self::sign( $record );
		if ( $network ) {
			update_site_option( self::NET_WINDOW, $record );
		} elseif ( false === get_option( self::WINDOW, false ) ) {
			add_option( self::WINDOW, $record, '', false );
		} else {
			update_option( self::WINDOW, $record, false );
		}
	}

	/**
	 * Forgets the changes noted during an unlock (locked again, unlocked for good, a new unlock, the app removed).
	 */
	public static function forget_window() {
		delete_option( self::WINDOW );
		if ( ! is_multisite() ) {
			return;
		}
		// Multisite: the changes were noted on each site where they were made, and for the network.
		delete_site_option( self::NET_WINDOW );
		foreach ( self::network_site_ids() as $id ) {
			if ( get_current_blog_id() !== $id ) {
				delete_blog_option( $id, self::WINDOW );
			}
		}
	}

	/**
	 * The names of the protected options changed during the current unlock, and the number of accounts that were
	 * made administrators (for the notice while it is open).
	 *
	 * @return array{options:string[], admins:int}
	 */
	public static function window_summary() {
		$record  = self::window_record();
		$network = is_multisite() ? self::window_record( false, true ) : null;
		$options = null !== $record ? array_keys( $record['values'] ) : array();
		if ( null !== $network ) {
			// Multisite: the network options too (only this site's own options are listed).
			$options = array_merge( $options, array_keys( $network['values'] ) );
		}
		$admins = 0;
		foreach ( null !== $record ? $record['users'] : array() as $kind ) {
			$admins += 2 === (int) $kind ? 1 : 0;
		}
		return array(
			'options' => array_values( array_unique( $options ) ),
			'admins'  => $admins,
		);
	}

	/**
	 * The snapshot that counts now. Normally the signed snapshot of the lock. When an unlock for a while has
	 * just ended and the snapshot was not taken again yet (PNCP_Lockdown::reseal_pending()), the signed
	 * snapshot with the changes noted during the unlock applied: the same values accept_window() will sign, so
	 * a request in between neither puts back the owner's changes nor accepts anything else.
	 *
	 * @return array{time:int, values:array<string, mixed>, admins:int[]}|null
	 */
	public static function current_snapshot() {
		$snap = self::snapshot();
		if ( null === $snap || ! PNCP_Lockdown::reseal_pending() ) {
			return $snap;
		}
		$record = self::window_record();
		if ( null === $record ) {
			return $snap;
		}
		foreach ( $record['values'] as $option => $value ) {
			if ( array_key_exists( (string) $option, $snap['values'] ) ) {
				$snap['values'][ (string) $option ] = $value;
			}
		}
		$users = array();
		foreach ( $record['users'] as $id => $kind ) {
			if ( (int) $kind > 0 ) {
				$users[ (int) $id ] = (int) $kind;
			}
		}
		if ( $users ) {
			// Only accounts the owner made administrators that still are: never an account that was given the
			// rights in the database (also not one the owner only edited, see PNCP_Lockdown::note_role()).
			$added = array();
			foreach ( $users as $id => $kind ) {
				if ( 2 === $kind ) {
					$added[] = $id;
				}
			}
			$admins         = array_intersect( $added, self::admin_ids() );
			$snap['admins'] = array_values( array_unique( array_map( 'intval', array_merge( $snap['admins'], $admins ) ) ) );
			sort( $snap['admins'] );
			if ( isset( $snap['apps'] ) && is_array( $snap['apps'] ) ) {
				// Accounts that became staff during the unlock keep the application passwords they had (staff cannot
				// add any while unlocked for a while), instead of the hourly check removing them as planted.
				foreach ( array_keys( $users ) as $id ) {
					if ( ! isset( $snap['apps'][ $id ] ) && PNCP_Lockdown::is_staff( $id ) ) {
						$uuids = array();
						foreach ( WP_Application_Passwords::get_user_application_passwords( $id ) as $item ) {
							if ( isset( $item['uuid'] ) ) {
								$uuids[] = (string) $item['uuid'];
							}
						}
						sort( $uuids );
						$snap['apps'][ $id ] = $uuids;
					}
				}
				ksort( $snap['apps'] );
			}
		}
		return $snap;
	}

	/**
	 * An unlock for a while has ended: signs the snapshot again with the changes the owner made through
	 * WordPress during it (current_snapshot()), and the administrators they added. Values changed any other way
	 * (directly in the database, during the unlock or at any other time) are not taken over: they are put back
	 * from it as usual (verify_options()). Run by PNCP_Lockdown::expire_window(), one request at a time.
	 *
	 * The caller notes the generation in the state (with the end of the unlock, in one write: a request in
	 * between then sees the state at most one generation behind the guard, which it waits for).
	 *
	 * @return int The generation of the new snapshot (0: none was signed, there is no genuine snapshot).
	 */
	public static function accept_window() {
		if ( is_multisite() && self::network_mode() ) {
			return self::accept_network_window();
		}
		$snap = self::current_snapshot();
		if ( null === $snap ) {
			return 0;
		}
		return self::store_snapshot( $snap['values'], $snap['admins'], isset( $snap['since'] ) ? (int) $snap['since'] : null, isset( $snap['apps'] ) ? $snap['apps'] : null, false, isset( $snap['pass'] ) ? $snap['pass'] : null );
	}

	/**
	 * Multisite: accept_window() for the whole network. Every site where the owner changed something during the
	 * unlock gets its snapshot again with those changes (the other sites keep theirs), and the snapshot of the
	 * network gets the changes to the network options, with one new generation for all of them.
	 *
	 * @return int The generation of the new snapshot of the network (0: there is no genuine one).
	 */
	private static function accept_network_window() {
		$net = self::current_network_snapshot();
		if ( null === $net ) {
			return 0;
		}
		$gen = PNCP_Lockdown::next_generation();
		foreach ( array_map( 'intval', array_keys( $net['sites'] ) ) as $id ) {
			switch_to_blog( $id );
			try {
				if ( null === self::window_record() ) {
					continue; // Nothing changed on this site.
				}
				$snap = self::current_snapshot();
				if ( null === $snap ) {
					continue;
				}
				self::write_site_snapshot( $snap['values'], $snap['admins'], (int) $net['since'], $gen, isset( $snap['apps'] ) ? $snap['apps'] : null );
				$net['sites'][ $id ] = self::site_entry( $snap['values'], $snap['admins'], $gen, true, isset( $net['sites'][ $id ]['guard'] ) );
			} finally {
				restore_current_blog();
			}
		}
		$net['gen']  = $gen;
		$net['time'] = time();
		self::store_network( $net );
		return $gen;
	}

	/**
	 * While locked: puts back any protected option that changed behind WordPress's back (WordPress itself
	 * cannot change them while locked), and reports it.
	 */
	public static function verify_options() {
		if ( is_multisite() && ( PNCP_Lockdown::is_locked() || PNCP_Lockdown::unlocked_until() ) && self::network_mode() && ! self::verify_site_of_network() ) {
			return;
		}
		if ( ! PNCP_Lockdown::is_locked() ) {
			return;
		}
		if ( PNCP_Lockdown::reseal_pending() ) {
			// 3.4: an unlock for a while has just ended and the snapshot could not be taken again yet (another
			// request is doing it): compared with the snapshot as it will be, the owner's changes included.
			$snap = self::current_snapshot();
			if ( null !== $snap ) {
				self::restore( $snap );
				return;
			}
		}
		// The quick way, on every request: the autoloaded fingerprints against the options (also autoloaded).
		// The snapshot itself is read only when something differs, or when there are no fingerprints yet.
		// The fingerprints cover the same options as the snapshot they were made with (an option added to the
		// protected list by a later version is in neither until the next lock), so they are enough on their own.
		$digests = self::digests();
		if ( null !== $digests ) {
			$same = true;
			foreach ( $digests as $option => $digest ) {
				if ( self::digest( self::stored_option( (string) $option ) ) !== $digest ) {
					$same = false;
					break;
				}
			}
			if ( $same ) {
				return;
			}
		}
		$snap = self::snapshot();
		if ( null === $snap && is_multisite() && self::network_mode() ) {
			// Multisite: taken again from the values that still match the snapshot of the network (and reported).
			self::ensure_site_snapshot();
			$snap = self::snapshot();
		}
		if ( null === $snap ) {
			$record = self::snapshot_record();
			if ( self::snapshot_pending( $record ) ) {
				// 3.4: the owner has just locked the site and the request that locks it is still taking the
				// snapshot (a visitor, or the background request it started, came in between): not an alarm.
				return;
			}
			if ( null !== $record ) {
				// Genuine, but from an older lock or before a later change: put back from a copy of the database.
				// Nothing can be put back from it; the guard still keeps the plugins and the theme.
				PNCP_Lockdown::tamper_alert( 'replay', 'snapshot' );
			} elseif ( false !== get_option( self::SNAP, false ) || ( ! is_multisite() && ! self::legacy() ) ) {
				// Multisite, a network locked before 3.4: only the site where it was locked has a snapshot. The other
				// sites have none, which is not an alarm (the Lockdown tab says to lock again).
				PNCP_Lockdown::tamper_alert( 'snapshot' );
			}
			return;
		}
		if ( self::$from_copy ) {
			// 3.4: the snapshot in the database was deleted, changed or set back to an older one: put back from the
			// copy in the guard file (signed, so nothing is signed again), then the settings from it as usual.
			self::$from_copy = false;
			$copy            = $snap;
			$copy['sig']     = self::sign( $snap );
			update_option( self::SNAP, $copy, false );
			wp_cache_delete( self::SNAP, 'options' );
			PNCP_Lockdown::tamper_alert( 'snapshot_copy' );
		}
		self::restore( $snap );
		if ( null === $digests ) {
			$old = self::digests_record();
			if ( null !== $old && isset( $snap['gen'] ) ) {
				// Genuine fingerprints of an older snapshot: put back from a copy of the database.
				PNCP_Lockdown::tamper_alert( 'replay', 'digests' );
			}
			// A snapshot from before 3.3.2, or fingerprints from an older snapshot: the fingerprints of this one
			// (from the signed snapshot, never from the options as they are now).
			self::save_digests( $snap['values'], isset( $snap['since'] ) ? (int) $snap['since'] : (int) PNCP_Lockdown::state()['since'], isset( $snap['gen'] ) ? (int) $snap['gen'] : 0 );
		}
	}

	/**
	 * Multisite, a network locked with 3.4 or later, while locked or unlocked for a while: checks the network
	 * options (while locked), and makes sure this site has its own snapshot (taken on its first request when it
	 * was not taken at once).
	 *
	 * @return bool Whether this site's own snapshot is to be checked next (false: the lock does not cover it).
	 */
	private static function verify_site_of_network() {
		$net = PNCP_Lockdown::is_locked() ? self::verify_network() : self::net_digests();
		if ( null === $net ) {
			return true; // Reported: each site still checks its own snapshot.
		}
		if ( ! isset( $net['sites'][ get_current_blog_id() ] ) ) {
			return false; // Added after the lock, or ScrapeLock was not active here: nothing to compare with.
		}
		$record = self::digests_record( true );
		if ( null === $record || ! empty( $record['lazy'] ) ) {
			self::ensure_site_snapshot();
		}
		return true;
	}

	/**
	 * Puts back the protected options that differ from a snapshot, and reports them.
	 *
	 * @param array{values:array<string, mixed>} $snap Snapshot.
	 */
	private static function restore( $snap ) {
		$restored = array();
		foreach ( $snap['values'] as $option => $value ) {
			if ( self::digest( self::stored_option( (string) $option ) ) !== self::digest( $value ) ) {
				PNCP_Lockdown::write_protected( (string) $option, $value );
				$restored[] = (string) $option;
			}
		}
		if ( $restored ) {
			$where = is_multisite() ? self::site_label( get_current_blog_id() ) . ': ' : '';
			PNCP_Lockdown::tamper_alert( 'options', $where . implode( ', ', $restored ) );
		}
	}

	/**
	 * The hourly check while locked: accounts that can administer the site now but could not when it was
	 * locked (rights given behind WordPress's back) are reported.
	 *
	 * @param bool $report Report them (false: only list them, for the warning when the owner unlocks).
	 * @return string[] The accounts found (at most 10).
	 */
	public static function check_admins( $report = true ) {
		if ( is_multisite() ) {
			return self::check_network_admins( $report );
		}
		$snap = self::current_snapshot();
		if ( null === $snap ) {
			return array();
		}
		$new = array_diff( self::admin_ids(), $snap['admins'] );
		if ( ! $new ) {
			return array();
		}
		$logins = array();
		foreach ( array_slice( $new, 0, 10 ) as $id ) {
			$user     = get_userdata( (int) $id );
			$logins[] = $user ? $user->user_login . ' (#' . (int) $id . ')' : '#' . (int) $id;
		}
		if ( $report ) {
			PNCP_Lockdown::tamper_alert( 'admin', implode( ', ', $logins ) );
		}
		return $logins;
	}

	/**
	 * Multisite: check_admins() for the network. Super admins who were not super admins when the network was
	 * locked, and on each site accounts that can administer it but could not then, are reported. On the main
	 * site every site the lock covers is checked, on the others only the site itself. Nothing for a network
	 * locked before 3.4 (it has no snapshot of the network).
	 *
	 * @param bool $report See check_admins().
	 * @return string[]
	 */
	private static function check_network_admins( $report = true ) {
		if ( ! self::network_mode() ) {
			return array();
		}
		$net = self::current_network_snapshot();
		if ( null === $net ) {
			return array();
		}
		$found = array();
		foreach ( array_diff( self::super_ids(), array_map( 'intval', (array) $net['super'] ) ) as $id ) {
			$found[] = 'super admin ' . self::user_label( $id );
		}
		$ids = is_main_site() ? array_map( 'intval', array_keys( $net['sites'] ) ) : array( get_current_blog_id() );
		foreach ( $ids as $id ) {
			if ( ! isset( $net['sites'][ $id ] ) ) {
				continue;
			}
			switch_to_blog( $id );
			try {
				$known = self::site_admins_known( $net['sites'][ $id ] );
				foreach ( array_diff( self::admin_ids(), $known ) as $user ) {
					$found[] = self::site_label( $id ) . ' ' . self::user_label( $user );
				}
			} finally {
				restore_current_blog();
			}
		}
		$found = array_slice( $found, 0, 10 );
		if ( $found && $report ) {
			PNCP_Lockdown::tamper_alert( 'admin', implode( ', ', $found ) );
		}
		return $found;
	}

	/**
	 * Multisite, in the site being checked: the accounts that could administer it when the network was locked
	 * (from its own snapshot, which also has the ones the owner added during an unlock for a while that has just
	 * ended, or else from the snapshot of the network).
	 *
	 * @param array<string, mixed> $entry The site's entry in the snapshot of the network.
	 * @return int[]
	 */
	private static function site_admins_known( $entry ) {
		$snap = self::current_snapshot();
		return array_map( 'intval', null !== $snap ? $snap['admins'] : ( isset( $entry['admins'] ) ? (array) $entry['admins'] : array() ) );
	}

	/**
	 * Multisite: authenticate() for the network. A user is refused when they are a super admin but were not when
	 * the network was locked, or when they can administer a site the lock covers but could not then (their
	 * rights were given behind WordPress's back). Every site the user belongs to is looked at, not only the one
	 * they sign in on: the login cookie works for the whole network.
	 *
	 * @param WP_User $user User.
	 * @return WP_User|WP_Error
	 */
	private static function authenticate_network( $user ) {
		if ( ! self::network_mode() ) {
			return $user; // A network locked before 3.4 (see the notice on the Lockdown tab).
		}
		$net = self::current_network_snapshot();
		if ( null === $net ) {
			return $user; // Reported by verify_network().
		}
		$id    = (int) $user->ID;
		$where = '';
		if ( is_super_admin( $id ) && ! in_array( $id, array_map( 'intval', (array) $net['super'] ), true ) ) {
			$where = 'network';
		}
		foreach ( '' === $where ? array_map( 'intval', array_keys( get_blogs_of_user( $id, true ) ) ) : array() as $blog ) {
			if ( ! isset( $net['sites'][ $blog ] ) ) {
				continue;
			}
			switch_to_blog( $blog );
			try {
				if ( ! in_array( $id, self::site_admins_known( $net['sites'][ $blog ] ), true ) && PNCP_Lockdown::can_administer( $id ) ) {
					$where = self::site_label( $blog );
				}
			} finally {
				restore_current_blog();
			}
			if ( '' !== $where ) {
				break;
			}
		}
		if ( '' === $where ) {
			return $user;
		}
		PNCP_Lockdown::tamper_alert( 'admin', $user->user_login . ' (' . $where . ')' );
		return new WP_Error( 'pncp_locked', __( 'This account cannot sign in while the site is locked: it was given administrator rights after the site was locked.', 'scrapelock' ) . ' ' . self::locked_signin_help() );
	}

	/**
	 * While locked: an account that can administer the site but did not when the site was locked cannot
	 * sign in (its rights were given behind WordPress's back: WordPress itself refuses that while locked).
	 *
	 * @param WP_User|WP_Error|null $user User so far.
	 * @return WP_User|WP_Error|null
	 */
	public static function authenticate( $user ) {
		if ( ! $user instanceof WP_User || ! PNCP_Lockdown::is_locked() ) {
			return $user;
		}
		if ( is_multisite() ) {
			return self::authenticate_network( $user );
		}
		if ( ! array_intersect( PNCP_Lockdown::control_caps(), array_keys( array_filter( (array) $user->allcaps ) ) ) ) {
			return $user;
		}
		$snap = self::current_snapshot();
		if ( null !== $snap && in_array( (int) $user->ID, $snap['admins'], true ) && ! self::password_ok( $snap, (int) $user->ID ) ) {
			// 3.4: the password hash was written in the database (WordPress itself refuses to change it while
			// locked, and a change through WordPress during an unlock is noted in the snapshot).
			PNCP_Lockdown::tamper_alert( 'login', $user->user_login );
			return new WP_Error( 'pncp_locked', __( 'This account cannot sign in while the site is locked: its password was changed after the site was locked.', 'scrapelock' ) . ' ' . self::locked_signin_help() );
		}
		if ( null === $snap || in_array( (int) $user->ID, $snap['admins'], true ) ) {
			return $user; // Without a valid snapshot there is nothing to compare with (reported by verify_options()).
		}
		PNCP_Lockdown::tamper_alert( 'admin', $user->user_login );
		return new WP_Error( 'pncp_locked', __( 'This account cannot sign in while the site is locked: it was given administrator rights after the site was locked.', 'scrapelock' ) . ' ' . self::locked_signin_help() );
	}

	/**
	 * 3.13.0: what the owner can do when an account is refused at sign-in while locked (for example after setting a
	 * new password with the host's tools): the way in from the server.
	 *
	 * @return string
	 */
	public static function locked_signin_help() {
		return __( 'If you made this change yourself (for example with your host\'s tools), add define( \'SCRAPELOCK_UNLOCK\', true ); to wp-config.php (over SSH: wp config set SCRAPELOCK_UNLOCK true --raw --type=constant), sign in, remove the line again, then unlock on the Lockdown page with your authenticator app or a recovery code: you stay signed in.', 'scrapelock' );
	}
}

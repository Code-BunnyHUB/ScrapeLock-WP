<?php
/**
 * Human check: a signed cookie that only a real browser with a person behind it gets without effort.
 *
 * @package ScrapeLock
 */

defined( 'ABSPATH' ) || exit;

/**
 * A small script waits for the first real interaction (scroll, tap, key, mouse movement), asks the server
 * for a challenge, solves a light proof of work and receives a signed cookie, tied to the IP (IPv6: its /64)
 * and the browser. Visitors without the cookie get the stricter "unverified" page limit.
 *
 * No nonce is involved, so it works with page caches (WP Rocket etc.). It is not a captcha: nobody is asked
 * anything. It is a light proof of work, not proof of a browser: a script that copies the steps gets the cookie
 * too (measured: 0.11 s in Python at the base difficulty). 3.13.0: so it costs more where a script is likely
 * (difficulty(), suspicion()), lasts hours instead of days there (cookie_seconds()), and one network gets at most
 * NET_COOKIES_PER_HOUR cookies an hour.
 */
final class PNCP_Human {

	const COOKIE = 'pncp_hv';

	/**
	 * 3.4.3: the second cookie, for the pre-cache check (PNCP_Precheck::human()): the same proof, signed with a
	 * key the check can read before WordPress loads.
	 */
	const PC_COOKIE = 'pncp_hvc';

	/**
	 * Seconds a challenge stays valid.
	 */
	const CHALLENGE_TTL = 300;

	/**
	 * Days the cookie stays valid.
	 */
	const COOKIE_DAYS = 7;

	/**
	 * 3.13.0: hours the cookie stays valid for a suspicious client (suspicion() > 0: a data center, a bad
	 * reputation, browser headers that do not fit the User-Agent). Filter `pncp_human_suspect_hours`.
	 */
	const SUSPECT_HOURS = 4;

	/**
	 * 3.13.0: at most this many cookies an hour for the addresses of one network (IPv4 /24, IPv6 /48): a script
	 * that solves the proof of work on many addresses of one network gets no more. Past it the visitor keeps the
	 * stricter page limit (nothing is refused). Filter `pncp_human_cookies_per_network` (0 = no cap).
	 */
	const NET_COOKIES_PER_HOUR = 60;

	/**
	 * Registers the hooks.
	 */
	public static function init() {
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
		add_action( 'wp_ajax_nopriv_pncp_hv', array( __CLASS__, 'ajax' ) );
		add_action( 'wp_ajax_pncp_hv', array( __CLASS__, 'ajax' ) );
	}

	/**
	 * Is the human check on?
	 *
	 * @return bool
	 */
	public static function enabled() {
		$s = PNCP_Options::get();
		return ! empty( $s['enabled'] ) && ! empty( $s['human_check'] );
	}

	/**
	 * Loads the script on every public page (in the footer, after the content).
	 */
	public static function enqueue() {
		if ( ! self::enabled() || is_admin() ) {
			return;
		}
		wp_enqueue_script(
			'pncp-human',
			PNCP_URL . 'assets/js/human.js',
			array(),
			PNCP_VERSION,
			array(
				'in_footer' => true,
				'strategy'  => 'defer',
			)
		);
		wp_localize_script(
			'pncp-human',
			'pncpHuman',
			array(
				'url'    => admin_url( 'admin-ajax.php' ),
				// 3.4.3: with the pre-cache check, the script looks for its cookie: a visitor verified before
				// it was turned on solves the check once more and gets both.
				'cookie' => PNCP_Precheck::wanted() ? self::PC_COOKIE : self::COOKIE,
			)
		);
	}

	/**
	 * Proof-of-work difficulty: leading zero hex digits of sha256( challenge . answer ). Each step is 16 times
	 * the work: 3 = about 4,000 attempts on average, a fraction of a second in a browser; 4 = about 65,000, a
	 * second or two on a phone; 5 = about a million, often 10–30 seconds on a phone, so a visitor who leaves
	 * sooner is never verified. Filter `pncp_human_difficulty` (1–5). The script tries up to 8 times the
	 * average before it gives up (fewer than 1 visitor in 2,900 gets that far), or until the challenge expires
	 * (CHALLENGE_TTL). Up to 3.3 it gave up after a million attempts at any difficulty, so at 5 about 4
	 * visitors in 10 were never verified.
	 *
	 * 3.13.0: per client: one or two steps more for a suspicious one (suspicion()), at most 5. Filter
	 * `pncp_human_difficulty_for` (difficulty, IP, base).
	 *
	 * @param string $ip The client's IP ('' = the base difficulty).
	 * @return int
	 */
	public static function difficulty( $ip = '' ) {
		$base = max( 1, min( 5, (int) apply_filters( 'pncp_human_difficulty', 3 ) ) );
		// 3.13.0: harder for a suspicious client (suspicion()): one step (16 times the work) per sign, at most two.
		// A person on a home or mobile connection with a normal browser keeps the base and notices nothing.
		$more = '' === (string) $ip ? 0 : min( 2, self::suspicion( (string) $ip ) );
		return max( 1, min( 5, (int) apply_filters( 'pncp_human_difficulty_for', $base + $more, (string) $ip, $base ) ) );
	}

	/**
	 * 3.13.0: how many signs of a script the client of this request shows (0–3): its address in a data center
	 * (PNCP_Ip::datacenter()), a bad reputation (PNCP_Reputation::suspect()), and browser headers that do not fit its
	 * User-Agent (PNCP_Bots::fake_browser(), PNCP_Bots::header_mismatch()). No lookup outside the site.
	 *
	 * @param string $ip IP.
	 * @return int
	 */
	public static function suspicion( $ip ) {
		$ua    = PNCP_Bots::user_agent();
		$score = 0;
		if ( '' !== PNCP_Ip::datacenter( $ip ) ) {
			++$score;
		}
		if ( PNCP_Reputation::suspect( $ip ) ) {
			++$score;
		}
		if ( '' !== PNCP_Bots::fake_browser( $ua ) || '' !== PNCP_Bots::header_mismatch( $ua, PNCP_Bots::request_headers(), is_ssl() ) ) {
			++$score;
		}
		return $score;
	}

	/**
	 * 3.13.0: seconds the cookie stays valid for the client of this request: COOKIE_DAYS, or SUSPECT_HOURS for a
	 * suspicious one.
	 *
	 * @param string $ip IP.
	 * @return int
	 */
	public static function cookie_seconds( $ip ) {
		if ( self::suspicion( $ip ) > 0 ) {
			return max( 300, (int) apply_filters( 'pncp_human_suspect_hours', self::SUSPECT_HOURS ) * HOUR_IN_SECONDS );
		}
		return self::COOKIE_DAYS * DAY_IN_SECONDS;
	}

	/**
	 * 3.13.0: the cap on cookies per network and hour (NET_COOKIES_PER_HOUR).
	 *
	 * @return int 0 = no cap.
	 */
	public static function net_cookies_per_hour() {
		return max( 0, (int) apply_filters( 'pncp_human_cookies_per_network', self::NET_COOKIES_PER_HOUR ) );
	}

	/**
	 * Maximum challenge requests and answer attempts per minute, per IP (IPv6: per /64). Stops a script from
	 * hammering the endpoint (each call boots WordPress) or brute-forcing many challenges at once. A real
	 * visitor needs one or two. Filter `pncp_human_max_per_minute`.
	 *
	 * @return int
	 */
	public static function max_per_minute() {
		return max( 1, (int) apply_filters( 'pncp_human_max_per_minute', 20 ) );
	}

	/**
	 * Signature tied to this site, the IP and the browser.
	 *
	 * @param string $data Data.
	 * @param string $ip   IP.
	 * @return string
	 */
	private static function sign( $data, $ip ) {
		$ua = PNCP_Bots::user_agent();
		return hash_hmac( 'sha256', $data . '|' . PNCP_Ip::limit_key( $ip ) . '|' . md5( $ua ), wp_salt( 'auth' ) . 'pncp-human' );
	}

	/**
	 * A new challenge: "time.difficulty.random.signature" (3.13.0; "time.random.signature" before).
	 *
	 * @param string $ip         IP.
	 * @param int    $difficulty 3.13.0: the difficulty to ask (0 = difficulty() for this client).
	 * @return string
	 */
	public static function challenge( $ip, $difficulty = 0 ) {
		// 3.13.0: "time.difficulty.random.signature": the difficulty asked is signed with it, so the answer is
		// checked against the work this client was given (difficulty() depends on the client).
		$difficulty = $difficulty > 0 ? max( 1, min( 5, (int) $difficulty ) ) : self::difficulty( $ip );
		$data       = time() . '.' . $difficulty . '.' . wp_generate_password( 16, false );
		return $data . '.' . self::sign( 'c|' . $data, $ip );
	}

	/**
	 * Checks a solved challenge.
	 *
	 * @param string $challenge Challenge.
	 * @param string $answer    Answer.
	 * @param string $ip        IP.
	 * @return bool
	 */
	public static function check_answer( $challenge, $answer, $ip ) {
		$parts = explode( '.', $challenge );
		// 3.13.0: four parts, with the difficulty (challenge()). A challenge of three parts was given before the
		// update (at most CHALLENGE_TTL ago): it is checked with the base difficulty, as then.
		if ( ! in_array( count( $parts ), array( 3, 4 ), true ) || ! ctype_digit( $parts[0] ) || ! preg_match( '/^[0-9]{1,12}$/', $answer ) ) {
			return false;
		}
		$age = time() - (int) $parts[0];
		if ( $age < 0 || $age > self::CHALLENGE_TTL ) {
			return false;
		}
		$signature  = (string) array_pop( $parts );
		$difficulty = 3 === count( $parts ) ? (int) $parts[1] : self::difficulty();
		if ( 3 === count( $parts ) && ( ! ctype_digit( $parts[1] ) || $difficulty < 1 || $difficulty > 5 ) ) {
			return false;
		}
		if ( ! hash_equals( self::sign( 'c|' . implode( '.', $parts ), $ip ), $signature ) ) {
			return false;
		}
		return 0 === strpos( hash( 'sha256', $challenge . $answer ), str_repeat( '0', $difficulty ) );
	}

	/**
	 * 3.4.3: Marks a solved challenge as spent, in one atomic step: true only for the first caller, false if it
	 * was already spent (also by a request running at the same moment). With a persistent object cache or APCu
	 * an atomic add; otherwise one INSERT IGNORE into wp_options, which the unique option_name decides. The
	 * marker is the same transient as before ("pncp_hvu_" . md5( challenge ), CHALLENGE_TTL), so expired ones
	 * go with the hourly cleanup (PNCP_Log::purge_expired_transients()) and WordPress's own daily one.
	 * add_option() is not used: it inserts with ON DUPLICATE KEY UPDATE, so a second insert does not fail.
	 *
	 * @param string $challenge Challenge (already checked).
	 * @return bool
	 */
	private static function spend( $challenge ) {
		global $wpdb;
		$key = 'pncp_hvu_' . md5( $challenge );
		if ( wp_using_ext_object_cache() ) {
			return wp_cache_add( $key, 1, 'pncp', self::CHALLENGE_TTL );
		}
		if ( PNCP_Log::apcu_ok() ) {
			return apcu_add( PNCP_Log::apcu_key( $key ), 1, self::CHALLENGE_TTL );
		}
		// 3.6.1: one row in the plugin's own table where it exists (atomic too); wp_options otherwise.
		$added = PNCP_Log::kv_add( $key, 1, self::CHALLENGE_TTL );
		if ( null !== $added ) {
			return $added;
		}
		// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Atomic insert; the options API has none.
		$added = $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} ( option_name, option_value, autoload ) VALUES ( %s, %s, 'off' )",
				'_transient_' . $key,
				'1'
			)
		);
		if ( 1 !== (int) $added ) {
			return false;
		}
		$wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} ( option_name, option_value, autoload ) VALUES ( %s, %s, 'off' )",
				'_transient_timeout_' . $key,
				(string) ( time() + self::CHALLENGE_TTL )
			)
		);
		// phpcs:enable
		wp_cache_delete( '_transient_' . $key, 'options' );
		wp_cache_delete( '_transient_timeout_' . $key, 'options' );
		wp_cache_delete( 'notoptions', 'options' );
		return true;
	}

	/**
	 * The cookie value: "expiry.signature".
	 *
	 * @param string $ip      IP.
	 * @param int    $seconds 3.13.0: how long it stays valid (0 = COOKIE_DAYS).
	 * @return string
	 */
	public static function cookie_value( $ip, $seconds = 0 ) {
		$expires = time() + ( $seconds > 0 ? (int) $seconds : self::COOKIE_DAYS * DAY_IN_SECONDS );
		return $expires . '.' . self::sign( 'v|' . $expires, $ip );
	}

	/**
	 * 3.4.3: the value of the cookie for the pre-cache check: "expiry.signature", as
	 * PNCP_Precheck_Runtime::human_ok() checks it (the raw User-Agent: the check has no WordPress functions).
	 *
	 * @param string $ip      IP.
	 * @param int    $seconds 3.13.0: how long it stays valid (0 = COOKIE_DAYS).
	 * @return string
	 */
	public static function pc_value( $ip, $seconds = 0 ) {
		$expires = time() + ( $seconds > 0 ? (int) $seconds : self::COOKIE_DAYS * DAY_IN_SECONDS );
		$ua      = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Only hashed, as the check hashes it.
		return $expires . '.' . hash_hmac( 'sha256', $expires . '|' . PNCP_Ip::limit_key( $ip ) . '|' . md5( $ua ), PNCP_Precheck::human_key() );
	}

	/**
	 * Does the request carry a valid cookie for this IP and browser?
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function verified( $ip ) {
		if ( '' === $ip || empty( $_COOKIE[ self::COOKIE ] ) ) {
			return false;
		}
		$parts = explode( '.', sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) );
		if ( 2 !== count( $parts ) || ! ctype_digit( $parts[0] ) || (int) $parts[0] < time() ) {
			return false;
		}
		return hash_equals( self::sign( 'v|' . $parts[0], $ip ), $parts[1] );
	}

	/**
	 * Deletes a cookie that is no longer valid (e.g. the visitor moved from Wi-Fi to mobile data and the IP
	 * changed). The script sees no cookie and checks again at the next interaction, instead of keeping the
	 * stricter limit for up to 7 days.
	 */
	public static function forget_invalid() {
		if ( empty( $_COOKIE[ self::COOKIE ] ) || headers_sent() ) {
			return;
		}
		foreach ( array( self::COOKIE, self::PC_COOKIE ) as $name ) {
			setcookie(
				$name,
				'',
				array(
					'expires'  => time() - YEAR_IN_SECONDS,
					'path'     => COOKIEPATH ? COOKIEPATH : '/',
					'secure'   => is_ssl(),
					'httponly' => false,
					'samesite' => 'Lax',
				)
			);
			unset( $_COOKIE[ $name ] );
		}
	}

	/**
	 * admin-ajax: GET = new challenge, POST = answer (sets the cookie). Never cached.
	 */
	public static function ajax() {
		nocache_headers();
		$ip = PNCP_Ip::client_ip();
		if ( ! self::enabled() || '' === $ip ) {
			wp_send_json_error( null, 404 );
		}
		// Throttle both challenge requests and answer attempts per IP (IPv6: per /64), so a script cannot
		// hammer the endpoint or brute-force many challenges at once.
		$bucket = 'pncp_hv_' . md5( PNCP_Ip::limit_key( $ip ) ) . '_' . (int) floor( time() / MINUTE_IN_SECONDS );
		$tries  = PNCP_Log::cache_incr( $bucket, MINUTE_IN_SECONDS ); // 3.4.3: atomic where it can be.
		// 3.6.1: or not counted at all (a flood from many addresses used up the minute's allowance of new
		// transients, on a site with no object cache, APCu or the plugin's table): refused rather than unlimited.
		if ( $tries > self::max_per_minute() || PNCP_Log::unstored() ) {
			$retry = PNCP_Bots::retry_after(); // 3.5: the bucket is per minute, like the limits.
			header( 'Retry-After: ' . $retry );
			wp_send_json_error( array( 'retry_after' => $retry ), 429 );
		}
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		if ( 'POST' !== $method ) {
			$difficulty = self::difficulty( $ip ); // 3.13.0: per client (signed into the challenge).
			wp_send_json_success(
				array(
					'c' => self::challenge( $ip, $difficulty ),
					'd' => $difficulty,
					't' => self::CHALLENGE_TTL, // The script stops trying when the challenge would have expired.
				)
			);
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Proof of work instead of a nonce, so cached pages work.
		$challenge = isset( $_POST['c'] ) ? sanitize_text_field( wp_unslash( $_POST['c'] ) ) : '';
		$answer    = isset( $_POST['n'] ) ? sanitize_text_field( wp_unslash( $_POST['n'] ) ) : '';
		// phpcs:enable
		// Single use: a challenge that was already spent cannot be replayed (so one solved proof of work
		// cannot hand out many cookies, e.g. across rotating IPs in the same /64).
		// 3.4.3: checked first, spent in one atomic step after the answer is right (see spend()). Up to 3.4.2 the
		// marker was read here and written after the check, so two answers sent at the same moment both got a
		// cookie.
		if ( ! self::check_answer( $challenge, $answer, $ip ) || ! self::spend( $challenge ) ) {
			wp_send_json_error( null, 403 );
		}
		// 3.13.0: at most net_cookies_per_hour() cookies an hour for one network (IPv4 /24, IPv6 /48). Past it the
		// answer is right but no cookie is given: the visitor keeps the stricter page limit, nothing is refused.
		$cap = self::net_cookies_per_hour();
		if ( $cap > 0 ) {
			$net    = PNCP_Ip::network_key( $ip );
			$issued = PNCP_Log::cache_incr( 'pncp_hvn_' . md5( '' !== $net ? $net : $ip ) . '_' . (int) floor( time() / HOUR_IN_SECONDS ), HOUR_IN_SECONDS );
			if ( $issued > $cap ) {
				$retry = HOUR_IN_SECONDS - time() % HOUR_IN_SECONDS;
				header( 'Retry-After: ' . $retry );
				wp_send_json_error( array( 'retry_after' => $retry ), 429 );
			}
		}
		PNCP_Reputation::record( $ip, 'human' ); // 3.7: a person (or at least a browser that runs scripts) is behind it.
		$seconds = self::cookie_seconds( $ip ); // 3.13.0: shorter for a suspicious client.
		setcookie(
			self::COOKIE,
			self::cookie_value( $ip, $seconds ),
			array(
				'expires'  => time() + $seconds,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'secure'   => is_ssl(),
				'httponly' => false, // The script reads it, so it does not repeat the check on every page.
				'samesite' => 'Lax',
			)
		);
		if ( PNCP_Precheck::wanted() ) {
			setcookie(
				self::PC_COOKIE,
				self::pc_value( $ip, $seconds ),
				array(
					'expires'  => time() + $seconds,
					'path'     => COOKIEPATH ? COOKIEPATH : '/',
					'secure'   => is_ssl(),
					'httponly' => false, // The script reads it (see enqueue()).
					'samesite' => 'Lax',
				)
			);
		}
		wp_send_json_success();
	}
}

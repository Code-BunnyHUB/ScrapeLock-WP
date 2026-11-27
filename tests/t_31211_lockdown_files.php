<?php
/**
 * ScrapeLock 3.12.11 — τα αρχεία που γράφει το Κλείδωμα (Lockdown) δεν μοιάζουν πια με κακόβουλο λογισμικό που
 * μένει στο site (το Site Scanner της SiteGround έβαζε σε καραντίνα τον φύλακα της 3.12.10: PHP που φτιαχνόταν για
 * κάθε site, με base64(serialize()) μέσα, κρυφά προσωρινά αρχεία .php και αρχεία δεδομένων .php).
 *
 *   A. κλείδωμα με τον φύλακα: το μόνο .php είναι ο φύλακας, ίδιος byte προς byte με το includes/lockdown/guard.php
 *      (σταθερό hash)· οι τιμές των προστατευμένων ρυθμίσεων κρυπτογραφημένες (secretbox, hex), καμία σε καθαρό
 *      κείμενο, άλλο κλειδί δεν τις ανοίγει· τα δεδομένα σε JSON (guard.json, data-<hex>/snapshot.json, data-<hex>/fails.json) με index.html
 *      και .htaccess που αρνείται· πουθενά base64 ή serialize(), κανένα κρυφό ή προσωρινό αρχείο· το guard.json, που
 *      ο server δίνει σε όποιον το ζητήσει όπου δεν ισχύει το .htaccess, δεν έχει τίποτα μυστικό·
 *   B. ο φύλακας μόνος του (με ψεύτικα add_filter, όπως φορτώνεται πριν από το WordPress): ακολουθεί το γνήσιο
 *      guard.json, αρνείται αλλαγμένα δεδομένα, αλλαγμένη υπογραφή, άλλα κλειδιά (τότε μόνο το ScrapeLock μένει ενεργό),
 *      δεν κάνει τίποτα χωρίς guard.json ή με SCRAPELOCK_UNLOCK· αλλαγμένο snapshot.json → κανένα αντίγραφο·
 *   C. τιμές που η JSON δεν κρατά (bytes που δεν είναι UTF-8, INF, αντικείμενα, κλειδί «~pncp»): ίδιες μετά την
 *      ανάγνωση, η υπογραφή ταιριάζει·
 *   D. κλείδωμα χωρίς φύλακα: lock.json και fails.json στον ιδιωτικό φάκελο του uploads/scrapelock-lockdown, αλλαγμένο
 *      lock.json → δεν μετρά· σβήσιμο της κατάστασης στη βάση → μένει κλειδωμένο·
 *   E. ξεκλείδωμα: φεύγουν όλα (φάκελοι μαζί)·
 *   F. μετάβαση από την 3.12.10 (αρχεία φτιαγμένα όπως τα έγραφε η 3.12.10): ο παλιός φύλακας με το αντίγραφο σε base64
 *      και το fails.php γίνονται στατικός φύλακας + JSON στην πρώτη σελίδα του wp-admin, το site μένει κλειδωμένο όλη
 *      την ώρα (και με σβησμένο το αντίγραφο στη βάση), μια διακομμένη μετάβαση αφήνει τον παλιό φύλακα να δουλεύει·
 *      το παλιό lock-<hex>.php με fails-<hex>.php και index.php γίνεται lock.json (ίδια εγγραφή, διεύθυνση, ώρα)·
 *   G. απεγκατάσταση: ό,τι παλιό και νέο υπάρχει φεύγει (PNCP_Seal::remove_guard() / remove_beacon(), όπως στο
 *      uninstall.php).
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 WP_CLI="wp --path=…" php t_31211_lockdown_files.php
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );
if ( ! $wp_dir ) {
	fwrite( STDERR, "WP_DIR is required\n" );
	exit( 2 );
}
// Μια ρύθμιση widget με τιμές που η JSON δεν κρατά, πριν φορτώσει το WordPress: οι widget_* μπαίνουν στις
// προστατευμένες ρυθμίσεις όταν διαβάζονται οι επιλογές (PNCP_Lockdown::extra_options()), μία φορά ανά διεργασία.
$pncp_odd = null;
if ( '' !== $wp_cli ) {
	exec( $wp_cli . ' eval ' . escapeshellarg( 'update_option( "widget_pncp_t31211", array( "bin" => "\xff\xfeok", "f" => 1.0, "~pncp" => array( "x" => 1 ), "n" => null ), true );' ) . ' 2>&1', $pncp_out, $pncp_rc );
	$pncp_odd = 0 === $pncp_rc;
}
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
function skip( $label ) {
	echo 'SKIP ' . $label . "\n";
}
/** Καλεί μια ιδιωτική μέθοδο. */
function call( $class, $method, ...$args ) {
	$m = new ReflectionMethod( $class, $method );
	$m->setAccessible( true );
	return $m->invoke( null, ...$args );
}

/** Όπως ένα νέο αίτημα: η κατάσταση και τα αρχεία διαβάζονται ξανά (ο φύλακας δεν έτρεξε σε αυτή τη διεργασία). */
function fresh() {
	wp_cache_flush();
	clearstatcache();
	( function () {
		self::$state  = null;
		self::$tamper = '';
		self::$sig_ok = true;
		self::$older  = false;
	} )->bindTo( null, 'PNCP_Lockdown' )();
	( function () {
		$json = self::ours( self::path() ) ? self::guard_json() : null;
		if ( null !== $json ) {
			$record        = self::guard_record( $json );
			self::$current = null !== $record ? $record : self::record( false, 0 );
			self::$copy    = null;
			$copy          = '' !== self::legacy_guard_code() && preg_match( "/define\\( '" . self::COPY . "', '([A-Za-z0-9+\\/=]+)' \\);/", self::legacy_guard_code(), $m ) ? self::legacy_copy( $m[1] ) : self::read_snapshot_copy();
			self::$copy    = is_array( $copy ) ? $copy : false;
		} else {
			self::$current = null;
			self::$copy    = null;
		}
		self::$file          = null;
		self::$file_at_start = false;
		self::$config        = null;
		self::$net_digests   = null;
	} )->bindTo( null, 'PNCP_Seal' )();
}

/** Κλειδώνει όπως η σελίδα του Κλειδώματος (κατάσταση, φύλακας ή αρχείο κλειδώματος, αντίγραφο ρυθμίσεων). */
function lock_now() {
	fresh();
	( function () {
		$s                   = self::state();
		$s['locked']         = true;
		$s['until']          = 0;
		$s['since']          = time();
		$s['ack']            = true;
		$s['unlocked_by']    = 0;
		$s['unlock_session'] = '';
		self::save( $s );
	} )->bindTo( null, 'PNCP_Lockdown' )();
	PNCP_Seal::take_snapshot();
	fresh();
}

/** Ξεκλειδώνει «μέχρι να το κλειδώσω ξανά». */
function unlock_now() {
	fresh();
	( function () {
		$s          = self::state();
		$s['locked'] = false;
		$s['until']  = 0;
		self::save( $s, true );
	} )->bindTo( null, 'PNCP_Lockdown' )();
	PNCP_Seal::forget_snapshots();
	fresh();
}

/** Όλα τα αρχεία κάτω από φακέλους (σχετικά με το wp-content), ταξινομημένα. */
function files_under( $dirs ) {
	$out     = array();
	$content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
	foreach ( (array) $dirs as $dir ) {
		if ( ! is_dir( $dir ) ) {
			continue;
		}
		foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) ) as $f ) {
			$out[] = substr( wp_normalize_path( $f->getPathname() ), strlen( $content ) + 1 );
		}
	}
	sort( $out );
	return $out;
}

/** Υπάρχει κάτι που μοιάζει με base64 ή με serialize() σε ένα κείμενο; */
function looks_encoded( $text, $code = false ) {
	// Ένα string σε εισαγωγικά με 200+ χαρακτήρες base64 (το base64_long του amwscan: 260+): ποτέ, ούτε hex.
	if ( preg_match( '#["\'][A-Za-z0-9+/]{200,}#', $text ) ) {
		return 'a long quoted string';
	}
	if ( $code ) {
		return '';
	}
	if ( preg_match( '/(?:^|[^A-Za-z0-9])(?:a:\d+:\{|s:\d+:"|O:\d+:"|i:\d+;|b:[01];)/', $text ) ) {
		return 'serialize';
	}
	if ( preg_match_all( '#[A-Za-z0-9+/]{40,}={0,2}#', $text, $m ) ) {
		foreach ( $m[0] as $run ) {
			if ( ! preg_match( '/^[0-9a-f]+$/', $run ) ) {
				return 'base64: ' . substr( $run, 0, 40 );
			}
		}
	}
	return false !== stripos( $text, 'base64' ) ? 'the word base64' : '';
}

/** Τα αρχεία δεδομένων του Κλειδώματος: κανένα PHP, κανένα κρυφό εκτός από .htaccess, τίποτα κωδικοποιημένο. */
function check_data_files( $label, $files ) {
	$content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
	$php     = array();
	$hidden  = array();
	$coded   = array();
	foreach ( $files as $rel ) {
		$name = basename( $rel );
		if ( 'mu-plugins/scrapelock-lockdown-guard.php' !== $rel && preg_match( '/\.php|\.phtml|\.phar/i', $name ) ) {
			$php[] = $rel;
		}
		if ( '.' === $name[0] && '.htaccess' !== $name ) {
			$hidden[] = $rel;
		}
		$why = looks_encoded( (string) file_get_contents( $content . '/' . $rel ), 'mu-plugins/scrapelock-lockdown-guard.php' === $rel );
		if ( '' !== $why ) {
			$coded[] = $rel . ' (' . $why . ')';
		}
	}
	t( $label . ': κανένα αρχείο .php εκτός από τον φύλακα', ! $php, implode( ' ', $php ) );
	t( $label . ': κανένα κρυφό αρχείο εκτός από .htaccess, κανένα προσωρινό', ! $hidden && ! preg_grep( '/\.tmp/', $files ), implode( ' ', array_merge( $hidden, preg_grep( '/\.tmp/', $files ) ) ) );
	t( $label . ': πουθενά base64, serialize() ή string 200+ χαρακτήρων base64', ! $coded, implode( ' ', $coded ) );
}

/** Καμία προστατευμένη τιμή σε καθαρό κείμενο: ούτε το μυστικό, ούτε το email του διαχειριστή. */
function check_no_clear( $label, $files ) {
	global $pncp_secret;
	$content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
	$found   = array();
	foreach ( $files as $rel ) {
		$text = (string) file_get_contents( $content . '/' . $rel );
		if ( 'lock.json' === basename( $rel ) ) {
			// Η διεύθυνση των ειδοποιήσεων ("mail") είναι μέρος της υπογεγραμμένης εγγραφής, αναγνώσιμη όπως πριν.
			$data = json_decode( $text, true );
			unset( $data['mail'] );
			$text = (string) wp_json_encode( $data );
		}
		foreach ( array( $pncp_secret, (string) get_option( 'admin_email' ), wp_json_encode( (string) get_option( 'siteurl' ) ) ) as $needle ) {
			if ( false !== strpos( $text, $needle ) || false !== strpos( $text, trim( (string) wp_json_encode( $needle ), '"' ) ) ) {
				$found[] = $rel . ': ' . $needle;
			}
		}
	}
	t( $label . ': καμία προστατευμένη τιμή σε καθαρό κείμενο (μυστικό, email, διεύθυνση)', ! $found, implode( ' ', $found ) );
}

/** Τρέχει τον φύλακα μόνο του σε άλλη διεργασία, όπως πριν από το WordPress: τι ορίζει και τι φίλτρα βάζει. */
function run_guard( $consts = array() ) {
	$runner = get_temp_dir() . 'pncp-t31211-guard-' . wp_generate_password( 6, false ) . '.php';
	$defs   = array_merge(
		array(
			'ABSPATH'       => ABSPATH,
			'WP_PLUGIN_DIR' => WP_PLUGIN_DIR,
			'AUTH_KEY'      => AUTH_KEY,
			'AUTH_SALT'     => AUTH_SALT,
		),
		defined( 'SCRAPELOCK_KEY' ) ? array( 'SCRAPELOCK_KEY' => SCRAPELOCK_KEY ) : array(),
		$consts
	);
	$code   = "<?php\n";
	foreach ( $defs as $name => $value ) {
		$code .= 'define( ' . var_export( $name, true ) . ', ' . var_export( $value, true ) . " );\n";
	}
	$code .= '$GLOBALS["f"] = array();' . "\n"
		. 'function add_filter( $h, $cb ) { $GLOBALS["f"][ $h ] = $cb; }' . "\n"
		. 'function is_multisite() { return false; }' . "\n"
		. 'include ' . var_export( PNCP_Seal::path(), true ) . ";\n"
		. '$a = isset( $GLOBALS["f"]["option_active_plugins"] ) ? $GLOBALS["f"]["option_active_plugins"]( array( "evil/evil.php" ), "active_plugins" ) : null;' . "\n"
		. '$s = isset( $GLOBALS["f"]["option_stylesheet"] ) ? $GLOBALS["f"]["option_stylesheet"]( "evil-theme", "stylesheet" ) : null;' . "\n"
		. 'echo json_encode( array( "beacon" => defined( "PNCP_LOCKDOWN_BEACON" ) ? PNCP_LOCKDOWN_BEACON : null, "v" => defined( "PNCP_LOCKDOWN_GUARD" ) ? PNCP_LOCKDOWN_GUARD : 0, "filters" => count( $GLOBALS["f"] ), "active" => $a, "stylesheet" => $s ) );' . "\n";
	file_put_contents( $runner, $code );
	exec( 'php ' . escapeshellarg( $runner ) . ' 2>&1', $out, $rc );
	unlink( $runner );
	$res = json_decode( implode( "\n", $out ), true );
	return is_array( $res ) ? $res : array( 'error' => implode( "\n", $out ) );
}

/** Ένα αίτημα HTTP στο site (με cookies). */
function http( $path, $cookies = array() ) {
	global $base;
	$ch = curl_init( $base . $path );
	curl_setopt_array(
		$ch,
		array(
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_TIMEOUT        => 60,
			CURLOPT_COOKIE         => implode( '; ', array_map( static function ( $k, $v ) { return $k . '=' . rawurlencode( $v ); }, array_keys( $cookies ), $cookies ) ),
		)
	);
	$body = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
	curl_close( $ch );
	return array( $code, $body );
}

/** Οι μετρητές λάθος κωδικών αποθηκεύονται (βάση και αντίγραφο στο αρχείο). */
function save_fails( $count ) {
	$now = time();
	call( 'PNCP_Lockdown', 'fails_save', array( 'pncp_t31211' => array( 'n' => $count, 'start' => $now, 'until' => 0, 'level' => 0, 'last' => $now ) ) );
}

/** Οι μετρητές όπως τους διαβάζει το Κλείδωμα. */
function fails_now() {
	return call( 'PNCP_Lockdown', 'fails_file_read' );
}

// Καθαρή αρχή: κανένα κλείδωμα, κανένα αρχείο από προηγούμενη εκτέλεση.
PNCP_Seal::remove_guard();
PNCP_Seal::remove_beacon();
PNCP_Lockdown::fails_remove();
foreach ( array( PNCP_Seal::SNAP, PNCP_Seal::DIGESTS, PNCP_Seal::WINDOW ) as $pncp_o ) {
	delete_option( $pncp_o );
}
foreach ( array( PNCP_Lockdown::OPTION, PNCP_Lockdown::FAILS_OPTION ) as $pncp_o ) {
	delete_site_option( $pncp_o );
}
add_filter( 'pre_wp_mail', '__return_false' );
// Μια μυστική τιμή σε προστατευμένη ρύθμιση (οι ρυθμίσεις PayPal του WooCommerce): δεν φαίνεται σε κανένα αρχείο.
$pncp_secret = 'PNCP-SECRET-' . wp_generate_password( 16, false );
update_option( 'woocommerce_paypal_settings', array( 'api_password' => $pncp_secret ) );
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'monitor_mode' => 0, 'monitor_until' => 0 ) ) );
PNCP_Options::flush();
fresh();
if ( PNCP_Lockdown::is_locked() || PNCP_Lockdown::server_unlocked() ) {
	echo "FAIL το site των δοκιμών είναι ήδη κλειδωμένο (ή έχει SCRAPELOCK_UNLOCK): καμία δοκιμή δεν έτρεξε\n";
	exit( 1 );
}
register_shutdown_function(
	static function () {
		$GLOBALS['pncp_t31211_done'] = true;
		@chmod( PNCP_Paths::mu_plugins(), 0755 );
		@chmod( PNCP_Seal::path(), 0644 );
		unlock_now();
		PNCP_Seal::remove_guard();
		PNCP_Seal::remove_beacon();
		PNCP_Lockdown::fails_remove();
		delete_option( 'widget_pncp_t31211' );
		delete_option( 'woocommerce_paypal_settings' );
	}
);

$mu       = PNCP_Paths::mu_plugins();
$data_dir = PNCP_Seal::data_dir();
$guard    = PNCP_Seal::path();
$shipped  = PNCP_DIR . 'includes/lockdown/guard.php';
$priv     = PNCP_Seal::guard_private_dir();
$up_dir   = PNCP_Seal::beacon_dirs()[0];

/* ---------- A. Κλείδωμα με τον φύλακα ---------- */

if ( ! PNCP_Seal::can_write_guard() ) {
	skip( 'A–C: ο φύλακας δεν γράφεται σε αυτό το WordPress' );
} else {
	lock_now();
	save_fails( 2 );
	t( 'A κλειδωμένο με τον φύλακα, χωρίς ένδειξη παρέμβασης', PNCP_Lockdown::is_locked() && PNCP_Seal::guard_installed() && '' === PNCP_Lockdown::tampered(), PNCP_Lockdown::tampered() );
	$pncp_files = files_under( array( $data_dir ) );
	$pncp_rel   = substr( wp_normalize_path( $priv ), strlen( untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) ) + 1 );
	$pncp_want  = array( 'mu-plugins/scrapelock-lockdown-data/.htaccess', 'mu-plugins/scrapelock-lockdown-data/guard.json', 'mu-plugins/scrapelock-lockdown-data/index.html', $pncp_rel . '/fails.json', $pncp_rel . '/guard-values.json', $pncp_rel . '/index.html', $pncp_rel . '/snapshot.json' );
	sort( $pncp_want );
	t( 'A τα αρχεία δεδομένων: guard.json, index.html, .htaccess, data-<hex>/{snapshot.json, fails.json, guard-values.json, index.html}', $pncp_want === $pncp_files && 1 === preg_match( '#/data-[0-9a-f]{20}$#', $pncp_rel ), implode( ' ', $pncp_files ) );
	t( 'A ο φύλακας είναι ακριβώς το αρχείο του plugin (ίδιο hash σε κάθε site)', is_file( $guard ) && hash_file( 'sha256', $shipped ) === hash_file( 'sha256', $guard ) );
	$pncp_mu_php = array_values( preg_grep( '/scrapelock/i', array_map( 'basename', (array) glob( $mu . '/*' ) ) ) );
	t( 'A στο mu-plugins: μόνο ο φύλακας και ο φάκελος δεδομένων (και το scrapelock-lockdown.lock των ελέγχων κωδικού)', array() === array_diff( $pncp_mu_php, array( 'scrapelock-lockdown-guard.php', 'scrapelock-lockdown-data', 'scrapelock-lockdown.lock', 'scrapelock-early.php' ) ), implode( ' ', $pncp_mu_php ) );
	check_data_files( 'A', array_merge( $pncp_files, array( 'mu-plugins/scrapelock-lockdown-guard.php' ) ) );
	$pncp_shipped_src = (string) file_get_contents( $shipped );
	t( 'A ο φύλακας: κεφαλίδα ScrapeLock, τι κάνει, πώς βγαίνει (SCRAPELOCK_UNLOCK / σβήσιμο), χωρίς base64 / eval / serialize', false !== strpos( $pncp_shipped_src, 'Plugin Name: ScrapeLock Lockdown guard' ) && false !== strpos( $pncp_shipped_src, "define( 'SCRAPELOCK_UNLOCK', true );" ) && false !== strpos( $pncp_shipped_src, 'or delete this file' ) && ! preg_match( '/base64|eval\s*\(|serialize\s*\(|gzinflate|str_rot13/i', $pncp_shipped_src ) );
	t( 'A .htaccess που αρνείται και index.html «Silence is golden», ίδιο με το DIR_INDEX', false !== strpos( (string) file_get_contents( $data_dir . '/.htaccess' ), 'Require all denied' ) && PNCP_Seal::DIR_INDEX === file_get_contents( $data_dir . '/index.html' ) && PNCP_Seal::DIR_INDEX === file_get_contents( $priv . '/index.html' ) && '' !== PNCP_Seal::DIR_INDEX );
	$pncp_gj = json_decode( (string) file_get_contents( $data_dir . '/guard.json' ), true );
	t( 'A guard.json: αναγνώσιμο JSON με about / data / sig', is_array( $pncp_gj ) && isset( $pncp_gj['about'], $pncp_gj['data'], $pncp_gj['sig'] ) && false !== strpos( $pncp_gj['about'], 'ScrapeLock' ) && 1 === preg_match( '/^[0-9a-f]{64}$/', $pncp_gj['sig'] ) );
	// 3.13.0: τα plugins και το θέμα όχι στο guard.json (σταθερό όνομα, ορατό σε Nginx) αλλά στον ιδιωτικό φάκελο.
	t( 'A guard.json (3.13.0): μόνο η εγγραφή του κλειδώματος και το αρχείο του ScrapeLock, όχι plugins / θέμα (τίποτα μυστικό)', is_array( $pncp_gj ) && array( 'beacon', 'multisite', 'own' ) === ( function ( $k ) { sort( $k ); return $k; } )( array_keys( $pncp_gj['data'] ) ) && false === strpos( (string) file_get_contents( $data_dir . '/guard.json' ), (string) get_option( 'stylesheet' ) ) && false === strpos( (string) file_get_contents( $data_dir . '/guard.json' ), (string) get_option( 'admin_email' ) ) && false === strpos( (string) file_get_contents( $data_dir . '/guard.json' ), AUTH_KEY ) );
	$pncp_vj = json_decode( (string) @file_get_contents( PNCP_Seal::guard_values_path() ), true );
	t( 'A guard-values.json (3.13.0): στον ιδιωτικό φάκελο, υπογεγραμμένο, με τις γενιές της εγγραφής και τα plugins / θέμα', is_array( $pncp_vj ) && dirname( PNCP_Seal::guard_values_path() ) === PNCP_Seal::guard_private_dir() && isset( $pncp_vj['data']['values'], $pncp_vj['sig'] ) && 'values' === $pncp_vj['data']['kind'] && (int) $pncp_vj['data']['gen'] === (int) $pncp_gj['data']['beacon']['gen'] && (int) $pncp_vj['data']['snap'] === (int) $pncp_gj['data']['beacon']['snap'] && array() === array_diff( array_keys( (array) $pncp_vj['data']['values'] ), array( 'active_plugins', 'template', 'stylesheet' ) ) && hash_equals( PNCP_Seal::guard_sign( $pncp_vj['data'] ), $pncp_vj['sig'] ), wp_json_encode( $pncp_vj ) );
	$pncp_sj = json_decode( (string) file_get_contents( $priv . '/snapshot.json' ), true );
	$pncp_db = PNCP_Seal::snapshot();
	t( 'A snapshot.json: τα στοιχεία αναγνώσιμα (gen, sig, admins), οι τιμές κρυπτογραφημένες (secretbox, hex)', is_array( $pncp_sj ) && isset( $pncp_sj['snapshot']['sig'], $pncp_sj['snapshot']['gen'], $pncp_sj['snapshot']['admins'] ) && 'box' === ( $pncp_sj['snapshot']['values']['~pncp'] ?? '' ) && is_array( $pncp_sj['snapshot']['values']['v'] ?? null ) && 1 === preg_match( '/^[0-9a-f]{200,}$/', implode( '', $pncp_sj['snapshot']['values']['v'] ) ) && array() === array_filter( $pncp_sj['snapshot']['values']['v'], static function ( $l ) { return strlen( $l ) > 128; } ) && is_array( $pncp_db ) );
	check_no_clear( 'A', array_merge( $pncp_files, array( 'mu-plugins/scrapelock-lockdown-guard.php' ) ) );
	$pncp_hex = implode( '', $pncp_sj['snapshot']['values']['v'] );
	$pncp_raw = (string) hex2bin( $pncp_hex );
	$pncp_key = call( 'PNCP_Seal', 'box_key' );
	$pncp_wrong = hash_hmac( 'sha256', 'pncp_lockdown_values_box', hash( 'sha256', 'another site|pncp_lockdown_sig', true ), true );
	t( 'A το σωστό κλειδί ανοίγει τις τιμές, με το μυστικό μέσα', false !== strpos( (string) sodium_crypto_secretbox_open( substr( $pncp_raw, 24 ), substr( $pncp_raw, 0, 24 ), $pncp_key ), $pncp_secret ) );
	t( 'A άλλο κλειδί δεν τις ανοίγει', false === sodium_crypto_secretbox_open( substr( $pncp_raw, 24 ), substr( $pncp_raw, 0, 24 ), $pncp_wrong ) );
	$pncp_open = static function ( $v ) use ( $pncp_sj ) {
		return call( 'PNCP_Seal', 'open_copy', array_merge( $pncp_sj['snapshot'], array( 'values' => array( '~pncp' => 'box', 'v' => $v ) ) ) );
	};
	t( 'A οι γραμμές hex ενωμένες: το αντίγραφο ανοίγει', is_array( $pncp_open( $pncp_sj['snapshot']['values']['v'] ) ) );
	t( 'A ένα αλλαγμένο byte στο κρυπτογράφημα: κανένα αντίγραφο', null === $pncp_open( str_split( substr( $pncp_hex, 0, -2 ) . ( '00' === substr( $pncp_hex, -2 ) ? '01' : '00' ), 128 ) ) );
	t( 'A γραμμή που δεν είναι hex, μονό μήκος, ένα string αντί για γραμμές: κανένα αντίγραφο', null === $pncp_open( array_merge( array( 'zz' ), $pncp_sj['snapshot']['values']['v'] ) ) && null === $pncp_open( str_split( substr( $pncp_hex, 1 ), 128 ) ) && null === $pncp_open( $pncp_hex ) );
	t( 'A η σφραγίδα ξαναγράφει τα αρχεία μόνο όταν αλλάζουν (ίδιο snapshot.json μετά από νέα εγγραφή)', ( function () use ( $priv ) {
		$before = (string) file_get_contents( $priv . '/snapshot.json' );
		$state  = PNCP_Lockdown::state();
		return PNCP_Seal::write_guard( true, 0, (int) $state['gen'], (int) $state['snap'] ) && file_get_contents( $priv . '/snapshot.json' ) === $before;
	} )() );
	t( 'A snapshot.json: γνήσιο, το ίδιο με τη βάση', ( function () {
		$copy = self::guard_copy();
		return null !== $copy && self::snapshot_record() === $copy;
	} )->bindTo( null, 'PNCP_Seal' )() );
	t( 'A fails.json: οι μετρητές (JSON) και μετρούν', 2 === (int) ( fails_now()['rows']['pncp_t31211']['n'] ?? 0 ) && is_array( json_decode( (string) file_get_contents( PNCP_Lockdown::fails_file() ), true ) ) );
	// Ο server των δοκιμών (όπως ένας Nginx) δίνει τα .json: το guard.json δεν έχει τίποτα μυστικό, το όνομα του
	// ιδιωτικού φακέλου δεν μαντεύεται, ο φύλακας δεν δείχνει τίποτα.
	$pncp_mu_url = '/' . substr( wp_normalize_path( $mu ), strlen( untrailingslashit( wp_normalize_path( ABSPATH ) ) ) + 1 );
	list( $pncp_c, $pncp_b ) = http( $pncp_mu_url . '/scrapelock-lockdown-guard.php' );
	t( 'A ο φύλακας μέσω HTTP: κενή απάντηση (ABSPATH)', '' === trim( $pncp_b ), $pncp_c . ' ' . substr( $pncp_b, 0, 80 ) );
	list( $pncp_c ) = http( '/' );
	t( 'A το site απαντά κλειδωμένο με τον στατικό φύλακα', 200 === $pncp_c, (string) $pncp_c );
	t( 'A ο έλεγχος ακεραιότητας: ο φύλακας γνήσιος', PNCP_Seal::guard_genuine() );

	/* ---------- B. Ο φύλακας μόνος του ---------- */

	$pncp_r = run_guard();
	$pncp_own = plugin_basename( PNCP_FILE );
	t( 'B γνήσιο guard.json: ορίζει PNCP_LOCKDOWN_BEACON (υπογεγραμμένο, ίδιο με τον δίσκο), κρατά plugins και θέμα', isset( $pncp_r['beacon'] ) && is_string( $pncp_r['beacon'] ) && null !== call( 'PNCP_Seal', 'guard_record', $pncp_r['beacon'] ) && 3 === $pncp_r['v'] && 6 === $pncp_r['filters'] && is_array( $pncp_r['active'] ) && ! in_array( 'evil/evil.php', $pncp_r['active'], true ) && in_array( $pncp_own, $pncp_r['active'], true ) && get_option( 'stylesheet' ) === $pncp_r['stylesheet'], wp_json_encode( $pncp_r ) );
	$pncp_gtext = (string) file_get_contents( $data_dir . '/guard.json' );
	$pncp_bad   = $pncp_gj;
	$pncp_bad['data']['values']['active_plugins'][] = 'evil/evil.php';
	file_put_contents( $data_dir . '/guard.json', wp_json_encode( $pncp_bad ) );
	$pncp_r = run_guard();
	t( 'B αλλαγμένα δεδομένα (ένα plugin ακόμη): δεν ακολουθούνται, μόνο το ScrapeLock μένει ενεργό', null === $pncp_r['beacon'] && 6 === $pncp_r['filters'] && array( 'evil/evil.php', $pncp_own ) === $pncp_r['active'] && 'evil-theme' === $pncp_r['stylesheet'], wp_json_encode( $pncp_r ) );
	fresh();
	t( 'B αλλαγμένα δεδομένα: ούτε το ScrapeLock τα δέχεται', null === PNCP_Seal::read_guard_data() && ! PNCP_Seal::guard_genuine() );
	$pncp_bad        = $pncp_gj;
	$pncp_bad['sig'] = str_repeat( '0', 64 );
	file_put_contents( $data_dir . '/guard.json', wp_json_encode( $pncp_bad ) );
	$pncp_r = run_guard();
	t( 'B αλλαγμένη υπογραφή: δεν ακολουθείται', null === $pncp_r['beacon'] && array( 'evil/evil.php', $pncp_own ) === $pncp_r['active'], wp_json_encode( $pncp_r ) );
	file_put_contents( $data_dir . '/guard.json', $pncp_gtext );
	$pncp_r = run_guard( array( 'AUTH_KEY' => 'another key of another site, 64 characters long, for the guard test!', 'SCRAPELOCK_KEY' => 'another ScrapeLock key of another site, long enough for the guard test' ) );
	t( 'B άλλα κλειδιά στο wp-config.php: δεν ακολουθείται', null === $pncp_r['beacon'] && array( 'evil/evil.php', $pncp_own ) === $pncp_r['active'], wp_json_encode( $pncp_r ) );
	// 3.13.0: guard-values.json αλλαγμένο, ή υπογεγραμμένο για άλλη γενιά: η εγγραφή ισχύει, οι λίστες όχι.
	$pncp_vpath = PNCP_Seal::guard_values_path();
	$pncp_vtext = (string) file_get_contents( $pncp_vpath );
	$pncp_vbad  = $pncp_vj;
	$pncp_vbad['data']['values']['active_plugins'][] = 'evil/evil.php';
	file_put_contents( $pncp_vpath, wp_json_encode( $pncp_vbad ) );
	$pncp_r = run_guard();
	t( 'B αλλαγμένο guard-values.json: οι λίστες δεν ακολουθούνται (η εγγραφή ναι), μόνο το ScrapeLock μένει ενεργό', is_string( $pncp_r['beacon'] ) && array( 'evil/evil.php', $pncp_own ) === $pncp_r['active'] && 'evil-theme' === $pncp_r['stylesheet'], wp_json_encode( $pncp_r ) );
	$pncp_vbad                 = $pncp_vj;
	$pncp_vbad['data']['gen'] = (int) $pncp_vbad['data']['gen'] - 1;
	$pncp_vbad['sig']         = PNCP_Seal::guard_sign( $pncp_vbad['data'] );
	file_put_contents( $pncp_vpath, wp_json_encode( $pncp_vbad ) );
	$pncp_r = run_guard();
	t( 'B guard-values.json άλλου κλειδώματος (άλλη γενιά, γνήσια υπογραφή): δεν ακολουθείται', is_string( $pncp_r['beacon'] ) && array( 'evil/evil.php', $pncp_own ) === $pncp_r['active'], wp_json_encode( $pncp_r ) );
	file_put_contents( $pncp_vpath, $pncp_vtext );
	$pncp_r = run_guard();
	t( 'B guard-values.json όπως ήταν: ακολουθείται πάλι', is_string( $pncp_r['beacon'] ) && ! in_array( 'evil/evil.php', $pncp_r['active'], true ) && get_option( 'stylesheet' ) === $pncp_r['stylesheet'], wp_json_encode( $pncp_r ) );
	$pncp_r = run_guard( array( 'SCRAPELOCK_UNLOCK' => true ) );
	t( 'B SCRAPELOCK_UNLOCK: τίποτα δεν κρατιέται (η εγγραφή ορίζεται για το ScrapeLock)', is_string( $pncp_r['beacon'] ) && 0 === $pncp_r['filters'], wp_json_encode( $pncp_r ) );
	rename( $data_dir . '/guard.json', $data_dir . '/guard.json.away' );
	$pncp_r = run_guard();
	t( 'B χωρίς guard.json: ο φύλακας δεν κάνει τίποτα', null === $pncp_r['beacon'] && 0 === $pncp_r['filters'], wp_json_encode( $pncp_r ) );
	rename( $data_dir . '/guard.json.away', $data_dir . '/guard.json' );
	$pncp_r = run_guard();
	t( 'B πίσω το γνήσιο: ακολουθείται ξανά', is_string( $pncp_r['beacon'] ) && 6 === $pncp_r['filters'] );
	$pncp_stext = (string) file_get_contents( $priv . '/snapshot.json' );
	$pncp_bad   = $pncp_sj;
	$pncp_bad['snapshot']['admins'] = array( 999 );
	file_put_contents( $priv . '/snapshot.json', wp_json_encode( $pncp_bad ) );
	fresh();
	t( 'B αλλαγμένο snapshot.json: κανένα αντίγραφο (η υπογραφή δεν ταιριάζει)', null === call( 'PNCP_Seal', 'guard_copy' ) );
	file_put_contents( $priv . '/snapshot.json', $pncp_stext );
	fresh();
	t( 'B πίσω το γνήσιο snapshot.json: μετρά ξανά', null !== call( 'PNCP_Seal', 'guard_copy' ) );

	/* ---------- C. Τιμές που η JSON δεν κρατά ---------- */

	$pncp_obj    = new stdClass();
	$pncp_obj->a = array( 1, 2.5 );
	$pncp_vals   = array(
		'bin'   => "\xff\xfe\x00 not utf-8",
		"k\xff" => 'a key that is not UTF-8',
		'float' => 1.0,
		'inf'   => INF,
		'obj'   => $pncp_obj,
		'~pncp' => array( 'v' => 'hex' ),
		'list'  => array( 'a', array( '~pncp' => 'hex', 'v' => 'zz' ) ),
		'empty' => array(),
		'null'  => null,
		'big'   => PHP_INT_MAX,
		'str'   => 'Δοκιμή <script> & "quotes"',
	);
	$pncp_text = PNCP_Seal::json_text( array( 'v' => PNCP_Seal::pack( $pncp_vals ) ) );
	$pncp_back = PNCP_Seal::unpack( json_decode( $pncp_text, true )['v'] );
	t( 'C bytes / κλειδιά που δεν είναι UTF-8, 1.0, INF, αντικείμενο, κλειδί «~pncp»: ίδια μετά την ανάγνωση', '' !== $pncp_text && $pncp_back == $pncp_vals && $pncp_back['bin'] === $pncp_vals['bin'] && is_float( $pncp_back['float'] ) && is_infinite( $pncp_back['inf'] ) && $pncp_back['obj'] instanceof stdClass && $pncp_vals['list'] === $pncp_back['list'] && $pncp_vals['~pncp'] === $pncp_back['~pncp'] && PHP_INT_MAX === $pncp_back['big'] && array_key_exists( "k\xff", $pncp_back ), $pncp_text );
	t( 'C η υπογραφή ταιριάζει μετά την ανάγνωση', PNCP_Seal::valid( $pncp_back, PNCP_Seal::sign( $pncp_vals ) ) );
	t( 'C το κείμενο: hex για τα bytes, κανένα «<» (JSON_HEX_TAG)', false !== strpos( $pncp_text, '"~pncp": "hex"' ) && false === strpos( $pncp_text, '<' ) && '' === looks_encoded( $pncp_text ) );
	if ( true === $pncp_odd ) {
		$pncp_copy = call( 'PNCP_Seal', 'guard_copy' );
		$pncp_w    = is_array( $pncp_copy ) && isset( $pncp_copy['values']['widget_pncp_t31211'] ) ? $pncp_copy['values']['widget_pncp_t31211'] : null;
		t( 'C στο κλείδωμα: η ρύθμιση widget με bytes / 1.0 / «~pncp» ίδια στο snapshot.json και γνήσια', is_array( $pncp_w ) && "\xff\xfeok" === $pncp_w['bin'] && is_float( $pncp_w['f'] ) && array( 'x' => 1 ) === $pncp_w['~pncp'] && get_option( 'widget_pncp_t31211' ) === $pncp_w, wp_json_encode( $pncp_w ) );
	} else {
		skip( 'C ρύθμιση widget στο κλείδωμα (χωρίς WP_CLI)' );
	}

	/* ---------- E. Ξεκλείδωμα: φεύγουν όλα ---------- */

	unlock_now();
	t( 'E ξεκλείδωμα: ούτε φύλακας ούτε φάκελος δεδομένων', ! PNCP_Lockdown::is_locked() && ! file_exists( $guard ) && ! file_exists( $data_dir ), implode( ' ', files_under( array( $data_dir ) ) ) );
}

/* ---------- D. Κλείδωμα χωρίς φύλακα (αρχείο κλειδώματος) ---------- */

$pncp_ftp = static function () {
	return 'ftpext';
};
add_filter( 'filesystem_method', $pncp_ftp );
fresh();
if ( PNCP_Seal::can_write_guard() || '' === PNCP_Seal::beacon_writable_dir() ) {
	skip( 'D: χωρίς φύλακα δεν δοκιμάζεται εδώ' );
} else {
	lock_now();
	save_fails( 3 );
	$pncp_bp = PNCP_Seal::beacon_path();
	t( 'D κλειδωμένο με το αρχείο κλειδώματος, χωρίς φύλακα', PNCP_Lockdown::is_locked() && ! PNCP_Seal::guard_installed() && '' === PNCP_Lockdown::tampered() && wp_normalize_path( PNCP_Seal::beacon_private( $up_dir ) . '/lock.json' ) === wp_normalize_path( $pncp_bp ), $pncp_bp );
	$pncp_files = files_under( array( $up_dir ) );
	$pncp_rel   = substr( wp_normalize_path( PNCP_Seal::beacon_private( $up_dir ) ), strlen( untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) ) ) + 1 );
	$pncp_want  = array( 'uploads/scrapelock-lockdown/.htaccess', 'uploads/scrapelock-lockdown/index.html', $pncp_rel . '/fails.json', $pncp_rel . '/index.html', $pncp_rel . '/lock.json' );
	sort( $pncp_want );
	t( 'D τα αρχεία: .htaccess, index.html, data-<hex>/{lock.json, fails.json, index.html}', $pncp_want === $pncp_files, implode( ' ', $pncp_files ) );
	check_data_files( 'D', $pncp_files );
	$pncp_lj = json_decode( (string) file_get_contents( $pncp_bp ), true );
	t( 'D lock.json: αναγνώσιμο, η εγγραφή ως αντικείμενο, το αντίγραφο ως JSON με τις τιμές κρυπτογραφημένες', is_array( $pncp_lj ) && isset( $pncp_lj['about'], $pncp_lj['beacon']['sig'], $pncp_lj['xsig'], $pncp_lj['copy']['sig'] ) && 'box' === ( $pncp_lj['copy']['values']['~pncp'] ?? '' ) && ! empty( $pncp_lj['beacon']['locked'] ) && null !== call( 'PNCP_Seal', 'guard_copy' ) );
	check_no_clear( 'D', $pncp_files );
	t( 'D lock.json: καμία μυστική τιμή του κλειδιού (μόνο υπογραφές)', false === strpos( (string) file_get_contents( $pncp_bp ), AUTH_KEY ) && false === strpos( (string) file_get_contents( $pncp_bp ), AUTH_SALT ) );
	t( 'D ο φάκελος στα μηνύματα: χωρίς το όνομα του ιδιωτικού φακέλου', wp_normalize_path( $up_dir ) === wp_normalize_path( PNCP_Seal::beacon_folder() ) && false === strpos( wp_json_encode( get_site_option( PNCP_Lockdown::LOG_OPTION ) ), PNCP_Seal::private_name() ) );
	t( 'D fails.json δίπλα στο lock.json, μετρά', 3 === (int) ( fails_now()['rows']['pncp_t31211']['n'] ?? 0 ) && dirname( $pncp_bp ) . '/fails.json' === PNCP_Seal::beacon_fails_path() );
	$pncp_ltext = (string) file_get_contents( $pncp_bp );
	$pncp_bad   = $pncp_lj;
	$pncp_bad['beacon']['until'] = time() + 86400;
	file_put_contents( $pncp_bp, wp_json_encode( $pncp_bad ) );
	fresh();
	t( 'D αλλαγμένο lock.json (ξεκλείδωμα για μια μέρα): δεν μετρά', '' === PNCP_Seal::beacon_path() );
	file_put_contents( $pncp_bp, $pncp_ltext );
	// Όπως ένα SQL injection: η γραμμή στη βάση, χωρίς τα φίλτρα του WordPress (που το Κλείδωμα ελέγχει).
	global $wpdb;
	$pncp_state = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", PNCP_Lockdown::OPTION ) );
	$wpdb->delete( $wpdb->options, array( 'option_name' => PNCP_Lockdown::OPTION ) );
	fresh();
	t( 'D σβησμένη κατάσταση στη βάση: το lock.json το κρατά κλειδωμένο', PNCP_Lockdown::is_locked() && 'replay' === PNCP_Lockdown::tampered(), PNCP_Lockdown::tampered() );
	$wpdb->insert( $wpdb->options, array( 'option_name' => PNCP_Lockdown::OPTION, 'option_value' => $pncp_state, 'autoload' => 'off' ) );
	fresh();
	t( 'D πίσω η κατάσταση: όλα κανονικά', PNCP_Lockdown::is_locked() && '' === PNCP_Lockdown::tampered(), PNCP_Lockdown::tampered() );
	unlock_now();
	t( 'E ξεκλείδωμα χωρίς φύλακα: ο φάκελος του αρχείου κλειδώματος φεύγει όλος', ! PNCP_Lockdown::is_locked() && ! file_exists( $up_dir ), implode( ' ', files_under( array( $up_dir ) ) ) );
}
remove_filter( 'filesystem_method', $pncp_ftp );
fresh();

/* ---------- F. Μετάβαση από την 3.12.10 ---------- */

/**
 * Ο φύλακας όπως τον έγραφε η 3.12.10 (PNCP_Seal::code(), ένα site): η εγγραφή και το αντίγραφο (base64 του
 * serialize()) μέσα στον κώδικα, και τα φίλτρα.
 */
function old_guard( $json, $copy, $own, $values, $until ) {
	$export = array( 'PNCP_Seal', 'php_value' );
	$code   = "<?php\n/**\n * Plugin Name: ScrapeLock Lockdown guard\n * Description: Created by ScrapeLock while the site is locked with Lockdown. It keeps a signed copy of the lock outside the database, keeps the active plugins and the theme as they were when the site was locked and keeps ScrapeLock active. It is removed when the lock is turned off or ScrapeLock is deactivated.\n *\n * @package ScrapeLock\n */\n\n"
		. "defined( 'ABSPATH' ) || exit;\n\n"
		. "defined( 'PNCP_LOCKDOWN_BEACON' ) || define( 'PNCP_LOCKDOWN_BEACON', " . $export( $json ) . " );\n";
	if ( null !== $copy ) {
		$code .= "defined( 'PNCP_LOCKDOWN_SNAP_COPY' ) || define( 'PNCP_LOCKDOWN_SNAP_COPY', " . $export( base64_encode( serialize( $copy ) ) ) . " );\n";
	}
	return $code
		. 'if ( time() >= ' . (int) $until . " && ! ( defined( 'SCRAPELOCK_UNLOCK' ) && true === SCRAPELOCK_UNLOCK ) && ! is_multisite() && is_readable( " . $export( PNCP_FILE ) . " ) ) {\n"
		. "\t\$GLOBALS['pncp_lockdown_guard'] = array(\n\t\t'own'    => " . $export( $own ) . ",\n\t\t'values' => " . $export( $values ) . ",\n\t\t'pass'   => false,\n\t);\n"
		. "\t( static function () {\n\t\t\$filter = static function ( \$value, \$option ) {\n"
		. "\t\t\t\$guard = isset( \$GLOBALS['pncp_lockdown_guard'] ) && is_array( \$GLOBALS['pncp_lockdown_guard'] ) ? \$GLOBALS['pncp_lockdown_guard'] : array();\n"
		. "\t\t\tif ( ! empty( \$guard['pass'] ) || ! isset( \$guard['own'] ) ) {\n\t\t\t\treturn \$value;\n\t\t\t}\n"
		. "\t\t\tif ( isset( \$guard['values'] ) && is_array( \$guard['values'] ) && array_key_exists( \$option, \$guard['values'] ) ) {\n\t\t\t\t\$value = \$guard['values'][ \$option ];\n\t\t\t}\n"
		. "\t\t\tif ( 'active_plugins' === \$option ) {\n\t\t\t\t\$value = is_array( \$value ) ? array_values( \$value ) : array();\n\t\t\t\tif ( ! in_array( \$guard['own'], \$value, true ) ) {\n\t\t\t\t\t\$value[] = \$guard['own'];\n\t\t\t\t}\n\t\t\t}\n"
		. "\t\t\treturn \$value;\n\t\t};\n"
		. "\t\tforeach ( array( 'active_plugins', 'template', 'stylesheet' ) as \$option ) {\n\t\t\tadd_filter( 'option_' . \$option, \$filter, 1, 2 );\n\t\t\tadd_filter( 'default_option_' . \$option, \$filter, 1, 2 );\n\t\t}\n"
		. "\t} )();\n}\n";
}

/** Το αρχείο μετρητών της 3.12.10: «<?php exit; ?>» και JSON. */
function old_fails( $path, $count, $seq ) {
	$now  = time();
	$rows = array( 'pncp_t31211' => array( 'n' => $count, 'start' => $now, 'until' => 0, 'level' => 0, 'last' => $now ) );
	file_put_contents( $path, "<?php exit; ?>\n" . wp_json_encode( array( 'rows' => $rows, 'seq' => $seq, 'sig' => PNCP_Seal::sign( array( 'fails_file' => $rows, 'seq' => $seq ) ) ), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT ) );
}

/** Ο φάκελος δεδομένων του φύλακα όπως τον άφηνε η 3.12.10 (fails.php, index.php) με τον παλιό φύλακα. */
function plant_old_guard( $state, $count, $seq ) {
	global $data_dir, $guard;
	$rec  = call( 'PNCP_Seal', 'record', true, (int) $state['until'], (int) $state['gen'], (int) $state['snap'] );
	$json = wp_json_encode( array_merge( $rec, array( 'sig' => PNCP_Seal::sign( $rec ) ) ) );
	$copy = call( 'PNCP_Seal', 'snapshot_source', (int) $state['snap'] );
	file_put_contents( $guard, old_guard( $json, $copy, plugin_basename( PNCP_FILE ), call( 'PNCP_Seal', 'guarded_values', (int) $state['snap'] ), (int) $state['until'] ) );
	mkdir( $data_dir );
	file_put_contents( $data_dir . '/index.php', "<?php\n// Silence is golden.\n" );
	old_fails( $data_dir . '/fails.php', $count, $seq );
	file_put_contents( PNCP_Paths::mu_plugins() . '/.scrapelock-lockdown-guard.php.abcdef123456.tmp', '<?php // a cut-off write of 3.12.10' );
	return $copy;
}

if ( ! PNCP_Seal::can_write_guard() ) {
	skip( 'F: ο φύλακας δεν γράφεται σε αυτό το WordPress' );
} else {
	// Κλειδωμένο site της 3.12.10: η κατάσταση και το αντίγραφο στη βάση, ο παλιός φύλακας, το fails.php.
	lock_now();
	save_fails( 1 );
	$pncp_state = PNCP_Lockdown::state();
	$pncp_snap  = PNCP_Seal::snapshot();
	PNCP_Lockdown::fails_remove();
	( function () {
		self::remove_guard_data();
		self::delete_guard_file();
	} )->bindTo( null, 'PNCP_Seal' )();
	$pncp_copy = plant_old_guard( $pncp_state, 4, 99 );
	fresh();
	t( 'F το site της 3.12.10: κλειδωμένο από τον παλιό φύλακα (εγγραφή και αντίγραφο base64 μέσα του), fails.php', PNCP_Lockdown::is_locked() && '' === PNCP_Lockdown::tampered() && null !== call( 'PNCP_Seal', 'guard_copy' ) && false !== strpos( (string) file_get_contents( $guard ), 'PNCP_LOCKDOWN_SNAP_COPY' ) && 4 === (int) ( fails_now()['rows']['pncp_t31211']['n'] ?? 0 ), PNCP_Lockdown::tampered() );
	// Και το αντίγραφο στη βάση σβήνεται (μόνο το αντίγραφο στον παλιό φύλακα μένει): η μετάβαση δεν το χάνει.
	global $wpdb;
	$wpdb->delete( $wpdb->options, array( 'option_name' => PNCP_Seal::SNAP ) );
	wp_cache_flush();

	// Μια μετάβαση που κόβεται: ο φύλακας δεν αντικαθίσταται (φάκελος και αρχείο μόνο για ανάγνωση).
	chmod( $guard, 0444 );
	chmod( $mu, 0555 );
	clearstatcache();
	fresh();
	PNCP_Seal::migrate_files();
	chmod( $mu, 0755 );
	chmod( $guard, 0644 );
	clearstatcache();
	fresh();
	if ( '' !== call( 'PNCP_Seal', 'legacy_guard_code' ) ) {
		list( $pncp_c ) = http( '/' );
		t( 'F μετάβαση που κόπηκε: ο παλιός φύλακας μένει και κρατά το site κλειδωμένο', PNCP_Lockdown::is_locked() && false !== strpos( (string) file_get_contents( $guard ), 'PNCP_LOCKDOWN_SNAP_COPY' ) && 200 === $pncp_c, (string) $pncp_c );
	} else {
		skip( 'F μετάβαση που κόβεται (εδώ ο φάκελος γράφεται και μόνο για ανάγνωση: root)' );
	}

	// Η πρώτη σελίδα του wp-admin: ο παλιός φύλακας τρέχει (ορίζει τις σταθερές του), η μετάβαση γίνεται.
	$pncp_exp   = time() + HOUR_IN_SECONDS;
	$pncp_tok   = WP_Session_Tokens::get_instance( 1 )->create( $pncp_exp );
	$pncp_cooks = array(
		AUTH_COOKIE      => wp_generate_auth_cookie( 1, $pncp_exp, 'auth', $pncp_tok ),
		LOGGED_IN_COOKIE => wp_generate_auth_cookie( 1, $pncp_exp, 'logged_in', $pncp_tok ),
	);
	list( $pncp_c, $pncp_b ) = http( '/wp-admin/index.php', $pncp_cooks );
	fresh();
	$pncp_gd = PNCP_Seal::read_guard_data();
	t( 'F wp-admin: ο φύλακας είναι τώρα το αρχείο του plugin', hash_file( 'sha256', $shipped ) === hash_file( 'sha256', $guard ), $pncp_c . ' ' . substr( wp_strip_all_tags( $pncp_b ), 0, 200 ) );
	t( 'F μετά τη μετάβαση: κλειδωμένο, ίδια εγγραφή (gen, snap, until) στο guard.json, χωρίς ένδειξη παρέμβασης κατάστασης', PNCP_Lockdown::is_locked() && is_array( $pncp_gd ) && (int) $pncp_gd['beacon']['gen'] >= (int) $pncp_state['gen'] && ! empty( $pncp_gd['beacon']['locked'] ) && in_array( PNCP_Lockdown::tampered(), array( '' ), true ), wp_json_encode( $pncp_gd['beacon'] ?? null ) . ' ' . PNCP_Lockdown::tampered() );
	$pncp_new = call( 'PNCP_Seal', 'guard_copy' );
	t( 'F το αντίγραφο δεν χάθηκε: snapshot.json γνήσιο, ίδιες ρυθμίσεις και διαχειριστές με την 3.12.10', is_array( $pncp_new ) && is_array( $pncp_copy ) && $pncp_copy['values'] == $pncp_new['values'] && $pncp_copy['admins'] === $pncp_new['admins'] && is_file( PNCP_Seal::snapshot_copy_path() ), wp_json_encode( array_keys( (array) $pncp_new ) ) );
	t( 'F οι μετρητές μεταφέρθηκαν: fails.json με τους 4 λάθος κωδικούς, το fails.php έφυγε', 4 === (int) ( fails_now()['rows']['pncp_t31211']['n'] ?? 0 ) && is_file( PNCP_Lockdown::fails_file() ) && ! file_exists( $data_dir . '/fails.php' ) );
	$pncp_files = files_under( array( $data_dir ) );
	t( 'F κανένα παλιό αρχείο: ούτε index.php, ούτε κρυφό προσωρινό του φύλακα', ! file_exists( $data_dir . '/index.php' ) && ! glob( $mu . '/.scrapelock-lockdown-guard.php.*' ) && is_file( $data_dir . '/index.html' ), implode( ' ', $pncp_files ) );
	check_data_files( 'F', array_merge( $pncp_files, array( 'mu-plugins/scrapelock-lockdown-guard.php' ) ) );
	check_no_clear( 'F', $pncp_files );
	$pncp_r = run_guard();
	t( 'F ο νέος φύλακας ακολουθεί τα δεδομένα που έγραψε η μετάβαση', is_string( $pncp_r['beacon'] ) && 6 === $pncp_r['filters'] && in_array( plugin_basename( PNCP_FILE ), (array) $pncp_r['active'], true ) && ! in_array( 'evil/evil.php', (array) $pncp_r['active'], true ), wp_json_encode( $pncp_r ) );
	t( 'F ξανά: τίποτα να μεταφερθεί', array() === PNCP_Seal::migrate_files() && hash_file( 'sha256', $shipped ) === hash_file( 'sha256', $guard ) );

	// Χωρίς φύλακα, 3.12.10: lock-<hex>.php, fails-<hex>.php, index.php και .htaccess στο uploads/scrapelock-lockdown.
	unlock_now();
	add_filter( 'filesystem_method', $pncp_ftp );
	fresh();
	if ( PNCP_Seal::can_write_guard() || '' === PNCP_Seal::beacon_writable_dir() ) {
		skip( 'F αρχείο κλειδώματος της 3.12.10: εδώ δεν δοκιμάζεται' );
	} else {
		lock_now();
		$pncp_state = PNCP_Lockdown::state();
		$pncp_file  = call( 'PNCP_Seal', 'beacon_file' );
		PNCP_Lockdown::fails_remove();
		PNCP_Seal::remove_beacon();
		$pncp_rec   = $pncp_file['record'];
		$pncp_copy  = $pncp_file['copy'];
		$pncp_name  = call( 'PNCP_Seal', 'legacy_beacon_name' );
		$pncp_fname = call( 'PNCP_Seal', 'legacy_fails_name' );
		mkdir( $up_dir );
		file_put_contents( $up_dir . '/index.php', "<?php\n// Silence is golden.\n" );
		file_put_contents( $up_dir . '/.htaccess', PNCP_Seal::BEACON_HTACCESS );
		file_put_contents(
			$up_dir . '/' . $pncp_name,
			"<?php exit; ?>\n" . wp_json_encode(
				array(
					'beacon' => (string) wp_json_encode( array_merge( $pncp_rec, array( 'sig' => PNCP_Seal::sign( $pncp_rec ) ) ) ),
					'mail'   => $pncp_file['mail'],
					'since'  => $pncp_file['since'],
					'xsig'   => PNCP_Seal::sign( array( 'pncp_lockdown_beacon', $pncp_rec, $pncp_file['mail'], $pncp_file['since'] ) ),
					'copy'   => base64_encode( serialize( $pncp_copy ) ),
				),
				JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
			)
		);
		old_fails( $up_dir . '/' . $pncp_fname, 5, 77 );
		fresh();
		$pncp_before = call( 'PNCP_Seal', 'beacon_file' );
		t( 'F το site της 3.12.10 χωρίς φύλακα: κλειδωμένο από το lock-<hex>.php (αντίγραφο base64), fails-<hex>.php', PNCP_Lockdown::is_locked() && is_array( $pncp_before ) && ! empty( $pncp_before['legacy'] ) && null !== call( 'PNCP_Seal', 'guard_copy' ) && 5 === (int) ( fails_now()['rows']['pncp_t31211']['n'] ?? 0 ) );
		if ( '' !== $wp_cli ) {
			// Η ωριαία φροντίδα (και η αναβάθμιση): PNCP_Lockdown::maintain_files(), από το WP-CLI.
			exec( $wp_cli . ' eval ' . escapeshellarg( 'PNCP_Lockdown::maintain_files();' ) . ' 2>&1', $pncp_out, $pncp_rc );
		} else {
			PNCP_Lockdown::maintain_files();
		}
		fresh();
		$pncp_after = call( 'PNCP_Seal', 'beacon_file' );
		$pncp_files = files_under( array( $up_dir ) );
		t( 'F μετά: lock.json στον ιδιωτικό φάκελο, ίδια εγγραφή, διεύθυνση και ώρα κλειδώματος', is_array( $pncp_after ) && empty( $pncp_after['legacy'] ) && $pncp_rec === $pncp_after['record'] && $pncp_file['mail'] === $pncp_after['mail'] && $pncp_file['since'] === $pncp_after['since'] && 'lock.json' === basename( $pncp_after['path'] ) && PNCP_Lockdown::is_locked(), implode( ' ', $pncp_files ) );
		t( 'F το αντίγραφο δεν χάθηκε: στο lock.json, γνήσιο, ίδιες ρυθμίσεις', is_array( $pncp_after['copy'] ?? null ) && $pncp_copy == $pncp_after['copy'] && null !== call( 'PNCP_Seal', 'guard_copy' ) );
		t( 'F οι μετρητές: fails.json με τους 5, κανένα lock-/fails-*.php ούτε index.php', 5 === (int) ( fails_now()['rows']['pncp_t31211']['n'] ?? 0 ) && ! glob( $up_dir . '/*.php' ) && is_file( PNCP_Seal::beacon_fails_path() ), implode( ' ', $pncp_files ) );
		check_data_files( 'F χωρίς φύλακα', $pncp_files );
		check_no_clear( 'F χωρίς φύλακα', $pncp_files );
		unlock_now();
		t( 'F ξεκλείδωμα μετά τη μετάβαση: φεύγουν όλα', ! file_exists( $up_dir ) && ! PNCP_Lockdown::is_locked() );
	}
	remove_filter( 'filesystem_method', $pncp_ftp );
	fresh();
}

/* ---------- G. Απεγκατάσταση: παλιά και νέα αρχεία ---------- */

if ( PNCP_Seal::can_write_guard() ) {
	lock_now();
	save_fails( 1 );
	// Και παλιά αρχεία δίπλα στα νέα (μια μετάβαση που δεν έγινε ακόμη): fails.php, index.php, lock-<hex>.php.
	old_fails( $data_dir . '/fails.php', 1, 1 );
	file_put_contents( $data_dir . '/index.php', "<?php\n// Silence is golden.\n" );
	mkdir( $up_dir );
	file_put_contents( $up_dir . '/index.php', "<?php\n// Silence is golden.\n" );
	file_put_contents( $up_dir . '/.htaccess', PNCP_Seal::BEACON_HTACCESS );
	file_put_contents( $up_dir . '/' . call( 'PNCP_Seal', 'legacy_beacon_name' ), "<?php exit; ?>\n{\"beacon\":\"{}\"}" );
	call( 'PNCP_Seal', 'ensure_dir', PNCP_Seal::beacon_private( $up_dir ), false );
	file_put_contents( PNCP_Seal::beacon_private( $up_dir ) . '/lock.json', '{}' );
	PNCP_Seal::remove_guard();
	PNCP_Seal::remove_beacon();
	clearstatcache();
	t( 'G απεγκατάσταση (remove_guard / remove_beacon): ούτε φύλακας, ούτε φάκελοι δεδομένων, παλιοί ή νέοι', ! file_exists( $guard ) && ! file_exists( $data_dir ) && ! file_exists( $up_dir ) && ! file_exists( PNCP_Seal::beacon_dirs()[1] ), implode( ' ', files_under( array( $data_dir, $up_dir ) ) ) );
	$pncp_un = (string) file_get_contents( PNCP_DIR . 'uninstall.php' );
	t( 'G το uninstall.php καλεί τα ίδια', false !== strpos( $pncp_un, 'PNCP_Seal::remove_guard();' ) && false !== strpos( $pncp_un, 'PNCP_Seal::remove_beacon();' ) );
	unlock_now();
}

echo $fails ? "FAILURES: $fails\n" : "ALL PASS\n";
exit( $fails ? 1 : 0 );

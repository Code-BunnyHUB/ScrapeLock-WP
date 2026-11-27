<?php
/**
 * ScrapeLock 3.13.0 — το Κλείδωμα (Lockdown) δεν κλειδώνει ποτέ έξω τον διαχειριστή.
 *
 *   A. σύνδεση ενώ είναι κλειδωμένο: μετά το wp-login.php ο Πίνακας ελέγχου (όχι το profile.php που διάλεγε το
 *      WordPress για λογαριασμούς χωρίς edit_posts και που ήταν «The site is locked»)· Πίνακας ελέγχου, προφίλ (μόνο
 *      για ανάγνωση: η αποθήκευση απορρίπτεται) και καρτέλα Lockdown ανοίγουν· η σελίδα «The site is locked» και η
 *      καρτέλα δείχνουν τους δρόμους χωρίς εφαρμογή (κωδικός ανάκτησης, SCRAPELOCK_UNLOCK, WP-CLI, οθόνη στη σύνδεση)·
 *   B. άλλο plugin / θέμα που διώχνει από το wp-admin όσους δεν έχουν manage_options (το κλείδωμα τα παίρνει): πριν,
 *      ούτε η καρτέλα Lockdown άνοιγε (κανένας δρόμος)· τώρα η ανακατεύθυνση πάει στην οθόνη ξεκλειδώματος του
 *      wp-login.php, που δεν περνά από το wp-admin· ξεκλείδωμα εκεί (nonce, κωδικός, όρια όπως στην καρτέλα) και το
 *      wp-admin ανοίγει· μόνο για διαχειριστές, μόνο με σύνδεση· όχι όταν δεν είναι κλειδωμένο·
 *   C. σύνδεση που απορρίπτεται (κωδικός αλλαγμένος στη βάση, π.χ. από τα εργαλεία του host): το μήνυμα λέει τον δρόμο
 *      από τον server· «Ξέχασα τον κωδικό» για προσωπικό: χωρίς σύνδεσμο, αλλά email με τους δρόμους (μία φορά την ώρα)·
 *   D. guard.json (σταθερό όνομα, ορατό σε Nginx): χωρίς τη λίστα των plugins / θέματος, που είναι υπογεγραμμένη στον
 *      ιδιωτικό φάκελο· μετάβαση από guard.json της 3.12.13 (με τις λίστες μέσα)· ο φύλακας χωρίς τα αρχεία του
 *      ScrapeLock (φάκελος σβησμένος / μετονομασμένος) δεν κάνει τίποτα και δεν βγάζει σφάλμα.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 WP_CLI="wp --path=…" php t_31214_lockdown_access.php
 */

$wp_dir = getenv( 'WP_DIR' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );
define( 'WP_USE_THEMES', false );
require $wp_dir . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/user.php';

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/** Ξαναδιαβάζει την κατάσταση του κλειδώματος και τα αρχεία του, όπως ένα νέο αίτημα (όπως στο t_lockdown.php). */
function fresh() {
	wp_cache_flush();
	( function () {
		self::$state        = null;
		self::$staff        = array();
		self::$own          = array();
		self::$limited_caps = null;
		self::$session_ok   = array();
	} )->bindTo( null, 'PNCP_Lockdown' )();
	clearstatcache();
	( function () {
		$json = self::ours( self::path() ) ? self::guard_json() : null;
		if ( null !== $json ) {
			$record        = self::guard_record( $json );
			self::$current = null !== $record ? $record : self::record( false, 0 );
			$copy          = self::read_snapshot_copy();
			self::$copy    = is_array( $copy ) ? $copy : false;
		} elseif ( defined( 'PNCP_LOCKDOWN_BEACON' ) ) {
			self::$current = self::record( false, 0 );
			self::$copy    = false;
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

/** Καθαρό ξεκίνημα / τέλος: χωρίς κλείδωμα, φύλακα, μετρητές. */
function clean_lock() {
	PNCP_Seal::remove_guard();
	PNCP_Seal::remove_beacon();
	PNCP_Lockdown::fails_remove();
	foreach ( array( PNCP_Seal::SNAP, PNCP_Seal::DIGESTS, PNCP_Seal::WINDOW ) as $o ) {
		delete_option( $o );
	}
	foreach ( array( PNCP_Lockdown::OPTION, PNCP_Lockdown::LOG_OPTION, PNCP_Lockdown::FAILS_OPTION, PNCP_Lockdown::MUTEX, PNCP_Lockdown::MUTEX_PRI, PNCP_Lockdown::DB_FOREIGN ) as $o ) {
		delete_site_option( $o );
	}
	delete_metadata( 'user', 0, PNCP_Lockdown::PENDING_META, '', true );
	global $wpdb;
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( '_site_transient_pncp_ld_' ) . '%', $wpdb->esc_like( '_site_transient_timeout_pncp_ld_' ) . '%' ) );
	( function () {
		self::$state  = null;
		self::$tamper = '';
		self::$sig_ok = true;
	} )->bindTo( null, 'PNCP_Lockdown' )();
	( function () {
		self::$current = self::record( false, 0 );
		self::$copy    = false;
	} )->bindTo( null, 'PNCP_Seal' )();
	fresh();
}

/** Ιδιωτική μέθοδος. */
function call( $class, $method, ...$args ) {
	return ( function () use ( $method, $args ) {
		return self::$method( ...$args );
	} )->bindTo( null, $class )();
}

$sessions = array();
$cookies  = array();
/** Σύνδεση χρήστη: cookies για το HTTP και ίδια συνεδρία εδώ, ώστε τα nonces να ταιριάζουν. */
function as_user( $id ) {
	global $sessions, $cookies;
	if ( ! isset( $sessions[ $id ] ) ) {
		$expire           = time() + DAY_IN_SECONDS;
		$token            = WP_Session_Tokens::get_instance( $id )->create( $expire );
		$sessions[ $id ] = array(
			AUTH_COOKIE      => wp_generate_auth_cookie( $id, $expire, 'auth', $token ),
			LOGGED_IN_COOKIE => wp_generate_auth_cookie( $id, $expire, 'logged_in', $token ),
		);
	}
	$cookies                     = $sessions[ $id ];
	$_COOKIE[ LOGGED_IN_COOKIE ] = $cookies[ LOGGED_IN_COOKIE ];
	wp_set_current_user( $id );
}

/** Αίτημα HTTP: [κωδικός, σώμα, Location, cookies που έστειλε ο server]. */
function http( $path, $post = null, $extra = array() ) {
	global $base, $cookies;
	$ch  = curl_init( 0 === strpos( $path, 'http' ) ? $path : $base . $path );
	$jar = array();
	foreach ( $cookies as $k => $v ) {
		$jar[] = $k . '=' . rawurlencode( $v );
	}
	$opts = array(
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HEADER         => true,
		CURLOPT_COOKIE         => implode( '; ', $jar ),
		CURLOPT_HTTPHEADER     => array_merge( array( 'User-Agent: Mozilla/5.0 Chrome/141', 'Accept-Language: en' ), $extra ),
		CURLOPT_TIMEOUT        => 60,
	);
	if ( null !== $post ) {
		$opts[ CURLOPT_POST ]       = true;
		$opts[ CURLOPT_POSTFIELDS ] = is_array( $post ) ? http_build_query( $post ) : $post;
	}
	curl_setopt_array( $ch, $opts );
	$out  = (string) curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_HTTP_CODE );
	$hs   = (int) curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	curl_close( $ch );
	$head = substr( $out, 0, $hs );
	$loc  = preg_match( '/^location:\s*(\S+)/mi', $head, $m ) ? $m[1] : '';
	preg_match_all( '/^set-cookie:\s*([^=]+)=([^;]*)/mi', $head, $mm, PREG_SET_ORDER );
	$set = array();
	foreach ( $mm as $c ) {
		$set[ $c[1] ] = rawurldecode( $c[2] );
	}
	return array( $code, substr( $out, $hs ), $loc, $set );
}

function php_errors( $body ) {
	return preg_match( '/(Warning|Notice|Deprecated|Fatal error)<\/b>:|PHP (Warning|Notice|Deprecated)/', $body );
}

/** Ενέργεια της καρτέλας Lockdown: το μήνυμα της ανακατεύθυνσης (pncp_ld=…). */
function ld( $op, $fields = array() ) {
	list( $code, , $loc ) = http( '/wp-admin/admin-post.php', array_merge( array( 'action' => 'pncp_lockdown', 'op' => $op, '_wpnonce' => wp_create_nonce( 'pncp_lockdown' ) ), $fields ) );
	fresh();
	return 302 === $code && preg_match( '/pncp_ld=(\w+)/', $loc, $m ) ? $m[1] : "http $code";
}

/** Ο τρέχων κωδικός της εφαρμογής, για νέο βήμα κάθε φορά (χωρίς αναμονή 30″). */
function app_code( $secret ) {
	fresh();
	( function () {
		self::save( array_merge( self::state(), array( 'last_step' => 0 ) ) );
	} )->bindTo( null, 'PNCP_Lockdown' )();
	fresh();
	return PNCP_Totp::code( $secret, PNCP_Totp::step() );
}

$cookies = array();
if ( 0 === http( '/' )[0] ) {
	echo "FAIL ο server των δοκιμών δεν απαντά ($base): καμία δοκιμή δεν έτρεξε\n";
	exit( 1 );
}

/* ---------- Χρήστες, «πύλη» άλλου plugin ---------- */
clean_lock();
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'monitor_mode' => 0, 'monitor_until' => 0 ) ) );
PNCP_Options::flush();
foreach ( array( 'ld14_admin', 'ld14_other', 'ld14_editor' ) as $login ) {
	$old = get_user_by( 'login', $login );
	if ( $old ) {
		wp_delete_user( $old->ID );
	}
}
$pass     = 'Ld14-' . wp_generate_password( 16, false );
$admin_id = wp_insert_user( array( 'user_login' => 'ld14_admin', 'user_pass' => $pass, 'user_email' => 'ld14_admin@example.com', 'role' => 'administrator', 'first_name' => 'Before' ) );
$other_id = wp_insert_user( array( 'user_login' => 'ld14_other', 'user_pass' => wp_generate_password(), 'user_email' => 'ld14_other@example.com', 'role' => 'administrator' ) );
$edit_id  = wp_insert_user( array( 'user_login' => 'ld14_editor', 'user_pass' => wp_generate_password(), 'user_email' => 'ld14_editor@example.com', 'role' => 'editor' ) );
// Όπως το συνηθισμένο snippet «μόνο διαχειριστές στο wp-admin» (θέματα, membership plugins): ενεργό μόνο με το
// header X-Test-Gate, ώστε να μην αγγίζει άλλες δοκιμές αν μείνει.
$mu   = PNCP_Paths::mu_plugins();
$gate = $mu . '/pncp-t31214-gate.php';
file_put_contents( $gate, "<?php\nif ( isset( \$_SERVER['HTTP_X_TEST_GATE'] ) ) {\n\tadd_action( 'admin_init', static function () {\n\t\tif ( ! current_user_can( 'manage_options' ) && ! wp_doing_ajax() ) {\n\t\t\twp_safe_redirect( home_url( '/' ) );\n\t\t\texit;\n\t\t}\n\t} );\n}\n" );
$g = array( 'X-Test-Gate: 1' );

as_user( $admin_id );
list( $code, $body, $loc ) = http( '/wp-admin/index.php', null, $g );
t( 'πύλη, ξεκλείδωτο: ο διαχειριστής περνά (manage_options)', 200 === $code, "$code $loc" );

/* ---------- Σύνδεση εφαρμογής και κλείδωμα ---------- */
t( 'σύνδεση εφαρμογής: έναρξη', 'setup' === ld( 'setup' ) );
list( , $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=lockdown' );
$secret = preg_match( '/<code class="pncp-ld-secret">([A-Z2-7 ]+)<\/code>/', $body, $m ) ? str_replace( ' ', '', $m[1] ) : '';
t( 'σύνδεση εφαρμογής: επιβεβαίωση', 'connected' === ld( 'confirm', array( 'code' => PNCP_Totp::code( $secret, PNCP_Totp::step() ) ) ) && PNCP_Lockdown::configured() );
t( 'κλείδωμα', 'locked' === ld( 'lock', array( 'code' => app_code( $secret ), 'ack' => 1 ) ) && PNCP_Lockdown::is_locked() );
PNCP_Lockdown::fails_remove();
delete_site_option( PNCP_Lockdown::FAILS_OPTION );

/* ---------- A. Σύνδεση και οθόνες ενώ είναι κλειδωμένο ---------- */
$cookies = array( 'wordpress_test_cookie' => 'WP Cookie check' );
list( $code, $body, $loc, $set ) = http( '/wp-login.php', array( 'log' => 'ld14_admin', 'pwd' => $pass, 'testcookie' => 1 ) );
t( 'A σύνδεση κλειδωμένο: → Πίνακας ελέγχου (όχι profile.php)', 302 === $code && admin_url( 'index.php' ) === $loc, "$code $loc" );
t( 'A σύνδεση κλειδωμένο: με cookies σύνδεσης', isset( $set[ LOGGED_IN_COOKIE ] ) );
$cookies = $set;
list( $code, $body ) = http( '/wp-admin/index.php' );
t( 'A Πίνακας ελέγχου (με τα cookies της σύνδεσης): 200, ειδοποίηση «This site is locked.» με ξεκλείδωμα', 200 === $code && false !== strpos( $body, 'This site is locked.' ) && false !== strpos( $body, 'tab=lockdown' ) && ! php_errors( $body ), (string) $code );
as_user( $admin_id );
list( $code, $body ) = http( '/wp-admin/profile.php' );
t( 'A προφίλ: ανοίγει (200), με τη φόρμα και την ειδοποίηση «δεν αποθηκεύεται»', 200 === $code && false !== strpos( $body, 'id="your-profile"' ) && false !== strpos( $body, 'changes to it are not saved while the site is locked' ) && ! php_errors( $body ), (string) $code );
list( $code, $body ) = http( '/wp-admin/user-edit.php?user_id=' . $admin_id );
t( 'A user-edit.php του ίδιου: ανοίγει', 200 === $code && false !== strpos( $body, 'id="your-profile"' ), (string) $code );
list( $code, $body ) = http(
	'/wp-admin/profile.php',
	array(
		'_wpnonce'         => wp_create_nonce( 'update-user_' . $admin_id ),
		'_wp_http_referer' => '/wp-admin/profile.php',
		'from'             => 'profile',
		'action'           => 'update',
		'user_id'          => $admin_id,
		'first_name'       => 'Hacked',
		'nickname'         => 'ld14_admin',
		'display_name'     => 'ld14_admin',
		'email'            => 'evil14@example.com',
	)
);
clean_post_cache( 0 );
wp_cache_flush();
t( 'A προφίλ: η αποθήκευση απορρίπτεται (σελίδα «The site is locked»), τίποτα δεν αλλάζει', 403 === $code && false !== strpos( $body, 'class="pncp-locked"' ) && 'Before' === get_user_meta( $admin_id, 'first_name', true ) && 'ld14_admin@example.com' === get_userdata( $admin_id )->user_email, (string) $code );
t( 'A μόνο η σελίδα του προφίλ: εδώ (όχι σελίδα προφίλ) edit_user για τον εαυτό του όχι', ! current_user_can( 'edit_user', $admin_id ) && ! current_user_can( 'edit_user', $other_id ) );
list( $code, $body ) = http( '/wp-admin/user-edit.php?user_id=' . $other_id );
t( 'A άλλος χρήστης: σελίδα «The site is locked» με ξεκλείδωμα και «Cannot use the app?» (SCRAPELOCK_UNLOCK, WP-CLI, οθόνη σύνδεσης)', 403 === $code && false !== strpos( $body, 'pncp-locked-btn' ) && false !== strpos( $body, 'Cannot use the app?' ) && false !== strpos( $body, "SCRAPELOCK_UNLOCK" ) && false !== strpos( $body, 'wp config set SCRAPELOCK_UNLOCK true --raw --type=constant' ) && false !== strpos( $body, 'action=scrapelock-unlock' ), (string) $code );
list( $code, $body ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=lockdown' );
t( 'A καρτέλα Lockdown: φόρμα ξεκλειδώματος και όλοι οι δρόμοι (κωδικός ανάκτησης, wp-config.php, WP-CLI, οθόνη σύνδεσης, ο φύλακας δεν αρκεί)', 200 === $code && false !== strpos( $body, 'name="op" value="unlock"' ) && false !== strpos( $body, 'recovery codes' ) && false !== strpos( $body, 'wp config set SCRAPELOCK_UNLOCK' ) && false !== strpos( $body, 'action=scrapelock-unlock' ) && false !== strpos( $body, 'does not unlock the site' ) && ! php_errors( $body ), (string) $code );

/* ---------- B. Πύλη άλλου plugin και οθόνη ξεκλειδώματος στη σύνδεση ---------- */
list( $code, , $loc ) = http( '/wp-admin/index.php', null, $g );
t( 'B πύλη, κλειδωμένο: όχι στην αρχική σελίδα αλλά στην οθόνη ξεκλειδώματος (pncp_from=away)', 302 === $code && false !== strpos( $loc, 'wp-login.php?action=scrapelock-unlock' ) && false !== strpos( $loc, 'pncp_from=away' ), "$code $loc" );
list( $code, , $loc ) = http( '/wp-admin/options-general.php?page=scrapelock&tab=lockdown', null, $g );
t( 'B πύλη, κλειδωμένο: και η καρτέλα Lockdown → οθόνη ξεκλειδώματος', 302 === $code && false !== strpos( $loc, 'action=scrapelock-unlock' ), "$code $loc" );
$unlock = '/wp-login.php?action=scrapelock-unlock';
list( $code, $body ) = http( $unlock . '&pncp_from=away', null, $g );
t( 'B οθόνη ξεκλειδώματος: 200, εξήγηση, φόρμα, δρόμοι χωρίς εφαρμογή, χωρίς PHP warnings', 200 === $code && false !== strpos( $body, 'sent you away from wp-admin' ) && false !== strpos( $body, 'name="op" value="unlock"' ) && false !== strpos( $body, 'name="_wpnonce"' ) && false !== strpos( $body, 'SCRAPELOCK_UNLOCK' ) && false !== strpos( $body, 'assets/css/unlock.css' ) && ! php_errors( $body ), (string) $code );
$keep    = $cookies;
$cookies = array();
list( $code, , $loc ) = http( $unlock );
t( 'B οθόνη ξεκλειδώματος χωρίς σύνδεση: στη φόρμα σύνδεσης, με επιστροφή εδώ', 302 === $code && false !== strpos( $loc, 'redirect_to=' ) && false !== strpos( rawurldecode( $loc ), 'action=scrapelock-unlock' ), "$code $loc" );
list( $code, , $loc ) = http( $unlock, array( 'op' => 'unlock', 'code' => '000000' ) );
t( 'B POST χωρίς σύνδεση: τίποτα (στη φόρμα σύνδεσης)', 302 === $code && PNCP_Lockdown::is_locked(), "$code $loc" );
as_user( $edit_id );
list( $code ) = http( $unlock );
t( 'B οθόνη ξεκλειδώματος: editor → 403', 403 === $code, (string) $code );
$cookies = $keep;
as_user( $admin_id );
list( $code, , $loc ) = http( $unlock, array( 'op' => 'unlock', 'code' => app_code( $secret ), 'minutes' => 15 ) );
t( 'B POST χωρίς nonce: απορρίπτεται, μένει κλειδωμένο', 403 === $code && PNCP_Lockdown::is_locked(), "$code $loc" );
list( $code, , $loc ) = http( $unlock, array( 'op' => 'lock', 'code' => app_code( $secret ), '_wpnonce' => wp_create_nonce( 'pncp_lockdown' ) ) );
t( 'B άλλη ενέργεια από την οθόνη σύνδεσης (μόνο unlock): error', 302 === $code && false !== strpos( $loc, 'action=scrapelock-unlock' ) && false !== strpos( $loc, 'pncp_ld=error' ) && PNCP_Lockdown::is_locked(), "$code $loc" );
list( $code, , $loc ) = http( $unlock, array( 'op' => 'unlock', 'code' => '000000', 'minutes' => 15, '_wpnonce' => wp_create_nonce( 'pncp_lockdown' ) ) );
fresh();
t( 'B λάθος κωδικός: πίσω στην οθόνη με «wrong», κλειδωμένο', 302 === $code && false !== strpos( $loc, 'action=scrapelock-unlock' ) && false !== strpos( $loc, 'pncp_ld=wrong' ) && PNCP_Lockdown::is_locked(), "$code $loc" );
list( $code, , $loc ) = http( $unlock, array( 'op' => 'unlock', 'code' => app_code( $secret ), 'minutes' => 15, '_wpnonce' => wp_create_nonce( 'pncp_lockdown' ) ) );
fresh();
t( 'B σωστός κωδικός: ξεκλείδωμα για λίγο (μόνο αυτή η συνεδρία), πίσω στην οθόνη με «unlocked»', 302 === $code && false !== strpos( $loc, 'pncp_ld=unlocked' ) && PNCP_Lockdown::unlocked_until() > time() && (int) PNCP_Lockdown::state()['unlocked_by'] === $admin_id, "$code $loc" );
list( $code, $body ) = http( '/wp-admin/plugins.php', null, $g );
t( 'B μετά το ξεκλείδωμα: το wp-admin ανοίγει παρά την πύλη (plugins.php 200)', 200 === $code && false === strpos( $body, 'pncp-locked' ), (string) $code );
list( $code, $body ) = http( $unlock );
t( 'B οθόνη ξεκλειδώματος, ξεκλείδωτο για λίγο: «Unlocked until», χωρίς φόρμα', 200 === $code && false !== strpos( $body, 'Unlocked until' ) && false === strpos( $body, 'name="op" value="unlock"' ), (string) $code );
t( 'B κλείδωμα πάλι (καρτέλα)', 'locked' === ld( 'relock' ) && PNCP_Lockdown::is_locked() );

/* ---------- C. Σύνδεση που απορρίπτεται, «ξέχασα τον κωδικό» ---------- */
global $wpdb;
$old_hash = $wpdb->get_var( $wpdb->prepare( "SELECT user_pass FROM {$wpdb->users} WHERE ID = %d", $admin_id ) );
$wpdb->update( $wpdb->users, array( 'user_pass' => wp_hash_password( 'HostTool-' . $pass ) ), array( 'ID' => $admin_id ) );
clean_user_cache( $admin_id );
$cookies = array( 'wordpress_test_cookie' => 'WP Cookie check' );
list( $code, $body ) = http( '/wp-login.php', array( 'log' => 'ld14_admin', 'pwd' => 'HostTool-' . $pass, 'testcookie' => 1 ) );
t( 'C κωδικός αλλαγμένος στη βάση: η σύνδεση απορρίπτεται, με τον δρόμο από τον server (SCRAPELOCK_UNLOCK, WP-CLI)', 200 === $code && false !== strpos( $body, 'its password was changed after the site was locked' ) && false !== strpos( $body, 'SCRAPELOCK_UNLOCK' ) && false !== strpos( $body, 'wp config set SCRAPELOCK_UNLOCK true --raw --type=constant' ), (string) $code );
$wpdb->update( $wpdb->users, array( 'user_pass' => $old_hash ), array( 'ID' => $admin_id ) );
clean_user_cache( $admin_id );
$mails = array();
$rec   = static function ( $r, $atts ) use ( &$mails ) {
	$mails[] = $atts;
	return true;
};
add_filter( 'pre_wp_mail', $rec, 10, 2 );
delete_site_transient( 'pncp_ld_lost_' . $admin_id );
t( 'C «ξέχασα τον κωδικό» για διαχειριστή: όχι σύνδεσμος (false)', false === apply_filters( 'allow_password_reset', true, $admin_id ) );
do_action( 'lostpassword_post', new WP_Error(), get_userdata( $admin_id ) );
do_action( 'lostpassword_post', new WP_Error(), get_userdata( $admin_id ) );
t( 'C «ξέχασα τον κωδικό»: ένα email στον λογαριασμό με τους δρόμους (μία φορά την ώρα)', 1 === count( $mails ) && 'ld14_admin@example.com' === $mails[0]['to'] && false !== strpos( $mails[0]['message'], 'SCRAPELOCK_UNLOCK' ) && false !== strpos( $mails[0]['message'], 'recovery codes' ), (string) count( $mails ) );
$mails = array();
$cust  = wp_insert_user( array( 'user_login' => 'ld14_cust', 'user_pass' => wp_generate_password(), 'user_email' => 'ld14_cust@example.com', 'role' => 'subscriber' ) );
do_action( 'lostpassword_post', new WP_Error(), get_userdata( $cust ) );
t( 'C «ξέχασα τον κωδικό» για συνδρομητή: κανονικά, κανένα email του κλειδώματος', array() === $mails && apply_filters( 'allow_password_reset', true, $cust ) );
remove_filter( 'pre_wp_mail', $rec, 10 );
wp_delete_user( $cust );
if ( '' !== $wp_cli ) {
	exec( $wp_cli . ' user update ' . (int) $edit_id . ' --user_pass=Other-' . escapeshellarg( $pass ) . ' 2>&1', $out );
	t( 'C WP-CLI «user update --user_pass» κλειδωμένο: προειδοποίηση ότι δεν άλλαξε', false !== strpos( implode( "\n", $out ), 'email address and password of staff accounts are kept' ), implode( ' | ', $out ) );
}

/* ---------- D. guard.json χωρίς τις λίστες, μετάβαση από την 3.12.13, φύλακας χωρίς ScrapeLock ---------- */
fresh();
$data_dir = PNCP_Seal::data_dir();
$gj       = json_decode( (string) file_get_contents( PNCP_Seal::guard_data_path() ), true );
$gtext    = (string) file_get_contents( PNCP_Seal::guard_data_path() );
$active   = (array) get_option( 'active_plugins' );
$found    = array();
foreach ( $active as $plugin ) {
	if ( false !== strpos( $gtext, dirname( (string) $plugin ) . '/' ) && plugin_basename( PNCP_FILE ) !== $plugin ) {
		$found[] = $plugin;
	}
}
t( 'D guard.json: μόνο beacon / own / multisite, κανένα άλλο ενεργό plugin, κανένα θέμα', array( 'beacon', 'multisite', 'own' ) === ( function ( $k ) { sort( $k ); return $k; } )( array_keys( (array) $gj['data'] ) ) && ! $found && false === strpos( $gtext, '"' . get_option( 'stylesheet' ) . '"' ), implode( ',', $found ) );
$mu_url = '/' . substr( wp_normalize_path( $data_dir ), strlen( untrailingslashit( wp_normalize_path( ABSPATH ) ) ) + 1 );
list( $code, $body ) = http( $mu_url . '/guard.json' );
t( 'D guard.json μέσω HTTP (όπως σε Nginx): χωρίς λίστα plugins / θέματος', false === strpos( $body, 'active_plugins' ) && false === strpos( $body, '"stylesheet"' ), $code . ' ' . substr( $body, 0, 60 ) );
t( 'D guard-values.json: στον ιδιωτικό φάκελο (όνομα από τα κλειδιά)', is_file( PNCP_Seal::guard_values_path() ) && 1 === preg_match( '#/data-[0-9a-f]{20}/guard-values\.json$#', PNCP_Seal::guard_values_path() ) );

/** Τρέχει τον φύλακα μόνο του σε άλλη διεργασία, πριν από το WordPress (όπως στο t_31211_lockdown_files.php). */
function run_guard( $consts = array() ) {
	$runner = get_temp_dir() . 'pncp-t31214-guard-' . wp_generate_password( 6, false ) . '.php';
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
	$code   = "<?php\nerror_reporting( E_ALL );\nini_set( 'display_errors', '1' );\n";
	foreach ( $defs as $name => $value ) {
		$code .= 'define( ' . var_export( $name, true ) . ', ' . var_export( $value, true ) . " );\n";
	}
	$code .= '$GLOBALS["f"] = array();' . "\n"
		. 'function add_filter( $h, $cb ) { $GLOBALS["f"][ $h ] = $cb; }' . "\n"
		. 'function is_multisite() { return false; }' . "\n"
		. 'include ' . var_export( PNCP_Seal::path(), true ) . ";\n"
		. '$a = isset( $GLOBALS["f"]["option_active_plugins"] ) ? $GLOBALS["f"]["option_active_plugins"]( array( "evil/evil.php" ), "active_plugins" ) : null;' . "\n"
		. '$s = isset( $GLOBALS["f"]["option_stylesheet"] ) ? $GLOBALS["f"]["option_stylesheet"]( "evil-theme", "stylesheet" ) : null;' . "\n"
		. 'echo json_encode( array( "beacon" => defined( "PNCP_LOCKDOWN_BEACON" ), "inline" => defined( "PNCP_LOCKDOWN_GUARD_INLINE" ), "filters" => count( $GLOBALS["f"] ), "active" => $a, "stylesheet" => $s ) );' . "\n";
	file_put_contents( $runner, $code );
	exec( 'php ' . escapeshellarg( $runner ) . ' 2>&1', $out );
	unlink( $runner );
	$res = json_decode( implode( "\n", $out ), true );
	return is_array( $res ) ? $res : array( 'error' => implode( "\n", $out ) );
}

$own = plugin_basename( PNCP_FILE );
$r   = run_guard();
t( 'D ο φύλακας ακολουθεί το guard-values.json (plugins, θέμα)', true === $r['beacon'] && false === $r['inline'] && is_array( $r['active'] ) && ! in_array( 'evil/evil.php', $r['active'], true ) && in_array( $own, $r['active'], true ) && get_option( 'stylesheet' ) === $r['stylesheet'], wp_json_encode( $r ) );
// guard.json όπως το έγραφε η 3.12.13: οι λίστες μέσα, υπογεγραμμένες μαζί με την εγγραφή· χωρίς guard-values.json.
$vj                 = json_decode( (string) file_get_contents( PNCP_Seal::guard_values_path() ), true );
$old_data           = $gj['data'];
$old_data['values'] = $vj['data']['values'];
file_put_contents( PNCP_Seal::guard_data_path(), PNCP_Seal::json_text( array( 'about' => 'old', 'data' => $old_data, 'sig' => PNCP_Seal::guard_sign( $old_data ) ) ) );
unlink( PNCP_Seal::guard_values_path() );
$r = run_guard();
t( 'D guard.json της 3.12.13 (λίστες μέσα): ο νέος φύλακας το ακολουθεί και το λέει (PNCP_LOCKDOWN_GUARD_INLINE)', true === $r['beacon'] && true === $r['inline'] && ! in_array( 'evil/evil.php', (array) $r['active'], true ) && get_option( 'stylesheet' ) === $r['stylesheet'], wp_json_encode( $r ) );
fresh();
t( 'D μετάβαση (migrate_guard_values()): guard.json ξαναγράφεται χωρίς λίστες, guard-values.json ξανά', PNCP_Seal::migrate_guard_values() && ! isset( PNCP_Seal::read_guard_data()['values'] ) && is_file( PNCP_Seal::guard_values_path() ) && PNCP_Lockdown::is_locked() && '' === PNCP_Lockdown::tampered() );
$r = run_guard();
t( 'D μετά τη μετάβαση: ο φύλακας κρατά plugins και θέμα', true === $r['beacon'] && false === $r['inline'] && ! in_array( 'evil/evil.php', (array) $r['active'], true ) && get_option( 'stylesheet' ) === $r['stylesheet'], wp_json_encode( $r ) );
t( 'D μετάβαση δεύτερη φορά: τίποτα να γίνει', false === PNCP_Seal::migrate_guard_values() );
// Ο φάκελος του ScrapeLock σβησμένος / μετονομασμένος ενώ είναι κλειδωμένο: ο φύλακας δεν κάνει τίποτα, χωρίς σφάλματα.
$empty = get_temp_dir() . 'pncp-t31214-plugins-' . wp_generate_password( 6, false );
mkdir( $empty );
$r = run_guard( array( 'WP_PLUGIN_DIR' => $empty ) );
rmdir( $empty );
t( 'D χωρίς τα αρχεία του ScrapeLock: ο φύλακας δεν βάζει φίλτρα, κανένα σφάλμα PHP', isset( $r['filters'] ) && 0 === $r['filters'] && ! isset( $r['error'] ), wp_json_encode( $r ) );
// Και το WordPress με τον φύλακα όταν ο φάκελος του ScrapeLock λείπει: κανένα fatal (λευκή σελίδα).
$folder = WP_PLUGIN_DIR . '/' . dirname( $own );
$away   = WP_PLUGIN_DIR . '/' . dirname( $own ) . '-t31214-away';
if ( ! is_link( $folder ) && is_dir( $folder ) && rename( $folder, $away ) ) {
	$cookies = array();
	list( $code, $body ) = http( '/wp-login.php' );
	rename( $away, $folder );
	t( 'D ScrapeLock μετονομασμένο ενώ είναι κλειδωμένο: η σύνδεση ανοίγει χωρίς σφάλμα', 200 === $code && false === stripos( $body, 'critical error' ) && ! php_errors( $body ), (string) $code );
} elseif ( is_link( $folder ) ) {
	$target = readlink( $folder );
	unlink( $folder );
	$cookies = array();
	list( $code, $body ) = http( '/wp-login.php' );
	symlink( $target, $folder );
	t( 'D ScrapeLock σβησμένο ενώ είναι κλειδωμένο (symlink): η σύνδεση ανοίγει χωρίς σφάλμα', 200 === $code && false === stripos( $body, 'critical error' ) && ! php_errors( $body ), (string) $code );
}

/* ---------- Μετά: ξεκλείδωτο, η πύλη δουλεύει όπως πριν ---------- */
clean_lock();
as_user( $edit_id );
list( $code, , $loc ) = http( '/wp-admin/index.php', null, $g );
t( 'ξεκλείδωτο: η πύλη άλλου plugin δεν αλλάζει (editor → αρχική σελίδα)', 302 === $code && untrailingslashit( home_url( '/' ) ) === untrailingslashit( $loc ), "$code $loc" );

/* ---------- Καθάρισμα ---------- */
@unlink( $gate );
foreach ( array( $admin_id, $other_id, $edit_id ) as $id ) {
	if ( $id && ! is_wp_error( $id ) ) {
		wp_delete_user( $id );
	}
}
clean_lock();

echo $fails ? "$fails FAIL\n" : "OK\n";
exit( $fails ? 1 : 0 );

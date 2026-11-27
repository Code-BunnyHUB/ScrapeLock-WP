<?php
/**
 * ScrapeLock 3.12.11 — ScrapeLock never writes a PHP file a malware scanner could take for a backdoor. SiteGround's
 * Site Scanner checks every new file as it is written and quarantined ScrapeLock 3.12.10 for these:
 *   - the check of "PHP in the uploads folder" wrote uploads/pncp-selftest-RANDOM.php (a PHP file that prints a
 *     word), opened it over HTTP and deleted it, every 6 hours from the admin card, Site Health and WP-CLI;
 *   - the temporary copy of wp-config.php was wp-config.scrapelock-RANDOM.php in the site's folder;
 *   - the temporary copy of the early check was scrapelock-early.php.RANDOM.tmp.
 *
 * On the test WordPress (as the user that owns it, as run-all.sh runs it), with "No PHP in the uploads folder", the
 * pre-cache check and the early check on, while every file created or renamed under WP_DIR is watched
 * (inotifywait -m -r, from the web server too; without inotify-tools: strace -f of the PHP processes of the test,
 * and a list of the PHP files before and after):
 *   A. the settings saved, the vulnerable points' checks (PNCP_Hardening::live()), the Site Health test
 *      "scrapelock_hardening" in wp-admin, `wp scrapelock harden check` (with WP_CLI), the pre-cache check and the
 *      early check written, rewritten and removed: no file ending in .php created anywhere under WP_DIR, except
 *      wp-config.php itself (renamed over) and wp-content/mu-plugins/scrapelock-early.php; no temporary name with
 *      ".php" in it; no pncp-selftest file;
 *   B. the result of "PHP in the uploads folder" is still sensible: here (PHP's built-in server sends a missing
 *      .php address to WordPress) "off" with a note, "partial" in the list (turned on, not enforced); and with the
 *      answers of other servers (pre_http_request): a bare 403 = on, WordPress's 404 = off, Nginx's own 404 =
 *      unknown with the reason, the same with ScrapeLock's Nginx rules installed and current = off (rule below the
 *      PHP location), Apache with the uploads .htaccess block but PHP answering = off (AllowOverride);
 *   C. backward compatibility: the one-line block of 3.12.10 in wp-config.php is replaced once by maybe_sync() and
 *      by the upgrade (pncp_upgrade_files()), and removed when the setting goes off; the 3.12.10 early mu-plugin
 *      ($pncp_early_dir) is recognised and rewritten; leftovers of 3.12.10 (wp-config.scrapelock-RANDOM.php older
 *      than an hour, uploads/pncp-selftest-RANDOM.php with its one line) are deleted;
 *   D. the new lines in wp-config.php and the new mu-plugin: valid PHP, plain loaders of the plugin's own file by
 *      its full path, with the plugin's name and how to remove them; no variable path.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 WP_CLI="wp --path=…" php t_31211_no_php_writes.php
 *
 * Only on a test WordPress: settings, wp-config.php and the early check's file are put back at the end.
 */

$wp_dir = rtrim( (string) getenv( 'WP_DIR' ), '/' );
$base   = rtrim( (string) getenv( 'BASE' ), '/' );
$wp_cli = (string) getenv( 'WP_CLI' );
if ( ! $wp_dir || ! $base ) {
	fwrite( STDERR, "WP_DIR and BASE are required\n" );
	exit( 2 );
}

$fails = 0;
function t( $label, $ok, $extra = '' ) {
	global $fails;
	if ( ! $ok ) {
		++$fails;
	}
	echo ( $ok ? 'PASS ' : 'FAIL ' ) . $label . ( '' !== (string) $extra && ! $ok ? "  [$extra]" : '' ) . "\n";
}

/** The first of these programs found in PATH, or ''. */
function find_bin( $names ) {
	foreach ( $names as $name ) {
		$path = trim( (string) shell_exec( 'command -v ' . escapeshellarg( $name ) . ' 2>/dev/null' ) );
		if ( '' !== $path ) {
			return $path;
		}
	}
	return '';
}

$root   = function_exists( 'posix_geteuid' ) && 0 === posix_geteuid();
$tmp    = sys_get_temp_dir() . '/pncp-t31211-' . getmypid();
$strace = find_bin( array( 'strace' ) );
if ( '' !== $strace && 0 !== (int) shell_exec( escapeshellarg( $strace ) . ' -f -qq -o /dev/null true >/dev/null 2>&1; echo $?' ) ) {
	$strace = ''; // ptrace not allowed here.
}
@mkdir( $tmp, 0755, true );
$traces = array();

/**
 * PHP code in a WordPress of its own process (DOING_CRON, or wp-admin with $admin), under strace when there is one:
 * what it returns.
 *
 * @param string $code  PHP code (a function body).
 * @param bool   $admin Load it as a wp-admin page (is_admin()), as the administrator.
 * @return mixed
 */
function wp_run( $code, $admin = false ) {
	global $wp_dir, $tmp, $base, $strace, $traces, $root;
	$file = $tmp . '/run-' . md5( $code . microtime() ) . '.php';
	$host = (string) parse_url( $base, PHP_URL_HOST ) . ( parse_url( $base, PHP_URL_PORT ) ? ':' . parse_url( $base, PHP_URL_PORT ) : '' );
	file_put_contents(
		$file,
		"<?php\n" . ( $admin ? "define( 'WP_ADMIN', true );\n" : "define( 'DOING_CRON', true );\n" )
		. ( $root ? "define( 'FS_METHOD', 'direct' );\n" : '' )
		. '$_SERVER[\'HTTP_HOST\'] = ' . var_export( $host, true ) . ";\n\$_SERVER['REQUEST_URI'] = '/wp-admin/';\n"
		. 'require ' . var_export( $wp_dir . '/wp-load.php', true ) . ";\n"
		. ( $admin ? "wp_set_current_user( 1 );\n" : '' )
		. "\$pncp_fn = function () {\n" . $code . "\n};\necho \"\\n@@PNCP@@\" . json_encode( \$pncp_fn() );\n"
	);
	$cmd = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $file );
	if ( '' !== $strace ) {
		$log      = $tmp . '/strace-' . count( $traces ) . '.log';
		$traces[] = $log;
		$cmd      = escapeshellarg( $strace ) . ' -f -qq -e trace=open,openat,creat,rename,renameat,renameat2,link,linkat -o ' . escapeshellarg( $log ) . ' ' . $cmd;
	}
	$out = (string) shell_exec( 'cd ' . escapeshellarg( $tmp ) . ' && ' . $cmd . ' 2>&1' );
	unlink( $file );
	$at = strrpos( $out, '@@PNCP@@' );
	if ( false === $at ) {
		fwrite( STDERR, "wp_run failed: $out\n" );
		return null;
	}
	if ( '' !== trim( substr( $out, 0, $at ) ) ) {
		echo trim( substr( $out, 0, $at ) ) . "\n"; // Warnings of the helper: run-all.sh counts them.
	}
	return json_decode( substr( $out, $at + 8 ), true );
}

/** Every *.php file under a folder (symlinks not followed), as path => size.mtime.inode. */
function php_files( $dir ) {
	$out = array();
	$it  = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::SELF_FIRST, RecursiveIteratorIterator::CATCH_GET_CHILD );
	foreach ( $it as $f ) {
		if ( $f->isLink() ) {
			continue;
		}
		if ( $f->isFile() && preg_match( '/\.php$/i', $f->getFilename() ) ) {
			$out[ $f->getPathname() ] = $f->getSize() . '.' . $f->getMTime() . '.' . $f->getInode();
		}
	}
	return $out;
}

/* ---------- Setup ---------- */

$saved = wp_run(
	'return array(
		"settings" => base64_encode( serialize( get_option( PNCP_OPTION ) ) ),
		"config"   => PNCP_Precheck::config_path(),
		"text"     => base64_encode( (string) file_get_contents( PNCP_Precheck::config_path() ) ),
		"early"    => file_exists( PNCP_Early::path() ),
		"mu"       => PNCP_Early::path(),
		"uploads"  => wp_get_upload_dir()["basedir"],
		"probe"    => method_exists( "PNCP_Hardening", "upload_php_probe_url" ) ? PNCP_Hardening::upload_php_probe_url() : "",
		"runtime"  => PNCP_Precheck::runtime_file(),
		"dir"      => PNCP_Precheck::dir(),
		"plugin"   => PNCP_DIR,
	);'
);
if ( ! is_array( $saved ) || '' === (string) $saved['config'] ) {
	echo "FAIL WordPress could not be loaded, or it has no wp-config.php\n";
	exit( 1 );
}
$config   = (string) $saved['config'];
$original = (string) base64_decode( $saved['text'] );
$uploads  = rtrim( (string) $saved['uploads'], '/' );
$mu_file  = (string) $saved['mu'];
$restore  = static function () use ( $saved, $config, $original, $mu_file ) {
	wp_run(
		'update_option( PNCP_OPTION, unserialize( base64_decode( ' . var_export( $saved['settings'], true ) . ' ) ) );
		PNCP_Options::flush();
		PNCP_Precheck::sync();
		PNCP_Early::sync();
		delete_transient( PNCP_Hardening::LIVE );
		return true;'
	);
	if ( (string) file_get_contents( $config ) !== $original ) {
		file_put_contents( $config, $original );
	}
	if ( ! $saved['early'] && file_exists( $mu_file ) && false !== strpos( (string) file_get_contents( $mu_file ), 'Plugin Name: ScrapeLock early check' ) ) {
		unlink( $mu_file );
	}
};
// Leftovers of 3.12.10 (written before the watch starts): deleted by this version.
$old_tmp  = dirname( $config ) . '/' . preg_replace( '/\.php$/', '', basename( $config ) ) . '.scrapelock-AbCd1234.php';
$old_self = $uploads . '/pncp-selftest-AbCdEfGh1234.php';
$young    = dirname( $config ) . '/' . preg_replace( '/\.php$/', '', basename( $config ) ) . '.scrapelock-YoUnG123.php';
file_put_contents( $old_tmp, $original );
touch( $old_tmp, time() - 2 * 3600 );
file_put_contents( $young, $original ); // Under an hour old: may be another request's copy in use, kept.
file_put_contents( $old_self, "<?php echo 'pncp' . '-ran';\n" );
$keep_self = $uploads . '/pncp-selftest-NotOurs12345.php';
file_put_contents( $keep_self, "<?php // someone else's\n" ); // Same name shape, other contents: never deleted.
$before = php_files( $wp_dir );

// The watch: every file created or moved into a folder under WP_DIR, by any process (the web server's included).
$watch = null;
$wlog  = $tmp . '/inotify.log';
$werr  = $tmp . '/inotify.err';
$inotify = find_bin( array( 'inotifywait' ) );
if ( '' !== $inotify ) {
	$watch = proc_open(
		'exec ' . escapeshellarg( $inotify ) . ' -m -r -e create -e moved_to --format ' . escapeshellarg( '%e|%w%f' ) . ' -o ' . escapeshellarg( $wlog ) . ' ' . escapeshellarg( $wp_dir ),
		array( array( 'file', '/dev/null', 'r' ), array( 'file', '/dev/null', 'w' ), array( 'file', $werr, 'w' ) ),
		$pipes
	);
	for ( $i = 0; $i < 300 && false === strpos( (string) @file_get_contents( $werr ), 'Watches established' ); $i++ ) {
		usleep( 100000 );
	}
	if ( false === strpos( (string) @file_get_contents( $werr ), 'Watches established' ) ) {
		echo '# inotifywait did not start: ' . trim( (string) @file_get_contents( $werr ) ) . "\n";
		proc_terminate( $watch );
		$watch = null;
	}
}
echo '# watch: ' . ( $watch ? 'inotifywait' : 'none' ) . ', strace: ' . ( '' !== $strace ? 'yes' : 'no' ) . ', as ' . ( $root ? 'root' : 'uid ' . getmyuid() ) . "\n";
if ( ! $watch && '' === $strace ) {
	echo "# neither inotifywait nor strace: only the PHP files before and after are compared\n";
}

/* ---------- A. Everything that wrote a PHP file in 3.12.10 ---------- */

$on = wp_run(
	'$s = get_option( PNCP_OPTION );
	$s = array_merge( is_array( $s ) ? $s : array(), array( "enabled" => 1, "monitor" => 0, "precheck" => 1, "early_mode" => 1, "block_upload_php" => 1 ) );
	update_option( PNCP_OPTION, $s );
	PNCP_Options::flush();
	$pre = PNCP_Precheck::sync();
	PNCP_Early::sync();
	return array( "precheck" => $pre, "in_config" => PNCP_Precheck::in_config(), "early" => PNCP_Early::installed(), "block" => PNCP_Precheck::block(), "code" => PNCP_Early::code() );'
);
t( 'A the pre-cache check is written into wp-config.php', is_array( $on ) && 'ok' === $on['precheck'] && $on['in_config'], wp_json_encode_safe( $on ) );
t( 'A the early check is written (mu-plugins/scrapelock-early.php)', is_array( $on ) && $on['early'] );
t( 'A leftover wp-config.scrapelock-RANDOM.php of 3.12.10 (older than an hour) deleted', ! file_exists( $old_tmp ) );
t( 'A a copy under an hour old kept (another request\'s, in use)', file_exists( $young ) );
@unlink( $young );

$live = wp_run(
	'$live = PNCP_Hardening::live( true );
	$row  = null;
	foreach ( PNCP_Hardening::rows() as $r ) {
		if ( "upload_php" === $r["id"] ) {
			$row = array( "state" => $r["state"], "note" => $r["note"], "applied" => $r["applied"] );
		}
	}
	return array( "check" => $live["upload_php"], "row" => $row );'
);
t( 'A leftover uploads/pncp-selftest-RANDOM.php of 3.12.10 deleted by the check', ! file_exists( $old_self ) );
t( 'A a file of that name shape with other contents left alone', file_exists( $keep_self ) );
@unlink( $keep_self );

// The Site Health test, as in wp-admin (the cache of the checks emptied, so it makes them).
$health = wp_run(
	'delete_transient( PNCP_Hardening::LIVE );
	require_once ABSPATH . "wp-admin/includes/class-wp-site-health.php";
	$tests = WP_Site_Health::get_tests();
	$test  = $tests["direct"]["scrapelock_hardening"]["test"] ?? null;
	$out   = is_callable( $test ) ? call_user_func( $test ) : null;
	return array( "status" => is_array( $out ) ? $out["status"] : "", "ran" => is_array( get_transient( PNCP_Hardening::LIVE ) ) );',
	true
);
t( 'A Site Health "scrapelock_hardening" ran the checks in wp-admin', is_array( $health ) && $health['ran'] && in_array( $health['status'], array( 'good', 'recommended' ), true ), wp_json_encode_safe( $health ) );

if ( '' !== $wp_cli ) {
	$cmd = $wp_cli . ' scrapelock harden check --format=json';
	if ( '' !== $strace ) {
		$log      = $tmp . '/strace-cli.log';
		$traces[] = $log;
		$cmd      = escapeshellarg( $strace ) . ' -f -qq -e trace=open,openat,creat,rename,renameat,renameat2,link,linkat -o ' . escapeshellarg( $log ) . ' ' . $cmd;
	}
	exec( $cmd . ' 2>/dev/null < /dev/null', $cli_out, $rc );
	$rows = json_decode( (string) end( $cli_out ), true );
	$up   = null;
	foreach ( is_array( $rows ) ? $rows : array() as $r ) {
		if ( 'upload_php' === ( $r['id'] ?? '' ) ) {
			$up = $r;
		}
	}
	t( 'A wp scrapelock harden check: runs, lists upload_php', 0 === $rc && is_array( $up ), implode( "\n", $cli_out ) );
	t( 'A wp scrapelock harden check: upload_php is on, off, partial or unknown, with a note when not on', is_array( $up ) && in_array( $up['status'], array( 'on', 'off', 'partial', 'unknown' ), true ) && ( 'on' === $up['status'] || '' !== (string) $up['note'] ), wp_json_encode_safe( $up ) );
} else {
	echo "SKIP wp scrapelock harden check (no WP_CLI)\n";
}

/* ---------- C. The lines and the mu-plugin of 3.12.10 ---------- */

$old = wp_run(
	'$runtime = var_export( PNCP_Precheck::runtime_file(), true );
	$data    = var_export( PNCP_Precheck::dir(), true );
	$key     = var_export( PNCP_Server_Ips::sig_key( true ), true );
	$line    = PNCP_Precheck::BEGIN . " (added and removed by the plugin\'s \"Pre-cache check\" setting)\n"
		. "if ( is_file( " . $runtime . " ) ) { include_once " . $runtime . "; PNCP_Precheck_Runtime::boot( " . $data . ", " . $key . " ); }\n"
		. PNCP_Precheck::END . "\n";
	$path = PNCP_Precheck::config_path();
	$now  = (string) file_get_contents( $path );
	$old  = str_replace( PNCP_Precheck::block(), $line, $now );
	file_put_contents( $path, $old );
	update_option( PNCP_Precheck::BLOCK_HASH, md5( $line ), false );
	update_option( PNCP_Precheck::STATUS, "ok", false );
	delete_transient( PNCP_Precheck::RETRY );
	$seen = array( "outdated" => PNCP_Precheck::line_outdated(), "in" => PNCP_Precheck::in_config() );
	PNCP_Precheck::maybe_sync();
	$after = (string) file_get_contents( $path );
	$seen["replaced"] = PNCP_Precheck::in_config() && false === strpos( $after, $line ) && 1 === substr_count( $after, PNCP_Precheck::BEGIN ) && PNCP_Precheck::without_block( $after ) === PNCP_Precheck::without_block( $now );
	// The upgrade of a new version (pncp_upgrade_files()) replaces it too.
	file_put_contents( $path, $old );
	pncp_upgrade_files();
	$after = (string) file_get_contents( $path );
	$seen["upgrade"] = PNCP_Precheck::in_config() && false === strpos( $after, $line ) && 1 === substr_count( $after, PNCP_Precheck::BEGIN );
	// Removed when the setting goes off, also in the old shape.
	file_put_contents( $path, $old );
	$seen["strip"] = PNCP_Precheck::without_block( $old ) === PNCP_Precheck::without_block( $now );
	return $seen + array( "line" => $line );'
);
t( 'C the 3.12.10 line in wp-config.php: recognised as outdated', is_array( $old ) && $old['outdated'] && ! $old['in'] );
t( 'C maybe_sync() replaces it once with the new lines (the rest of wp-config.php unchanged)', is_array( $old ) && $old['replaced'] );
t( 'C the upgrade (pncp_upgrade_files()) replaces it too', is_array( $old ) && $old['upgrade'] );
t( 'C without_block() removes the 3.12.10 line', is_array( $old ) && $old['strip'] );

// The 3.12.10 mu-plugin: recognised as ScrapeLock's, rewritten by the sync of the setting and the upgrade.
$old_early = "<?php\n/**\n * Plugin Name: ScrapeLock early check\n * Description: Created by ScrapeLock (setting \"Early check\"). Blocks known bots before the theme and the other plugins load. It is removed when the setting is turned off or ScrapeLock is deactivated.\n *\n * @package ScrapeLock\n */\n\ndefined( 'ABSPATH' ) || exit;\n\n"
	. '$pncp_early_dir = ' . var_export( (string) $saved['plugin'], true ) . ";\nif ( is_readable( \$pncp_early_dir . 'includes/class-pncp-early.php' ) ) {\n\trequire_once \$pncp_early_dir . 'includes/class-pncp-early.php';\n\tPNCP_Early::run( \$pncp_early_dir, 'scrapelock/scrapelock.php' );\n}\nunset( \$pncp_early_dir );\n";
file_put_contents( $mu_file, $old_early );
$early = wp_run( 'return array( "ours" => PNCP_Early::ours( PNCP_Early::path() ), "installed" => PNCP_Early::installed(), "sync" => PNCP_Early::sync(), "now" => PNCP_Early::installed() );' );
t( 'C the 3.12.10 mu-plugin: ScrapeLock\'s (ours()), not current (installed())', is_array( $early ) && $early['ours'] && ! $early['installed'] );
t( 'C PNCP_Early::sync() rewrites it (no $pncp_early_dir any more)', is_array( $early ) && $early['sync'] && $early['now'] && false === strpos( (string) file_get_contents( $mu_file ), '$pncp_early_dir' ) );

/* ---------- Off again: lines and mu-plugin removed ---------- */

$off = wp_run(
	'$s = get_option( PNCP_OPTION );
	$s["precheck"]   = 0;
	$s["early_mode"] = 0;
	update_option( PNCP_OPTION, $s );
	PNCP_Options::flush();
	return array( "in" => PNCP_Precheck::in_config(), "early" => file_exists( PNCP_Early::path() ) );'
);
$text = (string) file_get_contents( $config );
t( 'C off: the lines (here the 3.12.10 shape) removed, wp-config.php as it was', is_array( $off ) && ! $off['in'] && false === strpos( $text, 'ScrapeLock pre-cache check' ) && $text === $original, substr( $text, 0, 300 ) );
t( 'C off: the mu-plugin removed', is_array( $off ) && ! $off['early'] );
// On and off once more in the new shape (rewrite, then removal: two more renames of wp-config.php).
wp_run(
	'$s = get_option( PNCP_OPTION );
	$s["precheck"] = 1;
	$s["early_mode"] = 1;
	update_option( PNCP_OPTION, $s );
	PNCP_Options::flush();
	$s["precheck"] = 0;
	$s["early_mode"] = 0;
	update_option( PNCP_OPTION, $s );
	return true;'
);

/* ---------- The watch: no PHP file created ---------- */

sleep( 1 ); // The last events.
$events = array();
if ( $watch ) {
	proc_terminate( $watch );
	proc_close( $watch );
	foreach ( (array) file( $wlog, FILE_IGNORE_NEW_LINES ) as $line ) {
		$parts = explode( '|', (string) $line, 2 );
		if ( 2 === count( $parts ) && false === strpos( $parts[0], 'ISDIR' ) ) {
			$events[] = $parts[1];
		}
	}
}
// strace: files opened with O_CREAT, and rename / link targets and sources, under WP_DIR.
$real_wp = (string) realpath( $wp_dir );
foreach ( $traces as $log ) {
	foreach ( (array) @file( $log, FILE_IGNORE_NEW_LINES ) as $line ) {
		if ( preg_match( '/\b(?:open|openat|creat)\((?:[^,]*, )?"([^"]+)"(?:, ([^,)]+))?/', (string) $line, $m ) && ( 'creat' === substr( (string) $line, strpos( (string) $line, ' ' ) + 1, 5 ) || ( isset( $m[2] ) && false !== strpos( $m[2], 'O_CREAT' ) ) ) && ! preg_match( '/= -1 /', (string) $line ) ) {
			$events[] = $m[1];
		} elseif ( preg_match( '/\b(?:rename|renameat2?|link|linkat)\((?:[^,]*, )?"([^"]+)", (?:[^,]*, )?"([^"]+)"/', (string) $line, $m ) && ! preg_match( '/= -1 /', (string) $line ) ) {
			$events[] = $m[1];
			$events[] = $m[2];
		}
	}
}
$after = php_files( $wp_dir );
foreach ( array_diff_key( $after, $before ) as $path => $unused ) {
	$events[] = $path;
}
$allowed = array( $config, (string) realpath( $config ), $mu_file, (string) realpath( dirname( $mu_file ) ) . '/' . basename( $mu_file ) );
$bad     = array();
$dotphp  = array();
foreach ( array_unique( $events ) as $path ) {
	$path = (string) $path;
	$in   = 0 === strpos( $path, $wp_dir . '/' ) || ( '' !== $real_wp && 0 === strpos( $path, $real_wp . '/' ) );
	if ( ! $in ) {
		continue;
	}
	if ( preg_match( '/\.php$/i', $path ) && ! in_array( $path, $allowed, true ) ) {
		$bad[] = $path;
	}
	// Ours: the temporary copies of wp-config.php and of the early check, the uploads test.
	if ( preg_match( '/scrapelock|pncp/i', basename( $path ) ) && preg_match( '/\.php\./i', basename( $path ) ) ) {
		$dotphp[] = $path;
	}
}
t( 'A no file ending in .php created under WP_DIR (but wp-config.php and mu-plugins/scrapelock-early.php)', array() === $bad, implode( ', ', $bad ) );
t( 'A no temporary file of ScrapeLock with ".php" in its name', array() === $dotphp, implode( ', ', $dotphp ) );
t( 'A no pncp-selftest file was ever created', ! preg_grep( '/pncp-selftest-/', $events ) );
if ( $watch ) {
	t( 'A the watch saw the renames of wp-config.php and of the mu-plugin (it worked)', in_array( $config, $events, true ) && in_array( $mu_file, $events, true ), implode( ', ', array_slice( preg_grep( '/wp-config|scrapelock-early/', $events ), 0, 10 ) ) );
	t( 'A the temporary copy of wp-config.php ends in .tmp', (bool) preg_grep( '/\/' . preg_quote( preg_replace( '/\.php$/', '', basename( $config ) ), '/' ) . '\.scrapelock-[A-Za-z0-9]{8}\.tmp$/', $events ) );
}
t( 'A no new PHP file left in uploads', array() === array_diff_key( php_files( $uploads ), $before ), implode( ', ', array_keys( array_diff_key( php_files( $uploads ), $before ) ) ) );

/* ---------- B. The result of "PHP in the uploads folder" ---------- */

t( 'B here: the PHP address in uploads reached WordPress: off, with what to do', is_array( $live ) && 'off' === $live['check']['state'] && false !== strpos( $live['check']['note'], 'reached PHP' ), wp_json_encode_safe( $live ) );
t( 'B in the list: partial (turned on, the server does not refuse it)', is_array( $live ) && is_array( $live['row'] ) && 'partial' === $live['row']['state'] && $live['row']['applied'] && '' !== $live['row']['note'], wp_json_encode_safe( $live ) );
$code = wp_remote_retrieve_response_code_safe( (string) $saved['probe'] );
t( 'B the address asked is a PHP file in uploads that does not exist (nothing written there)', $code >= 300 && ! file_exists( $uploads . '/' . basename( (string) $saved['probe'] ) ) && (bool) preg_match( '#/scrapelock-check-no-such-file\.php$#', (string) $saved['probe'] ), $code . ' ' . $saved['probe'] );

$sim = wp_run(
	'$s = get_option( PNCP_OPTION );
	$s["block_upload_php"] = 1;
	update_option( PNCP_OPTION, $s );
	PNCP_Options::flush();
	$probe = PNCP_Hardening::upload_php_probe_url();
	$GLOBALS["pncp_answer"] = null;
	add_filter( "pre_http_request", function ( $pre, $args, $url ) use ( $probe ) {
		if ( $url !== $probe || null === $GLOBALS["pncp_answer"] ) {
			return $pre;
		}
		return $GLOBALS["pncp_answer"] + array( "cookies" => array(), "filename" => null );
	}, 10, 3 );
	$m = new ReflectionMethod( "PNCP_Hardening", "check_upload_php" );
	$m->setAccessible( true );
	$ask = function ( $code, $headers, $body ) use ( $m ) {
		$GLOBALS["pncp_answer"] = array( "response" => array( "code" => $code, "message" => "" ), "headers" => $headers, "body" => $body );
		return $m->invoke( null );
	};
	$out = array();
	$out["403"]   = $ask( 403, array( "server" => "nginx" ), "<html><center>nginx</center></html>" );
	$out["wp404"] = $ask( 404, array( "x-scrapelock" => "ok id=12345678" ), "<html>Page not found</html>" );
	delete_transient( PNCP_Rules_Status::NGINX );
	$out["ng404"] = $ask( 404, array( "server" => "nginx" ), "<html><center>nginx</center></html>" );
	$want = PNCP_Rules::nginx_fingerprint();
	set_transient( PNCP_Rules_Status::NGINX, array( "want" => $want, "v" => PNCP_Rules_Status::VERSION, "body" => $want, "error" => "", "via" => "origin", "ip" => "127.0.0.1", "kind" => "nginx", "code" => 200 ), 300 );
	$out["ng404rules"] = $ask( 404, array( "server" => "nginx" ), "<html><center>nginx</center></html>" );
	delete_transient( PNCP_Rules_Status::NGINX );
	add_filter( "pncp_harden_is_apache", "__return_true" );
	PNCP_Rules::sync_uploads_htaccess( true );
	$out["apache"] = $ask( 404, array( "x-scrapelock" => "ok id=12345678" ), "<html>Page not found</html>" );
	$out["apache403"] = $ask( 403, array( "server" => "Apache" ), "<address>Apache</address>" );
	return $out;'
);
t( 'B a bare 403 of the server: on', is_array( $sim ) && 'on' === $sim['403']['state'], wp_json_encode_safe( $sim['403'] ?? null ) );
t( 'B WordPress answered (404, X-ScrapeLock): off, on Nginx add the rule', is_array( $sim ) && 'off' === $sim['wp404']['state'] && false !== strpos( $sim['wp404']['note'], 'Server rules' ), wp_json_encode_safe( $sim['wp404'] ?? null ) );
t( 'B Nginx\'s own 404, no rules known: unknown, with the status and why (no PHP file is written)', is_array( $sim ) && 'unknown' === $sim['ng404']['state'] && false !== strpos( $sim['ng404']['note'], '404' ) && false !== strpos( $sim['ng404']['note'], 'does not write a PHP file' ), wp_json_encode_safe( $sim['ng404'] ?? null ) );
t( 'B Nginx\'s own 404 with ScrapeLock\'s rules current: off (the rule is below the PHP location)', is_array( $sim ) && 'off' === $sim['ng404rules']['state'] && false !== strpos( $sim['ng404rules']['note'], 'above the location' ), wp_json_encode_safe( $sim['ng404rules'] ?? null ) );
t( 'B Apache with the uploads .htaccess block, but PHP answered: off, the .htaccess is ignored', is_array( $sim ) && 'off' === $sim['apache']['state'] && false !== strpos( $sim['apache']['note'], 'AllowOverride' ), wp_json_encode_safe( $sim['apache'] ?? null ) );
t( 'B Apache refuses it (403): on', is_array( $sim ) && 'on' === $sim['apache403']['state'] );

/* ---------- D. What the new files look like ---------- */

if ( is_array( $on ) ) {
	$lint = static function ( $code ) use ( $tmp ) {
		$file = $tmp . '/lint.txt';
		file_put_contents( $file, $code );
		exec( escapeshellarg( PHP_BINARY ) . ' -l ' . escapeshellarg( $file ) . ' 2>&1', $out, $rc );
		unlink( $file );
		return 0 === $rc;
	};
	$block = (string) $on['block'];
	$code  = (string) $on['code'];
	t( 'D wp-config.php lines: valid PHP, several lines, the plugin\'s name and how to remove them', $lint( "<?php\n" . $block ) && substr_count( $block, "\n" ) >= 8 && false !== strpos( $block, 'ScrapeLock (WordPress plugin)' ) && false !== strpos( $block, 'To remove' ), $block );
	t( 'D wp-config.php lines: include_once of the plugin\'s own file by its full path, no variable', false !== strpos( $block, "include_once '" . $saved['runtime'] . "';" ) && ! preg_match( '/\$[a-z_]+/i', $block ) );
	t( 'D wp-config.php lines: the data folder and the key on lines of their own (the key never in the data folder)', false !== strpos( $block, "\t\t'" . $saved['dir'] . "', // The data folder." ) && false !== strpos( $block, "// The key of the site's signed requests to itself." ) );
	t( 'D mu-plugin: valid PHP, says what it is and how to remove it', $lint( $code ) && false !== strpos( $code, 'Plugin Name: ScrapeLock early check' ) && false !== strpos( $code, 'To remove it' ) && false !== strpos( substr( $code, 0, 200 ), 'Plugin Name: ScrapeLock early check' ) );
	t( 'D mu-plugin: require_once of the plugin\'s own file by its full path, no variable', false !== strpos( $code, "require_once '" . $saved['plugin'] . "includes/class-pncp-early.php';" ) && ! preg_match( '/\$[a-z_]+/i', $code ) );
}

$restore();
t( 'end: wp-config.php as it was', (string) file_get_contents( $config ) === $original );
exec( 'rm -rf ' . escapeshellarg( $tmp ) );
exit( $fails ? 1 : 0 );

/** JSON for a failure's details. */
function wp_json_encode_safe( $value ) {
	return substr( (string) json_encode( $value ), 0, 600 );
}

/** The status of a GET of an address (no WordPress loaded here). */
function wp_remote_retrieve_response_code_safe( $url ) {
	$ctx = stream_context_create( array( 'http' => array( 'ignore_errors' => true, 'timeout' => 10 ) ) );
	@file_get_contents( $url, false, $ctx );
	$head = isset( $http_response_header[0] ) ? (string) $http_response_header[0] : '';
	return preg_match( '#^HTTP/\S+ (\d{3})#', $head, $m ) ? (int) $m[1] : 0;
}

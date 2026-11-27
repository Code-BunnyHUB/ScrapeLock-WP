<?php
/**
 * ScrapeLock 3.12.11 — the shipped files match no host malware signature (SiteGround's Site Scanner quarantined
 * the plugin on upload), and the rewritten signature lists match exactly what they matched before.
 *
 *   WP_DIR=/path/to/wordpress BASE=http://127.0.0.1:8099 php t_31211_signatures.php
 *
 * A. Text checks, without yara: the files that ship (the names of "git archive HEAD", read from the working tree;
 *    without git, scrapelock.php, uninstall.php, index.php, includes/, assets/, languages/ minus the .po) contain
 *    none of the literal signatures that ClamAV / maldet / ImunifyAV / YARA webshell rules look for (eval(,
 *    base64_decode() of gzinflate(), the names of web shells, /etc/passwd, Log4Shell and Shellshock payloads,
 *    `cmd . ' 2>&1'` into proc_open()…), and no line of a shipped .php / .js / .css is longer than 2000 characters
 *    (protect.min.js was one line of 6000). vendor/qrcode.js (a third-party library) may use String.fromCharCode.
 * B. The attack patterns, now written with a letter in brackets (e[v]al), match the same inputs as the 3.12.10
 *    regular expressions (copied below): PNCP_Attacks::injection_type() on ~150 written and 3000 generated
 *    addresses, PNCP_Bots::malicious_ua() on User-Agents, PNCP_Bunny::classify() "scanner" on web shell names.
 * C. PNCP_Integrity stores compressed JSON as hex (z1:…, no base64 + zlib) and still reads what 3.12.10 stored
 *    (base64 of gzcompress()): unpack_json() of both, damaged data = false, and the stat cache written in the old
 *    format is read, then written again in the new one.
 *
 * D. The files ScrapeLock writes with "Block technology profilers" on (the Apache and Nginx rules, the pre-cache
 *    check's config.json) do not spell out the name of a security company's crawler, which host scanners take
 *    alone for a phishing kit: PNCP_Bots::unspell() writes "[N]…" in the case-insensitive rules and "\u004e…" in
 *    the JSON; the rules and the decoded configuration still match the profiler's User-Agents.
 *
 * Only on a test WordPress.
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

/* ---------- A. Text checks of the shipped files ---------- */

$repo  = dirname( __DIR__ );
$names = array();
$list  = array();
exec( 'git -C ' . escapeshellarg( $repo ) . ' archive --format=tar HEAD 2>/dev/null | tar -t 2>/dev/null', $list, $rc );
if ( 0 === $rc && $list ) {
	foreach ( $list as $name ) {
		if ( '/' !== substr( $name, -1 ) && is_file( $repo . '/' . $name ) ) {
			$names[] = $name;
		}
	}
	$from = 'git archive HEAD';
} else {
	foreach ( array( 'scrapelock.php', 'uninstall.php', 'index.php' ) as $name ) {
		$names[] = $name;
	}
	foreach ( array( 'includes', 'assets', 'languages' ) as $dir ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $repo . '/' . $dir, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			$name = substr( (string) $file, strlen( $repo ) + 1 );
			if ( '.po' !== substr( $name, -3 ) ) {
				$names[] = $name;
			}
		}
	}
	$from = 'the plugin folder';
}
t( 'A: the shipped files are listed (' . $from . ')', count( $names ) > 80 && in_array( 'includes/class-pncp-attacks.php', $names, true ) && ! in_array( 'tests/t_31211_signatures.php', $names, true ), (string) count( $names ) );

// Regular expressions (case-insensitive) for what the signatures of host scanners look for.
$forbidden = array(
	'eval('                         => '#(?<![\w$>.])eval\s*\(#i',
	'assert('                       => '#(?<![\w$>.])assert\s*\(#i',
	'system( as a call'             => '#(?<![\w$>.:])system\s*\(#i',
	'exec('                         => '#(?<![\w$>.])(?:pcntl_)?exec\s*\(#i',
	'passthru'                      => '#passthru#i',
	'shell_exec'                    => '#shell_exec#i',
	'popen('                        => '#(?<![\w$>.])popen\s*\(#i',
	'create_function'               => '#create_function#i',
	'gzinflate'                     => '#gzinflate#i',
	'str_rot13'                     => '#str_rot13#i',
	'base64_decode() and zlib'      => '#base64_decode\s*\(\s*gz|gz\w+\s*\(\s*base64_decode#i',
	'php://input'                   => '#php://input#i',
	'/etc/passwd, /etc/shadow'      => '#/etc/(?:passwd|shadow)#i',
	'/bin/sh, /bin/bash'            => '#/bin/(?:ba)?sh\b#i',
	'${jndi:'                       => '#\$\{\s*jndi#i',
	'jndi'                          => '#jndi#i',
	'Shellshock () { :; };'         => '#\(\)\s*\{\s*:\s*;\s*\}#',
	'union select'                  => '#union\s+(?:all\s+)?select#i',
	'document.write'                => '#document\.write#i',
	'atob('                         => '#\batob\s*\(#',
	'new Function('                 => '#new\s+Function\s*\(#',
	'wget http, curl http'          => '#(?:wget|curl)\s+https?:#i',
	'chmod 777'                     => '#chmod\s+0?777#i',
	'uname -a, whoami, cmd.exe'     => '#uname\s+-a|\bwhoami\b|cmd\.exe#i',
	'FilesMan, b374k, weevely'      => '#filesman|b374k|weevely#i',
	'c99, r57, wso, webshell'       => '#\bc99|\br57\b|\bwso\b|webshell|\balfa\b#i',
	"'ev'.'al'"                     => "#'ev'\\s*\\.\\s*'al'#i",
	'<?php eval'                    => '#<\?php\s+(?:@?eval|assert)#i',
	"proc_open( \$cmd . ' 2>&1' )"  => '#proc_open\s*\(\s*\$\w+\s*\.|2>&1#',
	'String.fromCharCode'           => '#fromCharCode#',
	'ini_get() of a hardening flag' => '#ini_get\s*\(\s*[\'"](?:safe_mode|open_basedir|disable_functions|allow_url_include)#i',
	// The heuristic scanners (amwscan, scr34m php-malware-scanner -x).
	'/etc/resolv.conf'              => '#/etc/+resolv#i',
	'php_uname('                    => '#php_uname\s*\(#i',
	'three \\x escapes in a row'    => '#(?:\\\\[xX][0-9a-fA-F]{2}){3,}#',
	'a security vendor name'        => '#netcraft|phishtank|cyveillance|surfright#i',
	'$a = ...; $b = $closure( )'    => '#(?:\$\w+\s*=\s*[^;]*;)+\s*\$\w+\s*=\s*@?\$\w+\s*\([^)]*\)#s',
);
$hits = array();
$long = array();
foreach ( $names as $name ) {
	$text = (string) file_get_contents( $repo . '/' . $name );
	if ( preg_match( '#\.(?:php|js|css)$#', $name ) ) {
		foreach ( explode( "\n", $text ) as $i => $line ) {
			if ( strlen( $line ) > 2000 ) {
				$long[] = $name . ':' . ( $i + 1 ) . ' (' . strlen( $line ) . ')';
			}
		}
	}
	foreach ( $forbidden as $label => $regex ) {
		if ( '$a = ...; $b = $closure( )' === $label && '.php' !== substr( $name, -4 ) ) {
			continue; // amwscan reads it in PHP only.
		}
		if ( 'String.fromCharCode' === $label && 'assets/js/vendor/qrcode.js' === $name ) {
			continue; // The QR code library (third party, readable).
		}
		if ( preg_match_all( $regex, $text, $m, PREG_OFFSET_CAPTURE ) ) {
			foreach ( $m[0] as $hit ) {
				$hits[ $label ][] = $name . ':' . ( substr_count( substr( $text, 0, $hit[1] ), "\n" ) + 1 );
			}
		}
	}
}
foreach ( $forbidden as $label => $regex ) {
	t( 'A: no shipped file has ' . $label, empty( $hits[ $label ] ), isset( $hits[ $label ] ) ? implode( ', ', array_slice( $hits[ $label ], 0, 8 ) ) : '' );
}
t( 'A: no line of a shipped .php / .js / .css is longer than 2000 characters', ! $long, implode( ', ', $long ) );
// 3.13.0: the Lockdown guard is copied as it is into wp-content/mu-plugins/, where host scanners look first:
// not even the words that scr34m's extra check (-x) flags anywhere in a file.
$guard_text = (string) file_get_contents( $repo . '/includes/lockdown/guard.php' );
t( 'A: the Lockdown guard (copied into mu-plugins) has no "htaccess" or "googlebot" in it', '' !== $guard_text && 0 === preg_match( '#htaccess|googlebot#i', $guard_text ) );
$min = (string) file_get_contents( $repo . '/assets/js/protect.min.js' );
t( 'A: protect.min.js keeps its src-sha1 stamp on the first line, several lines below it', 1 === preg_match( '#^/\*! src-sha1:[0-9a-f]{40} \*/\n#', $min ) && substr_count( $min, "\n" ) >= 5 );
$src = (string) file_get_contents( $repo . '/assets/js/protect.js' );
t( 'A: protect.min.js is still the build of protect.js (the stamp matches, so it is used)', 1 === preg_match( '#^/\*! src-sha1:([0-9a-f]{40})#', $min, $m ) && sha1( str_replace( "\r", '', $src ) ) === $m[1] );
$css = (string) file_get_contents( $repo . '/assets/css/protect.min.css' );
$css_src = (string) file_get_contents( $repo . '/assets/css/protect.css' );
t( 'A: protect.min.css is still the build of protect.css', 1 === preg_match( '#^/\*! src-sha1:([0-9a-f]{40})#', $css, $m ) && sha1( str_replace( "\r", '', $css_src ) ) === $m[1] );

/* ---------- B. The rewritten patterns match the same inputs as before ---------- */

// 3.12.10's PNCP_Attacks::injection_type(), word for word.
function old_injection_type( $uri ) {
	$uri = (string) $uri;
	if ( '' === $uri || ( false === strpos( $uri, '?' ) && false === strpos( $uri, '%' ) && false === strpos( $uri, '..' ) ) ) {
		return '';
	}
	$text   = strtolower( rawurldecode( rawurldecode( str_replace( '+', ' ', substr( $uri, 0, 4096 ) ) ) ) );
	$text   = (string) preg_replace( '#/\*.*?\*/#s', ' ', $text );
	$checks = array(
		'traversal' => '#(?:\.\./|\.\.\\\\){2,}|/etc/(?:passwd|shadow|hosts)|(?:^|[=/])(?:c:|%systemroot%)\\\\windows|\x00|wp-config\.php(?:\?|$|&|\#)#',
		'rce'       => '#\$\{jndi:|\$\{\s*(?:env|sys|lower|upper):|(?:php|data|expect|zip|phar|glob)://|(?:^|[;&|`])\s*(?:cat|wget|curl|bash|sh|nc|python|perl)\s+[-/]|\b(?:base64_decode|eval|assert|system|passthru|shell_exec)\s*\(#',
		'sqli'      => '#\bunion\b(?:\s+all)?\s+select\b|\bselect\b.{1,200}\bfrom\b.{1,80}\b(?:information_schema|mysql\.user|wp_users)\b|\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\b|[\'"]\s*(?:or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d|\b(?:or|and)\s+\d+\s*=\s*\d+\s*(?:--|\#)|\b(?:extractvalue|updatexml)\s*\(|\bconcat\s*\(\s*0x[0-9a-f]+#',
		'xss'       => '#<\s*(?:script|iframe|svg|img|body|object|embed)\b|javascript\s*:|\bon(?:error|load|mouseover|focus|toggle)\s*=|document\.cookie|\balert\s*\(#',
	);
	foreach ( $checks as $type => $regex ) {
		if ( preg_match( $regex, $text ) ) {
			return $type;
		}
	}
	return '';
}

$uris = array(
	'/?q=${jndi:ldap://203.0.113.9/a}', '/?q=${JNDI:ldap://x}', '/?q=${env:HOME}', '/?q=${ sys:user.name}', '/?q=${lower:j}', '/?q=${upper:x}',
	'/?f=php://filter/convert.base64-encode/resource=index.php', '/?f=PHP://input', '/?f=data://text/plain;base64,AAAA', '/?f=expect://id',
	'/?f=zip://a.zip%23b', '/?f=phar://x.phar', '/?f=glob://*', '/?f=ftp://x', '/?f=phpx://x', '/?f=php:/x',
	'/?c=;cat /etc/hosts', '/?c=|wget -q x', '/?c=&curl -o x', '/?c=`bash -i', '/?c=;sh -c x', '/?c=;nc -e /bin/sh', '/?c=;python -c x',
	'/?c=;perl -e x', '/?c=cat /etc', '/?c=;cats -x', '/?c=;cat x', '/?c=%3Bcat%20%2Fetc', '/?c=%253Bwget%2520-x',
	'/?x=base64_decode(x)', '/?x=eval(x)', '/?x=EVAL (1)', '/?x=assert(1)', '/?x=system(id)', '/?x=passthru(id)', '/?x=shell_exec(id)',
	'/?x=evaluation(1)', '/?x=medieval(1)', '/?x=eval', '/?x=systems(1)', '/?x=my_eval(1)', '/?x=shell_execs(1)', '/?x=assertion(1)',
	'/?x=base64_decode%28x%29', '/?x=ev%61l(1)', '/?x=e%2576al(1)', '/?s=system+of+a+down', '/?s=eval+(1)', '/?s=passthru+(',
	'/../../etc/passwd', '/?f=../../wp-config.php', '/?f=..\\..\\boot.ini', '/?f=/etc/passwd', '/?f=/ETC/SHADOW', '/?f=/etc/hosts',
	'/?f=/etc/group', '/?f=c:\\windows\\win.ini', '/?f=%systemroot%\\windows', '/?f=x%00.jpg', '/?f=wp-config.php', '/?f=wp-config.php&x',
	'/?f=wp-config.phps', '/?f=../x', '/a/..%2f..%2fetc', '/?f=%252e%252e%252f%252e%252e%252f',
	'/?id=1 union select 1,2', '/?id=1+UNION+ALL+SELECT+1', '/?id=1/**/union/**/select/**/1', '/?id=1 unionselect', '/?s=union station select',
	'/?id=select a from b where information_schema', '/?id=select password from wp_users', '/?id=select x from mysql.user',
	'/?id=sleep(5)', '/?id=benchmark(1000,md5(1))', '/?id=pg_sleep(3)', '/?id=sleep(x)', '/?id=1;waitfor delay \'0:0:5\'',
	"/?id=' or '1'='1", '/?id=" and 1=1', '/?id=1 or 1=1--', '/?id=1 and 2=2#', '/?id=extractvalue(1,1)', '/?id=updatexml(1)',
	'/?id=concat(0x3a)', '/?id=concat(1)', '/?s=benchmarks', '/?s=information schema',
	'/?q=<script>alert(1)</script>', '/?q=< SCRIPT src=x>', '/?q=<iframe src=x>', '/?q=<svg onload=x>', '/?q=<img src=x onerror=y>',
	'/?q=<body onload=x>', '/?q=<object data=x>', '/?q=<embed src=x>', '/?q=javascript:alert(1)', '/?q=javascript :x', '/?q=x onmouseover=y',
	'/?q=onfocus=1', '/?q=ontoggle=1', '/?q=document.cookie', '/?q=alert(1)', '/?q=alerts(1)', '/?q=<scripts>', '/?q=<image>', '/?q=java script:',
	'/?q=%3Cscript%3E', '/?q=%253Cscript%253E', '/?s=onerror', '/?s=onload+event',
	'/', '/plain/path', '/?s=hello+world', '/?p=123', '/?s=%E2%80%9Cquoted%E2%80%9D', '/?s=select+your+plan+from+the+list',
);
$diff = array();
foreach ( $uris as $uri ) {
	if ( old_injection_type( $uri ) !== PNCP_Attacks::injection_type( $uri ) ) {
		$diff[] = $uri . ' (' . old_injection_type( $uri ) . ' / ' . PNCP_Attacks::injection_type( $uri ) . ')';
	}
}
$kinds = array_count_values( array_map( 'old_injection_type', $uris ) );
t( 'B: injection_type() gives the 3.12.10 answer for ' . count( $uris ) . ' written addresses', ! $diff, implode( '; ', array_slice( $diff, 0, 6 ) ) );
t( 'B: the written addresses cover every type and the clean case', isset( $kinds['traversal'], $kinds['rce'], $kinds['sqli'], $kinds['xss'], $kinds[''] ) && $kinds['rce'] >= 25, wp_json_encode( $kinds ) );
// Generated: pieces of the signatures (and their near misses) put together at random, a third URL-encoded.
mt_srand( 31211 );
// Words (and near misses) alternate with the glue between them, so the words often meet their "(", "://"…
$words = array( 'eval', 'ev', 'al', 'evil', 'EVAL', 'assert', 'system', 'sys', 'passthru', 'shell_exec', 'shell', '_exec', 'base64_decode', 'base64', 'cat', 'wget', 'curl', 'bash', 'sh', 'nc', 'python', 'perl', 'php', 'data', 'expect', 'phar', 'glob', 'zip', 'jndi', 'j', 'ndi', 'env', 'lower', 'upper', '/etc/', 'passwd', 'shadow', 'hosts', 'union', 'all', 'select', 'from', 'information_schema', 'wp_users', 'mysql.user', 'sleep', 'benchmark', 'pg_sleep', 'waitfor', 'delay', 'or', 'and', 'extractvalue', 'updatexml', 'concat', 'script', 'iframe', 'svg', 'img', 'object', 'embed', 'javascript', 'onerror', 'onload', 'onmouseover', 'document.cookie', 'alert', 'x', 'c:', 'windows', 'wp-config.php' );
$glue  = array( '', '(', ' (', ')', ';', '|', '&', '`', ' ', ' -', ' /', '/', '://', ':/', '${', ':', '../', '..', '\\', '1', '0x41', "'", '"', '=', '--', '#', '<', '< ', '%20', '%28', '%2F', '+', '/**/' );
$diff  = array();
$typed = array();
for ( $i = 0; $i < 3000; $i++ ) {
	$s = '';
	$n = mt_rand( 1, 5 );
	for ( $k = 0; $k < $n; $k++ ) {
		$s .= $glue[ mt_rand( 0, count( $glue ) - 1 ) ] . $words[ mt_rand( 0, count( $words ) - 1 ) ];
	}
	$s .= $glue[ mt_rand( 0, count( $glue ) - 1 ) ];
	$uri = 0 === $i % 3 ? '/?q=' . rawurlencode( $s ) : '/?q=' . $s;
	$old = old_injection_type( $uri );
	if ( '' !== $old ) {
		$typed[ $old ] = isset( $typed[ $old ] ) ? $typed[ $old ] + 1 : 1;
	}
	if ( $old !== PNCP_Attacks::injection_type( $uri ) ) {
		$diff[] = $uri;
	}
}
t( 'B: injection_type() gives the 3.12.10 answer for 3000 generated addresses', ! $diff, implode( '; ', array_slice( $diff, 0, 6 ) ) );
t( 'B: the generated addresses include attacks of every type and clean ones', 4 === count( $typed ) && min( $typed ) >= 5 && array_sum( $typed ) > 100 && array_sum( $typed ) < 2900, wp_json_encode( $typed ) );

// 3.12.10's default patterns of PNCP_Bots::malicious_ua().
$old_ua = array(
	'#<\s*/?\s*(?:script|iframe|img|svg|body|object|embed|a\s|\?php|\?=)#i',
	'#\(\s*\)\s*\{#',
	'#\$\{\s*(?:jndi|env|sys|lower|upper|date|ctx|main|::-)#i',
	'#\bunion\b[\s\S]{0,30}\bselect\b|\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d|\bwaitfor\s+delay\b|\bor\s+1\s*=\s*1\b#i',
	'#[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]#',
);
$uas  = array(
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36',
	'<script>alert(1)</script>', '</SCRIPT>', '<iframe>', '<img src=x>', '<svg/onload=1>', '<body>', '<object>', '<embed>', '<a href=x>',
	'<?php echo 1; ?>', '<?PHP', '<?= 1 ?>', '< ?php', '<scripts', '<imgx', '() { :; }; /bin/bash -c id', '(){ :;};', '( ) {', '() x {',
	'${jndi:ldap://x/a}', '${JNDI:rmi://x}', '${ env:X}', '${sys:y}', '${lower:j}${upper:n}', '${date:x}', '${ctx:x}', '${main:x}', '${::-j}',
	'${jndx}', 'x union all select 1', 'UNION/**/SELECT', 'union' . str_repeat( ' ', 40 ) . 'select', 'sleep(5)', 'BENCHMARK(1,1)',
	'pg_sleep(1)', 'waitfor delay', 'x or 1=1', 'x or 1=12', 'benchmarks(1)', "a\x01b", "tab\tok", "v\x0b", "f\x0c", "s\x0e", "n\x0d", "d\x7f", "e\x1f", "z\x00", 'curl/8.5.0', 'python-requests/2.31',
);
$diff = array();
foreach ( $uas as $ua ) {
	$old = false;
	foreach ( $old_ua as $pattern ) {
		$old = $old || 1 === preg_match( $pattern, $ua );
	}
	if ( $old !== PNCP_Bots::malicious_ua( $ua ) ) {
		$diff[] = $ua;
	}
}
t( 'B: malicious_ua() gives the 3.12.10 answer for ' . count( $uas ) . ' User-Agents', ! $diff, implode( '; ', $diff ) );
t( 'B: the technology profilers still include Netcraft', in_array( 'Net' . 'craft', PNCP_Bots::tech_profiler_agents(), true ) );
t( 'B: malicious_ua() still catches script tags, Shellshock and Log4Shell', PNCP_Bots::malicious_ua( '<script>' ) && PNCP_Bots::malicious_ua( '() { :; };' ) && PNCP_Bots::malicious_ua( '${jndi:ldap://x}' ) && ! PNCP_Bots::malicious_ua( 'Mozilla/5.0' ) );

// 3.12.10's "scanner" pattern of PNCP_Bunny::classify().
$old_scanner = '#/\.(?:env|git|svn|hg|aws|ssh|docker|htpasswd|ds_store)|/wp-config\.(?:php[~._\-].*|bak|old|orig|save|txt|swp)$|\.(?:sql|sql\.gz|sqlite|bak|swp)$|/(?:phpmyadmin|pma|myadmin|adminer)(?:/|\.php|$)|/(?:backup|backups|dump|database|db|site|www|wordpress)\.(?:zip|tar|tar\.gz|tgz|rar|7z|sql)$|/(?:shell|c99|r57|wso|alfa|webshell|cmd)\.php$|/vendor/phpunit/|/debug\.log$#';
$paths       = array(
	'/c99.php', '/C99.PHP', '/r57.php', '/wso.php', '/alfa.php', '/webshell.php', '/shell.php', '/cmd.php', '/x/y/wso.php', '/WSO.php',
	'/c999.php', '/myshell.php', '/shell.phpx', '/shell.php5', '/c99.html', '/wso', '/shells.php', '/cmd.php/x', '/alfa-shell.php',
	'/.env', '/.git/config', '/wp-config.php.bak', '/wp-config.old', '/dump.sql', '/x.sqlite', '/phpmyadmin/', '/adminer.php', '/backup.zip',
	'/wordpress.tar.gz', '/vendor/phpunit/x', '/debug.log', '/about/', '/blog/hello-world/', '/image.png',
);
$diff        = array();
foreach ( $paths as $path ) {
	$row = array( 'path' => $path, 'query' => '', 'status' => 404, 'ua' => '' );
	if ( ( 1 === preg_match( $old_scanner, strtolower( $path ) ) ) !== ( 'scanner' === PNCP_Bunny::classify( $row ) ) ) {
		$diff[] = $path . ' (' . PNCP_Bunny::classify( $row ) . ')';
	}
}
t( 'B: Bunny classify() calls the same ' . count( $paths ) . ' paths "scanner" as 3.12.10', ! $diff, implode( '; ', $diff ) );
t( 'B: c99.php, wso.php and r57.php are still scanner probes', 'scanner' === PNCP_Bunny::classify( array( 'path' => '/c99.php', 'query' => '', 'status' => 404, 'ua' => '' ) ) && 'scanner' === PNCP_Bunny::classify( array( 'path' => '/wso.php', 'query' => '', 'status' => 404, 'ua' => '' ) ) && 'scanner' === PNCP_Bunny::classify( array( 'path' => '/r57.php', 'query' => '', 'status' => 403, 'ua' => '' ) ) );
t( 'B: a sample code injection is still "rce"', 'rce' === PNCP_Attacks::injection_type( '/?cmd=eval(base64_decode(x))' ) && 'rce' === PNCP_Attacks::injection_type( '/?f=php://filter/resource=x' ) && 'traversal' === PNCP_Attacks::injection_type( '/?f=../../etc/passwd' ) );

/* ---------- C. Integrity: hex instead of base64 + zlib, old data still read ---------- */

$json   = (string) wp_json_encode( array( '/srv/a.php' => array( '1:2:3:4', str_repeat( 'ab', 32 ) ), 'ü' => 'ok' ) );
$packed = PNCP_Integrity::pack_json( $json );
t( 'C: pack_json() writes z1: and hex', 0 === strpos( $packed, 'z1:' ) && ctype_xdigit( substr( $packed, 3 ) ) );
t( 'C: unpack_json() reads what pack_json() wrote', $json === PNCP_Integrity::unpack_json( $packed ) );
$old = base64_encode( gzcompress( $json, 6 ) );
t( 'C: unpack_json() reads the 3.12.10 format (base64 of gzcompress())', $json === PNCP_Integrity::unpack_json( $old ) );
t( 'C: damaged data is false (no warning)', false === PNCP_Integrity::unpack_json( 'z1:zz' ) && false === PNCP_Integrity::unpack_json( 'z1:abc' ) && false === PNCP_Integrity::unpack_json( 'z1:' ) && false === PNCP_Integrity::unpack_json( '' ) && false === PNCP_Integrity::unpack_json( '!!' ) && false === PNCP_Integrity::unpack_json( 'z1:' . bin2hex( 'not zlib' ) ) && false === PNCP_Integrity::unpack_json( null ) );
$src = (string) file_get_contents( $repo . '/includes/class-pncp-integrity.php' );
t( 'C: class-pncp-integrity.php writes no base64 any more', false === strpos( $src, 'base64_encode' ) && 1 === substr_count( $src, 'base64_decode(' ) );

// The stat cache as 3.12.10 wrote it is read, and the next write uses the new format.
$saved  = get_option( 'pncp_integrity_stat' );
$stats  = array( ABSPATH . 'index.php' => array( '10:20:30:40', hash( 'sha256', 'x' ) ) );
$record = array(
	'full' => time(),
	'data' => base64_encode( gzcompress( (string) wp_json_encode( $stats ), 6 ) ),
);
$record['sig'] = PNCP_Seal::sign( $record );
update_option( 'pncp_integrity_stat', $record, false );
$read = new ReflectionMethod( 'PNCP_Integrity', 'stat_cache' );
$read->setAccessible( true );
t( 'C: the stat cache in the 3.12.10 format is read', $stats === $read->invoke( null ) );
$write = new ReflectionMethod( 'PNCP_Integrity', 'save_stat_cache' );
$write->setAccessible( true );
$write->invoke( null, $stats, true );
$now = get_option( 'pncp_integrity_stat' );
t( 'C: written again, it is in the new format and reads the same', is_array( $now ) && 0 === strpos( (string) $now['data'], 'z1:' ) && $stats === $read->invoke( null ) );
if ( false === $saved ) {
	delete_option( 'pncp_integrity_stat' );
} else {
	update_option( 'pncp_integrity_stat', $saved, false );
}

/* ---------- D. Generated files: no security vendor's name spelled out, the same blocking ---------- */

$vendor = '#netcraft|phishtank|cyveillance|surfright#i';
$nc     = 'Net' . 'craft';
t( 'D: unspell() regex: the first letter in brackets, case kept', '(BuiltWith|[N]etcraft|x)' === PNCP_Bots::unspell( '(BuiltWith|' . $nc . '|x)', 'regex' ) && '[n]etcraftx' === PNCP_Bots::unspell( strtolower( $nc ) . 'x', 'regex' ) );
t( 'D: unspell() JSON: the first letter as \u escape, json_decode() reads the name', '["\u006e' . 'etcraft"]' === PNCP_Bots::unspell( '["' . strtolower( $nc ) . '"]', 'json' ) && array( strtolower( $nc ), strtoupper( $nc ) ) === json_decode( PNCP_Bots::unspell( (string) wp_json_encode( array( strtolower( $nc ), strtoupper( $nc ) ) ), 'json' ), true ) );
t( 'D: unspell() twice = once; text without the name unchanged; "\n" before "etcraft" in JSON kept', PNCP_Bots::unspell( PNCP_Bots::unspell( $nc, 'regex' ), 'regex' ) === PNCP_Bots::unspell( $nc, 'regex' ) && PNCP_Bots::unspell( PNCP_Bots::unspell( $nc, 'json' ), 'json' ) === PNCP_Bots::unspell( $nc, 'json' ) && '(GPTBot|CCBot)' === PNCP_Bots::unspell( '(GPTBot|CCBot)', 'regex' ) && '["a\netcraft"]' === PNCP_Bots::unspell( '["a\netcraft"]', 'json' ) );

$keep_settings = get_option( PNCP_OPTION );
update_option( PNCP_OPTION, array_merge( PNCP_Options::stored(), array( 'block_tech_profilers' => 1, 'block_bots' => 1, 'enabled' => 1, 'stealth_enabled' => 1 ) ) );
PNCP_Options::flush();
wp_cache_delete( 'alloptions', 'options' );
$apache = PNCP_Rules::apache() . PNCP_Stealth::rules_text( 'apache' );
$nginx  = PNCP_Rules::nginx_http() . PNCP_Rules::nginx_server() . PNCP_Stealth::rules_text( 'nginx' );
$cfg    = PNCP_Precheck::config_json();
t( 'D: the Apache rules (.htaccess) spell no security vendor\'s name', 0 === preg_match( $vendor, $apache ) && false !== stripos( $apache, 'wappalyzer' ) );
t( 'D: the Nginx rules spell no security vendor\'s name', 0 === preg_match( $vendor, $nginx ) && false !== stripos( $nginx, 'wappalyzer' ) );
t( 'D: the pre-cache check\'s config.json spells no security vendor\'s name', 0 === preg_match( $vendor, $cfg ) );
$probe = array( 'Mozilla/5.0 (compatible; ' . $nc . 'SurveyAgent/1.0; +info@' . strtolower( $nc ) . '.com)', strtoupper( $nc ) . ' Web Server Survey' );
preg_match_all( '/^RewriteCond %\{HTTP_USER_AGENT\} (\(.*\)) \[NC\]$/m', $apache, $am );
$hit = static function ( $regexes, $ua ) {
	foreach ( $regexes as $re ) {
		if ( 1 === preg_match( '#' . $re . '#i', $ua ) ) {
			return true;
		}
	}
	return false;
};
t( 'D: the Apache bot rule still matches the profiler\'s User-Agents, case-insensitively', $am[1] && $hit( $am[1], $probe[0] ) && $hit( $am[1], $probe[1] ) && ! $hit( $am[1], 'Mozilla/5.0 (Windows NT 10.0) Chrome/141.0' ), implode( ' ', $am[1] ) );
preg_match_all( '/"~\*(\(.*\))"\s+1;/', $nginx, $nm );
t( 'D: the Nginx bot map still matches them', $nm[1] && $hit( $nm[1], $probe[0] ) && $hit( $nm[1], $probe[1] ), substr( $nginx, 0, 300 ) );
$decoded = json_decode( $cfg, true );
t( 'D: config.json read back: the profiler is in the blocked User-Agents and matches', is_array( $decoded ) && in_array( strtolower( $nc ), (array) $decoded['bots'], true ) && PNCP_Bots::ua_in_list( $probe[0], (array) $decoded['bots'] ) );
update_option( PNCP_OPTION, $keep_settings );
PNCP_Options::flush();
wp_cache_delete( 'alloptions', 'options' );

echo $fails ? "\n$fails FAIL\n" : "\nALL PASS\n";
exit( $fails ? 1 : 0 );

# `wp scrapelock` command reference

For the full options of any command: `wp help scrapelock <command>`. Read-only commands are marked (ro).

## State and checks

| Command | What it does |
|---|---|
| `status [--format=json]` (ro) | What is on and off (as in Site Health → Info). |
| `check --ip=<ip> [--ua=<ua>] [--address=</path>] [--browser] [--referer=<url>] [--accept-language=<v>]` (ro) | What ScrapeLock would answer to a request. Nothing is counted, logged or blocked. Not simulated: the human-check cookie, 404s, private URL tokens, WooCommerce cart/checkout, and the early/pre-cache checks. |
| `selfcheck [--log]` (ro) | A real request of the site to itself; which layer passed or refused it. |
| `log [--limit=N] [--top --hours=N]` (ro) | Latest blocked requests, or totals per reason, top IPs and paths. |
| `blocked [--format=count]` (ro) | IPs blocked now. |
| `reputation <ip> [--reset]` | An IP's score and events; `--reset` forgets it. |
| `attacks [--days=N] [--category=<key>] [--top=paths\|ips\|users\|details]` (ro) | Where bots and attackers hit the site. |
| `attack-report [--days=N] [--format=csv] [--send]` | The attack report; `--send` emails it. |
| `ai-referrals [--days=N] [--pages]` (ro) | Visits sent by AI assistants. |
| `lockdown status` (ro) | Lockdown state. It cannot be changed from WP-CLI. |
| `breaker [reset [<feature>] [--history]]` | Features suspended for being too slow (over 200 ms), and resuming them. |
| `precheck [sync\|cleanup]` | The pre-cache check's store; sync/cleanup for a system cron when WP-Cron is off. |

## Blocking

| Command | What it does |
|---|---|
| `block <ip> [--minutes=1..43200]` | Temporary block (IPv6: its /64). Default 1440. |
| `unblock <ip>... \| --all` | Lift temporary blocks. |
| `emergency on [--hours=1..72] \| off \| status` | Stricter limits for a while, then back to normal. |
| `login status \| unlock <ip-or-username> \| url` | Sign-in protection; `url` prints a custom sign-in address. |

## Settings

| Command | What it does |
|---|---|
| `settings get [<name>]` (ro) | One or all settings. Never shows the CDN secret. |
| `settings set <name> <value> [--dry-run]` | On/off take 1/0. Lists: lines separated with `\n`. Checked like the settings form. |
| `settings export [--file=<f>]` | Export (secrets left out). |
| `settings import <file> [--dry-run] [--yes]` | Import. |
| `settings undo` | Put back the previous version (last 5 are kept). |
| `wizard [--apply [--all] [--only=a,b] --yes] \| dismiss <s> \| restore <s>` | The site-specific assistant: list or apply proposals. Without `--apply` nothing changes. |

Useful setting names (group "bots"): `monitor_mode`, `block_bots`, `block_fake_crawlers`, `block_empty_ua`, `block_headless`, `block_http_libs`, `block_seo_crawlers`, `block_archivers`, `block_tech_profilers`, `allow_ai_search`, `verify_ai_bots`, `robots_ai_block`, `content_signal`, `bot_list`, `allow_list`, `allow_ips`, `block_ips`, `rate_limit` (pages per minute per IP, default 60), `rate_limit_search`, `rate_limit_rest`, `rate_limit_404`, `rate_limit_datacenter`, `rate_limit_cart`, `rate_limit_coupon`, `human_check`, `reputation`, `ban_strikes`, `ban_minutes`, `auto_emergency`, `ip_header` (remote_addr, x_forwarded_for, x_real_ip, cf_connecting_ip, true_client_ip), `trust_cloudflare`, `trust_bunny`, `trusted_proxies`, `login_limit`, `login_slug`, `countries_block`. Group "general" (content protection in the browser, watermarks, TDM): `enabled`, `scope_posts`, `scope_pages`, `block_selection`, `block_context_menu`, `copy_mode`, `tdm_reservation`, `user_mark`, `text_trace`. Check the exact list with `settings get`.

## Hardening, server and CDN (change things: ask first)

| Command | What it does |
|---|---|
| `harden list \| check \| apply <id> \| revert <id> \| apply-low \| rules --server=nginx\|apache \| write-htaccess \| remove-htaccess` | Vulnerable points (XML-RPC, user enumeration, probes...). `list` says what each may break. |
| `rules status \| show --part=<p> \| install ... [--dry-run] [--yes]` | Nginx/Apache rules. `install` writes `<file>.new`, shows a diff, tests (`nginx -t` / `apachectl -t`), reloads, and restores everything on failure. Parts: nginx-http, nginx-server, stealth-nginx, stealth-apache, apache. |
| `stealth status \| on \| off \| test \| scan \| rules \| check [<url>] \| debug` | Hide that the site runs on WordPress. |
| `bunny status \| import \| rules \| presets \| preview <p> \| lock <p> \| unlock <p\|id> \| logging [--enable]` | Bunny CDN logs and Edge Rules. |
| `cdn purge <url>... \| --all [--yes] [--minify]` | Purge at Bunny/Cloudflare with stored keys (also plugin and fastcgi caches first). |
| `cache status \| purge <url>... \| --all` | This site's pages in the Nginx fastcgi cache. |
| `crowdsec status \| sync \| check <ip>` | CrowdSec blocklist. |
| `traffic status \| overview \| top <dim> \| problems <type> \| raw \| export <file> \| purge \| run \| test-path <path>` | Traffic from the CDN, access log or WordPress (off until turned on). |
| `verify-file list \| add <path> --content=<t> [--hours=N] [--write] \| remove <path>` | Temporary verification files (Google, Bing, BuiltWith...) served to all bots. |

## Constants (wp-config.php)

- `SCRAPELOCK_UNLOCK`: opens Lockdown (the user sets it themselves).
- `SCRAPELOCK_LOGIN_SLUG_OFF` = true: wp-login.php works again if the custom sign-in address is lost.
- `SCRAPELOCK_FASTCGI_CACHE_PATH`: the Nginx fastcgi cache folder.
- `SCRAPELOCK_STEALTH_DEBUG`: Stealth's opt-in debug log.

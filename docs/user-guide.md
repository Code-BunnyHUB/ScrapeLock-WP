# ScrapeLock – User guide

Content protection for WordPress / WooCommerce, by CodeBunny.

**What no plugin can do:** whatever a visitor sees has already reached their device. A photo taken with a phone or the browser's reader mode cannot be stopped. ScrapeLock closes the automated routes and leaves traces: watermarks, a source link on copied text, a block log and a legal rights reservation (TDM).

## Layers

| Layer | Where | Settings tab |
|---|---|---|
| Right click, selection, copy (or copy with a source link), drag, shortcuts, printing, blur on screenshot: deterrents for casual copying; the text is still in the page source | browser | On the page |
| Not inside another site's iframe (X-Frame-Options, CSP frame-ancestors) | header | On the page |
| AI / TDM opt-out (EU Directive 2019/790, art. 4): header, meta, `/.well-known/tdmrep.json`, `noai` | header / HTML | On the page |
| Scraper / AI bot list, no User-Agent, "browsers only"; a separate option for AI search (OAI-SearchBot, Claude-SearchBot, PerplexityBot…) while training crawlers (GPTBot, ClaudeBot, CCBot…) stay blocked | PHP | Bots and limits |
| Fake Googlebot / Bingbot / Applebot / Yandex: official IP lists (daily) + reverse/forward DNS | PHP | Bots and limits |
| AI search bots (OAI-SearchBot, ChatGPT-User, PerplexityBot, Perplexity-User) verified with their official IP lists when AI search is allowed: real ones are never limited, fakes get 403 | PHP | Bots and limits |
| Bot trap (invisible link, disallowed in robots.txt) | PHP | Bots and limits |
| Headless browsers (`HeadlessChrome` in `Sec-CH-UA`) and scripts that copy only a browser's User-Agent (on HTTPS without `Sec-Fetch-*` / `Sec-CH-UA`): 403, optional. 3.13.0: browser headers that do not fit the User-Agent (a `Sec-CH-UA` version or platform other than the User-Agent's, a Safari or Firefox without `Sec-Fetch-*`) get the stricter page limit, a 403 only together with a data-center address, a bad reputation or the CrowdSec list. It catches scripted browsers whose User-Agent was changed; one that keeps its own User-Agent and headers is not detected this way | PHP | Bots and limits |
| Per-IP limits: pages, search, REST / GraphQL; temporary block after N violations in 10 minutes | PHP | Bots and limits |
| "Page not found" (404) limit per IP, for scrapers that guess URLs; missing images, CSS, scripts and favicons do not count | PHP | Bots and limits |
| Always-blocked IPs / CIDRs and referrer domains (with their subdomains) | PHP | Bots and limits |
| Hidden usernames: `?author=N` → 404, REST `/wp/v2/users` → 401, no users sitemap, oEmbed shows the site instead of the author (logged-in users see everything). 3.13.0, optional (on for new installs): `/author/<slug>/` → 404, author links to the home page, no `comment-author-<slug>` class | PHP | Bots and limits |
| Early check (optional): `wp-content/mu-plugins/scrapelock-early.php` stops listed bots, blocked IPs and referrers before the theme and plugins load | PHP (mu-plugin) | Bots and limits |
| Pre-cache check (optional): one line at the top of `wp-config.php` applies the bot list, always-blocked IPs, temporary blocks, the page, network and human-check limits, fake Googlebot / Bingbot and headless browsers to pages served from a page cache (WP Rocket etc.); see "Page cache and static files" | PHP (wp-config.php) | Bots and limits |
| robots.txt, llms.txt and llms-full.txt are never blocked, for any bot (server rules too), so every bot can read the rules | PHP + server | — |
| Log: "Block permanently" button, "Blocked again and again (7 days)" list, fake / unverified User-Agents marked, how many User-Agents an event had | — | Log |
| Content Signals in robots.txt: `search=yes, ai-train=no`, and `ai-input` according to the AI search option | robots.txt | Bots and limits |
| Human check (optional): after the first real interaction (scroll, tap, key, mouse movement) the browser solves a light proof of work in the background and gets a `pncp_hv` cookie for 7 days; visitors without it get a stricter page limit. No captcha, works with page caches. It proves work, not a browser: a script can solve it too, so 3.13.0 makes it harder for data centers, IPs with a bad reputation and mismatched browser headers, gives them a cookie for 4 hours, and gives one network (/24, /48) at most 60 cookies an hour | PHP + JS | Bots and limits |
| Sitemap limit per IP (WordPress, Rank Math, Yoast…), never for verified search engines | PHP | Bots and limits |
| Countries: block, or a stricter limit. Country from `CF-IPCountry` (only from Cloudflare), `CDN-RequestCountryCode` (only from Bunny CDN) or the free DB-IP Lite database (monthly, in `uploads/scrapelock-geo`) | PHP | Bots and limits |
| "What they try to copy" report: the pages and files blocked most often (24 hours / 7 days) | — | Log |
| Pages of other plugins (e.g. a community at `/hub/space/`) counted as "Pages": from the rewrite rules or the "Content addresses" setting. No "Block permanently" for official addresses (Google, Bing, OpenAI, Perplexity, Anthropic, Cloudflare, Bunny) | — | Log, Bots and limits |
| Trusted proxy: `CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For` are read only from a trusted proxy (Cloudflare, Bunny CDN with its official list, private network, your own list); if every visitor appears with a Cloudflare or Bunny address, a one-click fix | PHP | Bots and limits |
| REST API and WPGraphQL without text for visitors; RSS excerpt only, or full text with "The post … first appeared on …" at the end | PHP | Feeds and API |
| Optional: REST API index hidden from visitors, pingbacks off, list of REST routes anyone can call | PHP | Feeds and API |
| Protected XML feeds with a token (header for ERPs, URL for price comparison sites and Merchant Center), only the hash stored, rotation with a grace period, statistics | PHP | Feeds and API |
| Watermark: corners, center or diagonal tiling; optionally on the full size too (the clean original is kept); a tool for existing images | images | Images |
| Nginx / Apache / Cloudflare rules generated for your site | server / CDN | Server rules |
| Log kept 1/7/30 days, 24-hour summary, lifting blocks | — | Log |

Ready-made presets (Balanced / Strict / Maximum) and **Emergency Mode** (1 hour to 3 days, without changing your settings).

## Lockdown

A **Lockdown** tab in Settings → ScrapeLock, and a "Lockdown" line under the "Protection" button in the admin bar (administrators only). The tab shows the warning "there is only one way to unlock" and a full report: what is locked, what keeps working and which accounts of the site are affected. While the site is locked, nobody can change anything from wp-admin, the REST API or XML-RPC, neither an administrator nor someone who stole a password. Visitors and customers carry on as usual (orders, payments, customer accounts, comments).

1. **Connect the app (once):** "Connect the app" → scan the QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy…) → type the 6-digit code → **print the 10 recovery codes** (shown only then).
2. **Lock:** app code → "Lock the site". The first time, tick that you saved the recovery codes. While locked, the ScrapeLock page opens only on the Lockdown tab and the admin bar button reads "Protection: ON · Locked".
3. **Unlock:** app code (or a recovery code) and a duration: 15 minutes to 2 hours (it locks again by itself) or "until I lock it again".

| Frozen | Not affected |
|---|---|
| Plugins and themes (install, update, delete, activate), WordPress updates, the file editor | Visitors, orders, payments, webhooks |
| New users, roles, new administrators, staff email / password / password reset | Customer registration and accounts, comments |
| All settings (ScrapeLock's too), posts, pages, products, media, menus | Cron and plugins' scheduled tasks |

**Who is frozen.** Roles that can change plugins, themes, users or settings are always frozen. Editors, authors, contributors, shop managers and any role that manages other people's content or orders are frozen by default; you choose the rest on the Lockdown tab (with the app code, only while unlocked). Customers, subscribers and members who post their own content are never frozen.

- While locked, orders cannot be edited in wp-admin: unlock for a while.
- While locked, an administrator can always sign in and reach the Dashboard, their own profile (to read; changes are not saved) and the Lockdown tab. After signing in you land on the Dashboard, which says that the site is locked and links to the Lockdown tab.
- If you open something that is frozen (for example another user's profile), you see the "The site is locked" page with an **Unlock the site** button (administrators only) that leads to the unlock page, and under "Cannot use the app?" the other ways in.
- **wp-admin does not open?** Some themes and plugins (membership, "remove dashboard access" snippets) send every account without administrator rights away from wp-admin, and while locked your account has none. ScrapeLock then sends you to an unlock screen on the sign-in page instead, `wp-login.php?action=scrapelock-unlock`, which does not go through wp-admin (you can also open it yourself once signed in). Unlock there with the app or a recovery code; wp-admin opens again.
- A two-factor plugin (for example Wordfence) may show while locked that your 2FA "is not active": Lockdown also freezes 2FA settings, so nobody with a stolen password can change or disable them. Signing in with 2FA works as usual; check its status while unlocked.
- Updates: the page shows how many are waiting. Unlock for 30 minutes, update, press "Lock again now".
- Every unlock sends an email to the site's admin address.
- **Lost phone:** type a recovery code instead of the app code. If none are left, add `define( 'SCRAPELOCK_UNLOCK', true );` to `wp-config.php` (FTP / hosting panel, or over SSH: `wp config set SCRAPELOCK_UNLOCK true --raw --type=constant`), remove the app on the Lockdown page, connect a new one, lock again and delete the line (`wp config delete SCRAPELOCK_UNLOCK`). Deleting the guard file in `wp-content/mu-plugins` does not unlock the site: the lock is kept in the database too.
- **Forgot the password, or set a new one with your host's tools:** "Lost your password" sends no reset link for staff while locked (the account's email gets the ways in instead), and a password changed straight in the database is refused at sign-in. Add the `SCRAPELOCK_UNLOCK` line, sign in, remove the line again and unlock with the app or a recovery code: you stay signed in. `wp user update --user_pass` keeps staff passwords as they are while locked and says so.
- **Site moved to a new address while locked:** the site address is put back to the one it had when you locked. Define `WP_HOME` and `WP_SITEURL` in `wp-config.php` with the new address (they override the database), sign in and unlock, then remove them if you like.
- Whoever has access to the server's files or database controls the site anyway: Lockdown protects against everything that goes through WordPress.

## Always exempt

- The roles in the "Who is exempt" setting (editors and administrators by default), requests from the server itself, and the "Always allowed IPs". A plain customer with an account is checked like any visitor.
- Verified search engines (never limited, never blocked).
- Limits do not count POST requests (forms, cart, checkout) and WooCommerce's declared `wc-ajax` calls. Bots and blocks are still checked there.
- Link previews (Facebook, Viber, WhatsApp…) from the "Always allowed" list.
- Watermark: site icon, logo, WooCommerce placeholder, the watermark image itself and, by default, product images. Google Merchant Center and price comparison platforms reject product images with a watermark. If a watermarked image later becomes a logo or a product image, the watermark is removed automatically.

## Page cache and static files

Anything served from a page cache (Nginx FastCGI cache, WP Rocket etc.) or as a static file never reaches the plugin. Listed bots never get pages from WP Rocket's cache, so they are checked as usual. For everyone else there are two solutions.

**Pre-cache check** (Bots and limits → Temporary block, "Pre-cache check"). For caches that run inside PHP (WP Rocket, WP Super Cache, W3 Total Cache…). ScrapeLock adds right after the `<?php` of `wp-config.php`:

```php
// BEGIN ScrapeLock pre-cache check (added and removed by the plugin's "Pre-cache check" setting)
if ( is_file( '/…/wp-content/plugins/scrapelock/includes/class-pncp-precheck-runtime.php' ) ) { include_once '/…/wp-content/plugins/scrapelock/includes/class-pncp-precheck-runtime.php'; PNCP_Precheck_Runtime::boot( '/…/wp-content/uploads/scrapelock/precheck-…' ); }
// END ScrapeLock pre-cache check
```

- It runs before the cache and WordPress, without the database. What it catches on cached pages: always-blocked IPs, temporary blocks, the bot list and requests without a User-Agent, scanner probes, the page limit (a sliding minute), the network limit (IPv4 /24, IPv6 /48), the human check's stricter limit and Emergency Mode's stricter values; since 3.13.0 also a fake Googlebot or Bingbot (403 while their official list is loaded and refreshed within a week; without one it is only counted), and with "Block headless and fake browsers" HeadlessChrome and a browser User-Agent without its headers (403) or with headers that do not fit it (stricter limit).
- What it does not catch (WordPress decides on pages it serves itself): "Browsers only", countries, data centers, the IP reputation, CrowdSec, the bot trap, the DNS check of Applebot and YandexBot (counted with 4 × the page limit), the REST API, and anything a page cache in the web server serves before PHP.
- Violations lead to a block as in the normal check. Blocks and their lifting apply on both sides. Events appear in the log.
- Settings, counters and events as plain data files (no PHP) in a protected folder with a random name in `uploads/scrapelock/` (in APCu or Redis when available: then a visitor's request reads and writes no file).
- Not counted: forms, prefetch (its own limit), wp-admin, wp-login, REST, cron, the server itself, always-allowed IPs, Google and Bing from their official addresses, payment gateway callbacks to WooCommerce. A login cookie gets 4 × the page limit (the check cannot verify it).
- If `wp-config.php` is not writable, the setting shows the lines to add by hand. Everything is removed when the setting is turned off or the plugin is deactivated. Not on multisite.

**Fake browsers in the server rules.** With "Block headless and fake browsers" on, the Nginx and Apache rules also block, on the server, a "Chrome" / "Firefox" without the headers a real browser always sends on HTTPS. This also catches scanners that request `.php` files and never reach WordPress. Googlebot and other bots with "Chrome/" in their User-Agent, Android in-app browsers (WebView) and the "Always allowed" list are not affected.

**Server rules.** For the Nginx cache (FastCGI cache) or a CDN cache, which never go through PHP, and for static files: the rules in the **Server rules** tab, generated with your site's domain, bot list, feeds and originals folder. The basics for Nginx:

```nginx
# http { }  (e.g. /etc/nginx/conf.d/scrapelock-example_com.conf)
map $http_user_agent $pncp_bad_bot_example_com {
    default 0;
    "~*(GPTBot|ClaudeBot|CCBot|Bytespider|HeadlessChrome|python-requests|curl/)" 1;
    "" 1;
}
limit_req_zone $binary_remote_addr zone=pncp_pages_example_com:10m rate=60r/m;

# server { }
if ($pncp_block_example_com) { return 403; }
location ^~ /wp-content/uploads/pncp-originals-XXXXXXXXXXXX/ { deny all; return 404; }
# inside the existing location / { }:
#   limit_req zone=pncp_pages_example_com burst=20 nodelay;
```

The tab gives the rules in two parts, `http { }` and `server { }`, made for your site. The above is only an example.

**Nginx on any server.**
- The names (variables, limit zone) carry the site's suffix, e.g. `_example_com`, so several WordPress sites on the same Nginx each add their own rules without a clash in `nginx -t`.
- The tab says where each part goes: Debian / Ubuntu, CentOS / RHEL, Plesk, aaPanel, other panels.
- **Status:** the plugin asks the site itself at `/.well-known/scrapelock-nginx`, which only Nginx with the rules answers. The tab shows "installed and matching the current settings", "installed but outdated" (with the part to copy again) or "not present".
- Without access to Nginx (shared hosting) the rules are skipped: protection comes from the plugin and the pre-cache check.
- The plugin **never** writes to the Nginx configuration itself: Nginx reads it as root, so a file PHP can change would be a risk.

## Tested compatibility

| What | How it was tested |
|---|---|
| WooCommerce | Full purchase (cart, Store API checkout, "Thank you") with a limit of 3 pages/minute and in Emergency Mode; bots on `wc-ajax` and the Store API → 403; payment webhooks unaffected |
| WPGraphQL | Text hidden from visitors, visible with an application password; bots, limits and blocks on `/graphql` |
| REST API | No text for visitors, also through `?rest_route=`, `_method=GET`, `X-HTTP-Method-Override`, HEAD |
| WP Super Cache | 403 responses and feeds are not cached; the cache is emptied after a settings change; bots on cached pages are stopped by the server rules |
| Nginx / Apache | The tab's rules pass `nginx -t` and work (bots, hotlinking, originals, feeds, Bearer) |
| Redis object cache | Atomic limits and blocks through `wp_cache_incr` |
| Elementor, Bricks, Divi, Beaver, Oxygen, SiteOrigin | The builder preview turns protection off only for whoever can edit the page |

Load (Nginx + PHP-FPM, 8 workers, MariaDB): the plugin's overhead on a page is within measurement noise. The limit is exact with 200 concurrent requests, 3,000 requests from a bot write one row in the log, and 1,500 concurrent blocks are all kept.

## Apache and `Authorization: Bearer`

With PHP-FPM/CGI, Apache does not pass `Authorization` to PHP. The Apache rules in the tab include the line that fixes it. Alternatively, use the `X-ScrapeLock-Token` header.

## Image originals

When the watermark is also applied to the full size, the clean file is kept in `wp-content/uploads/pncp-originals-<random>/`. The folder has an `.htaccess` for Apache; on Nginx add the `deny` rule. **Deleting** the plugin does not delete this folder, because it holds the only clean copies. Before using the "Apply watermark" tool, back up `uploads`.

## Site Health, WP-CLI and AI agents

- **Tools → Site Health:** ScrapeLock warns when protection is off, when every visitor appears with a Cloudflare or Bunny address (one-click fix on the Bots and limits tab), when the early or pre-cache check is on but not running, when `SCRAPELOCK_UNLOCK` is in `wp-config.php` and when updates are waiting while the site is locked. The Info tab has a ScrapeLock section (no secrets) for support requests.
- **WP-CLI:**

```
wp scrapelock status
wp scrapelock block 203.0.113.5 --minutes=60
wp scrapelock unblock 203.0.113.5        # or --all
wp scrapelock blocked
wp scrapelock emergency on --hours=6     # off · status
wp scrapelock log --top --hours=168
```

- **Abilities API (WordPress 6.9+):** an AI agent or MCP client signed in as an administrator can read the summary (`scrapelock/get-summary`), block or unblock an IP and start or stop Emergency Mode. While the site is locked it can only read the summary.
- **Lockdown cannot be unlocked** from WP-CLI or by an AI agent: only with the app, a recovery code or the `wp-config.php` line.

## For developers

| Filter | What it does |
|---|---|
| `pncp_should_protect` | Whether the current page is protected |
| `pncp_skip_guard` | Skip all server checks for a request (context `early` in the early check; only filters from mu-plugins reach it) |
| `pncp_404_exempt` | Whether a 404 is exempt from the "page not found" limit |
| `pncp_human_difficulty` | Difficulty of the human check challenge (1–5, default 3) |
| `pncp_visitor_country` | The visitor's country (e.g. from your own source) |
| `pncp_geo_source_url` | Download URL of the country database |
| `pncp_client_ip` | The visitor's IP (for the early check, the filter must be in an mu-plugin) |
| `pncp_rest_hide_content` | Exceptions to hiding text (REST, GraphQL) |
| `pncp_rest_post_types` | Post types filtered in REST |
| `pncp_watermark_attachment` | Whether an image gets a watermark |
| `pncp_watermark_batch_size` | Images per batch in the tool (3) |
| `pncp_robots_ai_agents` | AI crawlers in robots.txt |
| `pncp_ai_search_agents` | The AI search engines / assistants of the "Allow AI search" option |
| `pncp_hotlink_allowed` | Domains allowed to load images |
| `pncp_content_paths` | Path prefixes of other plugins' pages, for the log's "Pages" |
| `pncp_block_framing` | `false` to allow iframes |

For a piece of text that must stay copyable (a phone number, a coupon), add the `pncp-allow` class.

## Features in detail

The full description that used to be on the WordPress.org page (shortened there in 3.12.13).

Most content protection plugins disable right click in the browser. Scrapers and AI crawlers don't click or copy: they download the raw HTML, read the REST API and the feeds, or drive a (headless) browser. ScrapeLock works on the server, where automated copying actually happens, and leaves real visitors, customers and search engines alone.

* **Runs on your own server.** No account and no API key needed, and no visitor data sent anywhere by default. It downloads public IP lists; only if you turn on CDN blocking does it send the IPs it blocks to your own Cloudflare or Bunny account, with your API token (see External services).
* **Starts in Monitor only.** For its first 7 days a new install blocks nobody: requests that would be refused are logged as "Would block", so you can see what it would do and adjust before it enforces. You can switch Monitor only on again at any time.

### New in 3.8: see where bots attack, and close it with one click

* **Attack report (Attacks tab).** Where bots hit, also when nothing is refused: failed sign-ins and the usernames tried, how many try wp-admin and wp-login.php, XML-RPC calls, scanner and plugin probes, per day and hour, with country, "Block IP", CSV, a dashboard widget and an optional weekly email.
* **Vulnerable points.** Lock XML-RPC, wp-admin, the sign-in page, readme.html, PHP in uploads and more with one click, with the risk explained; Apache rules written with a self-test and rollback, Nginx rules to copy.
* **Sign-in protection.** Failed logins limited per IP and per username (wp-login.php, every XML-RPC multicall call, application passwords), one error message, and an optional sign-in address of your own.
* **Bunny CDN, deeper.** Reads your pull zone's logs to see attacks on cached pages, and locks wp-login.php, xmlrpc.php and .env/.git probes at Bunny. New in 3.9: every lock first shows what it would block and who hit it, and waits for your Confirm.
* **Stealth (optional).** BuiltWith and Wappalyzer get neutral addresses (/assets/…) instead of /wp-content/, another REST prefix and /sitemap.xml, without WordPress-only markup. Tested before it turns on.

### What it stops, and what it cannot

| Who | Result | How |
|---|---|---|
| AI training crawlers that say who they are (GPTBot, ClaudeBot, CCBot, Bytespider…) | Stopped | Bot list, 403 |
| Fake Googlebot or Bingbot | Stopped | Official IP lists plus reverse and forward DNS |
| Fast scrapers from one IP (IPv6: one /64) | Stopped | Per-IP limits (a sliding minute since 3.13.0) and temporary blocks |
| Scanners asking for .env, .git or backups | Stopped (optional) | Ban on the first probe |
| Site rippers (HTTrack, WebCopier, Offline Explorer…) and attacks in the User-Agent | Stopped | Built-in list, 403 |
| Scrapers that read only the REST API, feeds or sitemaps | Slowed (optional) | Limit for IPs that never opened a page |
| Scrapers that rotate addresses of one network (IPv4 /24, IPv6 /48) | Slowed | Network limit (5 × the page limit, at least 100 a minute; 3.13.0), data center limit |
| Scrapers spread over many networks (residential proxies) | Only partly slowed | Per-IP limits only bite per address; CrowdSec blocklist, IP reputation, surge email, Emergency Mode |
| Scripts that copy a browser's User-Agent | Stopped or slowed (optional) | Headless / fake-browser check, header consistency (3.13.0) |
| Real browsers driven by a script (Playwright, Puppeteer) on home connections | Only partly slowed | Header consistency catches a changed User-Agent; otherwise the human check (a script solves it too), bot trap and limits |
| Copying by hand, screenshots, logged-in scraping | Cannot be stopped | Watermark, source link and TDM leave traces |
| Attackers who can run PHP on your server | Out of scope | No plugin can stop them |

Whatever a visitor sees has already reached their device, so nothing stops a determined human. ScrapeLock closes the automated routes and leaves traces.

### Who it is for

* **Publishers, recipe, course and news sites:** block AI training but stay in AI search, keep post text out of the REST API, GraphQL and full-text RSS, TDM opt-out.
* **WooCommerce shops:** limits for the product catalogue (Store API too), cart actions and coupon attempts, private feeds for price comparison sites and Google Merchant.
* **Photographers:** watermarks with the clean originals kept, hotlink rules for Nginx, Apache and Cloudflare (3.13.0, optional: full-size originals only with a Referer, Nginx and Apache).
* **Directories and listing sites:** page, search and "page not found" limits, a stricter limit for data centers.
* **Agencies:** presets, settings export and import, WP-CLI and Site Health.

### Bots and crawlers

* **Real search engines vs. fakes.** Googlebot, Bingbot, Applebot and Yandex are verified against their official IP lists and with reverse + forward DNS. Real crawlers are never limited or blocked; fakes get a 403. 3.13.0: also on cached pages (pre-cache check) while the Google / Bing list is fresh, and in the Nginx rules (a `geo` of the official ranges, used for 30 days after the rules were copied and only for requests that did not come through a proxy).
* **AI training vs. AI search.** Training crawlers (GPTBot, ClaudeBot, CCBot, Google-Extended, Bytespider and more) are blocked. AI search assistants (OAI-SearchBot, ChatGPT-User, PerplexityBot, Claude-SearchBot and more) can be allowed with one option and are verified with their official IP lists, so your site still appears in AI answers with a link.
* robots.txt gets the AI crawler lines, Content Signals and the Disallow line of an invisible bot trap that catches bots ignoring it. robots.txt, llms.txt and llms-full.txt are never blocked.
* Generic HTTP libraries (curl, python-requests and the like, used by apps and integrations) pass by default; a strict option blocks them too, and the Log has an "Always allow this User-Agent" button.
* Optional blocking of headless browsers and of scripts that copy a browser's User-Agent but not its headers. 3.13.0: the headers that are there must fit the User-Agent too (version and platform in `Sec-CH-UA`, `Sec-Fetch-*` for Safari and Firefox); a mismatch gets the stricter page limit rather than a 403, because User-Agent switchers and proxies that strip headers cause one too. A real browser driven by a script that keeps its own User-Agent is not detected this way; the limits, the human check and the bot trap still apply to it.
* **3.13.0:** an "Always allowed" User-Agent that no address confirms (anyone can send "facebookexternalhit") still skips the bot list and "Browsers only", but gets the headless checks and the stricter limits like any visitor. Link previews of Meta, X and LinkedIn are recognised by their networks; an entry pinned with `@` works as before. Payment gateway callbacks to WooCommerce (`?wc-api=`, `/wc-api/`, the gateways' REST webhooks; filter `pncp_payment_webhooks`) are never refused, also in Emergency Mode.
* **New in 3.5, optional (off by default):** ban scanners on their first request for .env, .git, wp-config.php backups, database dumps and backup archives.
* **3.7:** site rippers (HTTrack, WebCopier, Offline Explorer…) and attacks in the User-Agent are blocked; optional: SEO data crawlers (Ahrefs, Semrush, Majestic…) and requests that use the site's IP instead of its name.

### Limits and blocks

* Per-IP limits for pages, searches, REST / GraphQL, "page not found" (404) requests, sitemaps, visitors from data centers and, with WooCommerce, cart actions and coupon attempts (IPv6: per /64). Verified search engines and real shoppers are not affected.
* IPs that keep exceeding the limits are blocked for a while, optionally also at Cloudflare or Bunny CDN ("Test connection" checks the token, the zone and the permissions).
* **Emergency Mode:** stricter limits for 1 hour to 3 days, then your settings return on their own. When traffic suddenly jumps, ScrapeLock emails you a one-click button to start it.
* Optional human check without a captcha: visitors who have not scrolled, tapped or typed get a stricter page limit.
* **3.7, optional:** IP reputation (good IPs are never blocked for a limit, bad ones stay slowed for days), a limit for IPs that read only the API, feeds or sitemaps, the CrowdSec community blocklist, and fail2ban. See the FAQ.
* Optional country rules, from Cloudflare's or Bunny CDN's country header or the free DB-IP Lite database.
* Optional pre-cache check (the bot list, the limits and the blocks also apply to pages served by WP Super Cache, W3 Total Cache, Cache Enabler, WP Rocket and the like) and early check (stops known bots and blocked IPs before the theme and the other plugins load).
* Always-blocked IPs / CIDR and referrers, usernames hidden from visitors, and trusted proxies (Cloudflare, Bunny CDN, your own), so the real IP cannot be spoofed.

### Feeds, API and server rules

* Post, page and product text hidden from the REST API, WPGraphQL and full-text RSS for visitors: the routes scrapers use instead of the HTML.
* RSS with a short excerpt only, or disabled; with full text, an optional "The post … first appeared on …" line.
* Private XML feeds (Skroutz, BestPrice, Google Merchant, ERP) with a token in a header or the URL; only its hash is stored, it can be rotated with a grace period, and each feed has statistics.
* Optional: hide the REST API map and the versions of WordPress, PHP and the plugins, turn off XML-RPC pingbacks, list the REST routes open to anyone.
* Ready-made Nginx, Apache and Cloudflare rules for your own site, so cached pages and static files are protected too.

### Check, test and tune

* **Check a request (Log tab):** pick GPTBot, a fake Googlebot, curl, a real browser or your own IP, User-Agent and address, and see whether ScrapeLock would allow, block or limit it, and why. Nothing is counted, logged or blocked; copy-ready curl lines test it for real.
* Staff are exempt while logged in (by default), so the admin bar reminds you: test in a private window.
* **Site Health** warns about settings that do not work as intended: robots.txt lines that crawlers do not get, private folders readable from the web, text still open through the REST API, feeds or WPGraphQL, another plugin doing the same job. These tests only fetch your own site.
* Settings that explain themselves: rejected lines are named, unsaved changes flagged, defaults labelled, options that may affect visitors or SEO tagged.
* Presets (Balanced, Strict, Maximum) with undo, settings export and import, and a block log with a 24-hour summary and automatic deletion.
* **3.7:** visitors from AI assistants (ChatGPT, Perplexity, Claude, Gemini…) per assistant and page, counted on your server without personal data.
* **Traffic (3.12):** every request, from the Bunny CDN logs, your web server's access log or WordPress itself: User-Agents by family, pages answering 404 or 5xx with the links that lead there, visitors, CSV and email alerts. Kept only in your database; off until you start it.
* WP-CLI: `wp scrapelock status`, `block`, `unblock`, `blocked`, `emergency`, `log`, `check --ip=<ip>` (what ScrapeLock would answer, without side effects), `settings`, `lockdown status`, `reputation`, `crowdsec`, `ai-referrals`, in 3.8 `attacks`, `attack-report`, `login`, `harden`, `bunny` and `stealth`, in 3.12 `traffic`, in 3.12.6 `rules`, `cdn` and `verify-file`, in 3.12.7 `cache`, in 3.12.8 `stealth check` and `stealth debug`, and in 3.12.9 `precheck` and `breaker`.
* Abilities API (WordPress 6.9+) for administrators: read the summary, block or unblock an IP and start Emergency Mode from an AI agent or MCP client. None of them unlocks Lockdown.

### On the page and images

* Block right click, copy, drag and common shortcuts, or allow copying with the source link appended. Text selection stays allowed by default, because blocking it also stops screen readers' "read selection" and translation tools.
* Printing with the page link at the bottom, or no printing; optional page blur on screenshot shortcuts (for everyone, or only for visitors who are not signed in); no framing by other sites.
* AI opt-out declaration (TDM): header, meta, `/.well-known/tdmrep.json`, `noai`.
* Watermark in a corner, the centre or repeated diagonally, optionally on the full-size image too; otherwise visitors get the largest watermarked size, also in the WooCommerce zoom, lightbox and Store API. The clean original is kept, so the watermark can always be removed. Product images are not watermarked by default, because Google Merchant Center rejects them.

### Members, courses and paid content (3.6)

* **Who is reading, on every screenshot:** a faint line over the page with the member's user name and the time, so a screenshot, a screen recording or a photo of the screen shows whose account it came from. No web page can block screenshots; this makes them traceable.
* **An invisible trace in the text:** copied text carries the account and the day, hidden in invisible characters. Paste it under Log → "Find whose copy this is".
* **Shared accounts:** a page limit per account, and an email when one account is used from several addresses at once, optionally signing it out everywhere else.
* **Fewer signs of WordPress** for tools such as BuiltWith and for scanners.

### Lockdown

* Freeze the site with a code from your authenticator app (Google Authenticator, Microsoft Authenticator, Authy and the like). While it is locked, nobody can change plugins, themes, WordPress core, users, roles or settings from wp-admin, the REST API or XML-RPC, not even an administrator or someone who stole a password.
* Administrators are frozen completely. Shop managers and other staff roles you do not tick keep their work (orders, products, coupons, posts, media), but not the rights that could take over the site. Visitors and customers browse, order, pay, register and comment as usual.
* Also enforced against code: a bug in another plugin cannot be used to activate plugins, change the site address or the admin email, add an administrator or unlock the lock. Code that can run its own PHP on your server can get around any plugin, ScrapeLock included. While the site is unlocked for a while, these rules are off for code too: unlock only for as long as you need.
* Sealed: the lock is signed with the keys in wp-config.php and kept outside the database (a guard file, a lock file, or a line in wp-config.php), so SQL injection in another plugin cannot unlock the site.
* Changes made straight in the database to the plugins, theme, site address, admin email, roles and ScrapeLock's settings are put back; new administrators and changed staff passwords are refused at sign-in. See the FAQ for the full list.
* File integrity: every PHP, .htaccess and .user.ini file is fingerprinted and checked every hour while locked, and WordPress and the plugins from WordPress.org are compared with their official checksums. New or changed files are emailed to you and shown in Site Health; optional quarantine. When the site is locked again after an unlock, the files that changed while it was open are emailed to you too, before they become part of the new fingerprint.
* Unlock for 15 minutes to 2 hours for yourself only, or until you lock it again; every lock and unlock is logged and emailed. Ten one-time recovery codes for a lost phone. The QR code is drawn in your browser and the secret is stored encrypted, never sent anywhere.

## More questions and answers

The answers that used to be in the readme's FAQ (it keeps the most common ones since 3.12.13).

### Why don't I see these bots in Google Analytics?

Most bots don't run JavaScript, so analytics never counts them. ScrapeLock sees them on the server, and Monitor only logs them without blocking anyone.

### Isn't robots.txt enough?

No. robots.txt is a request that only polite bots follow. ScrapeLock writes those lines for you and also enforces them on the server, where impolite bots get a 403.

### Does blocking right click stop AI scrapers?

No. Scrapers download the page or read the REST API and the feeds; they never right-click. What stops them is the server side: the bot list, the limits and hiding your text from REST, GraphQL and RSS. Right-click, copy, print and developer-tools blocking are deterrents for casual copying by hand: the text is still in the page source.

### Can I use it with a security or firewall plugin?

Yes, they do different jobs. Avoid two rate limits on the same pages (keep one, or set the other's limit higher), make both read the same real-IP header behind a CDN, and test in Monitor only first.

### Does ScrapeLock block WP Rocket's or Jetpack's own services?

No, while the plugin is active. WP Rocket's service bot (WP-Rocket-SaaS, for Remove Unused CSS and critical CSS) and its cache preload (WP Rocket/Preload), and Jetpack's servers and uptime monitor, are allowed like "Always allowed User-Agents" as long as that plugin is active. "Bots and limits" → "Always allowed" lists them, with a button to stop allowing each one. The page limits, the bot trap and the attack checks still apply to them. Developers can add other plugins' bots with the `pncp_plugin_bots` filter.

### Can I let one partner's crawler in?

Yes. Add it to "Always allowed User-Agents", pinned to its addresses so the name alone is not enough: `PartnerBot@203.0.113.0/24`. The page limit still applies to it.

### Does ScrapeLock empty the Nginx fastcgi cache?

Yes, where it empties the page caches (settings saved, Stealth turned on or off), when it knows the cache folder: set `define( 'SCRAPELOCK_FASTCGI_CACHE_PATH', '/path/to/fastcgi/cache' );` in wp-config.php, or Nginx Helper's `RT_WP_NGINX_HELPER_CACHE_PATH` (or its "Delete local server cache files" method). On the server, `wp scrapelock cache status` reads the Nginx configuration (nginx -T) to find the folder of the zone this site's server block uses with fastcgi_cache, and prints the line to add: `wp config set SCRAPELOCK_FASTCGI_CACHE_PATH '/path/to/fastcgi/cache' --type=constant --anchor="require_once ABSPATH . 'wp-settings.php';" --placement=before` (the anchor is needed where wp-config.php lacks WP-CLI's default anchor, the comment "That's all, stop editing!"). It also says whether the constant is already defined and names that folder; `wp scrapelock cache status --save-constant` adds it for you after a trial on a copy of wp-config.php. `wp scrapelock cache purge --all` (and `wp scrapelock cdn purge --all`) empties it. Only cache files whose key names this site's host are deleted, never files of other sites, links or folders outside it.

### What does the pre-cache check change on my server?

It adds two comment lines and one `include` line at the top of `wp-config.php`, which loads the check from the plugin's folder. Its data are plain files in a protected, randomly named folder in `uploads/scrapelock/` (in APCu or Redis when available, see below). It runs before the page cache, without a database, and stops blocked IPs, the bot list and visitors over the page limits. Search engines, forms, wp-admin and the REST API are left to the normal check; a login cookie, which it cannot verify, gets four times the page limit. If `wp-config.php` is not writable, it shows the lines to add. Everything is removed when you turn it off or deactivate the plugin. Not on multisite.

### Where does the pre-cache check keep its counters and bans?

In APCu when PHP has it (shared by the PHP-FPM or Apache processes), otherwise in the Redis server of your persistent object cache, otherwise in files of its data folder. With APCu or Redis a visitor's request reads and writes no file of the plugin: counters, bans, strikes, events and the configuration itself stay in memory, and a stalled disk does not stall the check. Redis is found automatically from the `WP_REDIS_*` constants (Redis Object Cache) or `WP_REDIS_CONFIG` when the PHP Redis extension is installed and the object cache is Redis, and its connection (the password masked) is written into the check's line in `wp-config.php`, because the check runs before the rest of that file. One server only (no Cluster or Sentinel); 50 ms to connect and to answer, otherwise the files are used for that request. Turn it off with `define( 'SCRAPELOCK_PRECHECK_REDIS', false );` or the filter `pncp_precheck_redis` (which also takes an array: host, port, path, db, user, password, prefix). APCu cannot be seen from WP-CLI: bans and settings changed there reach it through a signed request to the site, and every hour (WP-Cron) or from an admin page the bans are copied between memory and the files and the queued events go into the log. `wp scrapelock precheck` shows which store the check uses; `wp scrapelock precheck sync` and `wp scrapelock precheck cleanup` are there for a system cron job when WP-Cron is off.

### What is the early check?

An optional file, `wp-content/mu-plugins/scrapelock-early.php`, that runs before the theme and the other plugins and stops blocked IPs and referrers, temporarily blocked IPs and the bot list with less server load. Search engines, logged-in users, forms and private feeds are left to the normal check. It is removed when you turn it off, deactivate or delete the plugin.

### My site is behind Bunny CDN. What should I set?

If your server already replaces the IP, keep "REMOTE_ADDR". Otherwise set "Real visitor IP" to X-Real-IP and turn on "Trust Bunny CDN addresses". When every visitor appears with a Bunny address, a button does this for you.

Then set a "CDN shared secret" and click "Send the secret from Bunny" in the Bunny card (3.13.0): an Edge Rule in your account adds the secret as `X-ScrapeLock-CDN` to every request Bunny sends to your server. Bunny is multi-tenant: without the secret, anyone can point a pull zone of their own at your server and write any X-Real-IP, so ScrapeLock treats those IPs as unreliable. They are still counted for the limits, but they earn no violation, no ban and no block at the CDN, unlock no always-allowed IP, and wp-login.php cannot be locked at Bunny (ScrapeLock cannot see your own IP for sure). With the secret, Bunny's header is trusted, and so is a new Bunny edge server that is not yet in the daily list. Deactivating ScrapeLock removes its locks at Bunny but keeps this rule (server rules for "Only through the CDN" still need the header); deleting the plugin removes it too.

A request with Bunny's marks (`CDN-ServerId`, `Via: BunnyCDN`) from an address that is not in the edge list is treated the same way, as a shared address: no violations, bans or CDN blocks (a ban would refuse every visitor of that edge), and ScrapeLock downloads the edge list again (at most once an hour). The marks alone never make an address trusted.

In the pull zone's Caching settings, do not let Bunny cache error responses (403, 429 and the human check page): a cached refusal would be served to every visitor of that page. ScrapeLock sends these answers as not cacheable; a cache time forced at Bunny overrides that.

Behind Bunny and a page cache few requests reach WordPress, so WP-Cron runs rarely and the log import falls behind (Site Health warns when it has not run for an hour). Add a real cron job, e.g. every 5 minutes `wp cron event run --due-now --path=/path/to/wordpress`, and `define( 'DISABLE_WP_CRON', true );`.

### Can ScrapeLock block scrapers at Cloudflare or Bunny CDN?

Yes. In "Blocking at the CDN", choose Cloudflare (an API token with only Zone → Firewall Services → Edit, for this zone) or Bunny CDN (your API key) and the zone ID; the token can go in `wp-config.php` (`SCRAPELOCK_EDGE_TOKEN`) instead of the database. "Save and test the connection" only connects and tests. Once you turn on "Send temporary blocks to the CDN" (3.9; off on new sites, kept on for sites that already sent their blocks), every temporary block is also made at the CDN and removed when it ends. Your own rules are never changed; administrators' recent IPs, search engines and the CDN's addresses are never blocked there. Bunny CDN blocks single addresses only. Turning it off removes ScrapeLock's blocks.

### Can someone go around my CDN?

If they find your server's own address, yes. "Only through the CDN" (Real visitor IP) refuses every request without a secret header, `X-ScrapeLock-CDN`, that your CDN adds (Bunny: "Send the secret from Bunny" in the Bunny card; Cloudflare: Transform Rule). It can only be turned on from a request that has the secret. If the CDN stops sending it, add `define( 'SCRAPELOCK_CDN_ONLY', false );` to wp-config.php.

What it covers: WordPress refuses every request that reaches PHP, and the pre-cache check (when on) the pages of page cache plugins. Files the web server sends itself (images, CSS, JS) and pages from the Nginx fastcgi cache never reach PHP. For those (3.13.0), the Nginx server rules (Server rules tab) hold the same check while "Only through the CDN" is on: a map of the secret in part 1 and `if ($pncp_not_cdn_…) { return 403; }` in part 2, before the cache and the static files. The server itself, the "Always allowed IPs", `/.well-known/acme-challenge/` (Let's Encrypt) and `wp-cron.php` pass. The tab shows `YOUR_CDN_SECRET` in place of the secret; `wp scrapelock rules install` writes the real one and keeps the file readable only by root and Nginx (mode 640). Keep that file out of every folder the web server serves, and remove the line if the CDN ever stops sending the secret. The Apache rules (.htaccess) get the same check.

The other way, without any secret in a file: let the server's firewall accept ports 80 and 443 only from the CDN, e.g. for Bunny from the addresses at https://bunnycdn.com/api/system/edgeserverlist and its IPv6 list (refreshed daily, with a script such as `ufw allow from <address> to any port 443`), and from your own addresses.

### Does ScrapeLock block the site's own requests (Site Health, Vulnerable points, cron)?

No. WordPress signs every request to the site's own address with an `X-ScrapeLock-Sig` header (an HMAC of the method, host and path, valid for 60 seconds and once), so it passes every check, also behind a CDN and in the pre-cache check. ScrapeLock also learns the address the server's requests leave from and never blocks it, at the CDN either. If your server's own requests leave from an address ScrapeLock cannot learn (a NAT gateway, an outbound proxy, another server of a cluster), list it in wp-config.php: `define( 'SCRAPELOCK_SERVER_IPS', '203.0.113.50, 2001:db8::/64' );` (addresses or ranges, separated by commas). List only your own servers, never a proxy or load balancer in front of the site: every visitor comes through it.

### Vulnerable points says "Checked at the server: … refused by …". What does it mean?

The site asked for its own home page through its public address, and something on the way refused it. ScrapeLock then asked your server directly, so the result is still real, and the note names who refused. What to check:

* **Bunny CDN edge:** "Forward Host Header" is not needed any more (3.12.2). In the pull zone, check Bunny Shield or the WAF, bot protection, blocked IPs and countries, and Edge Rules that block: one of them refuses your server's own address. ScrapeLock removes its own CDN blocks of that address at once.
* **Cloudflare:** Security → Events for your server's address, then allow it.
* **Wordfence:** Firewall → Blocking and Live Traffic; add your server's address to its allowlisted IPs.
* **Another plugin or the web server:** its deny rules or firewall.
* **ScrapeLock:** the note names the check that refused it.

To see both sides of the request, use "Run a real self-check now" in Log → Check a request (or the preset "The site itself (loopback)", which shows each layer without sending anything), the Site Health test "ScrapeLock self-request test", or `wp scrapelock selfcheck --log`.

### What does "Ban scanners on their first probe" do?

Off by default. When an IP asks for a file only attack scanners look for (.env, .git, wp-config.php backups, database dumps and backup archives at the top of the site) and the file does not exist, it is refused and blocked for 10 minutes (or your block time, if shorter; nothing is blocked when "Block after this many violations" is 0); a second probe within 24 hours gets the full block. Staff, verified search engines and the always-allowed IPs and User-Agents are never banned. On Nginx, add the updated server rules. With the rules, .env, .git, wp-config.php copies and SSH keys are never served even if they exist; a real database dump or archive of the same name is still served.

### Does the human check show a captcha?

No. A small script waits for the first scroll, tap, key or mouse movement, solves a light proof of work in the background and gets a cookie. Visitors without it are not blocked: they get a stricter page limit (20 per minute by default). It is a light proof of work, not proof of a browser: a script that copies the steps gets the cookie too (in a fraction of a second). Since 3.13.0 the work is harder for clients from data centers, with a bad reputation or with browser headers that do not fit their User-Agent, their cookie lasts 4 hours instead of 7 days, and one network gets at most 60 cookies an hour. A person with a normal browser notices nothing.

### Can blocked bots still read robots.txt and llms.txt?

Yes. robots.txt, llms.txt and llms-full.txt are never blocked, so every bot can read the rules it is asked to follow. If a robots.txt file in your site's root replaces the one WordPress makes, Site Health shows the lines to add to it.

### Which visitors from AI assistants are counted?

A page view by a visitor (not your staff) whose referrer is ChatGPT, Perplexity, Claude, Gemini, Copilot, DeepSeek, Grok, Le Chat, Meta AI, You.com, Phind or Kagi, or whose address carries their utm_source (ChatGPT adds utm_source=chatgpt.com). One count per day, assistant and page; no IP, User-Agent or cookie is stored. Pages served by a page cache without reaching WordPress are not counted. Filter `pncp_ai_referrers` adds others. Turn it off under Log → Log settings.

### How does the IP reputation work?

Off by default (Bots and limits → Reputation). For each IP (IPv6: its /64) ScrapeLock keeps, for 7 days, when it last did something that tells about it: signed in (+80), passed the human check (+60), read pages (+10); the bot trap (−100), a scanner probe or an attack in the request (−80), a fake search engine (−70), a temporary block (−60), a bot-list refusal (−40), a limit exceeded (−20). Older events count about half. At 100 or more the IP is never blocked temporarily for exceeding a limit (it still gets "too many requests"); at −40 or less it gets the stricter page limit. `wp scrapelock reputation <ip>` shows the score; unblocking an IP by hand forgets it. Filters: `pncp_reputation_weights`, `pncp_reputation_good`, `pncp_reputation_bad`.

### How do I connect CrowdSec?

On a VPS: install CrowdSec (it subscribes to the community blocklist on its own), run `cscli bouncers add scrapelock`, and in Bots and limits → CrowdSec blocklist choose "From my CrowdSec agent", enter http://127.0.0.1:8080 and the key. Without your own agent (shared hosting), create a blocklist integration in the CrowdSec Console and enter its address with user:password as the key. "Stricter page limit" is the safer choice: addresses change hands. Private addresses, ranges wider than /16 (IPv6 /32), your server, CDN edges and official search engine addresses are never taken from a list. `wp scrapelock crowdsec status` shows the state.

### How do I use fail2ban with ScrapeLock?

Turn on "Write each temporary block to the system log" (Bots and limits → Temporary block), then copy the filter and the jail from the Server rules tab to /etc/fail2ban/filter.d/scrapelock.conf and /etc/fail2ban/jail.d/scrapelock.local, check logpath (/var/log/auth.log on Debian and Ubuntu, /var/log/secure on Red Hat) and run `fail2ban-client reload`. The line looks like `scrapelock[1234]: ban 203.0.113.5 for 60 minutes reason=rate_page site=example.com`. Blocks made by the pre-cache check before WordPress loads are not written.

### Where do I see which points bots attack, and how do I close them?

Settings → ScrapeLock → Attacks. Choose 24 hours, 7, 30 or 90 days: you get the attacks per day and hour, the kinds of attack, the addresses attacked most, the wp-admin and sign-in attempts with the usernames tried, the IPs (with country and reputation) and what the Bunny CDN edge saw. Next to an address, "Lock this" closes that point (Vulnerable points); next to an IP, "Block 24 h" or "Always block". Search engines, CDN addresses and your own address cannot be blocked there. "Download the report (CSV)" exports it, and "Weekly attack report by email" (Log tab) sends a summary every Monday. `wp scrapelock attacks --top=users` lists the usernames tried.

### Can I see the access log, which User-Agents hit the site and which pages fail?

Settings → ScrapeLock → Traffic (off until you press "Start collecting"). It reads the Bunny CDN logs when their import is on (they include the pages served from the CDN cache), else the web server's access log, else the pages WordPress serves itself. You get the requests over time, the User-Agents by family (browsers, verified and fake search engines, AI bots, scripts…), the pages that answer 404 or 5xx with the links that lead there (a link on your own site is marked as the one to fix), redirects, pages not served from the cache, the largest and slowest pages, the IPs and countries, and every single request with "Export CSV". From a User-Agent you can block it or always allow it, after a confirmation that shows the exact line added. Everything stays in your database: each request is kept 3 days by default, the daily figures 90 days, and IPs can be stored masked (the last part removed: IPv4 /24, IPv6 /48). "Start collecting" asks how IPs are stored, with Masked chosen in advance; new installs store them masked by default. The suggested privacy policy text (Settings → Privacy) describes Traffic, its retention and the IP setting.

### What does the attack report record?

Failed sign-ins (with the username tried), visits to wp-login.php and /wp-admin/ that do not sign in, XML-RPC calls (each call of a system.multicall), ?author=N and the REST users list, scanner probes, "page not found" under /wp-content/plugins/ and /themes/, SQL/script/path patterns in the address (recorded only) and every request ScrapeLock refused. One row per hour, address and IP; a normal page view writes nothing. Exempt staff, verified search engines and the server itself are not recorded. Turn it off with "Record where bots and attackers hit the site" (Log settings). install.php and upgrade.php run without plugins, so they are recorded only with "Early check" on (and from the Bunny CDN logs); setup-config.php is seen only in the CDN or server logs. The "WordPress's own files" point closes all three.

### What does "Vulnerable points" lock, and can it break my site?

Each point lists what it protects, how many attacks reached it, and what may stop working (for example Jetpack and the mobile app use XML-RPC; "Allow Jetpack" keeps Jetpack working). Low-risk points can be locked together. Points that only the web server can enforce (WordPress's own files, PHP in wp-includes or wp-content, directory listing) come with Apache and Nginx rules; on Apache ScrapeLock can write them into .htaccess, tests the site right after and puts the file back on its own if the site stops answering. Every point opens again with one click (or `wp scrapelock harden revert <id>`).

### I moved the sign-in page and forgot the address

Add define( 'SCRAPELOCK_LOGIN_SLUG_OFF', true ); to wp-config.php: wp-login.php works again. Sign in, look up or change the address (Bots and limits → Sign-in), then remove the line. "wp scrapelock login url" prints it too. In Monitor only both addresses work.

### Can password guessing lock me out of my own account?

No. A username under attack is paused for a few minutes, but not for IPs it signed in from before, and its email gets a one-time link that lets you sign in at once. "Lost your password" always works. Too many wrong passwords from one IP block that IP for a while (30 minutes by default); `wp scrapelock login unlock <ip>` lifts it.

### My site is behind Bunny CDN. What does ScrapeLock do with it?

Under Bots → Blocking at the CDN, the Bunny card reads the pull zone's logs (turn on logging at the pull zone; ScrapeLock has a button for it) and records attacks Bunny answered from its cache, which WordPress never saw. "Lock at Bunny" creates an Edge Rule in your own Bunny account that blocks an address (wp-login.php except your IPs, xmlrpc.php, .env/.git probes, readme.html…) before it reaches your server. Before every lock, ScrapeLock shows the addresses it cuts, the requests and IPs that hit them in the last 7 days and which of those IPs also used the site normally; nothing is sent before you click Confirm. wp-login.php is locked only when "Allowed IPs for the login page at Bunny" holds your current IP (an IPv6 /64 is fine); 3.13.0: your exact IP is sent too, next to its range, in case Bunny reads a range differently. While wp-login.php is locked, WordPress refuses wp-login.php itself from other IPs too (for requests that reach it around Bunny); only the password form of protected posts (`wp-login.php?action=postpass`, exactly) is open to everyone. "AI crawlers and scrapers (by User-Agent)" (3.13.0, off until you lock it) refuses the AI crawlers and site copiers of the bot list at Bunny, also on cached pages; the AI search bots you allow, search engines, always-allowed User-Agents and your plugins' services are left out, and the rule follows your settings. Bunny accepts at most 5 addresses or IPs in one condition, so a longer list is sent as several conditions of one rule, or as several rules "ScrapeLock: … (1/3)"; they are one lock in ScrapeLock (one Remove removes them all, and if one cannot be made, none is kept). "Allowed IPs for the login page at Bunny" holds at most 15 entries. ScrapeLock only changes rules it created (their description starts with "ScrapeLock:"); in Monitor only they are switched off. If a lock of wp-login.php keeps you out after your IP changed, remove the rule in the bunny.net dashboard or run wp scrapelock bunny unlock preset_login.

### Can ScrapeLock hide that my site runs on WordPress?

Mostly. Turn on Stealth (Vulnerable points tab). Visitors then get neutral addresses for the theme, plugin, media and core files, served by rules that ScrapeLock writes into .htaccess on Apache or that you add to Nginx; the site tests them first and never turns them on if a file would not load. The REST API can get another prefix, the sitemap becomes /sitemap.xml, and readme.html and the like answer "page not found". The footer comments of WP Rocket and Redis Object Cache and the file paths in script translations go too. Move the sign-in address too (Sign-in protection). What cannot be hidden: block and WooCommerce class names the styles depend on, cookies of signed-in users and shoppers, your hosting and DNS. WHOIS shows who registered the domain, not what the site is built with (use your registrar's privacy option for that). If the site ever loses its styles after moving host, add define( 'SCRAPELOCK_STEALTH_OFF', true ); to wp-config.php.

### Where do the Stealth rules go on Nginx and aaPanel, and how do I know they are current?

Inside the site's server { }, at its top level and above the WordPress rewrite: panels such as aaPanel, BT Panel and CloudPanel put that rewrite at server level (if (!-e $request_filename) { rewrite … }), and it runs before any location. On aaPanel, save them as a file of their own in /www/server/panel/vhost/nginx/extension/<site>/, after scrapelock.conf (the files there are read in alphabetical order), e.g. z-scrapelock-stealth.conf: that folder is included at the top of the site's server { }, before the rewrite include. Then nginx -t, reload, and "Test again" in Stealth. The rules carry a fingerprint: Server rules → Stealth (and Site Health) says whether they are installed and up to date, out of date, or not found, asking the server directly first. After the folder of the addresses changes or a plugin or theme is added, ScrapeLock asks you to copy them again. With WP Rocket, Autoptimize, LiteSpeed Cache or W3 Total Cache, the inner wp-content / wp-includes of their minified and combined files get neutral codes too; the rules map them back by pattern, so files written after "Clear cache" keep working.

### How do I check what visitors get with Stealth?

Run `wp scrapelock stealth check` (or `wp scrapelock stealth check <page of the site>`, 3.12.8). It asks for the page as a visitor gets it, through the page cache and the CDN, and prints how many wp-content and wp-includes are left, WP Rocket's minified addresses, the codes of the inner words, the cache headers and up to five addresses that still show a folder name. "words not used" means the server rules have words the pages are not rewritten with yet: run `wp scrapelock stealth test` ("Test again"). "rules" says whether the Stealth rules on the server are current, and "next" what to do: when they are out of date (as after an update that changes them), copy them again or run `wp scrapelock rules install --stealth=<file>`, then `wp scrapelock stealth test`. `wp scrapelock stealth status` shows the same, and whether the address map is in use or waiting for its rules. ScrapeLock now also tests a new address map by itself and uses it as soon as the server serves its rules. For a closer look add define( 'SCRAPELOCK_STEALTH_DEBUG', true ); to wp-config.php (or a number of hours, 1 to 72; the default is 24). Each page then writes one line per stage (Stealth's buffer, the optimization plugin's filter before and after) with counts only: no IP, User-Agent or query string, at most 256 KB, in uploads/scrapelock/ under a name that cannot be guessed. It stops by itself after those hours; `wp scrapelock stealth debug` prints the last lines and `--clear` deletes the log. Remove the line when done.

### Can WP-CLI install the server rules for me (aaPanel)?

Yes (3.12.6). `wp scrapelock rules show --part=nginx-http` (or `nginx-server`, `stealth-nginx`, `stealth-apache`, `apache`) prints a part exactly as the Server rules tab shows it. `wp scrapelock rules status` says whether the installed rules are current, out of date or not found, how the server was asked and both fingerprints (`--format=json` too). `wp scrapelock rules install` writes only the files you name: each one first as `<file>.new`, shows the diff, keeps the old file as `<file>.old`, runs `nginx -t`, reloads, removes the `.old` files and prints the status; when the test or the reload fails, every file is put back as it was. `--dry-run` only shows the diff. On aaPanel, as root, with `<site>` the site's folder name and `<id>` the name of part 1's file:

`wp --allow-root --skip-themes scrapelock rules install --nginx-http=/www/server/panel/vhost/nginx/0.scrapelock-<id>.conf --nginx-server=/www/server/panel/vhost/nginx/extension/<site>/scrapelock.conf --stealth=/www/server/panel/vhost/nginx/extension/<site>/z-scrapelock-stealth.conf --dry-run`

Then the same without `--dry-run` (add `--yes` to skip the question). Nginx files must end in .conf, Apache files be .htaccess (only ScrapeLock's block is replaced) or end in .conf; a symlink is written through only into its own folder, and a leftover .old stops it. If nginx is not on the PATH, give `--test-cmd="/www/server/nginx/sbin/nginx -t" --reload-cmd="/www/server/nginx/sbin/nginx -s reload"`: these two run through the shell exactly as typed. It never runs from a web request, and not while the site is locked. `wp scrapelock cdn purge <address>…` (or `--all --yes`) purges this site's addresses at Bunny CDN and Cloudflare with the keys stored in ScrapeLock, which are never printed; addresses of other hosts are refused. It first empties the page caches of the active cache plugins (WP Rocket, LiteSpeed Cache, W3 Total Cache, WP Super Cache, WP Fastest Cache, Nginx Helper, Cache Enabler, SiteGround Optimizer; `--no-plugin-cache` to skip), then the server's fastcgi cache, then the CDN, so no cache stores an old page again. WP Rocket's minified CSS / JS files stay unless you add `--minify` (with `--all`): use it after Stealth's words or addresses change, since those files keep the addresses they were made with.

### A service asks me to put a file on my site to verify it. The bot list blocks it.

Use Server rules → Verification files, or `wp scrapelock verify-file add /builtwith.txt --content=<the code>`. The file (one name at the root, e.g. /builtwith.txt, /google<code>.html, /BingSiteAuth.xml, or a name under /.well-known/; text only, at most 64 KB) is served by WordPress to every bot, also to one the bot list or "Block technology profilers" blocks, for 24 hours (1 to 168), then removed. It is purged at your CDN when added and when removed, and robots.txt lets the blocked bots read it. Server rules that block bots (Nginx part 1, Apache) let it through once you copy them again (or `wp scrapelock rules install`); their fingerprint does not change for it. "Also write it to the site's root folder" is only needed when the server answers that address without WordPress; it never replaces a file that is there. An HTML or XML file with markup needs the unfiltered_html capability.

### Does a REST API list count more toward the REST limit?

Yes (3.5): an anonymous request for a long list from the REST API (posts, pages, products) counts 2 above 20 items per page, 3 above 50. Lists of up to 20 items and logged-in users count as before, and the WooCommerce cart and checkout are not counted. JSON 429 answers (REST API, GraphQL, cart) also carry `retry_after`, the seconds of their Retry-After header.

### Can I customise it in code?

Yes, with filters such as `pncp_client_ip`, `pncp_skip_guard`, `pncp_should_protect`, `pncp_known_ai_agents`, `pncp_ai_search_agents`, `pncp_rest_post_types`, `pncp_rest_hide_content`, `pncp_404_exempt`, `pncp_trap_exempt_agents`, `pncp_trap_first_ban_minutes`, `pncp_watermark_attachment`, `pncp_hotlink_allowed`, `pncp_use_apcu` and `pncp_log_rows_per_minute`; 3.5 adds `pncp_rest_cost`, `pncp_probe_trap_paths` and `pncp_conflicting_plugins`; 3.13.0 adds `pncp_payment_webhooks`, `pncp_payment_webhooks_active`, `pncp_preview_pins`, `pncp_network_limit_factor`, `pncp_sliding_window`, `pncp_human_difficulty_for`, `pncp_human_suspect_hours`, `pncp_human_cookies_per_network` and `pncp_nginx_fake_crawlers`; 3.7 adds `pncp_ripper_agents`, `pncp_seo_agents`, `pncp_malicious_ua_patterns`, `pncp_host_is_foreign_ip`, `pncp_reputation_weights`, `pncp_reputation_good`, `pncp_reputation_bad`, `pncp_crowdsec_listed`, `pncp_crowdsec_max`, `pncp_crowdsec_range_ok`, `pncp_ai_referrers` and `pncp_syslog_facility`. The early and pre-cache checks run before plugins load, so filters in plugins and themes do not apply there. There is also WP-CLI and settings export and import.

### What personal data does it store?

For a blocked request: the IP, User-Agent, page and time, deleted after 1, 7 or 30 days; over a per-account limit, also the account's username. The attack record (3.8) keeps the IP, the address asked for, the hour and, for a failed sign-in, the username tried, for 7, 30 or 90 days. The sign-in protection keeps, per account, a keyed hash of the IPs it signed in from (180 days). With IP reputation (3.7, off by default): for each IP, stored under a hash, when it last read pages, passed the human check, signed in or was refused, for 7 days. Visits from AI assistants are counted per day and page only. With the human check, visitors who interact get a 7-day cookie, `pncp_hv`, holding only an expiry and a signature tied to their IP network and browser; it is not used for tracking. The country database is a local file.

### Does it guarantee legal protection of my content?

No. The TDM declaration is a machine-readable reservation of rights; it does not guarantee legal compliance or stop anyone who ignores it.

### What does Lockdown freeze, and what keeps working?

Frozen roles can log in but change nothing. Roles that can change plugins, themes, users or settings are always frozen; editors, authors, contributors and shop managers by default. Customers, members, visitors, orders, payments, webhooks, cron and comments are not affected. Shop staff cannot process orders in wp-admin while locked: unlock for a while.

What is put back when it is changed straight in the database: the active plugins and theme, the site address, the admin email, registration and the default role, the roles, the uploads folder, search engine visibility, the widgets, the theme's settings, WooCommerce's own payment methods and bank accounts, and ScrapeLock's own settings (more with the filter `pncp_lockdown_protected_options`). New administrators, new application passwords for staff and changed staff passwords are refused at sign-in and emailed. A capability given to one user alone, outside their role, does not work while the site is locked. The Site Editor's templates and template parts cannot be changed by code while locked; templates, template parts and global styles changed straight in the database are found every hour.

What it does not keep: posts, pages, products, orders, comments and media, navigation menus, scheduled events, and the settings and tables of other plugins (a payment gateway of another plugin, for example; add its option to the filter). Code that other plugins keep in the database and run (snippets of Code Snippets or WPCode) is checked every hour: new or changed code is emailed to you, and the quarantine deactivates the plugin that runs it.

### Can someone with access to my server bypass Lockdown?

Yes. Lockdown guards against changes through WordPress; someone who can only write to the database (SQL injection in another plugin) cannot unlock it. Whoever can edit files controls the site anyway: the file integrity check finds new files within the hour, and the "No PHP in the uploads folder" server rule stops most backdoors from running.

### Can I unlock Lockdown from WP-CLI or with an AI agent?

No, on purpose: only an app code, a recovery code or the SCRAPELOCK_UNLOCK line opens it (hosting panels and agents run WP-CLI too). Over SSH, WP-CLI can add that line: `wp config set SCRAPELOCK_UNLOCK true --raw --type=constant`. WP-CLI and the abilities can block IPs and start Emergency Mode; while locked the abilities can only read the summary.

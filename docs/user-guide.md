# ScrapeLock – User guide

Content protection for WordPress / WooCommerce, by CodeBunny.

**What no plugin can do:** whatever a visitor sees has already reached their device. A photo taken with a phone or the browser's reader mode cannot be stopped. ScrapeLock closes the automated routes and leaves traces: watermarks, a source link on copied text, a block log and a legal rights reservation (TDM).

## Layers

| Layer | Where | Settings tab |
|---|---|---|
| Right click, selection, copy (or copy with a source link), drag, shortcuts, printing, blur on screenshot | browser | On the page |
| Not inside another site's iframe (X-Frame-Options, CSP frame-ancestors) | header | On the page |
| AI / TDM opt-out (EU Directive 2019/790, art. 4): header, meta, `/.well-known/tdmrep.json`, `noai` | header / HTML | On the page |
| Scraper / AI bot list, no User-Agent, "browsers only"; a separate option for AI search (OAI-SearchBot, Claude-SearchBot, PerplexityBot…) while training crawlers (GPTBot, ClaudeBot, CCBot…) stay blocked | PHP | Bots and limits |
| Fake Googlebot / Bingbot / Applebot / Yandex: official IP lists (daily) + reverse/forward DNS | PHP | Bots and limits |
| AI search bots (OAI-SearchBot, ChatGPT-User, PerplexityBot, Perplexity-User) verified with their official IP lists when AI search is allowed: real ones are never limited, fakes get 403 | PHP | Bots and limits |
| Bot trap (invisible link, disallowed in robots.txt) | PHP | Bots and limits |
| Headless browsers (`HeadlessChrome` in `Sec-CH-UA`) and scripts that copy only a browser's User-Agent (on HTTPS without `Sec-Fetch-*` / `Sec-CH-UA`): 403, optional | PHP | Bots and limits |
| Per-IP limits: pages, search, REST / GraphQL; temporary block after N violations in 10 minutes | PHP | Bots and limits |
| "Page not found" (404) limit per IP, for scrapers that guess URLs; missing images, CSS, scripts and favicons do not count | PHP | Bots and limits |
| Always-blocked IPs / CIDRs and referrer domains (with their subdomains) | PHP | Bots and limits |
| Hidden usernames: `?author=N` → 404, REST `/wp/v2/users` → 401, no users sitemap, oEmbed shows the site instead of the author (logged-in users see everything) | PHP | Bots and limits |
| Early check (optional): `wp-content/mu-plugins/scrapelock-early.php` stops listed bots, blocked IPs and referrers before the theme and plugins load | PHP (mu-plugin) | Bots and limits |
| Pre-cache check (optional): one line at the top of `wp-config.php` applies the page limit, temporary blocks and always-blocked IPs to pages served from a page cache (WP Rocket etc.) | PHP (wp-config.php) | Bots and limits |
| robots.txt, llms.txt and llms-full.txt are never blocked, for any bot (server rules too), so every bot can read the rules | PHP + server | — |
| Log: "Block permanently" button, "Blocked again and again (7 days)" list, fake / unverified User-Agents marked, how many User-Agents an event had | — | Log |
| Content Signals in robots.txt: `search=yes, ai-train=no`, and `ai-input` according to the AI search option | robots.txt | Bots and limits |
| Human check (optional): after the first real interaction (scroll, tap, key, mouse movement) the browser solves a light challenge in the background and gets a `pncp_hv` cookie for 7 days; visitors without it get a stricter page limit. No captcha, works with page caches | PHP + JS | Bots and limits |
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
- If you open something that is frozen (for example your profile), you see the "The site is locked" page with an **Unlock the site** button (administrators only) that leads to the unlock page.
- A two-factor plugin (for example Wordfence) may show while locked that your 2FA "is not active": Lockdown also freezes 2FA settings, so nobody with a stolen password can change or disable them. Signing in with 2FA works as usual; check its status while unlocked.
- Updates: the page shows how many are waiting. Unlock for 30 minutes, update, press "Lock again now".
- Every unlock sends an email to the site's admin address.
- **Lost phone:** type a recovery code instead of the app code. If none are left, add `define( 'SCRAPELOCK_UNLOCK', true );` to `wp-config.php` (FTP / hosting panel), remove the app on the Lockdown page, connect a new one and delete the line. The same applies if you forget an administrator password while locked.
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
if ( is_file( '/…/wp-content/scrapelock-precheck/run.php' ) ) { include_once '/…/wp-content/scrapelock-precheck/run.php'; }
// END ScrapeLock pre-cache check
```

- It runs before the cache and WordPress, without the database. It stops only always-blocked IPs, temporary blocks and visitors over the "Pages per minute" limit.
- Violations lead to a block as in the normal check. Blocks and their lifting apply on both sides. Events appear in the log.
- Counters in APCu or in files in `wp-content/scrapelock-precheck`.
- Not counted: logged-in users, forms, prefetch, wp-admin, wp-login, REST, cron, the server itself, always-allowed IPs, Google and Bing from their official addresses. Applebot and YandexBot are left to the normal check, and WP Rocket does not serve them cached pages.
- It does not apply the stricter limits (human check, countries) or Emergency Mode: those apply to pages outside the cache.
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

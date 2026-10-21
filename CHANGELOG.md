# Changelog

All notable changes to ScrapeLock. The same list is in the Changelog section of `readme.txt`.

## 2.8.2

* The plugin now includes the full text of its license (GPL-2.0) in a LICENSE file. No code changes.

## 2.8.1

* Lockdown: while the site is locked, WordPress' bare "Sorry, you are not allowed to…" pages in wp-admin (for example your own profile) are replaced with a clear "The site is locked" page: what is frozen and why, an "Unlock the site" button for administrators, "ask an administrator" for other staff, and a link back to the Dashboard. WordPress' own message stays under "Technical detail". AJAX, REST and XML-RPC answers are unchanged.

## 2.8.0

* New: Site Health tests (protection off, every visitor appearing with a Cloudflare or Bunny CDN address, the early or pre-cache check on but not running, Lockdown off from the server, updates waiting while locked) and a ScrapeLock section on the Info tab, without secrets.
* New: WP-CLI commands `wp scrapelock status | block | unblock | blocked | emergency | log`.
* New: Abilities API (WordPress 6.9+): get-summary, block-ip, unblock-ip and emergency-mode, for administrators only. Changes are refused while Lockdown is locked; no ability unlocks it.
* New: optional "Hide the REST API map from visitors" and "Turn off pingbacks", and a list of the REST routes anyone can call.
* "Hide usernames" now also covers oEmbed: the author's name and link are replaced with the site's.
* Fix: "Unblock" in "IPs blocked now" did nothing for IPv6 addresses, which are blocked per /64 network.
* Tested with WordPress 7.2 beta 1.

## 2.7.2

* Fix: Lockdown froze every role with any capability beyond "read", so members who create content themselves (for example subscribers who post listings or community posts through another plugin) lost their rights and their password reset while the site was locked. Now only roles that manage the site are frozen: roles that can change plugins, themes, users or settings (always), and by default editorial and shop staff and WordPress' own content roles. Every other role keeps working as usual.
* New: "Who is frozen while locked" on the Lockdown tab: every role with its number of users, ticked if frozen. Saving needs the app code and is possible only while the site is not locked; roles that can take over the site cannot be unticked.
* Role changes while locked are refused only when the old or the new role is frozen, so another plugin can still move a member between member roles.

## 2.7.1

* Plugin Check: Lockdown no longer lists the automatic update options among the options it keeps unchanged (it never altered update routines; while locked, automatic updates are already off through the core filters). The lock's database queries are each prepared in one piece.
* Lockdown report: the "also by code" list no longer mentions automatic update lists.

## 2.7.0

* New: Lockdown, a tab in Settings → ScrapeLock and a line under the "Protection" button in the admin bar. Freezes every change to the site (plugins, themes, updates, the file editor, users and roles, staff email and password, settings, content) until an administrator unlocks it with a code from an authenticator app (TOTP, RFC 6238). Visitors and customers are not affected.
* Enforced through WordPress capabilities and also against code: protected options (active plugins, theme, site address, admin email, registration, default role, user roles, ScrapeLock's own settings), role changes, staff email and password changes, password resets and new application passwords are refused while locked.
* Each code is accepted once, even when two requests send it at the same moment (the check runs under a short database lock, on the state as it is in the database). New recovery codes stay in the database in plain form for 2 minutes at most, until they are shown.
* Temporary unlock (15 minutes to 2 hours, then it locks again by itself), ten one-time recovery codes, the SCRAPELOCK_UNLOCK constant as a last resort, 5 wrong codes per 15 minutes, a log of the last 30 events and an email to the admin address on every unlock.
* The secret is encrypted with the keys in wp-config.php; the QR code is drawn in the browser with the bundled qrcode-generator 1.4.4 (MIT, Kazuhiko Arase).
* The Lockdown tab warns that there is a single way to unlock, asks to confirm the recovery codes are saved before the first lock, and shows a full report: what is frozen, what keeps working, and the staff accounts, customers, plugins and theme on your site it applies to.

## 2.6.8

* Hardening: downloaded IP lists (Google, Bing, Cloudflare, Bunny, AI bots) are sanity-checked before use. An absurdly broad entry such as 0.0.0.0/0, ::/0 or any prefix shorter than /8 (IPv4) / /16 (IPv6) is dropped, so a bad or hostile source cannot make every IP an official crawler, a trusted proxy or a blocked one.
* Privacy (GDPR): the feed statistics now store the last client IP anonymised (IPv4 last octet zeroed, IPv6 last 80 bits), instead of keeping a full IP indefinitely in an option.
* Hardening: the one-time plaintext feed token is now kept for 2 minutes instead of 10 while it waits to be shown once, keeping it in the database as briefly as possible.
* Reliability: the strike counter that leads to a temporary ban is now atomic when a persistent object cache is present, so two simultaneous violations can no longer lose a strike.
* Cleanup on uninstall: the country-database folder is removed (not just its files), on multisite it is cleaned per site, and the per-attachment watermark marker (_pncp_wm) is deleted. The clean image originals and the pointer to them are kept on purpose.
* Fix: the "Feeds and token" link in the legacy-token notice pointed to a tab that does not exist; it now opens the Feeds and API tab.

## 2.6.7

* Fix: a blocked bot (e.g. a training crawler such as ClaudeBot) could still receive a 403 on /robots.txt in some setups. robots.txt, llms.txt and the TDM opt-out are now recognised directly from the raw request path, independent of the home-path/subfolder handling, and the main check has a safety net so no path can return a 403 for them. Every bot can always read the rules it is asked to follow.
* Change: the "CDN shared secret" field is now a single-line password input instead of a plain multi-line box.

## 2.6.6

* Security (M4): optional CDN shared secret. A multi-tenant CDN (Bunny, Cloudflare) shares its edge IPs, so by default anyone could point their own CDN zone at your origin and spoof the real-IP header. Set a secret under "Real visitor IP" and have your CDN send it as the header X-ScrapeLock-CDN; the CDN's real-IP header is then trusted only when it matches. Empty = unchanged behaviour.
* Security (M6): the WooCommerce Store API product catalogue (/wc/store/.../products) now counts toward the REST limit; only cart, checkout and batch stay exempt. Product descriptions are also stripped from cart line items, so the catalogue text cannot be read via "add to cart, then read the cart".
* Security (M8): the bot trap no longer bans allowed bots (link-preview, price-comparison, monitoring) or allowed AI search bots, even if another page embeds the trap URL; an old browser with no Sec-Fetch headers is treated as a bot only after a third hit, and the counter is per /64.
* Security (M10): when a crawler cannot be verified because the DNS budget is used up or DNS failed, the request is no longer blocked as a fake crawler (it falls through to the normal limits), so a flood of fake "Applebot" requests can no longer get the real Applebot or YandexBot a 403. Each crawler family now has its own DNS budget.
* Performance (M9): the pncp_version and pncp_db_version options are autoloaded, removing one database query per request on sites without a persistent object cache.

## 2.6.5

* Security: temporary bans are now kept per IPv6 /64 (like the limits and strikes), so a client can no longer dodge a ban by switching to another address in the same /64. IPv4 is unchanged.
* Security: the human-check endpoint now limits challenge requests and answer attempts per IP (per /64 on IPv6) and makes each challenge single-use, so one solved proof of work cannot be replayed and the endpoint cannot be hammered.
* Security: a User-Agent-only entry in the "Always allowed" list no longer skips country blocking (anyone can copy such a User-Agent). Pin an entry to its IP range (UA@1.2.3.0/24) to keep it fully exempt; verified AI search bots stay exempt.
* /.well-known/tdmrep.json is now always readable (normal check, early check, pre-cache check and the generated Nginx/Apache/Cloudflare rules), like robots.txt, so the AI/TDM bots meant to read your opt-out are never blocked from it. If you installed the server rules, copy them again.

## 2.6.4

* Security: a request could skip the per-minute limits (and so the strikes and temporary bans) by sending a "prefetch" header or by using POST. A prefetch is now trusted only with the browser's own Sec-Fetch-Dest signal, and an anonymous POST counts like a view; the pre-cache check still applies the always-blocked list and bans to every request.
* Security: the pre-cache events file is written with its "<?php exit;" guard and first line under one lock, and logged values can no longer contain <, > or ?, so a log file can never become executable code.
* Security: wp-config.php is now updated atomically (temporary file + rename) with a concurrent-change check, is never edited during a front-end request (it waits for wp-admin), and is left untouched when the file begins with declare() or namespace.

## 2.6.3

* Log: "Pages" now lists only addresses that exist on the site (posts, pages, products, archives…). Random strings and guesses get their own group, "Addresses that do not exist", next to "Files and admin paths".
* Log: the "Block permanently" button is also in "Top IPs" and in "Latest events".
* Log: "Persistent IPs" also lists IPs with at least 100 blocked requests in 7 days, even if they never got a temporary block (for example a User-Agent in the bot list), with their main reason.
* Log: pages that other plugins show (for example a community under /hub/space/) count as "Pages", found from the WordPress rewrite rules or from the new "Content addresses" setting.
* Log: no "Block permanently" for addresses in an official list (Google, Bing, OpenAI, Perplexity, Anthropic, Cloudflare, Bunny CDN): blocking them would also stop that company's search bots, or every visitor behind the CDN.
* Official IP lists that the settings need but were never downloaded (for example Anthropic after an update) are downloaded right away, not with the daily refresh. "Refresh lists now" button.
* robots.txt: the trap and Content-Signal go into the existing "User-agent: *" group instead of separate groups.
* Nginx rules: the names carry the site's suffix, so several WordPress sites can use their rules on the same Nginx. If you installed the 2.6.2 rules, copy both parts again.
* Nginx rules: the "Server rules" tab shows whether they are installed and up to date with the current settings, and where each part goes on the common servers and panels.

## 2.6.2

* robots.txt, llms.txt and llms-full.txt are never blocked, for any bot, in WordPress, the early check, the pre-cache check and the Nginx / Apache / Cloudflare rules.
* With "Allow AI search engines and assistants", the AI search bots are allowed at every level: they skip the stricter human-check limit, the Cloudflare rule blocks only the "AI Crawler" category, and Claude-SearchBot / Claude-User are verified with Anthropic's official IP list.
* New: the server rules also stop fake browsers (Nginx, Apache), so scanners asking for files that never reach WordPress are blocked too. Search engines are never affected.
* Log: "Block permanently" button, a list of IPs blocked again and again, fake / unverified marks on the top User-Agents, the number of different User-Agents of a grouped event, and better sorting of pages and scanner paths. Limit reasons are named after their settings.
* Fix: with AI search allowed, the Cloudflare bot rule could exceed Cloudflare's 4096-character limit; long lists are now split into several rules.

## 2.6.1

* The notices for Emergency Mode and the insecure 1.4 proxy setting now appear only on the Dashboard and the ScrapeLock settings page, not on every admin screen.
* Readme: every external service is listed with the exact addresses it is downloaded from, and the contributor name is corrected.

## 2.6.0

* New, optional: pre-cache check. One line at the top of wp-config.php applies the page limit, temporary blocks and always-blocked IPs also to pages served from a page cache such as WP Rocket, before the cache and WordPress load. Off until you turn it on; removed when turned off or deactivated.
* New: Bunny CDN support. "Trust Bunny CDN addresses" reads X-Real-IP / X-Forwarded-For only from Bunny's official edge servers, with detection and a one-click fix, and the country from Bunny's header.
* New, optional: human check. Visitors get a security cookie after their first real interaction; those without it get a stricter page limit. No captcha, works with page cache.
* New: a requests-per-minute limit for sitemaps (WordPress, Rank Math, Yoast). Verified search engines are never limited.
* New, optional: country rules (blocked countries, or a stricter limit), with Cloudflare's or Bunny's country header or the free DB-IP Lite database.
* New: the Log shows the pages and files that are blocked most, for 24 hours and 7 days.
* Redesigned settings page: status overview, cards, switches, section links and a save bar that stays visible.
* On existing sites every new option stays off after the upgrade.

## 2.5.0

* New: verify AI search bots (OpenAI OAI-SearchBot and ChatGPT-User, PerplexityBot, Perplexity-User) with their official IP lists. With AI search allowed, the real ones are never limited or blocked, and requests that only use their name get a 403. Off on existing sites until you turn it on.
* New, optional: block headless browsers (Puppeteer, Playwright, Selenium) and scripts that copy a browser's User-Agent without the headers a real browser sends. Off by default.
* The Cloudflare IP list now says when the current "Real visitor IP" setting does not use it.
* Includes the 2.4.1 fix for WP Rocket.

## 2.4.1

* Fix: on sites with WP Rocket, the first request after upgrading from 2.3.x could end with a critical error ("Call to undefined function get_rocket_cache_reject_uri()"). The cache purge now waits until all plugins have loaded.

## 2.4.0

* New, all off on existing sites until you turn them on: a "page not found" (404) limit per IP, always-blocked IP / CIDR and referrer lists, hiding usernames from visitors (`?author=N`, REST user list, users sitemap), Content Signals in robots.txt and a "first appeared on" source line in full-text feeds.
* Optional early check: a small must-use plugin that stops listed bots and blocked IPs before the theme and other plugins load. Always off until you enable it; removed when turned off, deactivated or deleted.
* Cloudflare: blocks, the bot trap and private feeds are never cached at the edge (APO), the Cloudflare plugin cache is purged when you save the settings, and a one-click fix appears when every visitor shows a Cloudflare address.

## 2.3.0

* Safer defaults for new installs: page, search and REST / GraphQL limits are on from the start (60 / 20 / 60 per minute). Existing sites keep their settings.
* DevTools shortcut blocking is off by default (it stops no bot); it is part of the Strict and Maximum presets.
* Security: an always-allowed User-Agent can be tied to IPs, e.g. `Skroutz@203.0.113.0/24`, so a fake User-Agent no longer bypasses the checks. Entries without `@` work as before.

## 2.2.4

* readme.txt: Contributors set to the plugin author's WordPress.org username. No code changes.

## 2.2.3

* The hidden bot-trap link is hidden with an enqueued stylesheet (`wp_add_inline_style()`) instead of an inline style attribute. No change in behaviour.

## 2.2.2

* New name: ScrapeLock (formerly Content Protect). Folder and main file `scrapelock/scrapelock.php`, text domain `scrapelock`. Settings, tokens and log are kept.
* Security: rate limits and violations are counted per /64 network for IPv6, so a scraper cannot bypass them by changing address. Filter `pncp_ipv6_prefix`.
* Security: a real Applebot / YandexBot is no longer banned when its DNS check cannot finish (DNS budget used up or reverse DNS failed).
* The feed token header is now `X-ScrapeLock-Token`. The old `X-Content-Protect-Token` header is still accepted.

## 2.2.1

* Security: the 1.x feed token is no longer kept in plain text during migration.
* New option to allow AI search assistants while training crawlers stay blocked.

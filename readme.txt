=== ScrapeLock – Content & AI Bot Protection ===
Contributors: codebunnyhube
Tags: anti-scraping, ai bots, bot protection, rate limit, content protection
Requires at least: 6.2
Tested up to: 7.2
Requires PHP: 7.4
Stable tag: 3.4.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Server-side anti-scraping: tells real Googlebot from fakes, blocks AI training bots, rate-limits per IP and locks private XML feeds with a token.

== Description ==

Most content protection plugins disable right click in the browser. Scrapers and AI crawlers don't click or copy: they either download the raw HTML or read the page directly from a (headless) browser, so these tricks don't stop them. ScrapeLock works on the server, where automated copying actually happens, and keeps real visitors, customers and search engines unaffected.

= What makes ScrapeLock different =

* **Real search engines vs. fakes.** Googlebot, Bingbot, Applebot and Yandex are verified against their official IP lists and with reverse + forward DNS. Real crawlers are never limited or blocked; scrapers that only pretend to be Googlebot get a 403.
* **AI training vs. AI search.** Training crawlers (GPTBot, ClaudeBot, CCBot, Google-Extended, Bytespider and more) are blocked, while AI search assistants (OAI-SearchBot, ChatGPT-User, PerplexityBot and more) can be allowed with one option and are verified with their official IP lists, so your site still appears in AI answers with a link.
* **Per-IP limits and temporary blocks.** Separate limits for pages, searches and REST / GraphQL requests (IPv6: per /64 network). IPs that keep exceeding them are blocked for a while, optionally also at your CDN, and an invisible trap link catches bots that ignore robots.txt.
* **Private feeds with a token.** XML feeds for price comparison sites, Google Merchant or an ERP are closed to everyone else. The token goes in a header or the URL, only its hash is stored, and it can be rotated with a grace period.
* **Your text stays out of the API.** Post, page and product text is hidden from the REST API, WPGraphQL and full-text RSS for visitors, which are the routes scrapers use instead of the HTML.
* **Emergency Mode.** One click during a scraping attack: stricter limits for 1 hour to 3 days, then your normal settings return on their own. When traffic suddenly jumps, ScrapeLock emails you with a one-click button to start it.
* **Monitor only.** Try every setting without blocking anyone: requests that would be refused are logged as "Would block". New installs start this way for their first 7 days.
* **Lockdown.** Freeze the whole site with a code from your authenticator app, so not even a stolen administrator password can change it.

Nothing can stop a determined human: whatever a visitor sees has already reached their device. ScrapeLock closes the automated routes and leaves traces: a block log, watermarks, a source link on copied text and a machine-readable rights reservation (TDM).

= Bots and limits =

* Generic HTTP libraries (curl, python-requests, okhttp and the like, used by apps and integrations) are not blocked by default; a strict option blocks them too, and the Log has an "Always allow this User-Agent" button.
* Optional blocking of headless browsers and of scripts that copy a browser's User-Agent but not its headers. A carefully disguised automated browser is not detected this way; the limits, the human check and the bot trap still apply to it.
* Extra limits for "page not found" (404) requests, sitemaps, visitors from data centers and, with WooCommerce, cart / checkout actions and coupon attempts. Verified search engines and real shoppers are not affected.
* Optional human check: visitors who have not interacted with the page (scroll, tap, key) get a stricter page limit. No captcha; with a page cache, turn on the pre-cache check so that the stricter limit applies to cached pages too.
* Optional country rules, from Cloudflare's or Bunny CDN's country header or the free DB-IP Lite database.
* Optional pre-cache check (the bot list, the limits and the blocks also apply to pages served by a page cache plugin such as WP Super Cache, W3 Total Cache, Cache Enabler or WP Rocket) and early check (stops known bots and blocked IPs before the theme and the other plugins load).
* Optional blocking at Cloudflare or Bunny CDN, with a "Test connection" that checks the token, the zone and the permissions in one click.
* Always-blocked IPs / CIDR and referrer domains, usernames hidden from visitors, and Content Signals in robots.txt.
* Trusted Proxy support for Cloudflare, Bunny CDN and reverse proxies, so the real IP cannot be spoofed. Works with the Cloudflare plugin (APO).
* Presets (Balanced, Strict, Maximum), undo for presets and imports, export and import of the settings, and a block log with a 24-hour summary and automatic deletion.

= Feeds, API and server rules =

* RSS with a short excerpt only, or disabled. With full text, an optional "The post … first appeared on …" line links republished copies back to the original.
* Private XML feeds (Skroutz, BestPrice, Google Merchant, ERP) with token rotation and per-feed statistics.
* Optional: hide the REST API map from visitors, turn off pingbacks over XML-RPC, and see which REST routes anyone can call without logging in.
* Hide the versions of WordPress, PHP and the plugins.
* Ready-made Nginx, Apache and Cloudflare rules for your own site, so cached pages and static files are protected too.

= Site Health, WP-CLI and AI agents =

* Tools → Site Health warns about settings that do not work as intended and has a ScrapeLock section in the Info tab.
* WP-CLI: `wp scrapelock status`, `block`, `unblock`, `blocked`, `emergency`, `log`, `check --ip=<ip>` (what ScrapeLock would answer, without side effects), `settings` and `lockdown status`.
* Abilities API (WordPress 6.9+) for administrators: read the summary, block or unblock an IP and start Emergency Mode from an AI agent or MCP client. None of them unlocks Lockdown.

= On the page and images =

* Block text selection, right click, copy, drag and common shortcuts, or allow copying with the source link appended. Text selection stays allowed by default, because blocking it also stops screen readers' "read selection" and translation tools.
* Printing with the page link at the bottom, or no printing; optional page blur on screenshot shortcuts; no framing by other sites.
* AI opt-out declaration (TDM): header, meta, `/.well-known/tdmrep.json`, `noai`.
* Watermark in a corner, the centre or repeated diagonally, optionally on the full-size image too. When the full size is not watermarked, visitors get the largest watermarked size instead, also in the WooCommerce zoom, lightbox and Store API. The clean original is kept, so the watermark can always be removed. Product images are not watermarked by default, because Google Merchant Center rejects them.

= Lockdown =

* Freeze the site with one click and a code from your authenticator app (Google Authenticator, Microsoft Authenticator, Authy and the like). While it is locked, nobody can change plugins, themes, WordPress core, users, roles or settings from wp-admin, the REST API or XML-RPC, not even an administrator or someone who stole a password.
* Administrators are frozen completely. Shop managers and other staff roles you do not tick keep their work (orders, products, coupons, posts, media), but not the rights that could take over the site.
* Also enforced against code: if a bug in another plugin is exploited to change settings or the database, it cannot activate plugins, change the site address or the admin email, add an administrator or unlock the lock. Code that can run its own PHP on your server can get around any plugin, ScrapeLock included.
* Visitors and customers are not affected: they browse, order, pay, register as customers and comment as usual.
* File integrity: a fingerprint of every PHP, .htaccess and .user.ini file is checked every hour while locked, and WordPress and the plugins from WordPress.org are compared with their official checksums. New or changed files are emailed to you and shown in Site Health; optional quarantine.
* Sealed: the lock is signed with the keys in wp-config.php and kept outside the database (a guard file, a lock file, or a line in wp-config.php), so SQL injection in another plugin cannot unlock the site. Settings changed in the database are put back.
* Unlock for 15 minutes to 2 hours for yourself only, or until you lock it again. Every lock and unlock is logged and emailed.
* Lost your phone: ten one-time recovery codes, or `define( 'SCRAPELOCK_UNLOCK', true );` in wp-config.php as a last resort.
* The QR code is drawn in your browser and the secret is stored encrypted: it is never sent anywhere.

== External services ==

ScrapeLock downloads public lists of IP addresses, only for the features that use them. Each download is a plain GET request for a public file, made from your server by WordPress (User-Agent "ScrapeLock/version"). No data about your site, your content or your visitors is sent, and the request does not include your site address; as with any download, the provider sees your server's IP address. The lists are stored in your database (or, for the country database, in uploads/scrapelock-geo) and checked on your server. They are data, not code or assets: no script, style, font or image is ever loaded from these addresses.

* **Google** crawler IP ranges, to tell real Googlebot from fakes. Downloaded once a day while protection is enabled, from https://developers.google.com/static/search/apis/ipranges/googlebot.json, https://developers.google.com/static/search/apis/ipranges/special-crawlers.json and https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json. Provided by Google LLC: [Terms of service](https://policies.google.com/terms), [Privacy policy](https://policies.google.com/privacy).
* **Bing** crawler IP ranges, to tell real Bingbot from fakes. Downloaded once a day while protection is enabled, from https://www.bing.com/toolbox/bingbot.json. Provided by Microsoft Corporation: [Terms of service](https://www.microsoft.com/servicesagreement), [Privacy policy](https://privacy.microsoft.com/privacystatement).
* **Cloudflare** IP ranges, to read the real visitor IP only from Cloudflare. Downloaded once a day only when "Real visitor IP" reads the CF-Connecting-IP or X-Forwarded-For header and "Trust Cloudflare addresses" is on, from https://api.cloudflare.com/client/v4/ips. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Bunny CDN** edge server addresses, to read the real visitor IP and country only from Bunny CDN. Downloaded once a day only when "Trust Bunny CDN addresses" is on and "Real visitor IP" reads the X-Real-IP or X-Forwarded-For header, or country rules are set, from https://bunnycdn.com/api/system/edgeserverlist and https://bunnycdn.com/api/system/edgeserverlist/IPv6. Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).
* **OpenAI** bot IP ranges (OAI-SearchBot, ChatGPT-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://openai.com/searchbot.json and https://openai.com/chatgpt-user.json. Provided by OpenAI: [Terms of use](https://openai.com/policies/terms-of-use/), [Privacy policy](https://openai.com/policies/privacy-policy/).
* **Perplexity** bot IP ranges (PerplexityBot, Perplexity-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://www.perplexity.com/perplexitybot.json and https://www.perplexity.com/perplexity-user.json. Provided by Perplexity AI, Inc.: [Terms of service](https://www.perplexity.ai/hub/legal/terms-of-service), [Privacy policy](https://www.perplexity.ai/hub/legal/privacy-policy).
* **Anthropic** bot IP ranges (Claude-SearchBot, Claude-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://claude.com/crawling/bots.json. Provided by Anthropic PBC: [Terms of service](https://www.anthropic.com/legal/consumer-terms), [Privacy policy](https://www.anthropic.com/legal/privacy).
* **DB-IP Lite** country database, to apply the country rules. Downloaded once a month only when "Download the free country database" is on, from https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz (the current or the previous month). Lookups happen on your server. Licensed under CC BY 4.0 ("IP Geolocation by DB-IP"). Provided by db-ip.com: [Terms of service](https://db-ip.com/tos.php), [Privacy policy](https://db-ip.com/privacy.php), [License](https://creativecommons.org/licenses/by/4.0/).

The five data center lists below are used only for the "Data center limit" (Bots and limits), a stricter page limit for visitors that come from cloud servers rather than from home or mobile connections. Each one is downloaded once a day only while protection is enabled and "Data center limit" is above 0 (set it to 0 to turn the lists off). They are JSON or CSV data files fetched by your server with wp_remote_get(); nothing from these hosts is ever loaded in your visitors' browsers.

* **Amazon Web Services** IP ranges (only the EC2 servers are used), from https://ip-ranges.amazonaws.com/ip-ranges.json. Provided by Amazon Web Services, Inc.: [Terms](https://aws.amazon.com/service-terms/), [Privacy policy](https://aws.amazon.com/privacy/).
* **Google Cloud** IP ranges, from https://www.gstatic.com/ipranges/cloud.json, the address where Google publishes the list. Provided by Google LLC: [Terms of service](https://policies.google.com/terms), [Privacy policy](https://policies.google.com/privacy).
* **Oracle Cloud** IP ranges, from https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json. Provided by Oracle Corporation: [Terms of use](https://www.oracle.com/legal/terms/), [Privacy policy](https://www.oracle.com/legal/privacy/).
* **DigitalOcean** IP ranges, from https://digitalocean.com/geo/google.csv. Provided by DigitalOcean, LLC: [Terms of service](https://www.digitalocean.com/legal/terms-of-service-agreement), [Privacy policy](https://www.digitalocean.com/legal/privacy-policy).
* **Akamai Cloud (Linode)** IP ranges, from https://geoip.linode.com/. Provided by Akamai Technologies, Inc.: [Terms of service](https://www.akamai.com/legal/msa), [Privacy policy](https://www.akamai.com/legal/privacy-statement).

Lockdown's file check also compares WordPress and the plugins hosted on WordPress.org with their official checksums. This happens when you lock the site or press "Check now" on the Lockdown tab, and then at most once a day while the site stays locked, through the same WordPress.org services WordPress itself uses for updates. The requests contain the WordPress version and language (https://api.wordpress.org/core/checksums/1.0/) and, for each installed plugin, its slug and version (https://downloads.wordpress.org/plugin-checksums/SLUG/VERSION.json); no other data about your site, your content or your visitors is sent. Provided by WordPress.org: [Privacy policy](https://wordpress.org/about/privacy/).

Optional blocking at the CDN (off by default) uses the API of the CDN you choose, with your token. It sends only the IPs ScrapeLock blocks temporarily (IPv4, IPv6 or an IPv6 /64), each with the reason and end time, and removes them when the block ends. Saving the setting, or "Test connection", checks the token and the zone; with Cloudflare it also adds a test block for a documentation address (203.0.113.x) and removes it again.

* **Cloudflare API** (IP Access rules of your zone), only when the CDN is set to Cloudflare: https://api.cloudflare.com/client/v4/zones/ZONE_ID/firewall/access_rules/rules, and for the check https://api.cloudflare.com/client/v4/user/tokens/verify (or /accounts/ACCOUNT_ID/tokens/verify) and /zones/ZONE_ID. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Bunny CDN API** (blocked IPs of your Pull Zone), only when the CDN is set to Bunny CDN: https://api.bunny.net/pullzone/PULL_ZONE_ID (addBlockedIp, removeBlockedIp, and reading the zone's list of blocked IPs). Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).

If a list has not been downloaded, ScrapeLock verifies search engine bots with reverse DNS, and uses a built-in copy of the Cloudflare ranges. AI search bots are not verified until their list has been downloaded. Reverse DNS lookups are made only for requests that claim to be a search engine, through your server's own DNS resolver.

If the official Cloudflare plugin is active, ScrapeLock asks it to purge its cache when you save the ScrapeLock settings. The request is made by the Cloudflare plugin, with the account you connected there; ScrapeLock itself does not contact Cloudflare for this and stores no Cloudflare credentials.

== Installation ==

1. Upload the `scrapelock` folder to `/wp-content/plugins/`, or install the plugin from the Plugins screen.
2. Activate it.
3. Go to Settings → ScrapeLock and choose a preset, or adjust each tab.
4. If your site is behind Cloudflare or another proxy, set "Real visitor IP" first.

Upgrading from "Content Protect" (folder `content-protect`), the former name of this plugin: deactivate the old plugin, activate ScrapeLock. Your settings, tokens and log are kept. If you pasted the old Apache rules, replace the "# BEGIN Content Protect" block with the new "# BEGIN ScrapeLock" block.

== Frequently Asked Questions ==

= Will it block Google or Bing? =

No. Verified search engines are never limited or blocked. Only fake ones that pretend to be Googlebot or Bingbot are blocked.

= Does it work with page cache? =

ScrapeLock tells WP Rocket not to serve cached pages to the bots in its list, so they are always checked. Other page cache plugins (WP Super Cache, W3 Total Cache, Cache Enabler and the like) serve stored pages before WordPress and ScrapeLock load: turn on "Pre-cache check" in "Bots and limits" to apply the bot list, the page limits, the human check's stricter limit and the blocks to those pages too. Site Health tells you when a page cache answers before ScrapeLock. A cache in the web server itself (Nginx FastCGI cache, LiteSpeed, Varnish) answers before PHP runs at all: there use the rules in the "Server rules" tab, or blocking at the CDN.

= What does the pre-cache check change on my server? =

It adds two comment lines and one `include` line right after `<?php` at the top of `wp-config.php`. The line loads the check from the plugin's own folder; its settings, counters and events are plain data files (no PHP) in a protected folder with a random name inside the uploads directory, `uploads/scrapelock/` (counters go to APCu instead, if your server has it). The check runs before the page cache and WordPress, without a database, and stops always-blocked IPs, temporarily blocked IPs, User-Agents in the bot list and visitors over the "Pages per minute" limit (and, with the human check, over the stricter limit for visitors who have not passed it). Verified search engines, forms, wp-admin and the REST API are left to the normal check; a request with a login cookie, which the check cannot verify, gets four times the page limit. If `wp-config.php` is not writable, the setting shows the lines to add yourself. Everything is removed when you turn the setting off or deactivate the plugin. Not available on multisite.

= My site is behind Bunny CDN. What should I set? =

If your server already replaces the IP (for example Nginx with `real_ip_header X-Real-IP` and the Bunny addresses in `set_real_ip_from`), keep "REMOTE_ADDR": ScrapeLock tells you it is correct. Otherwise set "Real visitor IP" to X-Real-IP and turn on "Trust Bunny CDN addresses"; ScrapeLock downloads the official list of Bunny edge servers and trusts the header only from them. When every visitor appears with a Bunny address, it shows a button that does this for you.

= Can I allow ChatGPT or Perplexity search but block training? =

Yes. Enable "Allow AI search engines and assistants" in the "Bots and limits" tab. Training crawlers stay blocked. With "Verify AI search bots" on, only requests from the official OpenAI and Perplexity addresses count as their bots; scanners that only copy the name get a 403.

= My site is behind Cloudflare. What should I set? =

In "Bots and limits", set "Real visitor IP" to CF-Connecting-IP and keep "Trust Cloudflare addresses" on. If ScrapeLock sees that every visitor arrives from a Cloudflare address, it shows a button that does this for you. With Nginx, also set `real_ip_header CF-Connecting-IP;` and the Cloudflare ranges with `set_real_ip_from`, so the server rules see the real visitor IP.

= Can ScrapeLock block scrapers at Cloudflare or Bunny CDN? =

Yes, since 3.1. In "Bots and limits" → "Blocking at the CDN", choose Cloudflare or Bunny CDN and enter the zone ID and a token. For Cloudflare, create an API token with the single permission Zone → Firewall Services → Edit, for this zone only; for Bunny CDN, use your account's API key. You can put the token in `wp-config.php` instead (`define( 'SCRAPELOCK_EDGE_TOKEN', '…' );`), so it is not stored in the database. From then on, every IP ScrapeLock blocks temporarily is also blocked at the CDN within a minute or two, and the block is removed there when it ends. The site must be served through that CDN (for Cloudflare: proxied, orange cloud). Rules you made yourself are never changed. Administrators' IPs from the last 30 days, search engines, AI search services and the CDN's own addresses are never blocked there. Bunny CDN blocks single addresses only, so a blocked IPv6 network stays blocked by ScrapeLock itself. Turning the setting off or deactivating the plugin removes the blocks ScrapeLock made.

= Can someone go around my CDN? =

If they find your server's own address, yes: then nothing the CDN blocks applies. Since 3.2, "Only through the CDN" (Bots and limits → Real visitor IP) refuses every request that does not bring a secret your CDN adds as the header `X-ScrapeLock-CDN` (Bunny CDN: an Edge Rule "Set Request Header"; Cloudflare: a Transform Rule "Modify Request Header"). It can only be turned on from a request that brings the secret, so a missing rule cannot lock you out. If the CDN ever stops sending it, add `define( 'SCRAPELOCK_CDN_ONLY', false );` to wp-config.php.

= What is the early check? =

An optional setting in "Bots and limits". ScrapeLock writes the small file `wp-content/mu-plugins/scrapelock-early.php`, which runs before the theme and the other plugins and stops blocked IPs and referrers, temporarily blocked IPs and User-Agents from the bot list, with less server load. Search engines, logged-in users, forms and private feeds are left to the normal check. The file is removed when you turn the setting off, deactivate or delete the plugin. If the server does not allow direct file writes, the setting shows a notice and everything else works as before.

= Does it guarantee legal protection of my content? =

No. The TDM declaration is a machine-readable reservation of rights; it does not guarantee legal compliance or stop anyone who ignores it.

= What personal data does it store? =

When a request is blocked, the IP address, User-Agent, page and time are logged. The log is deleted automatically after 1, 7 or 30 days.

With the human check on, visitors who interact with the page get a security cookie, `pncp_hv`, for 7 days. It contains only an expiry time and a signature tied to their IP network and browser; it is not used for tracking or statistics. The country database is a local file: no visitor data is sent to DB-IP.

= Can blocked bots still read robots.txt and llms.txt? =

Yes. robots.txt, llms.txt and llms-full.txt are never blocked, for any bot, so every bot can read the rules it is asked to follow. The server rules in the "Server rules" tab keep them open too.

= What does Lockdown freeze, and what keeps working? =

While locked, users with a frozen role keep only "read": they can log in and open the dashboard, but cannot change anything. Roles that can change plugins, themes, users or settings are always frozen; editors, authors, contributors and shop managers are frozen by default, and you choose the rest on the Lockdown tab. Customers, subscribers and members (for example accounts that post listings through another plugin) are not affected, and neither are visitors, orders, payments, webhooks, cron jobs and comments. Shop staff cannot process orders in wp-admin while the site is locked: unlock it for a while to do so.

= I lost my phone. How do I unlock the site? =

Type one of your recovery codes in the unlock field instead of an app code. If you have none left, add `define( 'SCRAPELOCK_UNLOCK', true );` to wp-config.php (FTP or your hosting panel), go to the Lockdown page, remove the app and connect a new one, then remove that line. The same works if you forget an administrator password while the site is locked, because password resets for staff are frozen too.

= Can someone with access to my server bypass Lockdown? =

Yes. Lockdown protects the site against changes through WordPress (wp-admin, the REST API, XML-RPC and code running inside WordPress). Someone who can only write to the database (for example through SQL injection in another plugin) cannot unlock it: the lock is signed with the keys in wp-config.php and copied into a must-use plugin file, changed protected settings are put back, and new administrators cannot sign in. Whoever can edit files on your server controls the site anyway, which is also why the server line is the last-resort unlock. The file integrity check is there for that case: a file written behind WordPress' back is found within the hour and emailed to you. Code that already runs on the server could also stop ScrapeLock itself, so "No PHP in the uploads folder" (a server rule) is what stops most backdoors from running in the first place.

= Can I unlock Lockdown from WP-CLI or with an AI agent? =

No, on purpose. Lockdown opens only with a code from your authenticator app, a recovery code, or the SCRAPELOCK_UNLOCK line in wp-config.php. The WP-CLI commands and the abilities can block IPs and start Emergency Mode; while the site is locked the abilities can only read the summary.

= Does the human check show a captcha? =

No. A small script waits for the first real interaction (scroll, tap, key or mouse movement), solves a light challenge in the background and receives the cookie. Visitors without it are not blocked: they get the stricter page limit you set (20 pages per minute by default). A determined scraper can repeat these steps, but every IP it uses has to do the work, and plain scripts never do.

== Screenshots ==

1. Block log: 24-hour summary by reason, top IPs and User-Agents, temporarily blocked IPs and the latest events.
2. Bots and limits: AI training crawlers, AI search assistants, fake search engine detection and the bot trap.
3. Feeds and API: token-protected XML feeds with per-feed statistics, and text hidden from REST, GraphQL and RSS.
4. Server rules: ready-made Cloudflare, Nginx and Apache rules generated for your own site.
5. Presets, Emergency Mode and the on-page protection settings.
6. Dashboard widget with the protection status and the last 24 hours.

== Changelog ==

= 3.4.3 =
* Security: private feeds can no longer be read without the token as `/?feed=_name` (WordPress drops the leading underscores of a feed name), or with extra slashes in the address (`//feed.xml`, `/feeds//feed.xml`, `/feed.xml//`).
* Security: the pre-cache check now applies temporary bans to requests that claim to be Applebot or YandexBot (or Googlebot / Bingbot before their lists are downloaded). Before, a banned scraper only had to add one of these names to its User-Agent to read cached pages. Only the page limit is still left to the normal check, which verifies these bots with DNS.
* Security: the pre-cache check no longer skips a page whose address carries `doing_wp_cron=`.
* Security: downloaded IP lists are checked more strictly: an IPv4-mapped range that would cover all or most of IPv4 is refused, and a download with nothing usable in it keeps the previous list instead of emptying it.
* Security: the Lockdown recovery codes are kept encrypted for the two minutes until the page shows them, and stored user capabilities are read as data only (no objects).
* Lockdown: the lock form warns when AUTH_KEY / AUTH_SALT are not in wp-config.php and SCRAPELOCK_KEY is not defined, because the keys are then kept in the database. Site Health and `wp scrapelock status` now count a valid SCRAPELOCK_KEY as keys in wp-config.php.
* Fix: the early check (mu-plugin) and the Lockdown guard file are written to a temporary file first and then renamed, so a write cut short (full disk, quota) or a request that loads them meanwhile never leaves a half-written file that would stop the whole site. The early check also does nothing, instead of a fatal error, when the plugin folder is only partly there (during an update).
* Fix: behind a CDN that does not pass the real visitor IP, a real Googlebot coming through a CDN edge address is no longer refused as a fake crawler.
* Fix: settings import checks every value against its setting: "false", "off" and "no" are read as off, and text that is not a number or not one of the allowed choices is left out. Numbers far out of range no longer wrap around to 0.
* Fix: the watermark tool stops, and changes nothing, when the clean full-size image cannot be put back, instead of carrying on from an image that already has a watermark.
* Fix: the generated Nginx hotlink rule quotes each allowed site, so `nginx -t` no longer fails on it.
* Fix: the file integrity check compares WordPress with the checksums of the language package it was installed from, and the quarantine also covers single-file plugins.
* Fix: password-protected posts no longer show an excerpt in the feeds, and the source link in feed excerpts is escaped.
* Fix: the "Copy" buttons in the admin work without the Clipboard API.
* Fix: removing blocks at the CDN no longer lists blocks already removed in the same run as "remove by hand", and the API token is replaced by "[token]" in error messages.
* Fix: smaller fixes in the human check request, the country database cleanup, the REST routes list, the log import and the "Monitor only" notice.
* Security: behind Bunny CDN without the CDN secret, the visitor IP read from the CDN header still counts for the limits, but it no longer unlocks the always-allowed IPs or the private URL IPs, and no longer gets an IP banned by the trap or blocked at the CDN. Anyone can point a Bunny pull zone of their own at your site and send any IP in that header. Set the CDN secret to trust it fully, as before.
* Security: a fake Googlebot or Bingbot from an address without reverse DNS is now blocked as a fake crawler once the official list is loaded. Before, it was treated as "could not verify" and let through.
* Bot trap: the first time an IP falls into the trap it is blocked for 10 minutes; if it falls in again within 24 hours, for the full time. One bad client behind a shared address (mobile networks, offices, schools) no longer locks everyone else out for hours. Filter: `pncp_trap_first_ban_minutes` (0 = always the full time).
* Performance: without an object cache or APCu, the site-wide traffic counter is written on 1 page in 10 (counting 10), so an attack no longer queues every request on one database row, and at most 2,000 new per-IP counters are created per minute. Filters: `pncp_surge_sample`, `pncp_db_new_counters_per_minute`.
* Security: while the site is locked, plugins, themes and WordPress can no longer be installed, updated, downgraded or deleted through WP-CLI or by code that runs WordPress's upgrader directly. Before, only wp-admin was stopped. Each attempt is refused and noted in the lockdown log.
* Lockdown: locking the site (and locking it again after an unlock for a while) is now emailed too, as the readme always said.
* Security: with a persistent object cache (Redis, Memcached), Lockdown and the file check now read their signed data from the database itself. Before, a row changed or deleted directly in the database went unseen while the cache kept the old copy: no alert, and in the worst case the owner could not unlock even with SCRAPELOCK_UNLOCK until the cache was emptied.
* Security, WooCommerce: the Store API order and checkout answers no longer give visitors the long product descriptions (a free cash-on-delivery order could be used to read them all).
* Lockdown, WooCommerce: shop managers can no longer create customer accounts through the WooCommerce REST API while the site is locked, as documented for every other way of creating users.
* Fix: the "site is locked" page no longer logs PHP notices when WordPress stops that early (e.g. the Customizer).
* WP-CLI: `wp scrapelock unblock` says that a web server keeping blocks in APCu may still refuse the IP for up to a minute.
* Lockdown: while the site is locked, you get an email (at most once a day, and only when the list changes) and a notice in wp-admin when updates are waiting, with WordPress security and maintenance releases first. Plugin, theme and translation updates still need an unlock.
* Lockdown: new filter `pncp_lockdown_allow_core_minor` (off by default). When it returns true, WordPress may install its own minor releases (e.g. 6.8.1 → 6.8.2) by itself while locked; the core files that match the official checksums are taken into the file check, and the update is noted in the lockdown log.
* Security: a private feed whose address resolves to a query variable (e.g. /feed.xml → feed_var=1) can no longer be read without the token as ?feed_var=01, ?feed_var=yes or ?feed_var[]=1.
* Security: the Bunny CDN rule above also holds behind a local proxy (Nginx or Varnish in front of PHP), where the Bunny edge is one hop further in X-Forwarded-For.
* Security: the country header of Cloudflare or Bunny CDN is no longer trusted when a CDN secret is set and the request does not carry it, as for the visitor IP.
* Security: hidden usernames could still be found with ?author=+1, ?author=x1 or author=1 sent by POST. These now get a 404 like ?author=1.
* Security: with "Watermark the full-size image too" off, an image inserted at full size in a post no longer shows visitors the clean original (the image, its "link to media file" and the lightbox now use the largest watermarked size).
* Security: the CDN API token can no longer appear cut in half in a stored network error message, and Site Health no longer counts AUTH_KEY / AUTH_SALT as set when WordPress itself ignores them (a value shared with another key, or the sample phrase).
* Fix: a damaged IP list in the database (an entry that is not text) no longer stops every request with a fatal error.
* Fix: Bunny CDN addresses written in the IPv4-mapped form, and data center ranges in that form, now match IPv4 visitors.
* Fix: the block log keeps logging after "Clear log". Before, events of the same IP and reason were lost for up to two minutes.
* Fix: the early check stops blocking when the plugin folder is renamed or removed on sites where it is a symbolic link.
* Fix: the pre-cache check removes old strike and ban files every hour; one of each used to stay behind for every IP that ever hit a limit.
* Fix: the file integrity report no longer loses files found by a check that ran during the comparison with WordPress.org, and is removed with the fingerprint when the authenticator app is removed.
* Fix: "Restore original image" in the image editor watermarks the restored image again, and deleting an edited image also deletes the clean copies of its earlier versions.
* Fix: number settings such as "1e999" are no longer saved as 0 (no limit), settings that are not text no longer give warnings, and control characters are removed from the lists.
* Fix: the Apache rules work for WordPress in a subfolder, and a backslash in the bot or allow list no longer breaks the Nginx rules.
* Fix: with the CDN unreachable, removing old blocks waits before it retries instead of calling the API every minute.
* Fix: `wp scrapelock check --address='?s=…'` checks a search on this site.
* Performance: Site Health reads the file fingerprint once instead of up to three times.
* Security: a private pattern with * (e.g. /feeds/*.xml) now also protects the same feed when it is asked for through its query variable (/?feed_var=name), which the rewrite rules for those addresses set.
* Security: a solved human check can be used only once, also when two answers to it arrive at the same moment.
* Security: in the REST API of the media, visitors no longer see the path and size of the clean full-size image when the full size is not watermarked: the largest watermarked size is shown instead.
* Fix: Emergency Mode only makes settings stricter. A site that blocks after 1 violation keeps 1 (it was raised to 2), and a site that never blocks keeps that choice; this applies to the pre-cache check too.
* Fix: percent-encoded addresses (e.g. Greek private feed paths, /robots%2Etxt) are recognised by the early check and the normal check.
* Fix: the "Updates are waiting" email of Lockdown is tried again about an hour later when sending fails, instead of never for that list.
* Fix: with DISABLE_WP_CRON set, ScrapeLock no longer starts wp-cron.php itself (which also ran every other due event of the site): its events run with your own cron.
* Fix: the mu-plugins folder is removed again when ScrapeLock created it and it is empty after deactivation or deletion.
* Fix: the forms on the ScrapeLock page, including the Lockdown and file check forms, no longer repeat the same HTML ids.
* Fix: an address that sends a single-value WordPress query variable as an array (?feed[]=x, ?year[]=1, ?author_name[]=x and the like, by GET or POST) now gets a plain 404. WordPress itself stopped such requests with a fatal error (500), which scanners use to fill the error log.
* Fix: with PHP-FPM or an object cache, many parallel requests of the same IP no longer write the same log event two or three times in one minute.
* Fix: lifting a block in wp-admin while the blocked IP keeps sending requests could leave the IP blocked for another minute on PHP-FPM (APCu).
* Fix: `wp scrapelock block` and `wp scrapelock unblock` take effect at once on PHP-FPM / mod_php with APCu; before, the web server could keep its old answer for up to a minute.
* Fix: data center lists refreshed from WP-CLI (e.g. cron run with `wp cron event run`) are used at once on PHP-FPM, instead of after up to an hour.
* Fix: the Nginx rules quote a private path (or a WordPress folder) that contains a space, a quote or a semicolon: such a path made `nginx -t` fail.
* Fix: the "once a minute" strike of fake crawlers and the human check throttle are counted atomically with APCu or an object cache.
* Fix: in Emergency Mode, a shopper who changed quantities in the WooCommerce block cart (block theme with the Mini-Cart) could be blocked for hours: WooCommerce asks a wrong Store API address after every change (404), and those 404s counted towards the "page not found" limit. Store API addresses, and requests made by the site's own scripts (Sec-Fetch-Site: same-origin), no longer count towards that limit; they still count as pages.
* Security: the pre-cache check applies the bot list (and "no User-Agent") to cached pages. With WP Super Cache, W3 Total Cache, Cache Enabler and the like, GPTBot, ClaudeBot and the other blocked bots read cached pages in every mode; only WP Rocket was told to skip them.
* Security: with the pre-cache check, a User-Agent with "Applebot" or "YandexBot" (which the check cannot verify) no longer reads cached pages without a limit: it gets four times the page limit there.
* Security: a login cookie (its name is public) no longer skips the pre-cache check. It still gets the always-blocked IPs and the bans, and four times the page limit; staff get their own rules from the normal check.
* Fix: the human check's stricter limit now also applies to cached pages with the pre-cache check (through a second cookie the check can verify), and Emergency Mode's IPv6 /56 limit too.
* Fix: Cache Enabler's cache is cleared when a setting that cached pages depend on changes, and every page cache is cleared when the watermark is turned on or off and after "Apply" / "Remove" of the watermark tool (cached pages kept linking the clean files).
* Fix: the Nginx page limit (limit_req) no longer limits the "Always allowed IPs"; the rules explain that Nginx cannot verify search engines.
* Site Health tells you when a page cache plugin answers before ScrapeLock and the pre-cache check is off.
* Readme: clearer wording about headless browsers and about what Lockdown can and cannot stop.

= Older versions =
The changes of 3.4.2 and earlier are in `changelog.txt` in the plugin folder.

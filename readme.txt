=== ScrapeLock – Content & AI Bot Protection ===
Contributors: codebunnyhube
Tags: ai crawlers, anti-scraping, bot protection, rate limit, content protection
Requires at least: 6.2
Tested up to: 7.2
Requires PHP: 7.4
Stable tag: 3.13.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Block AI scrapers like GPTBot, catch fake Googlebot, rate-limit content scraping per IP and guard WooCommerce. Runs on your server, no account.

== Description ==

Most content protection plugins only disable right click. Scrapers and AI crawlers never click: they download the HTML, read the REST API and the feeds, or drive a headless browser. ScrapeLock works on your server, where the copying happens: it blocks bots that identify themselves and slows fast scraping from one address; scrapers that imitate a browser and rotate IPs are only partly slowed. Real visitors, shoppers and search engines are left alone.

* **Runs on your own server.** No account, no API key, and no visitor data sent anywhere by default.
* **Starts in Monitor only.** For its first 7 days it only logs what it would block, so you can tune it first.

= Key features =

* **AI crawlers and fake bots:** blocks AI training crawlers (GPTBot, ClaudeBot, CCBot, Bytespider…) and fake Googlebot or Bingbot, checked against the official IP lists and DNS. AI search assistants can stay allowed.
* **Limits and blocks:** per-IP limits for pages, search, REST / GraphQL, 404s and WooCommerce cart and coupon attempts, temporary blocks (also at Cloudflare or Bunny CDN), Emergency Mode and a human check without a captcha.
* **Your text stays yours:** post text hidden from the REST API, WPGraphQL and full-text RSS, private XML feeds with a token, a TDM opt-out, watermarks, and traceable copies and screenshots for members.
* **Attacks and Vulnerable points:** see where bots attack (failed sign-ins, XML-RPC, scanner probes) and lock those points with one click.
* **Page cache and servers:** a pre-cache check, and ready-made Nginx, Apache and Cloudflare rules.
* **Stealth (optional):** hides that the site runs on WordPress from BuiltWith, Wappalyzer and scanners.
* **Lockdown:** freezes plugins, themes, users and settings until you unlock it with your authenticator app.
* **Traffic:** every request from your CDN, your access log or WordPress, with User-Agents, failing pages and email alerts, kept in your own database.
* **Check a request, Site Health and WP-CLI:** see why a request would be allowed or blocked, without side effects.

= What it cannot do =

Whatever a visitor sees has already reached their device, so nothing stops a person copying by hand or taking screenshots. ScrapeLock closes the automated routes and leaves traces: watermarks, a source link on copied text and a TDM declaration.

The full feature list and more answers are in the [user guide](https://github.com/Code-BunnyHUB/ScrapeLock-WP/blob/main/docs/user-guide.md).

== External services ==

ScrapeLock downloads public lists of IP addresses, only for the features that use them. Each download is a plain GET request for a public file, made from your server by WordPress (User-Agent "ScrapeLock/version"). No data about your site, your content or your visitors is sent, and the request does not include your site address; as with any download, the provider sees your server's IP address. The lists are stored in your database (or, for the country database, in uploads/scrapelock-geo) and checked on your server. They are data, not code or assets: no script, style, font or image is ever loaded from these addresses.

* **Google** crawler IP ranges, to tell real Googlebot from fakes. Downloaded once a day while protection is enabled, from https://developers.google.com/static/search/apis/ipranges/googlebot.json, https://developers.google.com/static/search/apis/ipranges/special-crawlers.json and https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json. Provided by Google LLC: [Terms of service](https://policies.google.com/terms), [Privacy policy](https://policies.google.com/privacy).
* **Bing** crawler IP ranges, to tell real Bingbot from fakes. Downloaded once a day while protection is enabled, from https://www.bing.com/toolbox/bingbot.json. Provided by Microsoft Corporation: [Terms of service](https://www.microsoft.com/servicesagreement), [Privacy policy](https://privacy.microsoft.com/privacystatement).
* **Apple** crawler IP ranges (3.10), to tell real Applebot from fakes without a DNS lookup. Downloaded once a day while protection is enabled, from https://search.developer.apple.com/applebot.json. Provided by Apple Inc.: [Terms of use](https://www.apple.com/legal/internet-services/terms/site.html), [Privacy policy](https://www.apple.com/legal/privacy/).
* **DuckDuckGo** crawler IP addresses (3.10), to recognize the real DuckDuckBot. Downloaded once a day while protection is enabled, from https://duckduckgo.com/duckduckbot.json. Provided by Duck Duck Go, Inc.: [Terms of service](https://duckduckgo.com/terms), [Privacy policy](https://duckduckgo.com/privacy).
* **Cloudflare** IP ranges, to read the real visitor IP only from Cloudflare. Downloaded once a day only when "Real visitor IP" reads the CF-Connecting-IP or X-Forwarded-For header and "Trust Cloudflare addresses" is on, from https://api.cloudflare.com/client/v4/ips. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Bunny CDN** edge server addresses, to read the real visitor IP and country only from Bunny CDN. Downloaded once a day only when "Trust Bunny CDN addresses" is on and "Real visitor IP" reads the X-Real-IP or X-Forwarded-For header, or country rules are set (3.13.0: also, at most once an hour, when a request comes from a Bunny edge not in the list yet), from https://bunnycdn.com/api/system/edgeserverlist and https://bunnycdn.com/api/system/edgeserverlist/IPv6. Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).
* **OpenAI** bot IP ranges (OAI-SearchBot, ChatGPT-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://openai.com/searchbot.json and https://openai.com/chatgpt-user.json. Provided by OpenAI: [Terms of use](https://openai.com/policies/terms-of-use/), [Privacy policy](https://openai.com/policies/privacy-policy/).
* **Perplexity** bot IP ranges (PerplexityBot, Perplexity-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://www.perplexity.com/perplexitybot.json and https://www.perplexity.com/perplexity-user.json. Provided by Perplexity AI, Inc.: [Terms of service](https://www.perplexity.ai/hub/legal/terms-of-service), [Privacy policy](https://www.perplexity.ai/hub/legal/privacy-policy).
* **Anthropic** bot IP ranges (Claude-SearchBot, Claude-User), to tell the real bots from fakes. Downloaded once a day only when "Allow AI search engines and assistants" and "Verify AI search bots" are on, from https://claude.com/crawling/bots.json (3.10: plus Anthropic's published outbound range 160.79.104.0/21, built in, nothing downloaded). Provided by Anthropic PBC: [Terms of service](https://www.anthropic.com/legal/consumer-terms), [Privacy policy](https://www.anthropic.com/legal/privacy).
* **DB-IP Lite** country database, to apply the country rules. Downloaded once a month only when "Download the free country database" is on, from https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz (the current or the previous month). Lookups happen on your server. Licensed under CC BY 4.0 ("IP Geolocation by DB-IP"). Provided by db-ip.com: [Terms of service](https://db-ip.com/tos.php), [Privacy policy](https://db-ip.com/privacy.php), [License](https://creativecommons.org/licenses/by/4.0/).

The five data center lists below are used only for the "Data center limit" (Bots and limits), a stricter page limit for visitors that come from cloud servers rather than from home or mobile connections. Each one is downloaded once a day only while protection is enabled and "Data center limit" is above 0 (set it to 0 to turn the lists off). They are JSON or CSV data files fetched by your server with wp_remote_get(); nothing from these hosts is ever loaded in your visitors' browsers.

* **Amazon Web Services** IP ranges (only the EC2 servers are used), from https://ip-ranges.amazonaws.com/ip-ranges.json. Provided by Amazon Web Services, Inc.: [Terms](https://aws.amazon.com/service-terms/), [Privacy policy](https://aws.amazon.com/privacy/).
* **Google Cloud** IP ranges, from https://www.gstatic.com/ipranges/cloud.json, the address where Google publishes the list. Provided by Google LLC: [Terms of service](https://policies.google.com/terms), [Privacy policy](https://policies.google.com/privacy).
* **Oracle Cloud** IP ranges, from https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json. Provided by Oracle Corporation: [Terms of use](https://www.oracle.com/legal/terms/), [Privacy policy](https://www.oracle.com/legal/privacy/).
* **DigitalOcean** IP ranges, from https://digitalocean.com/geo/google.csv. Provided by DigitalOcean, LLC: [Terms of service](https://www.digitalocean.com/legal/terms-of-service-agreement), [Privacy policy](https://www.digitalocean.com/legal/privacy-policy).
* **Akamai Cloud (Linode)** IP ranges, from https://geoip.linode.com/. Provided by Akamai Technologies, Inc.: [Terms of service](https://www.akamai.com/legal/msa), [Privacy policy](https://www.akamai.com/legal/privacy-statement).

Lockdown's file check also compares WordPress and the plugins hosted on WordPress.org with their official checksums. This happens when you lock the site or press "Check now" on the Lockdown tab, and then at most once a day while the site stays locked, through the same WordPress.org services WordPress itself uses for updates. The requests contain the WordPress version and language (https://api.wordpress.org/core/checksums/1.0/) and, for each installed plugin, its slug and version (https://downloads.wordpress.org/plugin-checksums/SLUG/VERSION.json); no other data about your site, your content or your visitors is sent. Provided by WordPress.org: [Privacy policy](https://wordpress.org/about/privacy/).

**CrowdSec blocklist (3.7, off by default).** Only when you turn it on, ScrapeLock downloads a list of IP addresses from the address you enter, with the key you enter, and checks visitors against it on your server. No data about your site's visitors is sent; the request carries only your key (in the X-Api-Key header, or as HTTP Basic authentication) and the User-Agent "ScrapeLock/version".

* **Your own CrowdSec agent (LAPI)**, usually on the same server (for example http://127.0.0.1:8080): every 15 minutes, GET /v1/decisions/stream. The agent itself is CrowdSec software you install and run; whether it exchanges data with CrowdSec's central service is set in the agent. CrowdSec is provided by CrowdSec SAS: [Terms of use](https://www.crowdsec.net/terms), [Privacy policy](https://www.crowdsec.net/privacy-policy).
* **A blocklist address** you choose, for example a CrowdSec Console blocklist integration (https://admin.api.crowdsec.net/…) or another provider's plain-text list: downloaded once an hour. The provider is the one you choose; their terms and privacy policy apply.

Optional blocking at the CDN (off by default) uses the API of the CDN you choose, with your token. It sends only the IPs ScrapeLock blocks temporarily (IPv4, IPv6 or an IPv6 /64), each with the reason and end time, and removes them when the block ends. Saving the setting, or "Test connection", checks the token and the zone; with Cloudflare it also adds a test block for a documentation address (203.0.113.x) and removes it again.

* **Cloudflare API** (IP Access rules of your zone), only when the CDN is set to Cloudflare: https://api.cloudflare.com/client/v4/zones/ZONE_ID/firewall/access_rules/rules, and for the check https://api.cloudflare.com/client/v4/user/tokens/verify (or /accounts/ACCOUNT_ID/tokens/verify) and /zones/ZONE_ID. Provided by Cloudflare, Inc.: [Terms of service](https://www.cloudflare.com/website-terms/), [Privacy policy](https://www.cloudflare.com/privacypolicy/).
* **Bunny CDN API** (blocked IPs of your Pull Zone), only when the CDN is set to Bunny CDN and, for the temporary blocks, "Send temporary blocks to the CDN" is on (3.9): https://api.bunny.net/pullzone/PULL_ZONE_ID (addBlockedIp, removeBlockedIp, and reading the zone's list of blocked IPs). Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).

**Bunny CDN, deeper (3.8, off until you use it).** With the Bunny CDN connection of "Blocking at the CDN" (or a pull zone ID and API key entered in the Bunny card), and your API key:

* **Bunny CDN logging API (logging.bunnycdn.com)** – only when "Import attacks from Bunny CDN's logs" is on: every 15 minutes the site downloads the new lines of its own pull zone's log, from https://logging.bunnycdn.com/DATE/PULL_ZONE_ID.log. Nothing about your visitors is sent; the log Bunny returns contains your visitors' IPs, addresses asked for, referrers, User-Agents and countries. Only attack-looking lines are kept, unless Traffic collects (3.12): then every line is kept in your own database for the days you choose. Provided by BunnyWay d.o.o. (bunny.net): [Terms of service](https://bunny.net/tos/), [Privacy policy](https://bunny.net/privacy/).
* **Bunny CDN API (api.bunny.net)** – when Bunny CDN is connected: reads the pull zone (GET https://api.bunny.net/pullzone/PULL_ZONE_ID: logging status, Edge Rules); when you click "Lock at Bunny" or "Turn on logging at Bunny" it creates, updates or deletes Edge Rules made by ScrapeLock (POST /pullzone/PULL_ZONE_ID/edgerules/addOrUpdate, DELETE /pullzone/PULL_ZONE_ID/edgerules/RULE_ID: URL or User-Agent patterns, a description starting with "ScrapeLock:", and for the login page the IPs and ranges listed under "Allowed IPs for the login page at Bunny", the exact IP of the administrator who locked it and the server's own addresses) or turns logging on (POST /pullzone/PULL_ZONE_ID). "Send the secret from Bunny" (3.13.0) makes an Edge Rule that adds your CDN shared secret to the requests Bunny sends to your server (header X-ScrapeLock-CDN): only with it are Bunny's real-IP header and new Bunny edges trusted. Purges (3.13.0: after a change of Stealth or the watermark, at most once every 10 minutes; and `wp scrapelock cdn purge`): POST /pullzone/PULL_ZONE_ID/purgeCache, or POST /purge?url=ADDRESS for this site's addresses. Same provider and terms as above.

Vulnerable points and Stealth (3.8) only request the site's own pages and files, from the site itself (loopback), to check what a visitor gets. The weekly attack report and the sign-in protection's emails go through the site's own wp_mail().

If a list has not been downloaded, ScrapeLock verifies search engine bots with reverse DNS, and uses a built-in copy of the Cloudflare ranges. AI search bots are not verified until their list has been downloaded. Reverse DNS lookups are made only for requests that claim to be a search engine, through your server's own DNS resolver.

If the official Cloudflare plugin is active, ScrapeLock asks it to purge its cache when you save the ScrapeLock settings. The request is made by the Cloudflare plugin, with the account you connected there; ScrapeLock itself does not contact Cloudflare for this and stores no Cloudflare credentials.

== Installation ==

1. Upload the `scrapelock` folder to `/wp-content/plugins/`, or install the plugin from the Plugins screen.
2. Activate it. A new install runs in Monitor only for 7 days: watch the Log, then let it block.
3. If your site is behind Cloudflare or another proxy, set "Real visitor IP" first (Bots and limits).
4. Go to Settings → ScrapeLock and choose a preset, or adjust each tab.

Upgrading from "Content Protect" (folder `content-protect`), the former name of this plugin: deactivate the old plugin, activate ScrapeLock. Your settings, tokens and log are kept. If you pasted the old Apache rules, replace the "# BEGIN Content Protect" block with the new "# BEGIN ScrapeLock" block.

== Frequently Asked Questions ==

= My server's CPU spikes, often at night. Can ScrapeLock help? =

Often, yes: the cause is usually a crawler reading thousands of pages. Open the Log: the 24-hour summary shows the top IPs, User-Agents and reasons. The bot list, the per-IP limits and the data center limit handle most of it; during an attack, start Emergency Mode.

= GPTBot or Bytespider is eating my bandwidth. =

They are on the bot list, which is on by default, and are refused with a 403 (in Monitor only they are just logged). robots.txt also asks them to stay away. A 403 costs your server far less than a full page.

= Bots fill carts or try coupon codes. =

With WooCommerce, ScrapeLock limits cart actions and coupon attempts per IP and blocks IPs that keep going. It is not a fraud or card-testing tool: use your payment provider's fraud protection for that.

= Will it block real visitors, shoppers or forms? =

Verified search engines are never limited or blocked, there is no captcha, and the first 7 days are Monitor only. If someone is blocked, the Log shows why: unblock the IP under "IPs blocked now", add it to "Always allowed IPs", or press "Always allow this User-Agent".

= Will it block Google or Bing? =

No. Verified search engines are never limited or blocked. Only fakes that pretend to be Googlebot or Bingbot are blocked.

= Can I allow ChatGPT or Perplexity search but block training? =

Yes. Turn on "Allow AI search engines and assistants" (Bots and limits). Training crawlers stay blocked. With "Verify AI search bots" on, only requests from the official addresses count as those bots; copies of the name get a 403. Turn the option off and ScrapeLock blocks them again from its own list, whether or not they are in your bot list.

= Can it stop screenshots or screen recording? =

No plugin can: the phone or computer takes the screenshot itself. ScrapeLock can blur the page on known screenshot keys, put the reader's user name and time over protected pages, and hide an invisible trace of the account in copied text (On the page → Members and readers).

= I can still right-click and copy. Is it working? =

Probably: staff are exempt while logged in ("Who is excluded", On the page tab). Test in a private window ("Check a request" tests the server-side checks, not the browser scripts). Right-click, copy, print and devtools blocking are deterrents for casual copying: the text is still in the page source.

= How do I test it? =

"Check a request" (Log tab) shows what ScrapeLock would answer to GPTBot, a fake Googlebot, curl and more, without sending anything. Its "Check it yourself" lines test for real with curl from another computer.

= Does it work with page cache? =

WP Rocket does not serve cached pages to listed bots. For other page caches turn on the pre-cache check (Bots and limits): on cached pages it applies the bot list, blocks, the page, network and human-check limits, fake Googlebot / Bingbot (with fresh official lists) and headless browsers; not "Browsers only", countries, data centers, reputation or the trap. A cache in the web server (Nginx FastCGI cache, LiteSpeed, Varnish) answers before PHP: use the "Server rules" tab or the CDN.

= My site is behind Cloudflare. What should I set? =

Set "Real visitor IP" to CF-Connecting-IP and keep "Trust Cloudflare addresses" on. With Nginx, also set `real_ip_header CF-Connecting-IP;` and `set_real_ip_from` for the Cloudflare ranges, so the server rules see the real IP.

= My site is behind Bunny CDN. What should I set? =

"Real visitor IP" X-Real-IP, "Trust Bunny CDN addresses" on, then "Send the secret from Bunny" in the Bunny card. Without the secret anyone's pull zone can write X-Real-IP: those IPs stay unreliable (no bans or CDN blocks; no login lock at Bunny).

= What personal data does it store? =

For a blocked request: the IP, User-Agent, page and time, deleted after 1, 7 or 30 days (over a per-account limit, also the username). The attack record keeps the IP, the address asked for, the hour and, for a failed sign-in, the username tried, for 7 to 90 days. The optional features keep only hashes or a signed expiry. No visitor data is sent anywhere by default. The full list is in the user guide.

= I lost my phone. How do I unlock the site? =

Type a recovery code instead of an app code. With none left, add `define( 'SCRAPELOCK_UNLOCK', true );` to wp-config.php (over SSH: `wp config set SCRAPELOCK_UNLOCK true --raw --type=constant`), connect a new app on the Lockdown page, then remove the line (also for a forgotten staff password). If another plugin or the theme keeps you out of wp-admin while locked, unlock at wp-login.php?action=scrapelock-unlock.

= Where are the other answers? =

CDN setups (Cloudflare, Bunny CDN), the server rules and aaPanel, the pre-cache and early checks, Stealth, Lockdown, WP-CLI, the filters for developers and more: see the [user guide](https://github.com/Code-BunnyHUB/ScrapeLock-WP/blob/main/docs/user-guide.md).

== Screenshots ==

1. Overview: protection status, blocked requests in the last 24 hours, the tab groups, one-click presets and Emergency Mode.
2. For my site: detects the shop, cache plugin, CDN and web server and suggests matching settings; only the ticked ones are applied.
3. On the page: right click, copy shortcuts, dragging images and text, screenshot blur, copying with the source link appended, and printing.
4. Members and readers: a faint “who is reading” mark over protected pages, an invisible trace in copied text, per-account limits and shared-account alerts, plus iframe and AI opt-out (TDM) headers.
5. Scrapers and bots: the bot list, requests without a User-Agent, fake Googlebot and Bingbot, headless browsers, the bot trap and bans for scanners.
6. AI search and training: AI search assistants may visit (checked against their official IP lists) while AI training crawlers stay blocked; robots.txt and Content Signals.
7. Limits per IP for pages, searches, the REST API, “page not found”, sitemaps and data centers, automatic Emergency Mode, and the reputation of each IP.
8. Check a request: what ScrapeLock would answer to any IP, User-Agent and address, here a fake Googlebot.
9. Feeds and API: an access token for private XML feeds with per-feed statistics, and post text hidden from the REST API, GraphQL and RSS.
10. Vulnerable points: XML-RPC, the file editor, usernames, PHP files and more, each with its attacks and the risk of locking it; lock with one click.
11. Lockdown: freezes plugins, themes, users and settings behind a code from an authenticator app, with what is locked and what keeps working.
12. Server rules: Cloudflare and Apache rules (Nginx further down) generated for your own site.
13. Bunny CDN: the Edge Rules ScrapeLock manages at Bunny, and the points that can be locked at the edge with one click.
14. Log: blocked requests in the last 24 hours by reason, and the top IPs.
15. Log: IPs blocked now, IPs that keep coming back, and the latest events with path and User-Agent.
16. Visitors sent by AI assistants (ChatGPT, Perplexity, Gemini…) in the last 30 days, and the pages they landed on.
17. Attack report: attacks per day, failed sign-ins, the share refused, and each kind of attack with how to close it.
18. Traffic: every request the site answered, per hour, by status code, by kind of visitor and by User-Agent.
19. Dashboard widgets: the protection status and the attacks of the last 7 days.
20. Site Health: ScrapeLock’s checks, e.g. password guessing and attacked points that are still open.

== Changelog ==

= 3.13.0 =
* Lockdown never locks the administrator out of wp-admin: after signing in while locked you land on the Dashboard, your profile opens read-only, a new unlock screen at wp-login.php?action=scrapelock-unlock works even when another plugin keeps locked users out of wp-admin, and every way back in (recovery code, SCRAPELOCK_UNLOCK in wp-config.php) is shown where you need it. The frozen actions stay frozen.
* Security: fixes a replayable self-signature that could make an address "the server's own", a CrowdSec key that followed a changed address, cross-site trap bans on old browsers, floods of unlock emails, and real crawlers refused when the DNS check budget ran out.
* Bunny CDN: the wp-login lock can no longer be bypassed through its own exception; server rules for "Only through the CDN" now cover the Nginx cache; new edges are never banned; safer log import; optional blocking of AI bots at the edge and a one-click CDN secret.
* Bots: payment webhooks are never blocked (also in Emergency Mode); fake Google/Bing caught on cached pages; browser header checks; limits per network (/24, /48); a harder human check for suspicious clients; new AI crawlers; plainer wording of what is stopped.

= 3.12.13 =
* Plugin Check: 0 errors and 0 warnings. `wp scrapelock rules install` runs the server's test and reload commands through WP-CLI's own runner instead of starting a process itself; the traffic and report queries pass every value through prepared statements; the translations load without load_plugin_textdomain() (a language pack still comes first, also on WordPress 6.2 to 6.6); temporary file names use PHP's random_bytes(); the readme is shorter, with the full feature list and the other answers in the user guide and the older changes in changelog.txt.
* Nothing changes for visitors or in the settings, and the server rules stay the same.

= 3.12.12 =
* Fix: after "Upload Plugin", the "Activate Plugin" button of 3.12.11 pointed at the Lockdown guard file (includes/lockdown-guard.php) instead of scrapelock.php, and activating ended in "The plugin does not have a valid header." The guard file now sits where WordPress does not look for plugins (includes/lockdown/guard.php). Activating from the Plugins list or with WP-CLI was not affected. A guard already in mu-plugins is refreshed on the update.

= 3.12.11 =
* Fix: host malware scanners (for example SiteGround's Site Scanner) flagged ScrapeLock's files and could quarantine them. ScrapeLock no longer writes any PHP file while the site runs: the check of "PHP in the uploads folder" asks the server for an address that does not exist instead of writing a test file there, and the temporary copies of wp-config.php and of the early check are no longer .php files. The lines in wp-config.php and the early check's file in mu-plugins are plain, commented loaders of the plugin's own files.
* Lockdown: the guard in mu-plugins is now a fixed file shipped with the plugin (the same on every site), and Lockdown keeps its data in JSON files, with the copy of the protected settings encrypted. Sites on 3.12.10 are converted automatically on the update; a locked site stays locked.
* The lists of attack patterns (web shell names, injection patterns, probe addresses) no longer read as malware to these scanners, and match exactly the same requests as before. With "Block technology profilers" on, the server rules and the pre-cache check's data no longer spell out a security company's name that scanners take for a phishing kit (the same bots are blocked); if you copied ScrapeLock's server rules by hand, the Server rules tab tells you when to copy them again.
* A visitor's request is unchanged: with APCu or Redis still no file access and no query of ScrapeLock.

The changes of 3.12.10 and earlier versions are in changelog.txt in the plugin folder.

== Upgrade Notice ==

= 3.13.0 =
Recommended: Lockdown no longer locks administrators out of wp-admin, security fixes, safer Bunny CDN rules, and payment webhooks are never blocked. Settings kept; new options start off on existing sites.

= 3.12.13 =
Passes the WordPress.org Plugin Check with no errors or warnings. No change in what ScrapeLock does: settings and server rules unchanged.

= 3.12.12 =
Fixes "The plugin does not have a valid header." when activating ScrapeLock 3.12.11 right after uploading it. Settings kept.

= 3.12.11 =

Recommended on hosts that scan files for malware (SiteGround and others): ScrapeLock no longer writes PHP files at runtime; Lockdown is converted on its own and stays locked. If your host quarantined ScrapeLock's files, restore them or reinstall, then ask for a new scan. Settings kept.

= 3.12.10 =
Fixes the site going down after a WP-CLI command run as root changed ScrapeLock's settings (wp-config.php became root's). Files keep their owner and permissions; run WP-CLI as the site's user when you can. Settings and server rules unchanged.

= 3.12.9 =

Recommended: APCu for PHP-FPM or a Redis object cache, so a visit never touches the disk or the database. ScrapeLock updates the pre-cache line in wp-config.php itself (or copy it from Settings). New: `wp scrapelock precheck` and `wp scrapelock breaker`. Settings kept.

= 3.12.8 =

After updating, copy the Stealth rules again (Server rules, Stealth, nginx -t, reload) or run `wp scrapelock rules install --stealth=<file>`, then `wp scrapelock stealth test` and `wp scrapelock cdn purge --all --minify --yes`. Settings kept.

= 3.12.7 =

With an Nginx fastcgi cache: run `wp scrapelock cache status`, add the line it prints to wp-config.php (or set Nginx Helper's folder), then `wp scrapelock cache purge --all`. Server and Stealth rules unchanged. Settings kept.

= 3.12.6 =

Copy the server and Stealth rules again (Server rules tab, then nginx -t and reload) or use `wp scrapelock rules install`: the Stealth rules now carry a fingerprint and cover WP Rocket's minified files. "Block technology profilers" starts off. Settings kept.

= 3.12.5 =
The screenshot blur can now apply only to visitors who are not signed in (On the page → Applies to). Existing sites keep "Everyone". Settings are kept.

= 3.12.4 =
Nginx: copy part 2 of the server rules again (Settings → ScrapeLock → Server rules), then nginx -t and reload: it now answers the status check before aaPanel's server-level WordPress rewrite. The fingerprint is unchanged. Settings are kept.

= 3.12.3 =
After updating, copy the server rules again from Settings → ScrapeLock → Server rules (Nginx: both parts, then nginx -t and reload; Apache: the .htaccess block): the new rules never block the server's own requests. Settings are kept.

= 3.12.2 =
Fixes Vulnerable points "Check again" and Site Health behind Bunny CDN without "Forward Host Header", and says who refuses the site's own requests (Bunny, Cloudflare, Wordfence, the web server). Settings are kept.

= 3.12.1 =
Fixes the site's own requests getting a 403 behind a CDN (Vulnerable points, Site Health), FluentCommunity members' limits and AI search blocking. The pre-cache check's line in wp-config.php is rewritten on the next wp-admin page. Settings are kept.

= 3.12.0 =
New Traffic tab: every request from the Bunny CDN logs, the access log or WordPress, with User-Agents, problem URLs, visitors, CSV and email alerts. Off until you press "Start collecting"; nothing is stored or scheduled before. Settings and exports from 3.11 are kept.

= 3.11.0 =

Fewer false blocks (the site's own requests through the CDN, /.well-known/, static files, plugin service bots, allowed AI search bots), a "For my site" assistant and grouped tabs. Settings kept; with "Allow AI search" on, its bots leave the bot list once (a copy is saved).

= 3.10.1 =
Site Health can create a missing apple-touch-icon.png and OneSignalSDKWorker.js with one click, and checks that Wordfence reads the visitor's address behind the CDN.

= 3.10.0 =

Locks at Bunny with more than 5 addresses (such as "Secret files") now work with the real Bunny API. Fewer false blocks of Google, Apple, DuckDuckBot, WP Rocket and Claude-User; site-metadata files no longer count as attacks.

= 3.9.1 =
Fixes for the lock of wp-login.php at Bunny: the allowed IPs can no longer be emptied while the lock is on, and changes reach Bunny at once.

= 3.9.0 =

New "Send temporary blocks to the CDN" switch: off on new installs, kept on for sites that already send them (a notice says so). Every lock at Bunny now asks for a Confirm first; wp-login.php needs your IP in "Allowed IPs for the login page at Bunny".

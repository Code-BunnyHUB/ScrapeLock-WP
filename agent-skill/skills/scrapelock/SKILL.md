---
name: scrapelock
description: Protect a WordPress site from AI training crawlers (GPTBot, ClaudeBot, CCBot, Bytespider), content scrapers and fake Googlebot/Bingbot with the free ScrapeLock plugin, using WP-CLI. Use when the user wants to block AI bots or scrapers on WordPress, stop content copying, rate-limit bots, catch fake search engine crawlers, handle a scraping attack, or install, configure, check or troubleshoot ScrapeLock.
---

# ScrapeLock for WordPress

ScrapeLock is a free WordPress plugin (wordpress.org/plugins/scrapelock) that stops scrapers and AI crawlers on the server: AI training bots, fake Googlebot/Bingbot (checked against the official IP lists and DNS), per-IP rate limits, Emergency Mode, hardening of attacked points, and optional server rules. Everything is driven here through its WP-CLI command, `wp scrapelock`.

The full command reference is in [reference.md](reference.md). Read it before using any command not shown below.

## Before you start

1. Find how to reach the site. You need WP-CLI against the WordPress install: in its folder (`wp core version`), with `--path=<dir>`, over SSH (`wp --ssh=user@host/path`), or inside a container (`docker compose exec wordpress wp ...`). If none works, stop and tell the user what you need (shell access with WP-CLI). Do not guess at production servers.
2. Ask which site it is, and whether it is production or staging, before changing anything.
3. Check requirements: WordPress 6.2+, PHP 7.4+ (`wp core version`, `wp eval 'echo PHP_VERSION;'`).

## Install

```bash
wp plugin install scrapelock --activate
wp scrapelock status
```

A new install starts in **Monitor only** for 7 days: nothing is blocked, requests that would be refused are logged as "Would block". Tell the user this. It is the safe default; do not turn it off unless the user asks.

## Set up for this site

1. Let the built-in assistant inspect the site (plugins, CDN, server) and list its proposals. Nothing changes yet:
   ```bash
   wp scrapelock wizard
   ```
2. Show the user the proposals in plain words. Then apply only the safe ones (those that block nothing more), or exactly the ones the user picked:
   ```bash
   wp scrapelock wizard --apply --yes
   wp scrapelock wizard --apply --only=trust_bunny,precheck --yes
   ```
   `--all` also applies proposals that block more. Use it only when the user agrees to each of them.
3. Behind Cloudflare, Bunny CDN or a reverse proxy, the real visitor IP must be read correctly, otherwise everyone shares the proxy's IP. Check `ip_header`, `trust_cloudflare`, `trust_bunny`, `trusted_proxies` with `wp scrapelock settings get <name>`; the wizard usually proposes the right values.

## Common requests

**"Block AI training bots but keep AI search (ChatGPT search, Perplexity, Claude search)"**
```bash
wp scrapelock settings set allow_ai_search 1 --dry-run
wp scrapelock settings set allow_ai_search 1
wp scrapelock settings get verify_ai_bots     # 1 = the AI search bots are checked against their official IP lists
```
AI training crawlers are blocked by `block_bots` (on by default) and disallowed in robots.txt by `robots_ai_block`.

**"Is it working?"** Ask ScrapeLock what it would answer, without counting, logging or blocking anything:
```bash
wp scrapelock check --ip=203.0.113.5 --ua="GPTBot/1.2"
wp scrapelock check --ip=203.0.113.5 --ua="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"   # fake Googlebot: should be refused
wp scrapelock check --ip=66.249.66.1 --ua="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"   # real Google IP: allowed
wp scrapelock check --ip=198.51.100.7 --ua="Mozilla/5.0 (Windows NT 10.0) Firefox/128.0" --browser                     # normal visitor: allowed
wp scrapelock selfcheck
```
Run `check` without `--user`, which may exempt that account. Report the result for each case in plain words.

**"What has it blocked?"**
```bash
wp scrapelock log --limit=50
wp scrapelock log --top --hours=168
wp scrapelock ai-referrals          # visits sent by AI assistants
wp scrapelock attacks --days=7
```

**"We are being scraped right now"**
```bash
wp scrapelock log --top --hours=1
wp scrapelock emergency on --hours=6      # stricter limits, returns to normal on its own
wp scrapelock block <ip> --minutes=1440   # a single obvious offender
```
Before blocking an IP, check it is not the user's own, a CDN edge, or a real search engine (`wp scrapelock check --ip=<ip> --ua=<its UA>` and `wp scrapelock reputation <ip>`).

**"A real visitor / my own IP / a service is blocked"**
```bash
wp scrapelock check --ip=<ip> --ua="<its user agent>"   # explains which rule refuses it
wp scrapelock unblock <ip>
wp scrapelock login unlock <ip-or-username>
wp scrapelock settings get allow_ips
```
To always allow an IP, add it to `allow_ips` (one per line, `\n` between lines; `get` it first and keep the existing entries).

## Changing settings safely

- Read first: `wp scrapelock settings get <name>`; all names: `wp scrapelock settings get`.
- Preview: add `--dry-run` to `settings set` and `settings import`, and show the user what changes.
- Every change keeps the previous settings (last 5). If something goes wrong: `wp scrapelock settings undo`.
- Before a larger change, export: `wp scrapelock settings export --file=scrapelock-backup.json` (secrets are left out).

## Do not do without the user's explicit yes

- Turn off Monitor only (`settings set monitor_mode 0`) during the first days, or turn protection off (`enabled`).
- `wizard --apply --all`, `harden apply-low`, `harden apply <id>` (some points break Jetpack or the mobile app; `harden list` says what may stop working).
- `rules install` (writes Nginx/Apache files and reloads the server): always run it with `--dry-run` first and show the diff.
- `stealth on`, `bunny lock`, `cdn purge --all`, `unblock --all`, `crowdsec` changes.
- Lockdown cannot be opened from WP-CLI (only the authenticator app or `SCRAPELOCK_UNLOCK` in wp-config.php). Only `lockdown status` is available; never try to work around it.

## Limits to tell the user

ScrapeLock closes the automated routes. It cannot stop a person copying by hand or taking screenshots; it leaves traces instead (watermarks, a source link on copied text, a TDM rights reservation). No visitor data leaves the server by default.

If a command is missing, the installed version is older: `wp plugin update scrapelock`. Help: `wp help scrapelock <command>`. User guide: https://github.com/Code-BunnyHUB/ScrapeLock-WP/blob/main/docs/user-guide.md

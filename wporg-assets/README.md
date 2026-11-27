# Images for the WordPress.org page

They go into the `assets/` folder of the plugin's SVN repository (not into the zip and not into `trunk/`).

| File | Use |
|---|---|
| `icon-128x128.png`, `icon-256x256.png`, `icon.svg` | Icon in search results and the plugin list |
| `banner-772x250.png`, `banner-1544x500.png` | Banner at the top of the plugin page |
| `screenshot-1.png` … `screenshot-20.png` | Screenshots (ScrapeLock 3.12.12); the captions are in the "== Screenshots ==" section of `readme.txt`, in the same order |

Sources are in `src/`: `icon.svg` and `banner.html`. The PNGs are rendered with headless Chromium (256×256 and 1544×500 screenshots) and resized with `convert -resize`.

## How the screenshots are made

- A throwaway test WordPress site ("Demo Store", English admin, SQLite, PHP's built-in server, WP-CLI) with the plugin from this repository, served as `store.example.com`. Update checks and core Site Health checks that only concern the test server are switched off, and only the ScrapeLock dashboard widgets are shown.
- Demo data only: documentation IP addresses (192.0.2.x / 198.51.100.x / 203.0.113.x, 2001:db8::/32) and example.com / example.org names. Live entries come from real HTTP requests to the site (bots, a fake Googlebot, scanners, the bot trap, failed sign-ins, a page-limit burst, AI-assistant referrers); the history of the attack record, the AI referrals and Traffic is written with WP-CLI. The Bunny CDN card talks to a stand-in Bunny API, and "For my site" is shown as it reads a shop with WooCommerce, WP Rocket, Yoast SEO, Nginx and Bunny CDN.
- Captured with Playwright (headless Chromium, 1280 px wide viewport, device scale factor 1). Each image is the WordPress admin cropped to one card or section, with the other cards of the tab hidden; the admin-bar avatar is hidden and the random key suggested on the Lockdown tab is masked.
- Optimised with `pngquant --quality=80-95` and `optipng -o2`.

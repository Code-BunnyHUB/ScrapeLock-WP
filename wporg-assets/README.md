# Images for the WordPress.org page

They go into the `assets/` folder of the plugin's SVN repository (not into the zip and not into `trunk/`).

| File | Use |
|---|---|
| `icon-128x128.png`, `icon-256x256.png`, `icon.svg` | Icon in search results and the plugin list |
| `banner-772x250.png`, `banner-1544x500.png` | Banner at the top of the plugin page |
| `screenshot-1.png` … `screenshot-6.png` | Screenshots; the captions are in the "== Screenshots ==" section of `readme.txt` |

Sources are in `src/`: `icon.svg` and `banner.html`. The PNGs are rendered with headless Chromium (256×256 and 1544×500 screenshots) and resized with `convert -resize`.

The screenshots come from a test WordPress site ("Demo Store") with documentation IP addresses (192.0.2.x / 198.51.100.x / 203.0.113.x).

# Caisson — Brand kit (marks & usage)

The marketing-facing marks. These are geometric, "serious," and built to read at any
size — the register the Caisson buyer (DoD programs, defense contractors, regulated
critical infrastructure) trusts. The color tokens are defined in
[`CHARACTER-SHEET.md`](CHARACTER-SHEET.md#color-palette--these-hexes-are-the-brand-tokens);
every mark here uses them.

## Marks

| File | What it is | Use it for |
|------|------------|------------|
| [`caisson-vault-logomark.svg`](caisson-vault-logomark.svg) | **Primary emblem** — a sealed gold payload locked across the airgap (cyan seam) between two steel bulkhead doors; encodes Caisson's job in one distinctive, monochrome-strong mark | App/site nav, **favicon**, GitHub avatar, decks, CLI, anywhere a single mark leads |
| [`caisson-logo-horizontal.svg`](caisson-logo-horizontal.svg) | **Horizontal lockup** — emblem + `CAISSON` wordmark + tagline | Site headers, slide masters, docs headers, email signatures, README banner |
| [`caisson-og-banner.svg`](caisson-og-banner.svg) / `.png` (1200×630) | **Social / OG card** — emblem, chrome wordmark, catchphrase, credibility line | Link previews (X, LinkedIn, Slack, GitHub social preview), blog headers |
| [`caisson-title-card.svg`](caisson-title-card.svg) | 16:9 title card with the chrome `CAISSON` wordmark | Video/deck title slide, hero art |

The **favicon** is the emblem — the gold payload locked between two bulkheads stays legible down to 16px, and the mark holds up in a single flat color (no gradients or glow needed).
The OG banner ships as both SVG (source) and a rendered **PNG** in `web/assets/`, because most
social scrapers don't render SVG. The site's `<head>` references the PNG via `og:image` /
`twitter:image`; **prefix those with the absolute site origin in production** (scrapers require
absolute URLs).

## Rendering

Marks are hand-authored SVG. To rasterize (e.g. regenerate the OG PNG or export for a deck):

```bash
# any width; SVG is resolution-independent
rsvg-convert -w 1200 -h 630 brand/caisson-og-banner.svg -o web/assets/caisson-og-banner.png
rsvg-convert -w 512 brand/caisson-vault-logomark.svg -o caisson-emblem-512.png
```

## Wordmark

`CAISSON`, all caps, heavy geometric sans (Arial Black / Helvetica Neue 900 / Impact stack in
the SVGs). For a production logo, outline the text so it renders identically without the font
installed. Pair with **Signal Cyan** for the tagline and **Vault Chrome** for the letters on
dark surfaces.

## The mascot

A cute character mascot (for community / dev-rel — stickers, Discord, GitHub) is intentionally
**not** in this kit: polished character illustration is best produced by an illustrator or an
image model. The full concept, style references, palette, and ready-to-run image prompts live in
[`mascot-brief.md`](mascot-brief.md) so it can be commissioned or generated to a marketing-grade
finish. Keep the character off the primary "trust" surfaces (landing hero, sales decks); use the
emblem there.

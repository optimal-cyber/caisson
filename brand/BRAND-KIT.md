# Caisson — Brand kit (marks, mascot & palette)

The Caisson brand marks. The emblem/wordmark are geometric and "serious" — the register the
buyer (DoD programs, defense contractors, regulated critical infrastructure) trusts — and the
mascot carries the warmth for community/dev-rel. Every mark uses the [palette](#color-palette)
tokens below.

## Marks

| File | What it is | Use it for |
|------|------------|------------|
| [`caisson-vault-logomark.svg`](caisson-vault-logomark.svg) | **Primary emblem** — a sealed gold payload locked across the airgap (cyan seam) between two steel bulkhead doors; encodes Caisson's job in one distinctive, monochrome-strong mark | App/site nav, **favicon**, GitHub avatar, decks, CLI, anywhere a single mark leads |
| [`caisson-logo-horizontal.svg`](caisson-logo-horizontal.svg) | **Horizontal lockup** — emblem + `CAISSON` wordmark + tagline | Site headers, slide masters, docs headers, email signatures, README banner |
| [`caisson-og-banner.svg`](caisson-og-banner.svg) / `.png` (1200×630) | **Social / OG card** — emblem, chrome wordmark, catchphrase, credibility line | Link previews (X, LinkedIn, Slack, GitHub social preview), blog headers |
| [`caisson-mascot.jpg`](caisson-mascot.jpg) | **Mascot art** — the Caisson otter poster ("Airgap. Secure. Simple.") | README banner, site hero, community/dev-rel, stickers, swag |

The **favicon** is the emblem — the gold payload locked between two bulkheads stays legible down
to 16px, and the mark holds up in a single flat color (no gradients or glow needed). The OG
banner ships as both SVG (source) and a rendered **PNG** in `web/assets/`, because most social
scrapers don't render SVG. The site's `<head>` references the PNG via `og:image` /
`twitter:image`; **prefix those with the absolute site origin in production** (scrapers require
absolute URLs).

## The mascot

The current mascot is the **otter** in [`caisson-mascot.jpg`](caisson-mascot.jpg) (a raster
image). It's a friendly, airgap-proud character for community and dev-rel surfaces — keep it off
the primary "trust" surfaces (sales decks, product chrome), where the emblem leads.

To evolve or re-commission the mascot to a cleaner, vector/marketing-grade finish, use
[`mascot-brief.md`](mascot-brief.md) — a production brief with style references, palette, and
copy-paste image-model / illustrator prompts. Polished character illustration is best produced by
an illustrator or an image model rather than hand-authored SVG.

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

## Color palette

These hexes ARE the brand tokens; the site's design tokens (`web/styles.css`) are lifted from
them. Cyan + Gold carry the brand; Violet is background-only at low opacity.

### Neutrals / structure
| Token        | Hex        | Role |
|--------------|------------|------|
| Abyss        | `#060912`  | Deepest background / the denied deep |
| Deep Hull    | `#0C1122`  | Primary page background |
| Bulkhead     | `#151C36`  | Cards / surface panels |
| Steel Seam   | `#263156`  | Borders, dividers, armor mid-tone |
| Steel Plate  | `#3A4668`  | Armor plating |
| Vault Chrome | `#E7ECF7`  | Headings, chrome wordmark, light metal |
| Muted Steel  | `#96A2C2`  | Body text |

### Accents / signal — brand-carrying
| Token           | Hex        | Role |
|-----------------|------------|------|
| Signal Cyan     | `#37E1D6`  | **Primary accent** — CTAs, links, active seams |
| Provenance Gold | `#F4B23C`  | The seal / "verified / evidence" highlight |
| Ember Orange    | `#F5793B`  | Sunset endpoint / warm accent (sparingly) |
| Horizon Violet  | `#8B5CF6`  | **Background depth wash only, ≤12% opacity** |

### Semantic (compliance UI)
| Token          | Hex        | Role |
|----------------|------------|------|
| Verified Green | `#38D178`  | Attestation pass / control-satisfied ticks |
| Breach Red     | `#F0503C`  | Unsealed / tamper / fail state |

## Taglines

- **Catchphrase:** *"Nothing crosses the gap unsealed."*
- **Tagline:** *"Sealed at the source. Evidence on arrival."* (variant: *"Assessment-ready on arrival."*)
- **CLI no-args line:** *"If it isn't sealed, it isn't shipped."*
- ❌ Retired (overclaim — do not use): ~~"ATO on arrival"~~

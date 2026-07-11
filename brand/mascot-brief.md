# Caisson — Mascot brief (for an illustrator or image model)

A production-ready spec for a **cute, original creature mascot**. Hand-authored SVG can't reach
the polish this needs, so this brief exists to hand to an illustrator (Dribbble / Fiverr /
99designs) or an image model (Midjourney, GPT-image / DALL·E, Stable Diffusion). Copy-paste
prompts are at the bottom.

---

## 1. What it's for (and what it isn't)

- **Use:** community & developer-relations surfaces — GitHub org avatar, stickers, Discord/Slack
  emoji, swag, docs "tips," 404 pages, conference booth.
- **Not for:** the primary "trust" surfaces (landing hero, sales decks, the product UI). Those
  stay on the **vault emblem** (`caisson-vault-logomark.svg`). Caisson sells to DoD programs,
  defense contractors, and regulated critical-infrastructure teams; the emblem carries the
  gravitas, the mascot carries the warmth. Keep them in their lanes.

**Tone target:** *cute but competent.* Adorable enough to want as a sticker, never childish or
silly enough to undercut a security product. Think "friendly guardian of the deep," not "toy."

---

## 2. The character

- **Name:** Caisson (same as the product/brand).
- **Species:** an **original, fictitious creature** — invented, not a real animal and not a
  robot. It reads as a small, soft, deep-dwelling guardian sprite.
- **Backstory hook (informs the design, not literal):** Caisson lives in the **denied deep** —
  the disconnected dark on the far side of the airgap. It's the little courier that carries a
  sealed payload down where the light (and the network) doesn't reach, and guarantees it arrives
  intact. Bioluminescent, unbothered by pressure, quietly dependable.
- **Personality:** calm, warm, steadfast, a little stoic; the friend who always shows up and
  never drops what you handed it.

### Signature design cues (the silhouette)
1. **Big, glossy, expressive eyes** — real cartoon eyes with white highlight glints (NOT glowing
   solid lenses — that reads robotic).
2. **Soft, rounded, squishy body** — chunky and huggable, ~2–2.5 heads tall (kawaii proportions).
3. **Bioluminescent frill-fins** — soft, feathery fin/gill frills at the sides of the head that
   glow faintly **Signal Cyan** (an original silhouette, in the *spirit* of an axolotl's gills but
   not a copy).
4. **A curly, finned tail.**
5. **Little squishy paws** with soft toes/nubs.
6. **Brand tie (subtle, organic):** it **cradles a small glowing sealed orb** — "the vault" as a
   softly glowing cyan pearl/egg with a single hairline seam and a tiny gold glint. This is the
   *only* brand prop, and it must stay organic (a pearl/egg, **not** a hexagon, keyhole, panel,
   or gadget). Optional alt: faint gold "seal" freckle-markings instead of the orb.

---

## 3. Visual style

- **Reference vibe:** modern kawaii "sticker/plush" illustration — clean vector look, **bold,
  consistent, slightly-soft outlines** (deep indigo/navy, not pure black), **flat fills with
  smooth gradient shading**, gentle rim light, rosy cheek blush, a couple of floating bubbles.
  (The image the founder shared — a rounded kawaii axolotl in blues/lavenders with big glossy
  eyes and gill frills — is the *style* target. Do **not** reproduce that specific character.)
- **Finish:** crisp, poster-clean, printable on a sticker. Subtle depth, no photorealism, no
  heavy texture, no 3D render unless requested.
- **Line weight:** bold outer silhouette, lighter interior lines.

## 4. Palette (Caisson brand tokens)

| Role | Token | Hex |
|------|-------|-----|
| Body (soft aqua-teal) | derived from Signal Cyan | `#7CC7DA` → `#4E93B8` (gradient) |
| Belly / highlights | Vault Chrome tint | `#F1F8FC` → `#D3EEF2` |
| Frill glow / accents | **Signal Cyan** | `#37E1D6` |
| Sealed-orb glow | cyan → white | `#CFFFFB` core, `#37E1D6` edge |
| Seal glint / freckles | **Provenance Gold** | `#F4B23C` |
| Outline | deep indigo-navy | `#241E46` (not `#000000`) |
| Cheeks | soft rose | `#F79BB4` |
| Background (if any) | Abyss / Deep Hull | `#060912` → `#0C1122` |

Cyan + a touch of gold are the brand carry-throughs. Keep violet/lavender as a minor secondary at
most; don't let the palette drift to "unicorn."

## 5. Do / Don't

**Do:** original creature · soft organic shapes · big glossy eyes with highlights · sticker-clean
vectors · cyan bioluminescence · one subtle organic brand prop (glowing sealed orb) · transparent
background for the primary deliverable.

**Don't:** ❌ robot / mecha / cyborg / any metal panels, seams, bolts, antennae, or glowing-lens
eyes · ❌ hexagons, keyholes, padlocks, circuitry, or gadgets on the creature (those are the
*emblem's* job) · ❌ a recognizable real animal (axolotl, badger, otter, cat…) or any existing
IP/Pokémon-style trade dress · ❌ weapons or anything "military" · ❌ baked-in text/wordmarks ·
❌ busy backgrounds on the primary cutout.

## 6. Deliverables

1. **Hero pose** — front ¾, standing/floating, cradling the glowing sealed orb, warm smile.
   Transparent background. This is the master.
2. **Avatar crop** — head-and-shoulders, centered, legible at **48px** (GitHub/Discord).
3. **Expression sheet** — 4–6 faces: happy, focused, sleepy/😴 ("airgapped"), success ✓,
   surprised, waving.
4. **A few poses** — waving, carrying the orb across a "gap," giving a thumbs-up / paw-up,
   curled up asleep around the orb.
5. **Formats:** layered source (AI/SVG/PSD) + transparent PNGs at 512 / 1024 / 2048, plus a flat
   sticker version with a white keyline.
6. **Consistency:** same creature, proportions, and palette across every asset.

---

## 7. Copy-paste prompts

> Iterate: generate 4, pick the closest, then re-prompt with tweaks. Always keep the negative
> list. Remove background with the tool's transparent/cutout option or a bg-removal pass.

### Midjourney (v6/v6.1)
```
kawaii original creature mascot, a small soft deep-sea guardian sprite, big glossy expressive
eyes with white highlights, chunky rounded huggable body, feathery bioluminescent cyan gill-frills
at the sides of its head, curly finned tail, little squishy paws cradling a small glowing cyan
sealed orb, teal-and-aqua body, soft indigo outlines, rosy cheeks, clean flat vector shading,
gentle rim light, a few floating bubbles, sticker illustration, centered, plain dark teal
background --style raw --ar 1:1 --niji 6
```
Negative (append or use `--no`): `--no robot, mecha, metal, hexagon, keyhole, padlock, circuitry,
antennae, glowing lens eyes, text, watermark, weapon, axolotl, real animal, 3d render`

### OpenAI GPT-image-1 / DALL·E 3
```
A cute, original kawaii creature mascot for a security software brand — NOT a robot and NOT any
real animal. A small, soft, rounded deep-sea "guardian sprite": big glossy cartoon eyes with
white highlight glints, a chunky huggable body in soft aqua-teal, feathery bioluminescent cyan
gill-frills at the sides of the head, a curly finned tail, and little squishy paws gently
cradling a small glowing cyan "sealed orb" (a smooth pearl/egg with one faint seam and a tiny
gold glint — NOT a hexagon or keyhole). Bold soft indigo outlines, flat vector shading with
smooth gradients, rosy cheek blush, a couple of floating bubbles. Clean sticker illustration,
centered, transparent or plain dark background. Palette: cyan #37E1D6, teal #4E93B8, gold accent
#F4B23C, indigo outline #241E46. No text, no robot parts, no circuitry, no weapons.
```

### Stable Diffusion (SDXL)
```
Prompt: (kawaii creature mascot:1.3), original fictitious deep-sea guardian sprite, big glossy
eyes with highlights, soft chunky rounded body, bioluminescent cyan gill-frills, curly finned
tail, tiny paws holding a glowing cyan sealed orb, aqua teal body, soft indigo outlines, flat
vector shading, subtle gradient, rosy cheeks, floating bubbles, sticker art, centered, dark teal
background, high quality, clean lineart
Negative: robot, mecha, cyborg, metal, panels, bolts, antennae, hexagon, keyhole, padlock,
circuitry, glowing lens eyes, text, watermark, signature, weapon, gun, axolotl, otter, badger,
real animal, photorealistic, 3d, blurry, extra limbs
```

## 8. If commissioning an illustrator

Send: this file + the emblem (`caisson-vault-logomark.svg`) + the founder's kawaii reference (for
*style only*) + the palette table. Ask for: 2–3 initial concept sketches → 1 refined → the full
deliverable list in §6. **Acceptance criteria:** reads as an original creature (passes a "what
animal is this?" — answer should be "none, it's the Caisson sprite"), zero robot/tech cues on the
body, legible at 48px, and consistent across the expression sheet. Budget guide: a solid mascot +
expression sheet is typically a mid-range illustration commission; ask for full commercial rights
and layered source files.

## 9. Originality / legal

The creature must be **wholly original** — no names, poses, palettes, or trade dress borrowed from
Pokémon or any existing character/IP. The style reference is a *look*, not a character to copy.
Secure full commercial rights and the working files from whoever produces it.

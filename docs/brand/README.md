# stash brand

<img src="logo-dark.svg" alt="stash" width="300">

The full guidelines are in [`brand-guidelines.html`](brand-guidelines.html). Download it and open it in a browser to see the boards: primary logo, logo system, color and type, and examples in use. This page is the quick reference.

**The idea:** the prompt chevron is the terminal. The keyhole is the cursor waiting for your fingerprint.

## Files

| File | Use it for |
|---|---|
| [`logo-dark.svg`](logo-dark.svg) | Primary lockup on dark backgrounds: README (dark mode), site, social |
| [`logo-light.svg`](logo-light.svg) | Primary lockup on light backgrounds: README (light mode), docs, slides, print |
| [`logo-ink.svg`](logo-ink.svg) | One-color lockup for amber backgrounds: stickers, swag, launch moments |
| [`mark.svg`](mark.svg) | App icon / avatar |
| [`favicon.svg`](favicon.svg) | Favicon (heavier strokes for small sizes) |
| [`menubar-template.svg`](menubar-template.svg) | macOS menu bar template image (black only; macOS tints it) |
| [`badge-secured-by-stash.svg`](badge-secured-by-stash.svg) | "secured by stash" badge for projects that use stash |
| [`social-preview.png`](social-preview.png) | GitHub social preview (1280×640) |

All SVG text is converted to outlines, so the files render the same everywhere, with no font needed.

To add the badge to your project's README:

```markdown
[![secured by stash](https://raw.githubusercontent.com/Mrlopez62/stash/main/docs/brand/badge-secured-by-stash.svg)](https://github.com/Mrlopez62/stash)
```

## Color

| Name | Hex | Role |
|---|---|---|
| Keyhole Amber | `#F5B544` | The secret, the unlock, the primary action. Use it sparingly |
| Vault Ink | `#0E1116` | Main background |
| Enclave | `#171B22` | Raised surfaces, the dark mark's tile |
| Redacted | `#8A93A3` | Secondary text, listed names |
| Plaintext | `#E8EAED` | Main text on dark |
| Paper | `#F4F2EC` | Light background |

Supporting colors: border `#2A303B`, body text on dark `#B9C0CC`, success `#7DD3A8`.

The balance is mostly ink with a little amber, roughly 60% ink, 22% enclave, 12% plaintext, and 6% amber.

## Type

- **JetBrains Mono:** the wordmark, headlines, and commands. Use ExtraBold 800 with tight tracking (−5%) for display, and Regular 400 for code.
- **IBM Plex Sans:** body text. Use SemiBold 600 for headings, and Regular 400 for body at 16–18 px.

## Rules

- **Always lowercase:** "stash", never "Stash" or "STASH".
- **Clear space:** at least the keyhole's height on every side.
- **Minimum size:** 16 px for the mark, 96 px wide for the lockup.
- **Amber is the secret.** Use it only for the keyhole, the cursor, and key actions.
- **Don't** recolor the chevron amber, and don't outline the wordmark.
- **Don't** animate the keyhole, except for a 1-second cursor blink.

## In the terminal

CLI output uses the same palette, and color appears only on a terminal with `NO_COLOR` unset:
- amber `❯` prompts and `stash://` references
- Redacted grey for listed names
- green `#7DD3A8` for success lines, such as `✓ unlocked · injected 1 secret into npm`

# Logo Placeholders

Tracking every spot the nuon logo needs to land in the final version. **Do not add the real nuon brand mark here yet** — Noah is saving the nuon-style branding for the final polish pass. The palette has been switched to nuon.ai colors, and the in-app sidebar uses a neutral interim shield mark (`ui/public/brand-mark.svg`); the nuon-style mark replaces it later.

A first draft sits at `ui/public/logo.svg` (not currently referenced) — keep or replace. The interim sidebar mark is `ui/public/brand-mark.svg`.

## Spots that need a logo / mark

| # | Surface | File | Line / hook | Asset format | Notes |
|---|---------|------|-------------|--------------|-------|
| 1 | Browser tab favicon | `ui/index.html` | `<!-- LOGO PLACEHOLDER: favicon goes here in final version -->` | `.svg` (small footprint) | Uncomment the `<link rel="icon">` once final logo lands at `ui/public/logo.svg`. |
| 2 | Electron window icon | `ui/electron/main.ts` | Comment near `backgroundColor: "#061a30"` | `.ico` for Windows, `.icns` for mac | Add `icon: path.join(__dirname, "../public/logo.ico")` to the `BrowserWindow` options. |
| 3 | App header / sidebar brand | `ui/src/App.tsx` (40×40 `<img src="/brand-mark.svg">` next to the "Cybersecurity Assessor" title) | Replace `src="/brand-mark.svg"` with the final nuon mark | `.svg` | Currently uses the neutral interim shield; swap when nuon branding lands. |
| 4 | Splash / loading state | (does not exist yet) | Sidecar-startup splash component | `.svg` | If we add a splash screen while the Python sidecar boots. |
| 5 | PDF assessment report header | `backend/cybersecurity_assessor/reports/pdf.py` | Reportlab `drawImage` call | `.png` @ 300dpi or `.svg` via svglib | Top-left of every page in the generated report. |
| 6 | Settings → About panel | `ui/src/routes/Settings.tsx` (built-by-Nuon footer near line 110) | Currently a code comment | `.svg` | "Built by Nuon" footer / about block. |
| 7 | Installer artwork | `ui/build/` (electron-builder) | `installerIcon`, `uninstallerIcon`, `installerHeader`, `installerSidebar` | `.ico` + `.bmp` | Set when we wire up `electron-builder` config in v0.2. |

## Color palette already in use (nuon.ai)

See `ui/src/styles/globals.css` — sourced from `C:\Users\Noah.Jaskolski\Projects\nuon-site\styles.css`.

| Token | Hex | Role |
|-------|-----|------|
| `--navy` | `#0a2540` | primary / CTA |
| `--navy-deep` | `#061a30` | dark background |
| `--blue` | `#2563eb` | accent / link |
| `--blue-bright` | `#3b82f6` | accent (dark mode) |
| `--ink` | `#1a2540` | body text |
| `--muted` | `#5b6b85` | secondary text |
| `--line` | `#e5ebf3` | borders |
| `--bg-soft` | `#f6f9fc` | subtle surface |

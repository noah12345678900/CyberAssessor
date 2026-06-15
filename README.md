# Cybersecurity Assessor

Standalone desktop app for assessing NIST SP 800-53 controls from eMASS CCIS workbooks.

**Status:** v2.0.0 — wired end-to-end, packaged as a Windows installer (NSIS). Electron front-end spawns a PyInstaller-bundled Python sidecar; no separate runtime install required.

## Stack

- **UI:** Electron 32 + React 18 + TypeScript + Vite, styled with Tailwind v4 + shadcn/ui + Radix
- **Backend sidecar:** Python 3.12 + FastAPI + SQLite (via SQLModel)
- **LLM:** Anthropic SDK with prompt caching
- **Excel I/O:** openpyxl (reads) + xlwings (writes that preserve comments/formatting)
- **CUI-safe:** runs entirely on the assessor's workstation; only outbound traffic is the Anthropic API

## Layout

```
ui/         Electron + React frontend
backend/    Python FastAPI sidecar (all assessment logic)
tests/      Pytest fixtures + tests
```

## Install (end users)

Download **Cybersecurity Assessor Setup 2.0.0.exe** from the [latest release](https://github.com/noah12345678900/CyberAssessor/releases/latest) and run it. The installer is self-contained — it bundles the Python sidecar, so no separate Python/Node install is needed. On first run, open Settings and paste your `ANTHROPIC_API_KEY`.

## Dev setup

Prerequisites:
- Node.js 20+, pnpm 9+
- Python 3.12+, [uv](https://docs.astral.sh/uv/) (or pip)
- Microsoft Excel (for xlwings writes)

```bash
# Backend
cd backend
uv sync                    # or: pip install -e .

# Frontend
cd ../
pnpm install

# Run (two terminals)
pnpm dev:backend           # uvicorn on 127.0.0.1:8765
pnpm dev                   # Electron + Vite
```

In production builds, Electron spawns the Python sidecar as a child process with a port handshake — no manual backend start needed.

## Building the installer

Two stages — the PyInstaller sidecar must be built before electron-builder packages it as an extra resource:

```bash
# 1. Build the sidecar (onedir bundle → backend/dist/cybersec-server/)
pwsh ./backend/scripts/build-sidecar.ps1

# 2. Package the Windows installer → ui/release/
pnpm --filter ui package
```

The sidecar is built onedir (not onefile) to stay under the 15s Electron handshake budget — see `backend/cybersec-server.spec`.

## Configuration

On first run, open Settings and paste your `ANTHROPIC_API_KEY`. It is stored in the OS keyring (Windows Credential Manager on Windows).

Per-user config lives at `~/.cybersecurity-assessor/config.toml`.

## Verification (end-to-end smoke test)

1. `pnpm install && cd backend && uv sync`
2. `pnpm dev:backend` in one terminal, `pnpm dev` in another
3. Open Settings, paste `ANTHROPIC_API_KEY`
4. Workbooks → open a CCIS `.xlsx` export
5. Catalog page shows 800-53r5 loaded (run **Load NIST 800-53r5** once)
6. Ingest → point at evidence folder → see file counts per extractor
7. Controls grid → drill into a CCI → review proposed status + narrative → **Apply to workbook**
8. Reopen workbook in Excel — comments, named ranges, formatting all preserved
9. `pnpm test:backend` to run pytest

## Roadmap

- **v2.0** (current): end-to-end pipeline, Windows installer (electron-builder + PyInstaller sidecar), 800-53r5
  — acceptance bar tracked in [docs/e2e-assessment-coverage-deliverable.md](docs/e2e-assessment-coverage-deliverable.md) (every feature lane exercised + per-CCI evidence traceability)
- **Next**: 800-171 catalog, embedding-based evidence search, auto-update, SharePoint/Tenable connectors
- **Later**: FedRAMP, NIST CSF 2.0, ISO 27001, SOC 2

## Support &amp; contact

Built by [Nuon](https://nuon.ai) — an SDVOSB cybersecurity firm specializing in AI-driven assessments.

- General inquiries: [contact@nuon.ai](mailto:contact@nuon.ai)
- Engagement / sales: see the [services catalog](https://nuon.ai/services.html)
- Careers: [careers@nuon.ai](mailto:careers@nuon.ai)

"""Optional connector clients (eMASS, SharePoint, Tenable, ...).

Each submodule is independent — the sidecar imports them lazily so a missing
SDK / unreachable upstream / disabled feature flag never breaks core flows.
v0.1 ships only the eMASS *stub* so the Settings UI can show "not
configured" instead of "feature missing".
"""

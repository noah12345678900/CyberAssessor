/**
 * User-facing error humanization.
 *
 * Most toast error sites used to pass `err.message` directly, which leaked
 * the raw `${status} ${detail}` string produced by api.ts request() — e.g.
 * "500 Internal Server Error" or "422 missing field 'foo'" — into the
 * description line of a toast. That's noisy for users and rarely actionable.
 *
 * humanize() strips the leading HTTP status prefix that api.ts prepends,
 * and routes a handful of common status codes to friendlier copy. The raw
 * error is always console.error'd so it stays diagnosable in DevTools.
 *
 * This intentionally does NOT swallow detail content — for 4xx responses
 * with a structured FastAPI detail message, the existing detail text comes
 * through (just without the "422 " prefix). The goal is "less noise", not
 * "less information".
 */

import { ApiError } from "./api";

const STATUS_PREFIX_RE = /^\d{3}\s+/;

export function humanize(err: unknown): string {
  // Always log raw so DevTools has the full context regardless of what the
  // user sees in the toast.
  console.error("[humanize]", err);

  if (err instanceof ApiError) {
    // Friendly substitutions for the loud generic statuses. 4xx detail
    // messages from FastAPI are usually actionable, so we let those through
    // after stripping the prefix.
    if (err.status === 401 || err.status === 403) {
      return "Sign-in expired or insufficient permission. Check Settings → SharePoint or your API key.";
    }
    if (err.status === 503) {
      return "Service unavailable. Is the desktop sidecar running?";
    }
    if (err.status >= 500) {
      // 5xx detail tends to be a stack trace fragment — hide it.
      return "Server error. See DevTools console for details.";
    }
    // 4xx (other than auth) — strip the "NNN " status prefix, keep the
    // FastAPI detail text.
    return err.message.replace(STATUS_PREFIX_RE, "");
  }

  if (err instanceof Error) {
    // TypeError: Failed to fetch — the most common non-ApiError, network down.
    if (err.name === "TypeError" && /fetch/i.test(err.message)) {
      return "Network error. Check that the desktop app is running.";
    }
    return err.message;
  }

  return "Unexpected error. See DevTools console for details.";
}

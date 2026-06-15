/**
 * Forces the UI into "pending scope" mode even when a workbook is open.
 *
 * Background — the pending-scope path (boundary docs + sweep keyed on
 * SystemContext, with workbook_id IS NULL) is meant for the gap before
 * any workbook exists. But once a workbook is opened we have no
 * "close workbook" affordance, so the natural pending-mode UI never
 * renders and the code path is unreachable for testing.
 *
 * This hook is a deliberately tiny escape hatch: a single bool persisted
 * in localStorage. When true, SweepContext and the SharePoint browse /
 * sweep dialogs ignore the active workbook and route through the pending
 * SystemContext endpoints instead.
 *
 * Will be superseded by a proper `Setting.active_workbook_id` with an
 * Open/Close affordance on the Workbooks page — at which point this hook
 * and its `PendingModeToggle` component can be deleted.
 */
import { useCallback, useEffect, useState } from "react";

const STORAGE_KEY = "ccis-assessor.use-pending-scope";
const STORAGE_EVENT = "ccis-assessor.use-pending-scope.changed";

function read(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    // localStorage can throw in private browsing / sandboxed contexts.
    return false;
  }
}

export function usePendingModeOverride(): [boolean, (v: boolean) => void] {
  const [value, setValue] = useState<boolean>(() => read());

  // Subscribe to in-tab changes (storage events only fire across tabs, so
  // we dispatch a CustomEvent ourselves for same-tab consumers).
  useEffect(() => {
    function onChange() {
      setValue(read());
    }
    window.addEventListener(STORAGE_EVENT, onChange);
    window.addEventListener("storage", onChange);
    return () => {
      window.removeEventListener(STORAGE_EVENT, onChange);
      window.removeEventListener("storage", onChange);
    };
  }, []);

  const set = useCallback((v: boolean) => {
    try {
      if (v) {
        window.localStorage.setItem(STORAGE_KEY, "1");
      } else {
        window.localStorage.removeItem(STORAGE_KEY);
      }
    } catch {
      // Best-effort; the UI will simply not persist the choice.
    }
    window.dispatchEvent(new CustomEvent(STORAGE_EVENT));
  }, []);

  return [value, set];
}

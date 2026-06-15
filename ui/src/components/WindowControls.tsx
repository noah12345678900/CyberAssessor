/**
 * Custom window controls (min / max / close) — replaces Electron's
 * `titleBarOverlay` so the buttons match the rest of the shadcn UI.
 *
 * Why custom controls:
 *   `titleBarOverlay` lets you tint the buttons (color + symbolColor) but
 *   the *shape* — square, sharp corners, fixed 46×32 footprint — is drawn
 *   by Windows and can't be reskinned. Against a rounded, navy shadcn shell
 *   the native buttons read as a Windows app accidentally embedded in our
 *   chrome. These HTML controls use the same radii, hover treatment, and
 *   nuon palette as the sidebar nav and toolbar buttons.
 *
 * Layout contract:
 *   - Fixed top-right, z-50, above the DragStrip so clicks land here first.
 *   - 36px tall to match the old titleBarOverlay height (App.tsx DragStrip
 *     was sized against that, so existing math still works).
 *   - 132px wide total (3 × 44px buttons) — DragStrip reserves `right-[140px]`
 *     in App.tsx, leaving an 8px breathing gap.
 *   - WebkitAppRegion: 'no-drag' on the buttons so they receive clicks
 *     instead of being eaten by the drag region.
 *
 * Browser-mode behavior:
 *   `hasNativeBridge()` is false outside Electron — render nothing. The
 *   browser tab keeps its own window chrome and we'd otherwise show
 *   non-functional buttons.
 */

import { useEffect, useState } from "react";
import { Minus, Square, Copy, X } from "lucide-react";

import { cn } from "@/lib/utils";
import { hasNativeBridge } from "@/lib/api";

export function WindowControls() {
  const native = hasNativeBridge();
  const [maximized, setMaximized] = useState<boolean>(() =>
    native ? window.ccis!.windowControls.isMaximized() : false,
  );

  useEffect(() => {
    if (!native) return;
    return window.ccis!.windowControls.onMaximizedChange(setMaximized);
  }, [native]);

  if (!native) return null;

  const wc = window.ccis!.windowControls;

  return (
    <div
      className="fixed right-2 top-1 z-[60] flex h-8 items-center gap-1"
      style={{ WebkitAppRegion: "no-drag" } as React.CSSProperties}
      aria-label="Window controls"
    >
      <ControlButton
        ariaLabel="Minimize"
        title="Minimize"
        onClick={() => wc.minimize()}
      >
        <Minus className="h-4 w-4" strokeWidth={2.5} />
      </ControlButton>

      <ControlButton
        ariaLabel={maximized ? "Restore" : "Maximize"}
        title={maximized ? "Restore" : "Maximize"}
        onClick={() => wc.toggleMaximize()}
      >
        {maximized ? (
          // "Restore" — two overlapping squares, the standard Windows glyph
          // for un-maximize. lucide's `Copy` icon is two offset rounded
          // rectangles, which reads as exactly this at 14px.
          <Copy className="h-4 w-4" strokeWidth={2.5} />
        ) : (
          <Square className="h-3.5 w-3.5" strokeWidth={2.5} />
        )}
      </ControlButton>

      <ControlButton
        ariaLabel="Close"
        title="Close"
        onClick={() => wc.close()}
        variant="danger"
      >
        <X className="h-4 w-4" strokeWidth={2.5} />
      </ControlButton>
    </div>
  );
}

function ControlButton({
  children,
  onClick,
  ariaLabel,
  title,
  variant = "default",
}: {
  children: React.ReactNode;
  onClick: () => void;
  ariaLabel: string;
  title: string;
  variant?: "default" | "danger";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={ariaLabel}
      title={title}
      // Window controls are chrome, not page content — they should not be
      // in the tab order. The prior CSS-only fix (focus-visible:ring-0,
      // outline-none, etc.) hid Tailwind's ring but Electron's *initial*
      // focus on app start could still flash the browser's default focus
      // indicator (a 2px border around the Minimize button) for a frame
      // before our styles applied. Taking the buttons out of the tab
      // order means Electron's "auto-focus first focusable element"
      // pass skips them, so there's nothing to suppress in the first
      // place. Keyboard users invoke window controls via Alt+Space.
      tabIndex={-1}
      className={cn(
        // Rounded squares matching sidebar nav radius (rounded-md = 6px).
        // Tighter footprint than Windows' 46×32 so the cluster reads as UI,
        // not OS chrome.
        // Match SidebarItem aesthetic: muted ink on light surface, soft
        // accent on hover. The app runs in light mode (--background = white),
        // so light-on-light text-white made the icons invisible. Use the
        // same muted-foreground → foreground transition the sidebar uses.
        "inline-flex h-7 w-9 items-center justify-center rounded-md border-0",
        "text-muted-foreground transition-colors duration-150",
        // Belt-and-suspenders: even with tabIndex=-1 a stray programmatic
        // .focus() call shouldn't paint a ring on top of our chrome.
        "outline-none focus:outline-none focus-visible:outline-none focus-visible:ring-0",
        variant === "danger"
          ? // Close button: muted on idle, red on hover — Windows convention
            // but rounded to match the rest of the shell.
            "hover:bg-destructive hover:text-destructive-foreground active:bg-red-700"
          : "hover:bg-accent hover:text-foreground",
      )}
    >
      {children}
    </button>
  );
}

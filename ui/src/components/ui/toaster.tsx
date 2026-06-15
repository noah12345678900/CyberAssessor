/**
 * Lightweight in-app toast.
 *
 * Sonner isn't installed in this workspace, so this is a small bespoke
 * implementation that mounts a portal-style fixed container and exposes
 * a module-level `toast.success` / `toast.error` / `toast.info` API
 * that matches the shape callers would use with sonner. Swap for sonner
 * later by replacing this file's exports.
 */

import * as React from "react";
import { CheckCircle2, AlertTriangle, Info, X } from "lucide-react";
import { cn } from "@/lib/utils";

type ToastKind = "success" | "error" | "info";

interface ToastItem {
  id: number;
  kind: ToastKind;
  title: string;
  description?: string;
}

type Listener = (toasts: ToastItem[]) => void;

let nextId = 1;
let items: ToastItem[] = [];
const listeners = new Set<Listener>();

function emit() {
  for (const l of listeners) l(items);
}

function push(kind: ToastKind, title: string, description?: string) {
  const id = nextId++;
  items = [...items, { id, kind, title, description }];
  emit();
  window.setTimeout(() => dismiss(id), 5_000);
  return id;
}

function dismiss(id: number) {
  items = items.filter((t) => t.id !== id);
  emit();
}

export const toast = {
  success: (title: string, description?: string) => push("success", title, description),
  error: (title: string, description?: string) => push("error", title, description),
  info: (title: string, description?: string) => push("info", title, description),
  dismiss,
};

export function Toaster() {
  const [list, setList] = React.useState<ToastItem[]>(items);
  React.useEffect(() => {
    listeners.add(setList);
    return () => {
      listeners.delete(setList);
    };
  }, []);
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2">
      {list.map((t) => (
        <div
          key={t.id}
          className={cn(
            "pointer-events-auto flex items-start gap-3 rounded-md border bg-card p-3 shadow-lg",
            t.kind === "success" && "border-emerald-500/50",
            t.kind === "error" && "border-destructive/60",
            t.kind === "info" && "border-sky-500/50",
          )}
        >
          {t.kind === "success" && (
            <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
          )}
          {t.kind === "error" && (
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
          )}
          {t.kind === "info" && (
            <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-600 dark:text-sky-400" />
          )}
          <div className="flex-1">
            <div className="text-sm font-medium leading-tight">{t.title}</div>
            {t.description && (
              <div className="mt-1 text-xs text-muted-foreground leading-snug">
                {t.description}
              </div>
            )}
          </div>
          <button
            onClick={() => dismiss(t.id)}
            className="rounded-sm text-muted-foreground hover:text-foreground"
            aria-label="Dismiss"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}

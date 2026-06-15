import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HashRouter } from "react-router-dom";

import { App } from "./App";
import { Toaster } from "@/components/ui/toaster";
import { hasNativeBridge } from "@/lib/api";
import "./styles/globals.css";

const rootEl = document.getElementById("root")!;

// Hard-block browser-mode entry. The Electron shell injects window.ccis via
// preload; a plain browser tab does not. Running in a browser without the
// bridge means native file dialogs, OS keyring, and sidecar handshake are
// all broken — half the app silently misbehaves. Refuse to mount the React
// tree unless we have the bridge OR the user has explicitly opted in with
// VITE_ALLOW_BROWSER=1 at vite dev time.
const allowBrowser = import.meta.env.VITE_ALLOW_BROWSER === "1";
if (!hasNativeBridge() && !allowBrowser) {
  rootEl.innerHTML = `
    <div style="
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
      font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: #0a0a0a;
      color: #f5f5f5;
    ">
      <div style="max-width: 36rem; line-height: 1.55;">
        <div style="
          font-size: 0.75rem;
          letter-spacing: 0.08em;
          text-transform: uppercase;
          color: #f59e0b;
          margin-bottom: 0.75rem;
        ">Electron required</div>
        <h1 style="font-size: 1.5rem; font-weight: 600; margin: 0 0 0.75rem;">
          This app must run in the Electron shell.
        </h1>
        <p style="color: #a3a3a3; margin: 0 0 1rem;">
          Native file pickers, OS keyring, and the Python sidecar handshake
          all live in the Electron preload bridge. A plain browser tab can't
          reach them, so the UI is intentionally refusing to mount.
        </p>
        <p style="color: #a3a3a3; margin: 0 0 1.5rem;">
          Launch the desktop shell instead:
        </p>
        <pre style="
          background: #171717;
          border: 1px solid #262626;
          border-radius: 0.5rem;
          padding: 0.75rem 1rem;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          font-size: 0.875rem;
          margin: 0 0 1.5rem;
          overflow-x: auto;
        ">pnpm --filter ui dev:electron</pre>
        <details style="color: #737373; font-size: 0.8125rem;">
          <summary style="cursor: pointer; user-select: none;">
            Need browser mode anyway?
          </summary>
          <p style="margin: 0.75rem 0 0;">
            Set <code style="
              background: #171717;
              padding: 0.125rem 0.375rem;
              border-radius: 0.25rem;
              font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            ">VITE_ALLOW_BROWSER=1</code> in your env (or in a
            <code style="
              background: #171717;
              padding: 0.125rem 0.375rem;
              border-radius: 0.25rem;
              font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            ">.env.local</code> file under <code style="
              background: #171717;
              padding: 0.125rem 0.375rem;
              border-radius: 0.25rem;
              font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
            ">ui/</code>) and restart Vite. Half the UI will be broken — this
            is an escape hatch, not a supported mode.
          </p>
        </details>
      </div>
    </div>
  `;
} else {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: 1,
        refetchOnWindowFocus: false,
        staleTime: 30_000,
      },
    },
  });

  ReactDOM.createRoot(rootEl).render(
    <React.StrictMode>
      <QueryClientProvider client={queryClient}>
        {/*
          Opt into the v7 router behaviors that v6 currently warns about.
          These are the actual v7 semantics, not warning suppressors — v6
          emits a warning per unopted flag on every navigation, and adopting
          them now means the eventual jump to react-router 7 is a no-op.
            • v7_startTransition  — wraps router state updates in
              React.startTransition (smoother nav, no behavior break here
              since we don't use Suspense boundaries on route change).
            • v7_relativeSplatPath — fixes relative path resolution inside
              splat (`*`) routes. We have zero splat routes (see App.tsx),
              so this is a free upgrade.
          The data-router flags (v7_fetcherPersist, v7_normalizeFormMethod,
          v7_partialHydration, v7_skipActionErrorRevalidation) only apply
          to createBrowserRouter / RouterProvider, not HashRouter, so they
          are intentionally omitted.
        */}
        <HashRouter
          future={{
            v7_startTransition: true,
            v7_relativeSplatPath: true,
          }}
        >
          <App />
          <Toaster />
        </HashRouter>
      </QueryClientProvider>
    </React.StrictMode>,
  );
}

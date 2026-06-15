// CheckCircle2 and Mail restore with the "Stuck?" support card when v1.0 ships
import { ArrowRight, Database, HelpCircle, Workflow, Zap } from "lucide-react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

/**
 * Reference + conventions. For the end-to-end setup flow, see /workflow.
 */
export function Help() {
  return (
    <div className="p-8 space-y-6 max-w-4xl">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <HelpCircle className="h-6 w-6 text-primary" />
          Help
        </h1>
        <p className="text-sm text-muted-foreground">
          File locations and where to turn when something breaks. For the
          step-by-step setup flow, see{" "}
          <Link to="/workflow" className="text-primary hover:underline">
            Workflow
          </Link>
          .
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Workflow className="h-5 w-5 text-primary" />
            New here?
          </CardTitle>
          <CardDescription>
            Start with the end-to-end assessment workflow — it walks you from
            empty install to a first assessed CCI.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline" size="sm">
            <Link to="/workflow">
              Open Workflow <ArrowRight className="h-3 w-3" />
            </Link>
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Where things live</CardTitle>
          <CardDescription>
            Everything runs on this workstation. The only outbound traffic is the
            Anthropic API.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <Row label="API key">
            <Mono>Windows Credential Manager</Mono> (via{" "}
            <Mono>keyring</Mono>)
          </Row>
          <Row label="Config">
            <Mono>~/.cybersecurity-assessor/config.toml</Mono>
          </Row>
          <Row label="Local catalog DB">
            <Mono>~/.cybersecurity-assessor/catalog.db</Mono> (SQLite)
          </Row>
          <Row label="Evidence text extracts">
            <Mono>~/.cybersecurity-assessor/extracts/</Mono>
          </Row>
          <Row label="Sidecar">
            FastAPI on <Mono>127.0.0.1</Mono> with a random port, spawned by
            Electron at launch.
          </Row>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            Faster ingestion: skip the LLM
          </CardTitle>
          <CardDescription>
            Ingestion is fastest when an artifact tags itself. If the
            deterministic tagger can map an artifact to at least two control
            objectives on its own, it never calls the LLM judge — so the more
            high-signal references your evidence carries, the faster (and more
            repeatable) the run.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-muted-foreground">
            The tagger runs deterministic passes first and only falls back to
            the LLM when an artifact still has fewer than{" "}
            <Mono>2</Mono> objective tags. Give each artifact one or more of the
            tokens below — in the document body unless noted — and it clears
            that gate without ever reaching the model.
          </p>
          <Row label="Program doc number">
            A <Mono>USD</Mono> number (e.g. <Mono>USD00123456</Mono>) in the{" "}
            <em>filename</em> or body. Resolved identity-first, so the filename
            alone is enough.
          </Row>
          <Row label="CCI reference">
            A <Mono>CCI-######</Mono> token (e.g. <Mono>CCI-000130</Mono>).
            Scraped from the body of STIG/Nessus findings, and from a dedicated
            CCI column in an evidence workbook.
          </Row>
          <Row label="Control ID">
            A control identifier in the body, e.g. <Mono>AC-2</Mono> or{" "}
            <Mono>IA-5(1)</Mono>. Body text only — filenames and titles are
            ignored for control IDs.
          </Row>
          <Row label="Recognizable workbook shape">
            Inventory / account / POA&amp;M / training rosters whose columns
            match a known shape tag deterministically by content — no special
            tokens needed.
          </Row>
          <p className="text-muted-foreground pt-1">
            Anything the deterministic passes can&apos;t place still gets a fair
            read from the LLM — these tokens only make the fast path faster,
            they don&apos;t change what counts as evidence.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" />
            Scale &amp; limits
          </CardTitle>
          <CardDescription>
            How much evidence one workbook holds before retention trims the
            oldest non-load-bearing artifacts.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <Row label="Evidence retention cap">
            <Mono>30,000</Mono> artifacts per workbook
          </Row>
          <p className="text-muted-foreground pt-1">
            30,000 is the realistic worst case for the largest systems we
            assess. A ~10,000-person system implies roughly that many user
            endpoints plus ~10–15% servers, network, and appliance hosts
            (~11–12k hosts), and a granular per-host evidence model ingests
            about two artifacts per host (a STIG CKL plus a scan/config
            export). Adding scan rollups, policy/SSP/CRM documents, and
            re-ingested supersession copies lands a defensible upper bound near
            30,000.
          </p>
          <p className="text-muted-foreground">
            Once a workbook exceeds the cap, the oldest artifacts are evicted
            oldest-first — but never anything load-bearing (tagged as evidence,
            an asset list, a boundary document, or a supersession anchor).
            Every eviction is recorded in an append-only retention ledger, so
            nothing is silently dropped.
          </p>
        </CardContent>
      </Card>

      {/*
        "Stuck?" support card — hidden until v1.0 ships. Restore CheckCircle2
        and Mail imports at the top when re-enabling.

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
              Stuck?
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="text-muted-foreground">
              If the sidecar shows offline in the lower-left, the FastAPI process
              either failed to spawn or crashed. Check the Electron console (
              <Mono>View → Toggle Developer Tools</Mono>) for the port handshake
              failure.
            </p>
            <p className="text-muted-foreground">
              For anything more, contact{" "}
              <a
                href="mailto:contact@nuon.ai"
                className="inline-flex items-center gap-1 text-primary hover:underline"
              >
                <Mail className="h-3 w-3" /> contact@nuon.ai
              </a>
              .
            </p>
          </CardContent>
        </Card>
      */}
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b last:border-0 py-1.5">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className="text-right">{children}</span>
    </div>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-xs">{children}</span>;
}

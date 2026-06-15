import {
  ArrowRight,
  ClipboardList,
  FileSpreadsheet,
  FileText,
  FolderSearch,
  KeyRound,
  ListChecks,
  ShieldCheck,
  Workflow as WorkflowIcon,
} from "lucide-react";
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
 * End-to-end workflow for a fresh system. After first setup the day-to-day
 * loop collapses to Evidence → Controls → Control Detail; the rest of the
 * steps are one-time.
 */
export function Workflow() {
  return (
    <div className="p-8 space-y-6 max-w-4xl">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight flex items-center gap-2">
          <WorkflowIcon className="h-6 w-6 text-primary" />
          Workflow
        </h1>
        <p className="text-sm text-muted-foreground">
          Run these screens top-to-bottom for a fresh system. After the first
          setup, the day-to-day loop is Evidence → Controls → Control Detail.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>The assessment loop</CardTitle>
          <CardDescription>
            Seven steps from empty install to assessed CCIs, a Security
            Assessment Report, and a POAM bundle ready to export.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ol className="space-y-5">
            <Step
              number={1}
              title="Set your API key and CCI overlay"
              to="/settings"
              icon={KeyRound}
              cta="Open Settings"
            >
              Paste your Anthropic API key — stored in <Mono>Windows Credential
              Manager</Mono> via <Mono>keyring</Mono>, never written to disk in
              plain text. Set your default tester name and the system under
              assessment. Then point the <Strong>DISA CCI List</Strong> card at
              the NIST CSRC{" "}
              <Mono>stig-mapping-to-nist-800-53.xlsx</Mono> (or an archived{" "}
              <Mono>U_CCI_List.xml</Mono> if you have one) so controls get
              their CCI objectives — without it, controls show <Mono>0
              CCIs</Mono>.
            </Step>

            <Step
              number={2}
              title="Load the catalog: framework + workbook"
              to="/workbooks"
              icon={FileSpreadsheet}
              cta="Go to Workbooks"
            >
              On the Workbooks screen, use the <Strong>Framework</Strong> control
              in the header. Click <Strong>Load NIST 800-53r5</Strong> (or{" "}
              <Strong>Load NIST 800-53r4</Strong> for older systems still on the
              Rev 4 baseline) to download the official OSCAL JSON, or use{" "}
              <Strong>Browse…</Strong> to load a local catalog file (for
              air-gapped runs). Both revisions can coexist — load whichever a
              given workbook targets, then pick it from the dropdown. With the
              framework selected, click <Strong>Open workbook</Strong> and
              browse to the <Mono>.xlsx</Mono> / <Mono>.xlsm</Mono>. Opening with
              a framework bound materializes a <Strong>Baseline</Strong> from
              column A ("Required" rows) — that's how the app knows which CCIs
              are in-scope for this system.
            </Step>

            <Step
              number={3}
              title="Ingest the evidence folder"
              to="/evidence"
              icon={FolderSearch}
              cta="Ingest evidence"
            >
              On the Evidence screen, click <Strong>Ingest folder…</Strong> and
              point it at your evidence drop. The ingester walks every file,
              extracts text (PDF / DOCX / PPTX / XLSX / STIG{" "}
              <Mono>.ckl</Mono>, <Mono>.cklb</Mono>, XCCDF, Nessus), and tags
              artifacts to objectives by doc-number regex + family keyword.
            </Step>

            <Step
              number={4}
              title="Review the baseline"
              to="/baselines"
              icon={ListChecks}
              cta="Review baselines"
            >
              Sanity-check what got marked in-scope vs out-of-scope. Use the family
              filter to spot anything missing (e.g. all of AU is excluded — is that
              real, or did the workbook's column A get edited?). Click{" "}
              <Strong>Refresh from source</Strong> after re-reading the workbook.
            </Step>

            <Step
              number={5}
              title="Assess controls"
              to="/controls"
              icon={ShieldCheck}
              cta="Open Controls grid"
            >
              Click <Strong>Assess all in-scope</Strong> in the header to run
              every in-scope CCI through the engine in one pass — accepted
              decisions persist as draft assessments for review. Narrow
              with the family filter first if you want a partial run (e.g. AC
              only). Then drill into individual CCIs to review the proposed
              status (column N) and results narrative (column Q), and click{" "}
              <Strong>Apply to workbook</Strong> — that writes back through
              xlwings, preserving comments, named ranges, and formatting.
            </Step>

            <Step
              number={6}
              title="Download the Security Assessment Report"
              to="/workbooks"
              icon={FileText}
              cta="Go to Workbooks"
            >
              With assessments applied, click <Strong>SAR</Strong> on the
              workbook's row to download a NIST SP 800-53A Security Assessment
              Report. The SAR rolls up per-control findings, results
              narratives, and the evidence cited for each — a snapshot of the
              assessment that stakeholders can review alongside the live
              workbook.
            </Step>

            <Step
              number={7}
              title="Generate and export POAMs"
              to="/poams"
              icon={ClipboardList}
              cta="Open POAMs"
            >
              Once findings are stable, click <Strong>Generate from open
              findings</Strong> to cluster Non-Compliant CCIs at the remediation
              boundary (shared owner + fix + schedule) — one POAM per cluster,
              not one per CCI. Edit milestones, scheduled completion, and risk
              level inline, then <Strong>Export to eMASS</Strong> for the POAM
              workbook upload. Re-imports merge by external ID so milestone
              updates round-trip without losing local edits.
            </Step>
          </ol>
        </CardContent>
      </Card>
    </div>
  );
}

function Step({
  number,
  title,
  to,
  icon: Icon,
  cta,
  children,
}: {
  number: number;
  title: string;
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  cta: string;
  children: React.ReactNode;
}) {
  return (
    <li className="flex gap-4">
      <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary">
        {number}
      </div>
      <div className="flex-1 space-y-2">
        <div className="flex items-center gap-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
          <h3 className="text-sm font-semibold">{title}</h3>
        </div>
        <p className="text-sm text-muted-foreground">{children}</p>
        <Button asChild variant="link" size="sm" className="h-auto p-0 text-xs">
          <Link to={to}>
            {cta} <ArrowRight className="h-3 w-3" />
          </Link>
        </Button>
      </div>
    </li>
  );
}

function Mono({ children }: { children: React.ReactNode }) {
  return <span className="font-mono text-xs">{children}</span>;
}

function Strong({ children }: { children: React.ReactNode }) {
  return <strong className="font-medium text-foreground">{children}</strong>;
}

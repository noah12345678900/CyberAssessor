/**
 * Pre-Assessment — framework-aware how-to guides for baselining a system
 * before the per-CCI assessment loop kicks off.
 *
 * Each framework has its own pre-assessment paradigm:
 *   - NIST 800-53 / FedRAMP → FIPS 199 categorization → Low/Mod/High baseline
 *   - CSF 2.0              → Current/Target Profile + Tier (1-4)
 *   - 800-171              → Level 1/2/3 by CUI handling
 *   - ISO 27001            → Risk assessment + Statement of Applicability
 *   - CIS Controls         → Implementation Group (IG1/IG2/IG3)
 *   - PCI DSS              → SAQ type by merchant level / processing path
 *   - SOC 2                → Trust services criteria selection
 *
 * Only NIST 800-53 / FedRAMP carries a full how-to today; the other tabs
 * are roadmap stubs that summarize the paradigm and point at the
 * authoritative standard. They flip on as each framework lands in the
 * assessor (see project_ccis_assessor_frameworks memory for the v0.X
 * sequencing). Surfacing them now keeps the page from reading as
 * NIST-only and gives users a heads-up on the per-framework scoping
 * differences before they arrive.
 *
 * This page is *guidance only* — no backend wiring, no mutations. The
 * actual baseline / framework selection happens on the Baselines tab.
 *
 * Original asset-list flagging UI was removed 2026-06-04 per user
 * direction ("preassessment should just have a how to for baselining
 * a system in correspondance to it's CIA level"). Supporting backend
 * models (Evidence.is_asset_list, asset_crosscheck) remain in place but
 * unused, awaiting a clearer surface.
 */

import { Link } from "react-router-dom";
import {
  ArrowRight,
  BookOpen,
  ClipboardCheck,
  ExternalLink,
  Layers,
  ListChecks,
  Settings as SettingsIcon,
  ShieldCheck,
} from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { type Framework } from "@/lib/api";
import { useFrameworks } from "@/lib/queries";

export function PreAssessment() {
  // Framework-aware tab visibility. When a framework is toggled OFF in
  // Settings (`enabled === false`) we temporarily REMOVE its guidance tab
  // from view here — not delete it — mirroring the `f.enabled !== false`
  // presentation gate the Catalog / pickers use. A tab whose framework
  // is NOT loaded in the catalog (zero matching rows) is also hidden — an
  // absent framework has no enabled/disabled state, so hiding it is the
  // correct empty-state behavior (only loaded+enabled frameworks show).
  // The "nist" core flow tab is always shown: NIST 800-53 / FedRAMP is the
  // app's permanent base lens and provides a sensible single default tab
  // in the fresh/empty state.
  const frameworks = useFrameworks();
  const fws = frameworks.data ?? [];

  const tabVisible = (matchers: ((f: Framework) => boolean)[]): boolean => {
    const matched = fws.filter((f) => matchers.some((m) => m(f)));
    if (matched.length === 0) return false; // not loaded → hide tab
    return matched.some((f) => f.enabled !== false); // shown if any enabled
  };

  const visible = {
    nist: true,
    csf: tabVisible([(f) => /cybersecurity framework/i.test(f.name)]),
    "nist-800-171": tabVisible([(f) => /800-171/.test(f.name)]),
    iso: tabVisible([(f) => /27001/.test(f.name)]),
    "cis-ig1": tabVisible([(f) => f.name === "CIS Controls"]),
    "cisa-essentials": tabVisible([(f) => /cyber essentials/i.test(f.name)]),
    pci: tabVisible([(f) => /pci dss/i.test(f.name)]),
    soc: tabVisible([(f) => f.name === "SOC 2"]),
  };

  return (
    <div className="p-8 space-y-6 max-w-5xl">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Pre-Assessment</h1>
        <p className="text-sm text-muted-foreground">
          What the system owner should have settled <em>before</em> the
          assessor opens a workbook. Each framework has a different scoping
          paradigm — pick the one you're assessing against.
        </p>
      </header>

      <Tabs defaultValue="nist" className="w-full">
        <TabsList className="h-auto flex-wrap justify-start">
          <TabsTrigger value="nist">NIST 800-53 / FedRAMP</TabsTrigger>
          {visible.csf && <TabsTrigger value="csf">CSF 2.0</TabsTrigger>}
          {visible["nist-800-171"] && (
            <TabsTrigger value="nist-800-171">800-171</TabsTrigger>
          )}
          {visible.iso && <TabsTrigger value="iso">ISO 27001</TabsTrigger>}
          {visible["cis-ig1"] && (
            <TabsTrigger value="cis-ig1">CIS IG1 (Small Biz)</TabsTrigger>
          )}
          {visible["cisa-essentials"] && (
            <TabsTrigger value="cisa-essentials">CISA Cyber Essentials</TabsTrigger>
          )}
          {visible.pci && <TabsTrigger value="pci">PCI DSS</TabsTrigger>}
          {visible.soc && <TabsTrigger value="soc">SOC 2</TabsTrigger>}
        </TabsList>

        <TabsContent value="nist" className="space-y-6">
          <NistFedrampGuide />
        </TabsContent>

        {visible.csf && (
        <TabsContent value="csf">
          <FrameworkStub
            name="NIST Cybersecurity Framework 2.0"
            paradigm="Profile + Tier"
            summary="No system categorization. Define a Current Profile (what you do today) and a Target Profile (where you need to be), then pick an Implementation Tier (1 Partial → 4 Adaptive) based on risk tolerance and mission drivers."
            preSteps={[
              "Define organizational mission, legal/regulatory obligations, and risk tolerance.",
              "Build the Current Profile — which CSF outcomes you currently achieve, and how well.",
              "Build the Target Profile — the outcomes required to meet your risk tolerance.",
              "Pick the Implementation Tier (1-4) describing how rigorous your cybersecurity risk management process needs to be.",
              "Identify gaps between Current and Target — these become the assessment scope.",
            ]}
            link={{
              href: "https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-20/final",
              label: "NIST CSF 2.0",
            }}
          />
        </TabsContent>
        )}

        {visible["nist-800-171"] && (
        <TabsContent value="nist-800-171">
          <FrameworkStub
            name="NIST SP 800-171"
            paradigm="CUI protection in non-federal systems"
            summary="No FIPS 199. Scope is driven by where Controlled Unclassified Information (CUI) lives: the 110 security requirements across 14 families apply to every non-federal system that processes, stores, or transmits CUI."
            preSteps={[
              "Inventory contracts and identify whether you handle FCI, CUI, or both.",
              "Define the CUI boundary — every system, person, and process that handles CUI.",
              "Document the System Security Plan (SSP) for the CUI environment.",
              "Build the plan of action & milestones (POA&M) for any unmet requirements.",
              "Determine whether self-assessment or a third-party assessment is required by contract.",
            ]}
            link={{
              href: "https://csrc.nist.gov/pubs/sp/800/171/r3/final",
              label: "NIST SP 800-171",
            }}
          />
        </TabsContent>
        )}

        {visible.iso && (
        <TabsContent value="iso">
          <FrameworkStub
            name="ISO/IEC 27001"
            paradigm="Risk assessment → Statement of Applicability"
            summary="No prescriptive baseline. Define the ISMS scope, perform a risk assessment, then justify in the Statement of Applicability (SoA) which Annex A controls you applied, modified, or excluded — and why."
            preSteps={[
              "Define the ISMS scope (clause 4.3) — boundary, interfaces, dependencies.",
              "Identify interested parties and their requirements (clause 4.2).",
              "Establish the information security risk assessment process (clause 6.1.2).",
              "Run the risk assessment — identify risks, owners, likelihood, impact.",
              "Author the Statement of Applicability — every Annex A control, included or excluded, with justification.",
            ]}
            link={{
              href: "https://www.iso.org/standard/27001",
              label: "ISO/IEC 27001",
            }}
          />
        </TabsContent>
        )}

        {visible["cis-ig1"] && (
        <TabsContent value="cis-ig1">
          <FrameworkStub
            name="CIS Controls v8.1 — Implementation Group 1 (IG1)"
            paradigm="Essential cyber hygiene for small / under-resourced orgs"
            summary="IG1 is the small-business floor: 56 Safeguards across the 18 CIS Controls that every org should meet regardless of size. CIS designed IG1 for organizations with limited IT/security expertise, where the cost of a breach is high and the staff to defend against APT-grade adversaries doesn't exist. Foundational asset/software inventory drives everything else."
            preSteps={[
              "Inventory enterprise assets — every device that connects to the network (CIS Control 1). IG1 expects a manual or lightweight tool, refreshed at least twice yearly.",
              "Inventory software assets — every authorized application (Control 2). Unsupported software gets flagged and removed or isolated.",
              "Confirm organizational profile fits IG1 (small/under-resourced, sensitivity to operational disruption, no expectation of APT defense). If you handle regulated data at scale, plan to step up to IG2.",
              "Use the CIS Controls Self-Assessment Tool (CIS CSAT) or IG1 worksheet to baseline current state against the 56 Safeguards before assessment.",
              "Identify the few enterprise-specific Safeguards beyond IG1 your business actually needs — don't blanket-adopt IG2.",
            ]}
            link={{
              href: "https://www.cisecurity.org/controls/implementation-groups/ig1",
              label: "CIS IG1 — Essential Cyber Hygiene",
            }}
          />
        </TabsContent>
        )}

        {visible["cisa-essentials"] && (
        <TabsContent value="cisa-essentials">
          <FrameworkStub
            name="CISA Cyber Essentials"
            paradigm="Six narrative Toolkits for leaders + IT staff"
            summary="CISA's plain-language starter kit for small and medium businesses (and small government). Not a control catalog — it's six Toolkits framed for two audiences: leadership (culture, strategy, risk decisions) and IT staff (technical actions). Pairs naturally with CIS IG1: Cyber Essentials sets the management narrative, IG1 names the specific safeguards."
            preSteps={[
              "Toolkit 1 — Yourself, The Leader: drive cybersecurity strategy, investment, and culture from the top; assign accountability for cyber risk.",
              "Toolkit 2 — Your Staff, The Users: develop security awareness and vigilance through training, phishing exercises, and clear acceptable-use policy.",
              "Toolkit 3 — Your Systems, What Makes You Operational: inventory and protect critical applications, data flows, and assets; patch and harden.",
              "Toolkit 4 — Your Surroundings, The Digital Workplace: limit access and admin privilege; segment networks; secure remote work.",
              "Toolkit 5 — Your Data, What The Business Is Built On: identify, classify, back up, and protect data — including offline backups for ransomware resilience.",
              "Toolkit 6 — Your Crisis Response, How To Respond If Incidents Occur: build and exercise an incident response plan; know who to call (CISA, FBI, MSP).",
            ]}
            link={{
              href: "https://www.cisa.gov/cyber-essentials",
              label: "CISA Cyber Essentials",
            }}
          />
        </TabsContent>
        )}

        {visible.pci && (
        <TabsContent value="pci">
          <FrameworkStub
            name="PCI DSS v4.0"
            paradigm="SAQ type by merchant level + processing path"
            summary="No CIA categorization. Scope is the Cardholder Data Environment (CDE) — every system that stores, processes, or transmits cardholder data, plus connected systems. SAQ type (A, A-EP, B, C, D, etc.) is fixed by merchant level and how you process payments."
            preSteps={[
              "Determine merchant level (1-4) based on annual transaction volume.",
              "Map the cardholder data flow — where it enters, traverses, and is stored.",
              "Define the CDE boundary and identify connected/security-impacting systems.",
              "Pick the matching SAQ type, or determine a full ROC is required (Level 1 / service providers).",
              "Reduce scope where possible: tokenization, network segmentation, P2PE.",
            ]}
            link={{
              href: "https://www.pcisecuritystandards.org/document_library/",
              label: "PCI SSC Document Library",
            }}
          />
        </TabsContent>
        )}

        {visible.soc && (
        <TabsContent value="soc">
          <FrameworkStub
            name="SOC 2 (AICPA Trust Services Criteria)"
            paradigm="Trust services criteria selection"
            summary="No control baseline per se. Security (Common Criteria) is required; the other four — Availability, Processing Integrity, Confidentiality, Privacy — are optional and selected based on customer commitments and the system's service description."
            preSteps={[
              "Author the system description — services, infrastructure, software, people, procedures, data.",
              "Identify customer commitments and system requirements driving each criterion.",
              "Select applicable Trust Services Criteria (Security always; others as commitments dictate).",
              "Pick report type — Type 1 (controls designed at a point in time) vs Type 2 (operating effectiveness over a period).",
              "Engage a licensed CPA firm — SOC 2 is auditor-attested, not self-asserted.",
            ]}
            link={{
              href: "https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2",
              label: "AICPA — SOC 2",
            }}
          />
        </TabsContent>
        )}
      </Tabs>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// NIST 800-53 / FedRAMP — full how-to (only filled framework today)
// ─────────────────────────────────────────────────────────────────────────────

function NistFedrampGuide() {
  return (
    <div className="space-y-6">
      {/* Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BookOpen className="h-5 w-5" />
            Two baselines, one workflow
          </CardTitle>
          <CardDescription>
            "Baselining" means two different things in the RMF. Both need to be
            settled before the first CCI gets a verdict.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <div className="rounded-md border p-4 space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold">
              <Layers className="h-4 w-4 text-primary" />
              Control baseline
            </div>
            <p className="text-sm text-muted-foreground">
              The Low / Moderate / High set of NIST 800-53 controls picked from
              your FIPS 199 categorization. Determines which CCIs the assessor
              even considers in-scope.
            </p>
            <p className="text-xs text-muted-foreground">
              Lives in this tool — pick it on the <strong>Baselines</strong> tab
              after categorizing below.
            </p>
          </div>
          <div className="rounded-md border p-4 space-y-2">
            <div className="flex items-center gap-2 text-sm font-semibold">
              <SettingsIcon className="h-4 w-4 text-primary" />
              Configuration baseline
            </div>
            <p className="text-sm text-muted-foreground">
              The documented "known-good" configuration of every component
              inside the authorization boundary (CM-2, CM-6). SP 800-128 is the
              canonical guide.
            </p>
            <p className="text-xs text-muted-foreground">
              Lives in the system owner's CM plan — the assessor's job is to
              <em> verify</em> one exists and is current, not to author it.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Step 1 — categorize */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <StepBadge n={1} />
            Categorize the system (FIPS 199)
          </CardTitle>
          <CardDescription>
            Rate the impact of a loss of <strong>Confidentiality</strong>,{" "}
            <strong>Integrity</strong>, and <strong>Availability</strong> for
            every information type the system handles.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <CiaTable />
          <Callout>
            <strong>Source for impact ratings:</strong> NIST SP 800-60 Vol. 2
            maps information types (e.g. "Financial Management", "System
            Development", "Personnel Records") to provisional C/I/A impact
            levels. Start there, then adjust for system-specific context.
          </Callout>
          <p className="text-sm text-muted-foreground">
            National security systems use <strong>CNSSI 1253</strong> instead —
            it keeps the three CIA values separate (no high-water mark) and
            adds overlays for classified, cross-domain, and intel community
            systems.
          </p>
        </CardContent>
      </Card>

      {/* Step 2 — high water mark */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <StepBadge n={2} />
            Apply the high-water mark
          </CardTitle>
          <CardDescription>
            For federal (non-national-security) systems, the overall system
            impact equals the <em>highest</em> of the three C/I/A ratings.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="rounded-md border p-4 font-mono text-sm">
            system_impact = max(confidentiality, integrity, availability)
          </div>
          <div className="grid gap-2 text-sm md:grid-cols-3">
            <Example c="Low" i="Low" a="Low" out="Low" />
            <Example c="Low" i="Moderate" a="Low" out="Moderate" />
            <Example c="Moderate" i="Low" a="High" out="High" />
          </div>
          <Callout>
            CNSSI 1253 systems <strong>do not</strong> apply the high-water
            mark — record the three values independently and pick the matching
            overlay.
          </Callout>
        </CardContent>
      </Card>

      {/* Step 3 — pick control baseline */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <StepBadge n={3} />
            Pick the matching control baseline
          </CardTitle>
          <CardDescription>
            Map the overall impact level to a NIST 800-53 baseline (or a
            FedRAMP profile if the system is a cloud service).
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <BaselineMappingTable />
          <div className="flex flex-wrap items-center gap-3 pt-2">
            <Button asChild>
              <Link to="/baselines">
                <ListChecks className="h-4 w-4" />
                Open Baselines tab
                <ArrowRight className="h-4 w-4" />
              </Link>
            </Button>
            <span className="text-xs text-muted-foreground">
              Pick the baseline that matches your impact level — this scopes
              every CCI the assessor evaluates.
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Step 4 — configuration baseline */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <StepBadge n={4} />
            Verify a configuration baseline exists (SP 800-128)
          </CardTitle>
          <CardDescription>
            Before assessing CM controls, confirm the system has a documented
            configuration baseline and a process to keep it current.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm">
            SP 800-128 calls this <em>security-focused configuration
            management (SecCM)</em>. The configuration baseline is the formally
            approved snapshot of:
          </p>
          <ul className="list-disc pl-6 text-sm space-y-1">
            <li>OS, firmware, and application versions on each component</li>
            <li>Hardening settings (STIG / CIS / vendor benchmark)</li>
            <li>Installed software inventory</li>
            <li>Network configuration (ACLs, routing, segmentation)</li>
            <li>Account / privilege settings</li>
          </ul>
          <p className="text-sm">
            Look for these artifacts during evidence ingest:
          </p>
          <ul className="list-disc pl-6 text-sm space-y-1">
            <li>
              <strong>Configuration Management Plan</strong> — describes the
              CCB, change control, and baseline review cadence
            </li>
            <li>
              <strong>System Security Plan (SSP)</strong> §CM-2 — names the
              current configuration baseline document
            </li>
            <li>
              <strong>STIG checklists</strong> (CKL/CKLB) — concrete evidence
              the hardening baseline was applied
            </li>
            <li>
              <strong>Scan reports</strong> (ACAS / Nessus) — verify the
              baseline still matches reality
            </li>
          </ul>
          <Callout>
            If the configuration baseline is missing or stale, that's a CM-2
            finding on its own — assessing the rest of the CM family without a
            baseline is wheel-spinning.
          </Callout>
        </CardContent>
      </Card>

      {/* References */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            References
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <ExtLink
            href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.199.pdf"
            title="FIPS 199"
            note="Standards for Security Categorization of Federal Information and Information Systems"
          />
          <ExtLink
            href="https://csrc.nist.gov/pubs/sp/800/60/v2/r1/final"
            title="NIST SP 800-60 Vol. 2 Rev. 1"
            note="Guide for Mapping Types of Information and Information Systems to Security Categories"
          />
          <ExtLink
            href="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"
            title="NIST SP 800-53 Rev. 5"
            note="Security and Privacy Controls for Information Systems and Organizations"
          />
          <ExtLink
            href="https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final"
            title="NIST SP 800-53B"
            note="Control Baselines for Information Systems and Organizations"
          />
          <ExtLink
            href="https://csrc.nist.gov/pubs/sp/800/128/upd1/final"
            title="NIST SP 800-128"
            note="Guide for Security-Focused Configuration Management of Information Systems"
          />
          <ExtLink
            href="https://www.cnss.gov/CNSS/issuances/Instructions.cfm"
            title="CNSSI 1253"
            note="Security Categorization and Control Selection for National Security Systems"
          />
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Framework guide — renders the per-framework pre-assessment paradigm so users
// see how scoping differs before they bring in their program workbook.
// ─────────────────────────────────────────────────────────────────────────────

interface FrameworkStubProps {
  name: string;
  paradigm: string;       // one-line label for the scoping model
  summary: string;        // 1-2 sentence prose summary
  preSteps: string[];     // pre-assessment steps the system owner does off-app
  link: { href: string; label: string };
}

function FrameworkStub({
  name,
  paradigm,
  summary,
  preSteps,
  link,
}: FrameworkStubProps) {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-3">
            <div>
              <CardTitle className="flex items-center gap-2">
                <BookOpen className="h-5 w-5" />
                {name}
              </CardTitle>
              <CardDescription className="mt-1">
                Pre-assessment paradigm: <strong>{paradigm}</strong>
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm">{summary}</p>

          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-2">
              Pre-assessment steps
            </div>
            <ol className="list-decimal pl-6 text-sm space-y-1">
              {preSteps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </div>

          <div className="pt-1">
            <a
              href={link.href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm font-medium text-primary hover:underline inline-flex items-center gap-1"
            >
              {link.label}
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

function StepBadge({ n }: { n: number }) {
  return (
    <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-primary text-primary-foreground text-xs font-semibold">
      {n}
    </span>
  );
}

function Callout({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-md border-l-4 border-primary bg-primary/5 px-4 py-3 text-sm">
      {children}
    </div>
  );
}

function CiaTable() {
  const rows: Array<{
    objective: string;
    low: string;
    moderate: string;
    high: string;
  }> = [
    {
      objective: "Confidentiality",
      low: "Limited adverse effect from unauthorized disclosure.",
      moderate: "Serious adverse effect from unauthorized disclosure.",
      high: "Severe or catastrophic effect — e.g. classified or PII at scale.",
    },
    {
      objective: "Integrity",
      low: "Limited adverse effect from unauthorized modification.",
      moderate: "Serious adverse effect from unauthorized modification.",
      high: "Severe or catastrophic — corrupted data drives bad decisions or unsafe behavior.",
    },
    {
      objective: "Availability",
      low: "Limited adverse effect from disruption.",
      moderate: "Serious adverse effect — meaningful mission degradation.",
      high: "Severe or catastrophic — mission cannot be performed.",
    },
  ];
  return (
    <div className="overflow-hidden rounded-md border">
      <table className="w-full text-sm">
        <thead className="bg-muted/50">
          <tr>
            <th className="px-3 py-2 text-left font-semibold">Objective</th>
            <th className="px-3 py-2 text-left font-semibold">Low</th>
            <th className="px-3 py-2 text-left font-semibold">Moderate</th>
            <th className="px-3 py-2 text-left font-semibold">High</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.objective} className="border-t">
              <td className="px-3 py-2 font-medium">{r.objective}</td>
              <td className="px-3 py-2 text-muted-foreground">{r.low}</td>
              <td className="px-3 py-2 text-muted-foreground">{r.moderate}</td>
              <td className="px-3 py-2 text-muted-foreground">{r.high}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Example({
  c,
  i,
  a,
  out,
}: {
  c: string;
  i: string;
  a: string;
  out: string;
}) {
  return (
    <div className="rounded-md border px-3 py-2 font-mono text-xs">
      <div>C:{c.padEnd(9)} I:{i.padEnd(9)} A:{a}</div>
      <div className="mt-1 text-primary">→ system_impact = {out}</div>
    </div>
  );
}

function BaselineMappingTable() {
  const rows: Array<{
    impact: string;
    nist: string;
    fedramp: string;
    notes: string;
  }> = [
    {
      impact: "Low",
      nist: "NIST 800-53 Low baseline",
      fedramp: "FedRAMP Low / Li-SaaS",
      notes: "Smallest control set; suitable for non-sensitive, low-risk systems.",
    },
    {
      impact: "Moderate",
      nist: "NIST 800-53 Moderate baseline",
      fedramp: "FedRAMP Moderate",
      notes: "Most common federal categorization; FedRAMP default for SaaS handling CUI.",
    },
    {
      impact: "High",
      nist: "NIST 800-53 High baseline",
      fedramp: "FedRAMP High",
      notes: "Mission-critical / life-safety / large-scale PII. Strictest tailoring.",
    },
  ];
  return (
    <div className="overflow-hidden rounded-md border">
      <table className="w-full text-sm">
        <thead className="bg-muted/50">
          <tr>
            <th className="px-3 py-2 text-left font-semibold">Overall impact</th>
            <th className="px-3 py-2 text-left font-semibold">NIST 800-53 baseline</th>
            <th className="px-3 py-2 text-left font-semibold">FedRAMP equivalent</th>
            <th className="px-3 py-2 text-left font-semibold">Notes</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.impact} className="border-t">
              <td className="px-3 py-2">
                <Badge variant="outline">{r.impact}</Badge>
              </td>
              <td className="px-3 py-2">{r.nist}</td>
              <td className="px-3 py-2">{r.fedramp}</td>
              <td className="px-3 py-2 text-xs text-muted-foreground">
                {r.notes}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ExtLink({
  href,
  title,
  note,
}: {
  href: string;
  title: string;
  note: string;
}) {
  return (
    <div className="flex items-start gap-2">
      <ClipboardCheck className="h-4 w-4 mt-0.5 shrink-0 text-muted-foreground" />
      <div>
        <a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="font-medium text-primary hover:underline inline-flex items-center gap-1"
        >
          {title}
          <ExternalLink className="h-3 w-3" />
        </a>
        <div className="text-xs text-muted-foreground">{note}</div>
      </div>
    </div>
  );
}

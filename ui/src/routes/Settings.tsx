import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Activity,
  AlertCircle,
  BookOpen,
  Check,
  Clock,
  Cloud,
  Copy,
  ExternalLink,
  FileCode2,
  FileSearch,
  FolderOpen,
  GitBranch,
  KeyRound,
  Layers,
  Loader2,
  LogOut,
  Pencil,
  PlugZap,
  Play,
  Plus,
  Radar,
  Save,
  Star,
  Server,
  ShieldCheck,
  Sparkles,
  Ticket,
  Trash2,
  Zap,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { toast } from "@/components/ui/toaster";
import { humanize } from "@/lib/errors";
import { cn } from "@/lib/utils";
import { baseUrl, hasNativeBridge } from "@/lib/api";
import {
  useAnthropicModels,
  useBaselines,
  useCatalogStatus,
  useClearAnthropicGatewayToken,
  useClearAnthropicKey,
  useClearConfluencePat,
  useClearOpenAIGatewayToken,
  useClearOpenAIKey,
  useConfluenceStatus,
  useDeleteBaseline,
  useDeleteRequirementSource,
  useFrameworks,
  useHealth,
  useImportOverlay,
  useLoadDisaCci,
  useLoadNistCsf,
  useLoadNist800171,
  useLoadIso27001,
  useLoadCisV8,
  useLoadPciDss,
  useLoadSoc2,
  useOverlaySheets,
  useRequirementSources,
  useScopeLabels,
  useWorkbooks,
  useOpenAIModels,
  useSetAnthropicGatewayToken,
  useSetAnthropicKey,
  useSetOpenAIGatewayToken,
  useSetOpenAIKey,
  useSettings,
  useSetSharePointPriorityLinks,
  useSharePointPriorityLinks,
  useSharePointStatus,
  useSignOutSharePoint,
  useCancelSharePointSignIn,
  useClearTenableAccessKey,
  useClearTenableSecretKey,
  useSetTenableAccessKey,
  useSetTenableSecretKey,
  useTenableStatus,
  useTestAnthropicGateway,
  useTestAnthropicKey,
  useTestOpenAIGateway,
  useTestOpenAIKey,
  useTestSharePoint,
  useTestTenable,
  useServicenowGrcStatus,
  useTestServicenowGrc,
  useSetServicenowGrcOauthSecret,
  useClearServicenowGrcOauthSecret,
  useSetServicenowGrcBasicPassword,
  useClearServicenowGrcBasicPassword,
  useArcherStatus,
  useTestArcher,
  useSetArcherPassword,
  useClearArcherPassword,
  useSplunkStatus,
  useTestSplunk,
  useSetSplunkToken,
  useClearSplunkToken,
  useGitlabStatus,
  useTestGitlab,
  useSetConfluencePat,
  useTestConfluence,
  useJiraStatus,
  useTestJira,
  useSetJiraPat,
  useClearJiraPat,
  useEmassStatus,
  useTestEmass,
  useSetFrameworkEnabled,
  useUpdateSettings,
  useAutomationSchedules,
  useCreateAutomationSchedule,
  useUpdateAutomationSchedule,
  useDeleteAutomationSchedule,
  useRunAutomationScheduleNow,
} from "@/lib/queries";
import type {
  LlmProvider,
  OverlayKind,
  SharePointPriorityLink,
  JiraAllowedQuery,
  AutomationSchedule,
} from "@/lib/api";

// Tab values must stay in sync with the <TabsTrigger value="..."> list below.
// Centralized so the ?tab= query-param deep-link can validate before honoring
// it (a stale link to a renamed tab falls back to "apis" instead of leaving
// shadcn's Tabs with no active panel).
const SETTINGS_TAB_VALUES = [
  "apis",
  "connectors",
  "catalogs",
  "defaults",
  "privacy",
  "about",
  "automation",
] as const;
type SettingsTabValue = (typeof SETTINGS_TAB_VALUES)[number];

export function Settings() {
  const health = useHealth();
  const settings = useSettings();

  // Deep-link support: callers like Evidence's "Configure SharePoint…" button
  // route to /settings?tab=connectors to land the user on the right pane.
  // `defaultValue` is consumed only on mount, so navigating from another route
  // re-mounts Settings and picks up a fresh ?tab=. Switching tabs inside
  // Settings doesn't update the URL — that's intentional; the URL is the
  // entry-point hint, not a stored selection.
  const [searchParams] = useSearchParams();
  const requestedTab = searchParams.get("tab");
  const initialTab: SettingsTabValue =
    requestedTab && (SETTINGS_TAB_VALUES as readonly string[]).includes(requestedTab)
      ? (requestedTab as SettingsTabValue)
      : "apis";

  return (
    <div className="p-8 space-y-6 max-w-3xl">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          API keys are stored in Windows Credential Manager. Other defaults live in{" "}
          <span className="font-mono text-xs">~/.cybersecurity-assessor/config.toml</span>.
        </p>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Sidecar</CardTitle>
          <CardDescription>FastAPI process started by Electron at launch</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <Row label="URL" value={<span className="font-mono">{baseUrl()}</span>} />
          <Row
            label="Status"
            value={
              health.data?.status === "ok" ? (
                <Badge variant="success">ok</Badge>
              ) : (
                <Badge variant="warning">offline</Badge>
              )
            }
          />
          <Row label="Version" value={health.data?.version ?? "—"} />
        </CardContent>
      </Card>

      <Tabs defaultValue={initialTab} className="w-full">
        <TabsList>
          <TabsTrigger value="apis">APIs</TabsTrigger>
          <TabsTrigger value="connectors">Connectors</TabsTrigger>
          <TabsTrigger value="catalogs">Catalogs</TabsTrigger>
          <TabsTrigger value="defaults">Defaults</TabsTrigger>
          <TabsTrigger value="privacy">Privacy</TabsTrigger>
          <TabsTrigger value="about">About</TabsTrigger>
          <TabsTrigger value="automation">Automation</TabsTrigger>
        </TabsList>

        <TabsContent value="apis" className="space-y-6">
          <SectionHeader>Anthropic</SectionHeader>

          <AnthropicKeyCard keySet={settings.data?.anthropic_key_set ?? false} />

          <CorporateGatewayCard
            baseUrl={settings.data?.anthropic_base_url ?? null}
            defaultBaseUrl={
              settings.data?.anthropic_default_base_url ?? "https://api.anthropic.com"
            }
            gatewayTokenSet={settings.data?.anthropic_gateway_token_set ?? false}
            envTokenSet={settings.data?.anthropic_auth_token_env_set ?? false}
            loading={settings.isLoading}
          />

          <SectionHeader>OpenAI</SectionHeader>

          <OpenAIKeyCard
            keySet={settings.data?.openai_key_set ?? false}
            envKeySet={settings.data?.openai_api_key_env_set ?? false}
          />

          <OpenAICorporateCard
            baseUrl={settings.data?.openai_base_url ?? null}
            defaultBaseUrl={
              settings.data?.openai_default_base_url ?? "https://api.openai.com/v1"
            }
            gatewayTokenSet={settings.data?.openai_gateway_token_set ?? false}
            envTokenSet={settings.data?.openai_auth_token_env_set ?? false}
            loading={settings.isLoading}
          />

          <p className="text-xs text-muted-foreground">
            Handling CUI? See the <strong>Privacy</strong> tab for routing
            guidance and which baselines require an authorized endpoint.
          </p>
        </TabsContent>

        <TabsContent value="connectors" className="space-y-6">
          <SectionHeader>External evidence connectors</SectionHeader>

          <SharePointConnectorCard />

          <TenableConnectorCard />

          <SplunkConnectorCard />

          <GitlabConnectorCard />

          <ServicenowGrcConnectorCard />

          <ArcherConnectorCard />

          <ConfluenceConnectorCard />

          <JiraConnectorCard />

          <EmassConnectorCard />

        </TabsContent>

        <TabsContent value="catalogs" className="space-y-6">
          <SectionHeader>Catalogs</SectionHeader>

          <CcisOverlayStatusCard />
          <DisaCciCard />
          <AdditionalFrameworksCard />
          <ImportOverlayCard />
        </TabsContent>

        <TabsContent value="defaults" className="space-y-6">
          <SectionHeader>Defaults</SectionHeader>

          <DefaultsCard
            defaultTester={settings.data?.default_tester ?? ""}
            provider={settings.data?.llm_provider ?? "anthropic"}
            anthropicModel={settings.data?.anthropic_model ?? ""}
            anthropicKeySet={settings.data?.anthropic_key_set ?? false}
            openaiModel={settings.data?.openai_model ?? ""}
            openaiKeySet={settings.data?.openai_key_set ?? false}
            loading={settings.isLoading}
          />

          {/* Audit v1 — citation co-emission. Sits under Defaults because it
              changes assessor behavior (prompt shape + response length), not
              connector wiring. Trace + evidence-shown capture is unconditional;
              this toggle only controls whether the LLM is asked for per-claim
              citations. Default OFF until the eval harness lands. */}
          <AuditCitationsCard
            enabled={settings.data?.features?.audit_citations ?? false}
            loading={settings.isLoading}
          />
        </TabsContent>

        <TabsContent value="privacy" className="space-y-6">
          <SectionHeader>Privacy &amp; data handling</SectionHeader>
          <PrivacyTab />
        </TabsContent>

        <TabsContent value="about" className="space-y-6">
          <SectionHeader>About this app</SectionHeader>
          <AboutTab />
        </TabsContent>

        <TabsContent value="automation" className="space-y-6">
          <SectionHeader>Automation</SectionHeader>
          <AutomationTab />
        </TabsContent>

      </Tabs>
    </div>
  );
}

function AnthropicKeyCard({ keySet }: { keySet: boolean }) {
  const setKey = useSetAnthropicKey({
    onSuccess: () => toast.success("API key saved", "Stored in Windows Credential Manager"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const clearKey = useClearAnthropicKey({
    onSuccess: () => toast.success("API key cleared", "Removed from Credential Manager"),
    onError: (err) => toast.error("Clear failed", humanize(err)),
  });
  const testKey = useTestAnthropicKey({
    onSuccess: (res) =>
      toast.success(
        "Key works",
        `${res.model} replied "${res.reply}" (${res.input_tokens} in / ${res.output_tokens} out)`,
      ),
    onError: (err) => toast.error("Key test failed", humanize(err)),
  });
  const [key, setKey_] = useState("");

  async function save() {
    if (key.trim().length < 10) return;
    await setKey.mutateAsync(key.trim());
    setKey_("");
  }

  async function clear() {
    await clearKey.mutateAsync();
  }

  async function test() {
    try {
      await testKey.mutateAsync();
    } catch {
      // toast handled by onError
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-4 w-4" />
          Personal API key
        </CardTitle>
        <CardDescription>
          Stored in Windows Credential Manager via{" "}
          <span className="font-mono text-xs">keyring</span> — never written to disk in plain text.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Row
          label="Status"
          value={
            keySet ? (
              <Badge variant="success">key set</Badge>
            ) : (
              <Badge variant="warning">not set</Badge>
            )
          }
        />

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground block">
            {keySet ? "Replace key" : "Set key"}
          </label>
          <div className="flex gap-2">
            <Input
              type="password"
              value={key}
              onChange={(e) => setKey_(e.target.value)}
              placeholder="sk-ant-…"
              autoComplete="off"
            />
            <Button onClick={save} disabled={key.trim().length < 10 || setKey.isPending}>
              <Save className="h-4 w-4" />
              {setKey.isPending ? "Saving…" : "Save"}
            </Button>
          </div>
          {setKey.isError && (
            <p className="text-xs text-destructive">{(setKey.error as Error).message}</p>
          )}
          {setKey.isSuccess && (
            <p className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
              <Check className="h-3 w-3" /> Key saved to Credential Manager
            </p>
          )}
        </div>

        {keySet && (
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={test}
              disabled={testKey.isPending}
              title="Send a tiny Haiku probe to confirm the stored key reaches Anthropic."
            >
              {testKey.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {testKey.isPending ? "Testing…" : "Test key"}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={clear}
              disabled={clearKey.isPending}
              className="text-destructive hover:text-destructive"
            >
              <Trash2 className="h-4 w-4" />
              {clearKey.isPending ? "Clearing…" : "Clear stored key"}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function CorporateGatewayCard({
  baseUrl,
  defaultBaseUrl,
  gatewayTokenSet,
  envTokenSet,
  loading,
}: {
  baseUrl: string | null;
  defaultBaseUrl: string;
  gatewayTokenSet: boolean;
  envTokenSet: boolean;
  loading: boolean;
}) {
  const update = useUpdateSettings({
    onSuccess: () => toast.success("Gateway URL saved", "Persisted to config.toml"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const setToken = useSetAnthropicGatewayToken({
    onSuccess: () =>
      toast.success("Gateway token saved", "Stored in Windows Credential Manager"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const clearToken = useClearAnthropicGatewayToken({
    onSuccess: () => toast.success("Gateway token cleared", "Removed from Credential Manager"),
    onError: (err) => toast.error("Clear failed", humanize(err)),
  });
  // Dedicated gateway probe — unlike /anthropic-key/test, this refuses to
  // fall back to the personal sk-ant key so the button's outcome is an
  // unambiguous verdict on (base_url + gateway token).
  const testGateway = useTestAnthropicGateway({
    onSuccess: (res) =>
      toast.success(
        "Gateway works",
        `${res.model} replied "${res.reply}" (${res.input_tokens} in / ${res.output_tokens} out)`,
      ),
    onError: (err) => toast.error("Gateway test failed", humanize(err)),
  });

  const [url, setUrl] = useState(baseUrl ?? "");
  const [token, setToken_] = useState("");
  useEffect(() => {
    setUrl(baseUrl ?? "");
  }, [baseUrl]);

  const customSet = !!baseUrl;
  const effectiveUrl = baseUrl || defaultBaseUrl;
  const urlDirty = (url.trim() || null) !== (baseUrl ?? null);

  async function saveUrl() {
    await update.mutateAsync({ anthropic_base_url: url.trim() });
  }

  async function clearUrl() {
    setUrl("");
    await update.mutateAsync({ anthropic_base_url: "" });
  }

  async function saveToken() {
    if (token.trim().length < 4) return;
    await setToken.mutateAsync(token.trim());
    setToken_("");
  }

  async function clearStoredToken() {
    await clearToken.mutateAsync();
  }

  async function testConnection() {
    try {
      await testGateway.mutateAsync();
    } catch {
      // toast handled by onError
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="h-4 w-4" />
          Corporate gateway
        </CardTitle>
        <CardDescription>
          Optional. Route requests through an internal proxy or high-side endpoint.
          Leave blank to talk to{" "}
          <span className="font-mono text-xs">api.anthropic.com</span> directly.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Row
          label="Active endpoint"
          value={<span className="font-mono text-xs break-all">{effectiveUrl}</span>}
        />
        <Row
          label="Mode"
          value={
            customSet ? (
              <Badge variant="warning">custom gateway</Badge>
            ) : (
              <Badge variant="success">direct</Badge>
            )
          }
        />

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground block">
            Gateway base URL
          </label>
          <div className="flex gap-2">
            <Input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://api.ai.corp.example"
              autoComplete="off"
              disabled={loading}
            />
            <Button onClick={saveUrl} disabled={!urlDirty || update.isPending}>
              <Save className="h-4 w-4" />
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            {customSet && (
              <Button
                variant="outline"
                onClick={clearUrl}
                disabled={update.isPending}
                title="Revert to https://api.anthropic.com"
              >
                <Trash2 className="h-4 w-4" />
                Clear
              </Button>
            )}
          </div>
        </div>

        <div className="space-y-2 pt-2 border-t">
          <div className="flex items-center justify-between">
            <label className="text-xs font-medium text-muted-foreground block">
              Gateway auth token
            </label>
            {gatewayTokenSet ? (
              <Badge variant="success">stored</Badge>
            ) : envTokenSet ? (
              <Badge
                variant="outline"
                title="Using ANTHROPIC_AUTH_TOKEN from this process's environment"
              >
                from env
              </Badge>
            ) : (
              <Badge variant="warning">not stored</Badge>
            )}
          </div>
          <div className="flex gap-2">
            <Input
              type="password"
              value={token}
              onChange={(e) => setToken_(e.target.value)}
              placeholder={gatewayTokenSet ? "•••••••• (replace)" : "Bearer token"}
              autoComplete="off"
            />
            <Button
              onClick={saveToken}
              disabled={token.trim().length < 4 || setToken.isPending}
            >
              <Save className="h-4 w-4" />
              {setToken.isPending ? "Saving…" : "Save"}
            </Button>
            {gatewayTokenSet && (
              <Button
                variant="outline"
                onClick={clearStoredToken}
                disabled={clearToken.isPending}
                className="text-destructive hover:text-destructive"
                title="Remove stored gateway token from Credential Manager"
              >
                <Trash2 className="h-4 w-4" />
                Clear
              </Button>
            )}
          </div>
          <p className="text-[11px] text-muted-foreground">
            Precedence when a gateway URL is set: stored token →{" "}
            <span className="font-mono">ANTHROPIC_AUTH_TOKEN</span> env var →
            personal sk-ant key.
          </p>
          <p className="text-[11px] text-muted-foreground">
            <span className="font-medium">Where to find this:</span> the
            corporate gateway (AI Gateway, host{" "}
            <span className="font-mono">api.ai.example.com</span>) issues a{" "}
            <span className="font-mono">Bearer</span> JWT tied to your Example
            account. Get it from the Example AI platform that issued your gateway
            access, or copy the same token from an existing working config — e.g.
            the <span className="font-mono">Authorization: Bearer …</span> header
            on a Example MCP server in your{" "}
            <span className="font-mono">.claude.json</span>. Paste the value
            after <span className="font-mono">Bearer</span> (the token only).
          </p>
          <p className="text-[11px] text-muted-foreground">
            It's a long three-part JWT (dot-separated). Example shape:{" "}
            <span className="font-mono break-all">
              eyJ1Ijoiai5kb2Ui…7…KWWd7rt6…AcZuo
            </span>{" "}
            — paste the whole thing, not the truncated sample.
          </p>
          {customSet && (
            <div className="pt-1">
              <Button
                variant="outline"
                size="sm"
                onClick={testConnection}
                disabled={
                  (!gatewayTokenSet && !envTokenSet) || testGateway.isPending
                }
                title={
                  !gatewayTokenSet && !envTokenSet
                    ? "Set a gateway token or ANTHROPIC_AUTH_TOKEN first"
                    : "Send a tiny probe through the gateway (no fallback to personal key)"
                }
              >
                {testGateway.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <PlugZap className="h-4 w-4" />
                )}
                {testGateway.isPending ? "Testing…" : "Test gateway"}
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function DefaultsCard({
  defaultTester,
  provider,
  anthropicModel,
  anthropicKeySet,
  openaiModel,
  openaiKeySet,
  loading,
}: {
  defaultTester: string;
  provider: LlmProvider;
  anthropicModel: string;
  anthropicKeySet: boolean;
  openaiModel: string;
  openaiKeySet: boolean;
  loading: boolean;
}) {
  const update = useUpdateSettings({
    onSuccess: () => toast.success("Defaults saved", "Persisted to config.toml"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const anthropicModels = useAnthropicModels(anthropicKeySet);
  const openaiModels = useOpenAIModels(openaiKeySet);
  const [tester, setTester] = useState(defaultTester);
  const [activeProvider, setActiveProvider] = useState<LlmProvider>(provider);
  const [aModel, setAModel] = useState(anthropicModel);
  const [oModel, setOModel] = useState(openaiModel);

  useEffect(() => setTester(defaultTester), [defaultTester]);
  useEffect(() => setActiveProvider(provider), [provider]);
  useEffect(() => setAModel(anthropicModel), [anthropicModel]);
  useEffect(() => setOModel(openaiModel), [openaiModel]);

  const dirty =
    tester !== defaultTester ||
    activeProvider !== provider ||
    aModel !== anthropicModel ||
    oModel !== openaiModel;

  async function save() {
    await update.mutateAsync({
      default_tester: tester,
      llm_provider: activeProvider,
      anthropic_model: aModel,
      openai_model: oModel,
    });
  }

  // Each model field independently chooses between a live dropdown (if its
  // provider's /v1/models call succeeded AND the stored model is in the
  // list) or a free-text input (no key, corp gateway blocks /v1/models, or
  // a custom model id the live list doesn't expose).
  const aLive = anthropicModels.data?.models ?? [];
  const aInLive = !aModel || aLive.some((m) => m.id === aModel);
  const aDropdown =
    anthropicKeySet && anthropicModels.isSuccess && aLive.length > 0 && aInLive;

  const oLive = openaiModels.data?.models ?? [];
  const oInLive = !oModel || oLive.some((m) => m.id === oModel);
  const oDropdown =
    openaiKeySet && openaiModels.isSuccess && oLive.length > 0 && oInLive;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Form defaults &amp; active LLM</CardTitle>
        <CardDescription>
          Pre-populate the assessment form and pick which LLM the orchestrator dispatches to.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Field label="Default tester">
          <Input value={tester} onChange={(e) => setTester(e.target.value)} disabled={loading} />
        </Field>
        <Field label="Active LLM provider">
          <Select
            value={activeProvider}
            onValueChange={(v) => setActiveProvider(v as LlmProvider)}
            disabled={loading}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="anthropic">Anthropic (Claude)</SelectItem>
              <SelectItem value="openai">OpenAI (GPT)</SelectItem>
            </SelectContent>
          </Select>
        </Field>

        <Field
          label={
            <span className="flex items-center gap-2">
              Anthropic model
              {activeProvider === "anthropic" && (
                <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                  Active
                </Badge>
              )}
            </span>
          }
        >
          {aDropdown ? (
            <Select value={aModel} onValueChange={setAModel} disabled={loading}>
              <SelectTrigger>
                <SelectValue placeholder="Pick a model" />
              </SelectTrigger>
              <SelectContent>
                {aLive.map((m) => (
                  <SelectItem key={m.id} value={m.id}>
                    {m.display_name || m.id}
                    {m.display_name && m.display_name !== m.id ? (
                      <span className="text-xs text-muted-foreground ml-2 font-mono">
                        {m.id}
                      </span>
                    ) : null}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <Input
              value={aModel}
              onChange={(e) => setAModel(e.target.value)}
              placeholder="claude-opus-4-6"
              disabled={loading}
            />
          )}
          {!anthropicKeySet && (
            <p className="text-[11px] text-muted-foreground mt-1">
              Set an Anthropic API key above to populate the live model list.
            </p>
          )}
          {anthropicKeySet && anthropicModels.isLoading && (
            <p className="text-[11px] text-muted-foreground mt-1 flex items-center gap-1">
              <Loader2 className="h-3 w-3 animate-spin" /> Fetching live model list…
            </p>
          )}
          {anthropicKeySet && anthropicModels.isError && (
            <p className="text-[11px] text-muted-foreground mt-1">
              Live model list unavailable — type any model id by hand.{" "}
              <span className="text-destructive">
                {(anthropicModels.error as Error).message}
              </span>
            </p>
          )}
          {anthropicKeySet && anthropicModels.isSuccess && !aInLive && aModel && (
            <p className="text-[11px] text-muted-foreground mt-1">
              Current value <span className="font-mono">{aModel}</span> isn't in
              Anthropic's live list (custom gateway?). Free-text input shown so
              you can edit it.
            </p>
          )}
        </Field>

        <Field
          label={
            <span className="flex items-center gap-2">
              OpenAI model
              {activeProvider === "openai" && (
                <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                  Active
                </Badge>
              )}
            </span>
          }
        >
          {oDropdown ? (
            <Select value={oModel} onValueChange={setOModel} disabled={loading}>
              <SelectTrigger>
                <SelectValue placeholder="Pick a model" />
              </SelectTrigger>
              <SelectContent>
                {oLive.map((m) => (
                  <SelectItem key={m.id} value={m.id}>
                    {m.display_name || m.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : (
            <Input
              value={oModel}
              onChange={(e) => setOModel(e.target.value)}
              placeholder="gpt-5.1"
              disabled={loading}
            />
          )}
          {!openaiKeySet && (
            <p className="text-[11px] text-muted-foreground mt-1">
              Set an OpenAI API key above to populate the live model list.
            </p>
          )}
          {openaiKeySet && openaiModels.isLoading && (
            <p className="text-[11px] text-muted-foreground mt-1 flex items-center gap-1">
              <Loader2 className="h-3 w-3 animate-spin" /> Fetching live model list…
            </p>
          )}
          {openaiKeySet && openaiModels.isError && (
            <p className="text-[11px] text-muted-foreground mt-1">
              Live model list unavailable — type any model id by hand.{" "}
              <span className="text-destructive">
                {(openaiModels.error as Error).message}
              </span>
            </p>
          )}
          {openaiKeySet && openaiModels.isSuccess && !oInLive && oModel && (
            <p className="text-[11px] text-muted-foreground mt-1">
              Current value <span className="font-mono">{oModel}</span> isn't in
              OpenAI's live list (custom re-host?). Free-text input shown so you
              can edit it.
            </p>
          )}
        </Field>

        <div className="flex items-center gap-3 pt-1">
          <Button onClick={save} disabled={!dirty || update.isPending}>
            <Save className="h-4 w-4" />
            {update.isPending ? "Saving…" : "Save defaults"}
          </Button>
          {update.isSuccess && !dirty && (
            <span className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
              <Check className="h-3 w-3" /> Saved
            </span>
          )}
          {update.isError && (
            <span className="text-xs text-destructive">
              {(update.error as Error).message}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Audit v1 — citation co-emission toggle. Lives next to DefaultsCard because
// it's an assessor behavior knob, not a connector. The inline pill toggle
// mirrors the SharePoint card pattern so a user already familiar with that
// switch reads this one the same way. PUT goes to /api/settings with the
// `audit_citations_enabled` field; the GET response surfaces the current
// value under features.audit_citations.
// ---------------------------------------------------------------------------

function AuditCitationsCard({
  enabled,
  loading,
}: {
  enabled: boolean;
  loading: boolean;
}) {
  const toggle = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.audit_citations_enabled
          ? "Citation co-emission enabled"
          : "Citation co-emission disabled",
      ),
    onError: (err) => toast.error("Couldn't update setting", humanize(err)),
  });
  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <FileSearch className="h-4 w-4" />
              Audit citations
              <Badge variant="outline" className="ml-1 text-[10px]">
                v1
              </Badge>
              {enabled ? (
                <Badge variant="success" className="ml-1">
                  on
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  off
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Asks the model to emit per-claim citations linking narrative to
              evidence. Increases response length. Enable for audit-prep runs;
              disable for production until verdict regression is measured.
            </CardDescription>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={
              enabled ? "Disable audit citations" : "Enable audit citations"
            }
            onClick={() =>
              toggle.mutate({ audit_citations_enabled: !enabled })
            }
            disabled={toggle.isPending || loading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      <CardContent>
        <p className="text-xs text-muted-foreground">
          Trace + evidence-shown capture (model, prompt, response, chunks seen)
          runs unconditionally on every assessment — only the per-claim citation
          array depends on this flag. Open the <strong>Audit trail</strong>{" "}
          panel on any control to inspect what was captured.
        </p>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// OpenAI cards — symmetric to AnthropicKeyCard / CorporateGatewayCard. OpenAI
// has no separate gateway-token concept (corporate re-hosts accept the same
// OPENAI_API_KEY bearer), so the corporate card only surfaces the base_url
// override, not a second credential field.
// ---------------------------------------------------------------------------

function OpenAIKeyCard({
  keySet,
  envKeySet,
}: {
  keySet: boolean;
  envKeySet: boolean;
}) {
  const setKey = useSetOpenAIKey({
    onSuccess: () => toast.success("API key saved", "Stored in Windows Credential Manager"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const clearKey = useClearOpenAIKey({
    onSuccess: () => toast.success("API key cleared", "Removed from Credential Manager"),
    onError: (err) => toast.error("Clear failed", humanize(err)),
  });
  const testKey = useTestOpenAIKey({
    onSuccess: (res) =>
      toast.success(
        "Key works",
        `${res.model} replied "${res.reply}" (${res.input_tokens} in / ${res.output_tokens} out)`,
      ),
    onError: (err) => toast.error("Key test failed", humanize(err)),
  });
  const [key, setKey_] = useState("");

  async function save() {
    if (key.trim().length < 10) return;
    await setKey.mutateAsync(key.trim());
    setKey_("");
  }

  async function clear() {
    await clearKey.mutateAsync();
  }

  async function test() {
    try {
      await testKey.mutateAsync();
    } catch {
      // toast handled by onError
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-4 w-4" />
          Personal API key
        </CardTitle>
        <CardDescription>
          Separate Credential Manager slot from the Anthropic key — both providers
          can be configured at once.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Row
          label="Status"
          value={
            keySet ? (
              <Badge variant="success">key set</Badge>
            ) : envKeySet ? (
              <Badge
                variant="outline"
                title="Using OPENAI_API_KEY from this process's environment"
              >
                from env
              </Badge>
            ) : (
              <Badge variant="warning">not set</Badge>
            )
          }
        />

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground block">
            {keySet ? "Replace key" : "Set key"}
          </label>
          <div className="flex gap-2">
            <Input
              type="password"
              value={key}
              onChange={(e) => setKey_(e.target.value)}
              placeholder="sk-…"
              autoComplete="off"
            />
            <Button onClick={save} disabled={key.trim().length < 10 || setKey.isPending}>
              <Save className="h-4 w-4" />
              {setKey.isPending ? "Saving…" : "Save"}
            </Button>
          </div>
          {setKey.isError && (
            <p className="text-xs text-destructive">{(setKey.error as Error).message}</p>
          )}
          {setKey.isSuccess && (
            <p className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
              <Check className="h-3 w-3" /> Key saved to Credential Manager
            </p>
          )}
        </div>

        {(keySet || envKeySet) && (
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={test}
              disabled={testKey.isPending}
              title={
                keySet
                  ? "Send a tiny gpt-4o-mini probe to confirm the stored key reaches OpenAI."
                  : "Send a tiny gpt-4o-mini probe using the OPENAI_API_KEY env var."
              }
            >
              {testKey.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {testKey.isPending ? "Testing…" : "Test key"}
            </Button>
            {keySet && (
              <Button
                variant="outline"
                size="sm"
                onClick={clear}
                disabled={clearKey.isPending}
                className="text-destructive hover:text-destructive"
              >
                <Trash2 className="h-4 w-4" />
                {clearKey.isPending ? "Clearing…" : "Clear stored key"}
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function OpenAICorporateCard({
  baseUrl,
  defaultBaseUrl,
  gatewayTokenSet,
  envTokenSet,
  loading,
}: {
  baseUrl: string | null;
  defaultBaseUrl: string;
  gatewayTokenSet: boolean;
  envTokenSet: boolean;
  loading: boolean;
}) {
  const update = useUpdateSettings({
    onSuccess: () => toast.success("OpenAI base URL saved", "Persisted to config.toml"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const setToken = useSetOpenAIGatewayToken({
    onSuccess: () =>
      toast.success("Gateway token saved", "Stored in Windows Credential Manager"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const clearToken = useClearOpenAIGatewayToken({
    onSuccess: () => toast.success("Gateway token cleared", "Removed from Credential Manager"),
    onError: (err) => toast.error("Clear failed", humanize(err)),
  });
  // Dedicated gateway probe — refuses to fall back to the personal OpenAI
  // key so the verdict is unambiguous about (base_url + gateway token).
  const testGateway = useTestOpenAIGateway({
    onSuccess: (res) =>
      toast.success(
        "Gateway works",
        `${res.model} replied "${res.reply}" (${res.input_tokens} in / ${res.output_tokens} out)`,
      ),
    onError: (err) => toast.error("Gateway test failed", humanize(err)),
  });

  const [url, setUrl] = useState(baseUrl ?? "");
  const [token, setToken_] = useState("");
  useEffect(() => {
    setUrl(baseUrl ?? "");
  }, [baseUrl]);

  const customSet = !!baseUrl;
  const effectiveUrl = baseUrl || defaultBaseUrl;
  const urlDirty = (url.trim() || null) !== (baseUrl ?? null);

  async function saveUrl() {
    await update.mutateAsync({ openai_base_url: url.trim() });
  }

  async function clearUrl() {
    setUrl("");
    await update.mutateAsync({ openai_base_url: "" });
  }

  async function saveToken() {
    if (token.trim().length < 4) return;
    await setToken.mutateAsync(token.trim());
    setToken_("");
  }

  async function clearStoredToken() {
    await clearToken.mutateAsync();
  }

  async function testConnection() {
    try {
      await testGateway.mutateAsync();
    } catch {
      // toast handled by onError
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Server className="h-4 w-4" />
          Corporate gateway
        </CardTitle>
        <CardDescription>
          Optional. Point the OpenAI SDK at a corporate proxy or Azure OpenAI
          endpoint instead of{" "}
          <span className="font-mono text-xs">api.openai.com/v1</span>.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Row
          label="Active endpoint"
          value={<span className="font-mono text-xs break-all">{effectiveUrl}</span>}
        />
        <Row
          label="Mode"
          value={
            customSet ? (
              <Badge variant="warning">custom endpoint</Badge>
            ) : (
              <Badge variant="success">direct</Badge>
            )
          }
        />

        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground block">
            OpenAI base URL
          </label>
          <div className="flex gap-2">
            <Input
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://openai.corp.example/v1"
              autoComplete="off"
              disabled={loading}
            />
            <Button onClick={saveUrl} disabled={!urlDirty || update.isPending}>
              <Save className="h-4 w-4" />
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            {customSet && (
              <Button
                variant="outline"
                onClick={clearUrl}
                disabled={update.isPending}
                title="Revert to https://api.openai.com/v1"
              >
                <Trash2 className="h-4 w-4" />
                Clear
              </Button>
            )}
          </div>
        </div>

        <div className="space-y-2 pt-2 border-t">
          <div className="flex items-center justify-between">
            <label className="text-xs font-medium text-muted-foreground block">
              Gateway auth token
            </label>
            {gatewayTokenSet ? (
              <Badge variant="success">stored</Badge>
            ) : envTokenSet ? (
              <Badge
                variant="outline"
                title="Using OPENAI_AUTH_TOKEN from this process's environment"
              >
                from env
              </Badge>
            ) : (
              <Badge variant="warning">not stored</Badge>
            )}
          </div>
          <div className="flex gap-2">
            <Input
              type="password"
              value={token}
              onChange={(e) => setToken_(e.target.value)}
              placeholder={gatewayTokenSet ? "•••••••• (replace)" : "Bearer token"}
              autoComplete="off"
            />
            <Button
              onClick={saveToken}
              disabled={token.trim().length < 4 || setToken.isPending}
            >
              <Save className="h-4 w-4" />
              {setToken.isPending ? "Saving…" : "Save"}
            </Button>
            {gatewayTokenSet && (
              <Button
                variant="outline"
                onClick={clearStoredToken}
                disabled={clearToken.isPending}
                className="text-destructive hover:text-destructive"
                title="Remove stored gateway token from Credential Manager"
              >
                <Trash2 className="h-4 w-4" />
                Clear
              </Button>
            )}
          </div>
          <p className="text-[11px] text-muted-foreground">
            Precedence when a base URL is set: stored token →{" "}
            <span className="font-mono">OPENAI_AUTH_TOKEN</span> env var →
            personal OpenAI key.
          </p>
          <p className="text-[11px] text-muted-foreground">
            <span className="font-medium">Where to find this:</span> the
            corporate gateway (AI Gateway, host{" "}
            <span className="font-mono">api.ai.example.com</span>) issues a{" "}
            <span className="font-mono">Bearer</span> JWT tied to your Example
            account. Get it from the Example AI platform that issued your gateway
            access, or copy the same token from an existing working config — e.g.
            the <span className="font-mono">Authorization: Bearer …</span> header
            on a Example MCP server in your{" "}
            <span className="font-mono">.claude.json</span>. Paste the value
            after <span className="font-mono">Bearer</span> (the token only).
          </p>
          <p className="text-[11px] text-muted-foreground">
            It's a long three-part JWT (dot-separated). Example shape:{" "}
            <span className="font-mono break-all">
              eyJ1Ijoiai5kb2Ui…7…KWWd7rt6…AcZuo
            </span>{" "}
            — paste the whole thing, not the truncated sample.
          </p>
          {customSet && (
            <div className="pt-1">
              <Button
                variant="outline"
                size="sm"
                onClick={testConnection}
                disabled={
                  (!gatewayTokenSet && !envTokenSet) || testGateway.isPending
                }
                title={
                  !gatewayTokenSet && !envTokenSet
                    ? "Set a gateway token or OPENAI_AUTH_TOKEN first"
                    : "Send a tiny probe through the gateway (no fallback to personal key)"
                }
              >
                {testGateway.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <PlugZap className="h-4 w-4" />
                )}
                {testGateway.isPending ? "Testing…" : "Test gateway"}
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * 800-53 catalog aggregation status. This is the NIST-800-53-specific
 * summary card; future frameworks (CSF 2.0, 800-171, FedRAMP
 * baselines, ISO 27001/27002, CIS Controls) each get their own peer card
 * with framework-appropriate layers — e.g. CSF doesn't have CCIs.
 *
 * For 800-53 specifically, what the Catalogs page exposes per row is the
 * join of three layers: the base framework, the DISA CCI global enrichment
 * that adds CCI-* objectives + NIST references, and zero-or-more overlays
 * (program-specific control mappings like SDA Enterprise Services Controls,
 * plus Customer Responsibility Matrices). This card surfaces all three
 * side-by-side so the user can see at a glance which layers are loaded.
 *
 * No actions here; mutations live in the cards below. Purely a status read.
 */
/**
 * Layered status row used by CcisOverlayStatusCard. Header sits on one line
 * (label + status badge); per-framework or per-overlay detail flows into
 * indented full-width sub-rows below — keeps tabular numbers readable
 * instead of cramming them into a narrow right column.
 */
function LayerRow({
  label,
  status,
  children,
}: {
  label: string;
  status: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div className="py-3 first:pt-0 last:pb-0">
      <div className="flex items-center justify-between gap-4">
        <span className="font-medium">{label}</span>
        {status}
      </div>
      {children ? <div className="mt-2 pl-4 space-y-1">{children}</div> : null}
    </div>
  );
}

/**
 * One indented detail row: framework/overlay name on the left, optional
 * count on the right. Two-column grid so the counts line up vertically
 * across rows even when names differ in length.
 */
function DetailLine({ name, value }: { name: string; value?: string }) {
  return (
    <div className="grid grid-cols-[1fr_auto] items-baseline gap-x-4 text-xs text-muted-foreground">
      <span className="truncate" title={name}>
        {name}
      </span>
      {value ? <span className="tabular-nums">{value}</span> : null}
    </div>
  );
}

function CcisOverlayStatusCard() {
  const status = useCatalogStatus();
  const baselines = useBaselines();
  const setEnabled = useSetFrameworkEnabled();
  const data = status.data;

  const frameworks = data?.frameworks ?? [];
  const sources = data?.requirement_sources ?? [];
  // CRM and OTHER overlays are Baseline rows (source_type === "crm" /
  // "other"), NOT RequirementSource rows — they're loaded by
  // baselines/crm_xlsx.py and baselines/other_xlsx.py and never flow
  // through the PSC (program-controls) loader. Merge them with PSC
  // overlays here so the global Catalogs view matches the assessor's
  // mental model ("all overlays") instead of splitting along an
  // implementation-detail seam.
  const crmBaselines = (baselines.data ?? []).filter(
    (b) => b.source_type === "crm",
  );
  const otherBaselines = (baselines.data ?? []).filter(
    (b) => b.source_type === "other",
  );
  type OverlayItem = {
    key: string;
    name: string;
    // "psc" is the user-facing label for the storage value "program_controls".
    kind: "psc" | "crm" | "other";
    refreshed_at?: string;
  };
  const overlays: OverlayItem[] = [
    ...sources.map(
      (s): OverlayItem => ({
        key: `rs-${s.id}`,
        name: s.name,
        kind: "psc",
        // RequirementSource exposes `loaded_at` (set/refreshed by the PSC
        // loader); CRM Baseline rows expose `refreshed_at`. Surface both
        // under the same key so PSC rows render a date matching CRM rows
        // instead of an empty placeholder.
        refreshed_at: s.loaded_at ?? undefined,
      }),
    ),
    ...crmBaselines.map(
      (b): OverlayItem => ({
        key: `b-${b.id}`,
        name: b.name,
        kind: "crm",
        refreshed_at: b.refreshed_at,
      }),
    ),
    // OTHER overlays are inert — registered as Baseline rows so the
    // file is visible/attachable on Workbooks, but no resolver runs
    // against them during assessment. Render with a subdued chip + a
    // "no resolver" hint so the user understands the difference.
    ...otherBaselines.map(
      (b): OverlayItem => ({
        key: `b-${b.id}`,
        name: b.name,
        kind: "other",
        refreshed_at: b.refreshed_at,
      }),
    ),
  ];

  // DISA CCI enrichment is a global overlay but it lights up CCI rows
  // per-framework (each loaded 800-53 catalog binds its own subset). Show
  // the per-framework counts so the user can see at a glance which
  // catalog mapping is hydrated, instead of a single aggregate total that
  // hides the breakdown when both r4 and r5 are loaded.
  const frameworksWithCcis = frameworks.filter((f) => f.objective_count > 0);
  const cciLoaded = frameworksWithCcis.length > 0;
  const hasFramework = frameworks.length > 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layers className="h-4 w-4" />
          Installed catalogs — load &amp; activate
        </CardTitle>
        <CardDescription>
          Each framework row has a toggle to enable or disable it. Disabling
          a catalog hides it from the compliance-target pickers (the framework
          stays loaded; it can be re-enabled at any time without re-importing).
          Use the loaders below to add or refresh any missing layer.
        </CardDescription>
      </CardHeader>
      <CardContent className="text-sm divide-y">
        {/* Layer 1: every loaded framework catalog gets its OWN section
            with its enable/disable toggle in the section header — NOT
            stacked as indented sub-rows under a single "NIST 800-53"
            heading. Disabling (migration 0012 `enabled`) drops the
            framework from the active Catalog list and from every
            assess/baseline picker — i.e. the toggle turns off all
            framework-related functionality — while keeping the catalog
            loaded so it can be re-enabled without re-importing. `enabled`
            is optional for back-compat — treat missing as enabled. */}
        {hasFramework ? (
          frameworks.map((f, i) => {
            const isEnabled = f.enabled !== false;
            const isPending =
              setEnabled.isPending &&
              setEnabled.variables?.frameworkId === f.id;
            return (
              <LayerRow
                key={f.id ?? i}
                label={`${f.name} ${f.version}`}
                status={
                  <div className="flex items-center gap-3">
                    {isEnabled ? (
                      <Badge variant="success">enabled</Badge>
                    ) : (
                      <Badge variant="subtle">disabled</Badge>
                    )}
                    {isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Switch
                        checked={isEnabled}
                        disabled={setEnabled.isPending}
                        aria-label={`${isEnabled ? "Disable" : "Enable"} ${f.name} ${f.version}`}
                        onCheckedChange={(next) =>
                          setEnabled.mutate(
                            { frameworkId: f.id, enabled: next },
                            {
                              onSuccess: () =>
                                toast.success(
                                  `${f.name} ${f.version} ${next ? "enabled" : "disabled"}`,
                                ),
                              onError: (e) => toast.error(humanize(e)),
                            },
                          )
                        }
                      />
                    )}
                  </div>
                }
              >
                <DetailLine
                  name={
                    isEnabled
                      ? "active in compliance-target pickers"
                      : "hidden from pickers (catalog still loaded)"
                  }
                  value={`${f.control_count.toLocaleString()} controls`}
                />
              </LayerRow>
            );
          })
        ) : (
          <LayerRow
            label="NIST 800-53"
            status={
              status.isLoading ? (
                <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
              ) : (
                <Badge variant="warning">not loaded</Badge>
              )
            }
          >
            {!status.isLoading ? (
              <div className="text-xs text-muted-foreground inline-flex items-center gap-1 pt-1">
                <AlertCircle className="h-3 w-3 shrink-0" />
                load NIST 800-53r5 from the Workbooks screen first
              </div>
            ) : null}
          </LayerRow>
        )}

        {/* Layer 2: DISA CCI enrichment */}
        <LayerRow
          label="DISA CCI"
          status={
            status.isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            ) : cciLoaded ? (
              <Badge variant="success">loaded</Badge>
            ) : (
              <Badge variant="warning">not loaded</Badge>
            )
          }
        >
          {cciLoaded ? (
            frameworksWithCcis.map((f) => (
              <DetailLine
                key={f.id}
                name={`${f.name} ${f.version}`}
                value={`${f.objective_count.toLocaleString()} objectives`}
              />
            ))
          ) : !status.isLoading ? (
            <div className="text-xs text-muted-foreground inline-flex items-center gap-1 pt-1">
              <AlertCircle className="h-3 w-3 shrink-0" />
              load DISA CCI before any program overlay
            </div>
          ) : null}
        </LayerRow>

        {/* Layer 3: overlays — both program-specific control mappings and
            CRMs (FedRAMP-style Customer Responsibility Matrix). They live
            in different tables (RequirementSource vs Baseline rows with
            source_type="crm") but from the assessor's view they're the
            same thing: "extra context layered onto the workbook." Merged
            into one row with a small kind tag so the count actually
            matches what the user sees on the per-workbook overlay chips.
            Read-only inventory; attach/detach lives on ManageOverlaysDialog. */}
        <LayerRow
          label="Overlays"
          status={
            status.isLoading || baselines.isLoading ? (
              <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
            ) : overlays.length === 0 ? (
              <Badge variant="warning">none loaded</Badge>
            ) : (
              <Badge variant="success">
                {overlays.length} overlay{overlays.length === 1 ? "" : "s"}
              </Badge>
            )
          }
        >
          {overlays.map((o) => {
            // Three chip tones — PSC/CRM are active resolvers, OTHER is
            // inert and gets a subdued chip + a secondary hint so the
            // user understands the file is metadata-only until a
            // resolver is programmed for its shape.
            const chipClass =
              o.kind === "other"
                ? "rounded border border-dashed border-muted-foreground/40 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground/70"
                : "rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground";
            return (
              <div
                key={o.key}
                className="grid grid-cols-[auto_1fr_auto] items-baseline gap-x-2 text-xs text-muted-foreground"
              >
                <span className={chipClass}>{o.kind}</span>
                <span className="truncate" title={o.name}>
                  {o.name}
                  {o.kind === "other" && (
                    <span className="ml-2 text-[10px] italic text-muted-foreground/70">
                      inert · no resolver
                    </span>
                  )}
                </span>
                {o.refreshed_at ? (
                  <span className="tabular-nums">
                    {new Date(o.refreshed_at).toLocaleDateString()}
                  </span>
                ) : (
                  <span />
                )}
              </div>
            );
          })}
        </LayerRow>
      </CardContent>
    </Card>
  );
}

function DisaCciCard() {
  const frameworks = useFrameworks();
  const load = useLoadDisaCci({
    onSuccess: (res) =>
      toast.success(
        "CCI catalog loaded",
        `Inserted ${res.inserted} · Updated ${res.updated} · Skipped ${res.skipped} · Deprecated ${res.deprecated}`,
      ),
    onError: (err) => toast.error("CCI load failed", humanize(err)),
  });
  const [sourcePath, setSourcePath] = useState("");
  const [frameworkId, setFrameworkId] = useState<number | undefined>();

  const fws = frameworks.data ?? [];

  // Auto-select the only framework once loaded
  useEffect(() => {
    if (!frameworkId && fws.length === 1) {
      setFrameworkId(fws[0].id);
    }
  }, [frameworkId, fws]);

  const native = hasNativeBridge();

  async function browse() {
    if (!native) return;
    // Accept both the NIST CSRC xlsx (preferred — DISA stopped publishing the
    // standalone XML mid-2026) and the archived U_CCI_List.xml for users who
    // kept an older download. "All Files" stays as a fallback so the picker
    // never renders blank when the user lands in a folder without a matching
    // extension.
    const path = await window.ccis!.openFile([
      { name: "CCI source (NIST CSRC xlsx or archived DISA xml)", extensions: ["xlsx", "xml"] },
      { name: "NIST CSRC mapping spreadsheet", extensions: ["xlsx"] },
      { name: "Archived DISA CCI List", extensions: ["xml"] },
      { name: "All Files", extensions: ["*"] },
    ]);
    if (path) setSourcePath(path);
  }

  async function loadCatalog() {
    if (!sourcePath.trim() || frameworkId === undefined) return;
    try {
      await load.mutateAsync({ source_path: sourcePath.trim(), framework_id: frameworkId });
    } catch {
      // toast handled by onError
    }
  }

  const result = load.data;
  const canSubmit = !!sourcePath.trim() && frameworkId !== undefined && !load.isPending;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileCode2 className="h-4 w-4" />
          DISA CCI List
        </CardTitle>
        <CardDescription>
          One-time global enrichment. Adds CCI definitions, NIST references,
          and deprecation status to every 800-53 objective. Required before
          PSC overlays (Program-Specific Controls — imported below) can
          resolve their CCI references.
          Preferred source is the NIST CSRC{" "}
          <span className="font-mono text-xs">stig-mapping-to-nist-800-53.xlsx</span>{" "}
          (DISA discontinued the standalone XML mid-2026); an archived{" "}
          <span className="font-mono text-xs">U_CCI_List.xml</span> still works
          if you have one.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Field label="Framework">
          {fws.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No frameworks loaded — load NIST 800-53r5 from the Workbooks screen first.
            </p>
          ) : (
            <Select
              value={frameworkId !== undefined ? String(frameworkId) : ""}
              onValueChange={(v) => setFrameworkId(v ? Number(v) : undefined)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Pick framework" />
              </SelectTrigger>
              <SelectContent>
                {fws.map((f) => (
                  <SelectItem key={f.id} value={String(f.id)}>
                    {f.name} {f.version}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </Field>

        <Field label="CCI source (.xlsx or .xml)">
          <div className="flex gap-2">
            <Input
              value={sourcePath}
              onChange={(e) => setSourcePath(e.target.value)}
              placeholder={
                native
                  ? "C:/path/to/stig-mapping-to-nist-800-53.xlsx"
                  : "Paste absolute path — browser mode has no native file picker"
              }
              autoComplete="off"
            />
            {native && (
              <Button variant="outline" onClick={browse} disabled={load.isPending}>
                <FolderOpen className="h-4 w-4" />
                Browse…
              </Button>
            )}
          </div>
        </Field>

        <div className="flex items-center gap-3 pt-1">
          <Button onClick={loadCatalog} disabled={!canSubmit}>
            {load.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <FileCode2 className="h-4 w-4" />
            )}
            {load.isPending ? "Loading…" : "Load CCI Catalog"}
          </Button>
          {load.isSuccess && result && (
            <span className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
              <Check className="h-3 w-3" />
              Inserted {result.inserted} · Updated {result.updated} · Skipped {result.skipped} ·
              Deprecated {result.deprecated}
            </span>
          )}
          {load.isError && (
            <span className="text-xs text-destructive">{(load.error as Error).message}</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

/**
 * Presentational wrapper for one framework row inside AdditionalFrameworksCard.
 * Renders title + an "already loaded" badge + a subtitle, then whatever load
 * controls the caller passes as children. No hooks — safe to render in a list.
 */
function FwRow({
  title,
  subtitle,
  loaded,
  children,
}: {
  title: string;
  subtitle: React.ReactNode;
  loaded: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-md border p-3 space-y-2">
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium">{title}</span>
          {loaded && (
            <span className="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400">
              <Check className="h-3 w-3" /> Loaded
            </span>
          )}
        </div>
        <p className="text-xs text-muted-foreground">{subtitle}</p>
      </div>
      {children}
    </div>
  );
}

/**
 * AdditionalFrameworksCard — loads the non-800-53 control catalogs that round
 * out the framework bundle. Mirrors DisaCciCard's load-card pattern.
 *
 * Two flavors, by how the source is obtained:
 *   - Public-domain downloads (NIST CSF 2.0, NIST 800-171 r3): one-click
 *     online load; an optional local-OSCAL Browse covers air-gapped runs.
 *   - License-aware (ISO 27001, CIS v8, PCI DSS, SOC 2): the control text is
 *     copyrighted, so the app neither bundles nor downloads it. Point each at
 *     your own exported .csv / .json of the catalog you're licensed for.
 *
 * "Loaded" badges derive from useFrameworks() by (name[, version]); a loaded
 * framework can still be enabled/disabled in CcisOverlayStatusCard above.
 */
function AdditionalFrameworksCard() {
  const frameworks = useFrameworks();
  const fws = frameworks.data ?? [];
  const native = hasNativeBridge();

  const isLoaded = (name: string, version?: string) =>
    fws.some(
      (f) => f.name === name && (version === undefined || f.version === version),
    );

  // --- public-domain downloads -----------------------------------------
  const csf = useLoadNistCsf({
    onSuccess: (fw) => toast.success("Framework loaded", `${fw.name} ${fw.version}`),
    onError: (err) => toast.error("CSF load failed", humanize(err)),
  });
  const sp171 = useLoadNist800171({
    onSuccess: (fw) => toast.success("Framework loaded", `${fw.name} ${fw.version}`),
    onError: (err) => toast.error("800-171 load failed", humanize(err)),
  });

  // --- license-aware (required local path) ------------------------------
  const iso = useLoadIso27001({
    onSuccess: (fw) => toast.success("Framework loaded", `${fw.name} ${fw.version}`),
    onError: (err) => toast.error("ISO 27001 load failed", humanize(err)),
  });
  const cis = useLoadCisV8({
    onSuccess: (fw) => toast.success("Framework loaded", `${fw.name} ${fw.version}`),
    onError: (err) => toast.error("CIS v8 load failed", humanize(err)),
  });
  const pci = useLoadPciDss({
    onSuccess: (fw) => toast.success("Framework loaded", `${fw.name} ${fw.version}`),
    onError: (err) => toast.error("PCI DSS load failed", humanize(err)),
  });
  const soc2 = useLoadSoc2({
    onSuccess: (fw) => toast.success("Framework loaded", `${fw.name} ${fw.version}`),
    onError: (err) => toast.error("SOC 2 load failed", humanize(err)),
  });
  const [isoPath, setIsoPath] = useState("");
  const [cisPath, setCisPath] = useState("");
  const [pciPath, setPciPath] = useState("");
  const [soc2Path, setSoc2Path] = useState("");

  // Pick a licensed-catalog export and stash the path. Most license-aware
  // loaders accept a .csv / .json export; CIS additionally accepts the native
  // CIS Controls workbook (.xlsx), so callers can widen the filter.
  async function browseExport(
    setter: (p: string) => void,
    extensions: string[] = ["csv", "json"],
  ) {
    if (!native) return;
    const label = `Catalog export (${extensions.map((e) => "." + e).join(" / ")})`;
    const path = await window.ccis!.openFile([
      { name: label, extensions },
      { name: "All Files", extensions: ["*"] },
    ]);
    if (path) setter(path);
  }

  // Pick a local OSCAL JSON for an air-gapped download-style load, then fire
  // the mutation immediately with that path (no intermediate input field).
  async function browseAndLoadOscal(
    mutate: (path: string) => void,
  ) {
    if (!native) return;
    const path = await window.ccis!.openFile([
      { name: "OSCAL Catalog (.json)", extensions: ["json"] },
    ]);
    if (path) mutate(path);
  }

  const has171 = isLoaded("NIST SP 800-171", "Rev 3");

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layers className="h-4 w-4" />
          Additional framework catalogs
        </CardTitle>
        <CardDescription>
          Load the non-800-53 catalogs in the framework bundle. Each becomes a
          first-class framework you can bind a workbook to and toggle above.
          NIST CSF and 800-171 are public-domain one-click downloads; ISO, CIS,
          and PCI control text is licensed, so point those at your own
          exported <span className="font-mono text-xs">.csv</span> /{" "}
          <span className="font-mono text-xs">.json</span>.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* NIST CSF 2.0 — public-domain OSCAL download */}
        <FwRow
          title="NIST Cybersecurity Framework 2.0"
          subtitle="Public-domain OSCAL download. Subcategories crosswalk to 800-53."
          loaded={isLoaded("NIST Cybersecurity Framework", "2.0")}
        >
          <div className="flex gap-2">
            <Button onClick={() => csf.mutate(undefined)} disabled={csf.isPending}>
              {csf.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Layers className="h-4 w-4" />
              )}
              {csf.isPending ? "Loading…" : "Download (online)"}
            </Button>
            {native && (
              <Button
                variant="outline"
                onClick={() => browseAndLoadOscal((p) => csf.mutate(p))}
                disabled={csf.isPending}
              >
                <FolderOpen className="h-4 w-4" />
                Local OSCAL…
              </Button>
            )}
          </div>
        </FwRow>

        {/* NIST 800-171 Rev 3 — public-domain OSCAL download */}
        <FwRow
          title="NIST SP 800-171 Rev 3"
          subtitle="CUI-protection baseline for non-federal systems."
          loaded={has171}
        >
          <div className="flex gap-2">
            <Button onClick={() => sp171.mutate(undefined)} disabled={sp171.isPending}>
              {sp171.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Layers className="h-4 w-4" />
              )}
              {sp171.isPending ? "Loading…" : "Download (online)"}
            </Button>
            {native && (
              <Button
                variant="outline"
                onClick={() => browseAndLoadOscal((p) => sp171.mutate(p))}
                disabled={sp171.isPending}
              >
                <FolderOpen className="h-4 w-4" />
                Local OSCAL…
              </Button>
            )}
          </div>
        </FwRow>

        {/* License-aware catalogs — required local .csv / .json export */}
        <LicensedFwRow
          title="ISO/IEC 27001:2022"
          subtitle="Annex A controls (93). Accepts a structured Annex A workbook (.xlsx) or a .csv / .json export."
          loaded={isLoaded("ISO/IEC 27001", "2022")}
          path={isoPath}
          setPath={setIsoPath}
          onBrowse={() => browseExport(setIsoPath, ["csv", "json", "xlsx"])}
          onLoad={() => iso.mutate({ path: isoPath.trim() })}
          pending={iso.isPending}
          native={native}
        />
        <LicensedFwRow
          title="CIS Controls v8"
          subtitle="CIS Critical Security Controls (IG1/IG2/IG3). Accepts the native CIS workbook (.xlsx) or a .csv / .json export."
          loaded={isLoaded("CIS Controls", "v8")}
          path={cisPath}
          setPath={setCisPath}
          onBrowse={() => browseExport(setCisPath, ["csv", "json", "xlsx"])}
          onLoad={() => cis.mutate({ path: cisPath.trim() })}
          pending={cis.isPending}
          native={native}
        />
        <LicensedFwRow
          title="PCI DSS 4.0"
          subtitle="Payment-card requirements & testing procedures workbook export."
          loaded={isLoaded("PCI DSS", "4.0")}
          path={pciPath}
          setPath={setPciPath}
          onBrowse={() => browseExport(setPciPath)}
          onLoad={() => pci.mutate({ path: pciPath.trim() })}
          pending={pci.isPending}
          native={native}
        />
        <LicensedFwRow
          title="SOC 2"
          subtitle="AICPA Trust Services Criteria export. Attestation engagement, not a certification."
          loaded={fws.some((f) => f.name === "SOC 2")}
          path={soc2Path}
          setPath={setSoc2Path}
          onBrowse={() => browseExport(setSoc2Path)}
          onLoad={() => soc2.mutate({ path: soc2Path.trim() })}
          pending={soc2.isPending}
          native={native}
        />
      </CardContent>
    </Card>
  );
}

/**
 * One license-aware framework row: required .csv / .json path Input + Browse +
 * Load. Pure presentational (no hooks) — the parent owns the mutation.
 */
function LicensedFwRow({
  title,
  subtitle,
  loaded,
  path,
  setPath,
  onBrowse,
  onLoad,
  pending,
  native,
}: {
  title: string;
  subtitle: React.ReactNode;
  loaded: boolean;
  path: string;
  setPath: (p: string) => void;
  onBrowse: () => void;
  onLoad: () => void;
  pending: boolean;
  native: boolean;
}) {
  const canSubmit = !!path.trim() && !pending;
  return (
    <FwRow title={title} subtitle={subtitle} loaded={loaded}>
      <div className="flex gap-2">
        <Input
          value={path}
          onChange={(e) => setPath(e.target.value)}
          placeholder={
            native
              ? "C:/path/to/catalog-export.csv"
              : "Paste absolute path — browser mode has no native file picker"
          }
          autoComplete="off"
        />
        {native && (
          <Button variant="outline" onClick={onBrowse} disabled={pending}>
            <FolderOpen className="h-4 w-4" />
            Browse…
          </Button>
        )}
        <Button onClick={onLoad} disabled={!canSubmit}>
          {pending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <FileCode2 className="h-4 w-4" />
          )}
          {pending ? "Loading…" : "Load"}
        </Button>
      </div>
    </FwRow>
  );
}

/**
 * Unified overlay import — single front door for any overlay xlsx.
 *
 * Classifier-driven flow: auto-detects file shape as CRM / PSC / OTHER
 * via ``baselines.overlay_classifier`` and dispatches to the right loader.
 * The sheet picker + Kind override ("Force PSC", etc.) cover every case
 * the legacy typed loader did — including multi-sheet PSC workbooks
 * (T1TL Ground vs SV) and forcing a misclassified file through a specific
 * loader. To replace an existing overlay by name, delete it from the
 * "Loaded overlays" list above and re-import.
 *
 * The "Loaded overlays" inventory sits at the top of the card so the user
 * can see what's already loaded before importing again.
 */
function ImportOverlayCard() {
  const frameworks = useFrameworks();
  const sources = useRequirementSources();
  // CRM/OTHER overlays land in the Baseline table (source_type="crm"/"other"),
  // NOT RequirementSource — mirror the merge already done by
  // CcisOverlayStatusCard so "Loaded overlays" reflects every import that
  // went through this card regardless of which loader the classifier picked.
  // Without this, a CRM imported via Workbooks→Manage (or here) is silently
  // absent from the list right above the Import button even though it was
  // saved successfully.
  const baselines = useBaselines();
  const workbooks = useWorkbooks();

  const [xlsxPath, setXlsxPath] = useState("");
  const [frameworkId, setFrameworkId] = useState<number | undefined>();
  const [overrideName, setOverrideName] = useState("");
  const [kindHint, setKindHint] = useState<OverlayKind | "auto">("auto");
  // Sheet picker — empty string = "Auto-pick" (let classify_overlay's first-
  // match-wins choose). User can override to target a specific tab; the T1TL
  // workbook is the motivating case (Ground vs SV both PSC-shaped, aggregate
  // classifier always returns Ground without this override).
  const [sheetOverride, setSheetOverride] = useState("");
  // Per-path sheet preview — fires only when xlsxPath is non-empty. The
  // per-path query key means switching the file naturally invalidates the
  // dropdown without manual cache clears.
  const sheetsQuery = useOverlaySheets(xlsxPath.trim());

  // Scope label — only CRM imports require one. The canonical list (cloud
  // service providers) plus an "Other…" sentinel that swaps the Select for a
  // free-text Input. "On-Premises" is reserved: the assessor derives the
  // on-prem residual implicitly, so it's rejected here.
  const scopeLabels = useScopeLabels();
  const [scopeChoice, setScopeChoice] = useState<string>("");
  const [scopeOther, setScopeOther] = useState<string>("");
  const otherLabel = scopeLabels.data?.other ?? "Other";
  const onPremLabel = scopeLabels.data?.on_prem ?? "On-Premises";

  // Reset the sheet override whenever the file path changes — a sheet name
  // valid for one workbook may not exist in another, and silently keeping
  // a stale override would surface as a confusing "sheet not found" import
  // error.
  useEffect(() => {
    setSheetOverride("");
  }, [xlsxPath]);

  const importMut = useImportOverlay({
    onSuccess: (res) => {
      // Per-kind toast subtitle — surface the loader's most useful
      // counter so the user can see at a glance whether the import
      // actually did what they expected (CRM: how many controls landed;
      // PSC: how many CCI mappings; OTHER: the "no resolver" warning so
      // it's not silently inert without notice).
      const kindUpper = res.kind.toUpperCase();
      let subtitle = res.name;
      if (res.kind === "crm" && res.controls_in_scope !== undefined) {
        subtitle = `${res.name} · ${res.controls_in_scope} controls in scope`;
      } else if (res.kind === "psc" && res.maps_written !== undefined) {
        const sheet = res.sheet_name ? ` · sheet "${res.sheet_name}"` : "";
        subtitle = `${res.name} · ${res.maps_written} CCI mappings${sheet}`;
      } else if (res.kind === "other") {
        const warn =
          res.warnings.find((w) => w.toLowerCase().includes("resolver")) ??
          res.warnings[0] ??
          "no resolver registered for this file's shape";
        subtitle = `${res.name} · ${warn}`;
      }
      toast.success(`Classified as ${kindUpper}`, subtitle);
    },
    onError: (err) => toast.error("Overlay import failed", humanize(err)),
  });

  const del = useDeleteRequirementSource({
    onSuccess: (r) =>
      toast.success(
        `${r.name} removed`,
        `${r.maps_removed} requirement mappings deleted`,
      ),
    onError: (err) => toast.error("Overlay delete failed", humanize(err)),
  });

  // CRM/OTHER overlays are Baselines — different delete endpoint. Backend
  // rejects with 409 if a workbook still points at the baseline as its
  // primary scope; humanize() surfaces the verbatim detail so the toast
  // can name the workbook that needs unattaching first.
  const delBaseline = useDeleteBaseline({
    onSuccess: (r) =>
      toast.success(
        `${r.name} removed`,
        `${r.controls_removed} controls, ${r.overlay_attachments_removed} workbook attachments cleared`,
      ),
    onError: (err) => toast.error("Overlay delete failed", humanize(err)),
  });

  const fws = frameworks.data ?? [];

  // MRU framework default: skip if user has already picked one or no
  // frameworks are loaded. Otherwise prefer the framework of the most-
  // recently-opened workbook (the assessment the user is working on),
  // then the framework of the most-recently-loaded overlay (which
  // framework they've been overlaying into), then fall back to the
  // first framework in the list. Each preference checks that its
  // candidate is still present in fws — a stale workbook pointing at
  // a deleted framework shouldn't pin frameworkId to an invalid id.
  useEffect(() => {
    if (frameworkId !== undefined || fws.length === 0) return;

    const wbMru = (workbooks.data ?? [])
      .filter((w) => w.framework_id != null)
      .sort((a, b) =>
        (b.last_opened ?? "").localeCompare(a.last_opened ?? ""),
      )[0];
    if (
      wbMru?.framework_id != null &&
      fws.some((f) => f.id === wbMru.framework_id)
    ) {
      setFrameworkId(wbMru.framework_id);
      return;
    }

    const srcMru = [...(sources.data ?? [])].sort((a, b) =>
      (b.loaded_at ?? "").localeCompare(a.loaded_at ?? ""),
    )[0];
    if (srcMru && fws.some((f) => f.id === srcMru.framework_id)) {
      setFrameworkId(srcMru.framework_id);
      return;
    }

    setFrameworkId(fws[0].id);
  }, [frameworkId, fws, workbooks.data, sources.data]);

  const native = hasNativeBridge();

  async function browse() {
    if (!native) return;
    const path = await window.ccis!.openFile([
      { name: "Overlay workbook", extensions: ["xlsx", "xlsm"] },
      { name: "All Files", extensions: ["*"] },
    ]);
    if (path) setXlsxPath(path);
  }

  // Mirror the backend's effective-kind resolution so the scope-label field
  // only appears when this import will actually classify as a CRM. Honor an
  // explicit kindHint override first; otherwise fall back to the previewed
  // per-sheet candidate (when a sheet is targeted) or the aggregate auto-pick.
  const effectiveKind: OverlayKind | "auto" = (() => {
    if (kindHint !== "auto") return kindHint;
    const sheets = sheetsQuery.data;
    if (!sheets) return "auto";
    if (sheetOverride.trim()) {
      const picked = sheets.sheets.find((s) => s.name === sheetOverride.trim());
      return (picked?.candidate_kind as OverlayKind | undefined) ?? "auto";
    }
    return (sheets.auto_pick.kind as OverlayKind | undefined) ?? "auto";
  })();
  const needsScopeLabel = effectiveKind === "crm";
  const resolvedScopeLabel =
    scopeChoice === otherLabel ? scopeOther.trim() : scopeChoice.trim();
  const scopeReady =
    !needsScopeLabel ||
    (resolvedScopeLabel !== "" && resolvedScopeLabel !== onPremLabel);

  async function doImport() {
    if (!xlsxPath.trim() || frameworkId === undefined) return;
    if (!scopeReady) return;
    try {
      await importMut.mutateAsync({
        framework_id: frameworkId,
        path: xlsxPath.trim(),
        name: overrideName.trim() || null,
        kind_hint: kindHint === "auto" ? null : kindHint,
        // Empty string = "Auto-pick" → let the classifier choose. The
        // backend route treats sheet_name as an explicit PSC override
        // (ignored+warned for CRM/OTHER).
        sheet_name: sheetOverride.trim() || null,
        // Scope label is CRM-only; null for PSC/OTHER (backend ignores it).
        scope_label: needsScopeLabel ? resolvedScopeLabel : null,
      });
    } catch {
      // toast handled by onError
    }
  }

  const importResult = importMut.data;
  const canImport =
    !!xlsxPath.trim() &&
    frameworkId !== undefined &&
    !importMut.isPending &&
    scopeReady;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Layers className="h-4 w-4" />
          Import overlay
        </CardTitle>
        <CardDescription>
          One front door for any overlay spreadsheet — a CRM (Customer
          Responsibility Matrix), a PSC (Program-Specific Controls) sheet,
          or any other program-supplied xlsx. The classifier reads the
          header row, picks the right loader, and registers the file. If
          it doesn't recognize the shape, the file imports as <em>OTHER</em>
          {" "}— visible and attachable on the Workbooks page, but inert
          until a resolver is programmed for it.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Loaded overlays — list+delete. Sits at the top of the card so
            the user can see what's already loaded before deciding whether
            to import again or replace an existing entry. Merges three
            storage backends (PSC RequirementSource + CRM/OTHER Baseline)
            so the list mirrors every kind the classifier dispatches to —
            see CcisOverlayStatusCard for the canonical merge pattern.
            Hidden on first-run when nothing is loaded yet. */}
        {(() => {
          type OverlayListItem = {
            key: string;
            id: number;
            name: string;
            framework_id: number;
            kind: "psc" | "crm" | "other";
            timestamp: string | null | undefined;
            detail: string;
            scope_label?: string | null;
          };
          const pscItems: OverlayListItem[] = (sources.data ?? []).map((s) => ({
            key: `rs-${s.id}`,
            id: s.id,
            name: s.name,
            framework_id: s.framework_id,
            kind: "psc" as const,
            timestamp: s.loaded_at,
            detail: `${s.map_count} mappings`,
          }));
          const baselineItems: OverlayListItem[] = (baselines.data ?? [])
            .filter((b) => b.source_type === "crm" || b.source_type === "other")
            .map((b) => ({
              key: `b-${b.id}`,
              id: b.id,
              name: b.name,
              framework_id: b.framework_id,
              kind: b.source_type === "crm" ? ("crm" as const) : ("other" as const),
              timestamp: b.refreshed_at,
              detail:
                b.source_type === "crm" ? "CRM scope" : "no resolver registered",
              scope_label: b.scope_label,
            }));
          // PSC + CRM + OTHER, newest first by load/refresh timestamp so a
          // just-imported overlay appears at the top of the list.
          const items = [...pscItems, ...baselineItems].sort((a, b) =>
            (b.timestamp ?? "").localeCompare(a.timestamp ?? ""),
          );
          if (items.length === 0) return null;
          return (
            <div className="space-y-2">
              <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Loaded overlays ({items.length})
              </div>
              <ul className="divide-y divide-border rounded-md border">
                {items.map((it) => {
                  const fwName = fws.find((f) => f.id === it.framework_id);
                  const loaded = it.timestamp
                    ? new Date(it.timestamp).toLocaleString()
                    : "—";
                  const isDeleting =
                    it.kind === "psc"
                      ? del.isPending && del.variables === it.id
                      : delBaseline.isPending && delBaseline.variables?.id === it.id;
                  const anyDeleting = del.isPending || delBaseline.isPending;
                  const kindLabel = it.kind.toUpperCase();
                  return (
                    <li
                      key={it.key}
                      className="flex items-center justify-between gap-3 px-3 py-2 text-sm"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="font-medium truncate">{it.name}</span>
                          <span className="shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                            {kindLabel}
                          </span>
                          {it.scope_label ? (
                            <span className="shrink-0 rounded border px-1.5 py-0.5 text-[10px] text-muted-foreground">
                              {it.scope_label}
                            </span>
                          ) : null}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {fwName
                            ? `${fwName.name} ${fwName.version}`
                            : `framework #${it.framework_id}`}
                          {" · "}
                          {it.detail}
                          {" · loaded "}
                          {loaded}
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        disabled={anyDeleting}
                        onClick={() => {
                          // Per-kind confirmation copy + delete dispatch.
                          // PSC: removes mappings only — CCIs/framework stay.
                          // CRM/OTHER: removes the Baseline row; backend 409s
                          // if any workbook still attaches it (toast surfaces
                          // the workbook name verbatim).
                          if (it.kind === "psc") {
                            if (
                              window.confirm(
                                `Delete overlay "${it.name}"? This removes ${it.detail}. The underlying CCIs and framework stay loaded.`,
                              )
                            ) {
                              del.mutate(it.id);
                            }
                          } else {
                            const kindWord = it.kind === "crm" ? "CRM" : "OTHER";
                            if (
                              window.confirm(
                                `Delete ${kindWord} overlay "${it.name}"? This removes the baseline and any workbook attachments to it. Fails if a workbook still uses it as its primary scope.`,
                              )
                            ) {
                              delBaseline.mutate({ id: it.id });
                            }
                          }
                        }}
                        aria-label={`Delete overlay ${it.name}`}
                      >
                        {isDeleting ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <Trash2 className="h-4 w-4 text-destructive" />
                        )}
                      </Button>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })()}

        {/* --- shared inputs (framework + xlsx path) ----------------- */}
        <Field label="Framework">
          {fws.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No frameworks loaded — load NIST 800-53r5 from the Workbooks
              screen first.
            </p>
          ) : (
            <Select
              value={frameworkId !== undefined ? String(frameworkId) : ""}
              onValueChange={(v) => setFrameworkId(v ? Number(v) : undefined)}
            >
              <SelectTrigger>
                <SelectValue placeholder="Pick framework" />
              </SelectTrigger>
              <SelectContent>
                {fws.map((f) => (
                  <SelectItem key={f.id} value={String(f.id)}>
                    {f.name} {f.version}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        </Field>

        <Field label="Overlay xlsx">
          <div className="flex gap-2">
            <Input
              value={xlsxPath}
              onChange={(e) => setXlsxPath(e.target.value)}
              placeholder={
                native
                  ? "C:/path/to/overlay.xlsx"
                  : "Paste absolute path — browser mode has no native file picker"
              }
              autoComplete="off"
            />
            {native && (
              <Button
                variant="outline"
                onClick={browse}
                disabled={importMut.isPending}
              >
                <FolderOpen className="h-4 w-4" />
                Browse…
              </Button>
            )}
          </div>
        </Field>

        {/* --- auto flow ------------------------------------------------- */}
        <Field label="Display name (optional)">
          <Input
            value={overrideName}
            onChange={(e) => setOverrideName(e.target.value)}
            placeholder="Leave blank to use the file name"
            autoComplete="off"
          />
        </Field>

        <Field label="Kind">
          {/* "Auto-detect" is the default — the classifier sniffs the
              header row and picks CRM / PSC / OTHER. The override is for
              cases where a future overlay format trips the heuristics or
              the user wants to force inert-OTHER registration. */}
          <Select
            value={kindHint}
            onValueChange={(v) => setKindHint(v as OverlayKind | "auto")}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="auto">Auto-detect (recommended)</SelectItem>
              <SelectItem value="crm">Force CRM</SelectItem>
              <SelectItem value="psc">Force PSC</SelectItem>
              <SelectItem value="other">Force OTHER (inert)</SelectItem>
            </SelectContent>
          </Select>
        </Field>

        {/* Sheet picker — only meaningful when a path is set and the file
            could be parsed. Multi-sheet PSC workbooks (T1TL ships with
            both Ground and SV) need this override because the aggregate
            classifier is first-match-wins and always returns Ground. The
            "Auto-pick" option reproduces the classifier's choice — we
            label it with the sheet name so the user knows what they'd
            get if they leave it alone. */}
        {xlsxPath.trim() && (
          <Field label="Sheet">
            {sheetsQuery.isLoading ? (
              <p className="text-xs text-muted-foreground flex items-center gap-1.5">
                <Loader2 className="h-3 w-3 animate-spin" />
                Reading sheets…
              </p>
            ) : sheetsQuery.isError ? (
              <p className="text-xs text-destructive">
                {(sheetsQuery.error as Error).message}
              </p>
            ) : sheetsQuery.data ? (
              <Select
                // Radix Select forbids empty-string values on SelectItem
                // (it throws at runtime), so we use "__auto__" as the
                // sentinel for "let the classifier choose" and unmap it
                // on the way into setSheetOverride.
                value={sheetOverride === "" ? "__auto__" : sheetOverride}
                onValueChange={(v) =>
                  setSheetOverride(v === "__auto__" ? "" : v)
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__auto__">
                    {(() => {
                      const auto = sheetsQuery.data.auto_pick;
                      if (auto.sheet_name) {
                        return `Auto-pick (${auto.sheet_name} · ${auto.kind.toUpperCase()})`;
                      }
                      return "Auto-pick (no candidate sheet — will import as OTHER)";
                    })()}
                  </SelectItem>
                  {sheetsQuery.data.sheets.map((s) => {
                    const label = s.candidate_kind
                      ? `${s.name} · ${s.candidate_kind.toUpperCase()}`
                      : `${s.name} · no match`;
                    return (
                      <SelectItem key={s.name} value={s.name}>
                        {label}
                      </SelectItem>
                    );
                  })}
                </SelectContent>
              </Select>
            ) : null}
          </Field>
        )}

        <Field label="Scope label">
          {needsScopeLabel ? (
            <div className="space-y-2">
              <Select value={scopeChoice} onValueChange={(v) => setScopeChoice(v)}>
                <SelectTrigger>
                  <SelectValue placeholder="Pick a scope label" />
                </SelectTrigger>
                <SelectContent>
                  {(scopeLabels.data?.canonical ?? []).map((label: string) => (
                    <SelectItem key={label} value={label}>
                      {label}
                    </SelectItem>
                  ))}
                  <SelectItem value={otherLabel}>{otherLabel}…</SelectItem>
                </SelectContent>
              </Select>
              {scopeChoice === otherLabel && (
                <Input
                  value={scopeOther}
                  onChange={(e) => setScopeOther(e.target.value)}
                  placeholder="Custom scope label (e.g. IBM Cloud for Government)"
                  autoComplete="off"
                />
              )}
              {resolvedScopeLabel === onPremLabel && (
                <p className="text-xs text-destructive">
                  "{onPremLabel}" is reserved — the assessor derives the
                  on-prem implementation automatically. Pick a cloud scope
                  label (or "{otherLabel}…" for a custom value).
                </p>
              )}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              Scope label only required for CRMs.
            </p>
          )}
        </Field>

        <div className="flex items-center gap-3 pt-1">
          <Button onClick={doImport} disabled={!canImport}>
            {importMut.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Layers className="h-4 w-4" />
            )}
            {importMut.isPending ? "Importing…" : "Import overlay"}
          </Button>
          {importMut.isSuccess && importResult && (
            <span className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
              <Check className="h-3 w-3" />
              Classified as <span className="font-mono uppercase">{importResult.kind}</span>
              {importResult.kind === "psc" && importResult.maps_written !== undefined
                ? ` · ${importResult.maps_written} mappings`
                : ""}
              {importResult.kind === "crm" && importResult.controls_in_scope !== undefined
                ? ` · ${importResult.controls_in_scope} controls`
                : ""}
            </span>
          )}
          {importMut.isError && (
            <span className="text-xs text-destructive">
              {(importMut.error as Error).message}
            </span>
          )}
        </div>

        {/* Surface warnings inline — OTHER imports always carry the
            "no resolver" warning, and CRM/PSC may surface their own
            (e.g. unmapped CCIs or unknown control ids). */}
        {importMut.isSuccess &&
          importResult &&
          importResult.warnings.length > 0 && (
            <ul className="space-y-1 text-xs text-muted-foreground">
              {importResult.warnings.slice(0, 4).map((w, i) => (
                <li key={i} className="flex gap-1.5">
                  <AlertCircle className="h-3 w-3 mt-0.5 shrink-0" />
                  <span>{w}</span>
                </li>
              ))}
              {importResult.warnings.length > 4 && (
                <li className="italic">
                  …and {importResult.warnings.length - 4} more.
                </li>
              )}
            </ul>
          )}

      </CardContent>
    </Card>
  );
}

/**
 * SharePoint connector — wires Settings → SharePoint card to the FastAPI
 * device-code flow.
 *
 * Two-phase test:
 *   1. First click → backend spawns MSAL device-code on a thread, returns
 *      `pending:true` with `user_code` + `verification_uri`. We render the
 *      sign-in panel and keep the response object in state.
 *   2. After the user signs in at microsoft.com/devicelogin, they click Test
 *      again → backend finds a cached refresh token, returns `ok:true` with
 *      site title + scan-root verification.
 *
 * Save is decoupled from Test — the user can save credentials without
 * authenticating, and we can authenticate against override values without
 * persisting them. Mirrors the Anthropic-key pattern (set ≠ test).
 */
/**
 * Privacy / data-handling notice for the Connectors tab.
 *
 * Be honest about what the app does and doesn't do, and frame as
 * operator guidance instead of declarative guarantees:
 *  - The app reads from wherever you point it (workbook on a local
 *    drive, evidence in a Downloads folder, SharePoint library). Source
 *    files stay where they live — only the SQLite index and the
 *    extracted-text cache (under ~/.cybersecurity-assessor/) are owned
 *    by this app. SharePoint pulls cache to a temp dir, not into the
 *    config folder.
 *  - Each connector below opts in to its own destination.
 *  - For the real CUI question — what happens when control text +
 *    evidence excerpts go to Claude — see the CUI routing card on the
 *    APIs tab.
 */
/**
 * Privacy tab — the canonical place for "where does my data go" questions.
 *
 * Two layers that previously lived in two separate cards (Data Handling on
 * Connectors, CUI Routing on APIs) and got conflated by users:
 *
 *   1. Vendor data-handling policy (zero-retention / no-training). The
 *      public Anthropic and OpenAI APIs already promise this by default
 *      for API traffic — most users' actual privacy concern stops here.
 *
 *   2. Regulatory authorization (FedRAMP / IL-level / CUI handling).
 *      A vendor's "we won't train on it" policy is NOT the same as a
 *      compliance authorization. This only matters when the assessment
 *      itself involves CUI — i.e. DoD baselines (800-171, FedRAMP,
 *      DoD Cloud Computing SRG IL2-IL6). For 800-53 against a non-CUI
 *      system, the public API is fine.
 *
 * Frame it as two layers so the user can see which one applies to them.
 */
function PrivacyTab() {
  return (
    <div className="space-y-4">
      <Card className="border-emerald-200 dark:border-emerald-900/50 bg-emerald-50/40 dark:bg-emerald-950/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-emerald-900 dark:text-emerald-200">
            <ShieldCheck className="h-4 w-4" />
            Local-first by default
          </CardTitle>
          <CardDescription className="text-emerald-900/80 dark:text-emerald-200/80 space-y-2">
            <p>
              The app runs entirely on this machine. Source artifacts —
              workbooks, evidence PDFs, scan exports — stay where you put
              them; the app never copies them into its own folder. Only
              the SQLite index and the extracted-text cache live under{" "}
              <span className="font-mono text-xs">~/.cybersecurity-assessor/</span>.
            </p>
            <p>
              With all connectors off (the default), the only outbound
              traffic is the call to your configured LLM provider when you
              assess a control. Each connector on the <strong>Connectors</strong>{" "}
              tab is opt-in — enabling one adds traffic to that specific
              destination (SharePoint tenant, ACAS, eMASS) and nothing else.
            </p>
          </CardDescription>
        </CardHeader>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" />
            What the LLM provider does with your prompts
          </CardTitle>
          <CardDescription className="space-y-2">
            <p>
              Assessing a control sends prompt content — control text,
              narrative excerpts, evidence snippets — to whichever LLM
              endpoint is configured on the <strong>APIs</strong> tab.
            </p>
            <p>
              Both <span className="font-mono text-xs">api.anthropic.com</span>{" "}
              and <span className="font-mono text-xs">api.openai.com</span>{" "}
              run API traffic under a <strong>zero-retention,
              no-training</strong> policy by default. Prompts are not
              persisted beyond the immediate response and are not used to
              train models. For most assessments — internal policy review,
              non-CUI 800-53 work, lab-system evaluations — that is the
              relevant privacy guarantee.
            </p>
            <p className="text-xs text-muted-foreground">
              See Anthropic&apos;s commercial terms and OpenAI&apos;s API
              data-usage policy for the authoritative statements; this
              app does not modify or override them.
            </p>
          </CardDescription>
        </CardHeader>
      </Card>

      <Card className="border-amber-200 dark:border-amber-900/50 bg-amber-50/40 dark:bg-amber-950/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-amber-900 dark:text-amber-200">
            <ShieldCheck className="h-4 w-4" />
            When CUI is in scope — DoD baselines only
          </CardTitle>
          <CardDescription className="text-amber-900/80 dark:text-amber-200/80 space-y-2">
            <p>
              Vendor policy (above) is not the same as a compliance{" "}
              <em>authorization</em>. The public Anthropic and OpenAI
              endpoints are not FedRAMP / DoD-IL authorized destinations,
              so they cannot lawfully process Controlled Unclassified
              Information.
            </p>
            <p>
              This restriction applies <strong>only when the assessment
              itself involves CUI</strong> — in practice, the DoD-aligned
              baselines:
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li>NIST SP 800-171 (CUI in non-federal systems)</li>
              <li>FedRAMP Moderate / High when handling CUI</li>
              <li>DoD Cloud Computing SRG IL4 / IL5 / IL6 systems</li>
            </ul>
            <p>
              For those, point the <strong>Corporate gateway URL</strong>{" "}
              on the APIs tab at an authorized destination before
              assessing: AWS Bedrock in GovCloud / IL5 (Claude models),
              Azure OpenAI in Azure Government, or an internal
              organization proxy that fronts an authorized backend. The
              app forwards your bearer token to that URL — it cannot
              verify the destination is itself authorized.
            </p>
            <p>
              For a regular 800-53 assessment of a non-CUI system, no
              special routing is required.
            </p>
          </CardDescription>
        </CardHeader>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" />
            Credential storage
          </CardTitle>
          <CardDescription className="space-y-2">
            <p>
              LLM API keys and gateway tokens are stored in{" "}
              <strong>Windows Credential Manager</strong> via the{" "}
              <span className="font-mono text-xs">keyring</span> library
              — never written to disk in plain text and never embedded
              in workbooks, exports, or POAM bundles.
            </p>
            <p>
              SharePoint authentication uses MSAL device-code flow
              against a public-client app registration. No client secret
              is stored anywhere; the encrypted token cache lives under{" "}
              <span className="font-mono text-xs">~/.cybersecurity-assessor/</span>{" "}
              and can be deleted from the Connectors tab.
            </p>
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  );
}

/**
 * About tab — what makes this app different, framed as selling points
 * rather than architecture. Aimed at someone deciding whether to use it,
 * not someone maintaining it. Keep the bullets focused on outcomes the
 * operator feels (faster, less risky, fewer copies of CUI) instead of
 * the internals that produce them (sqlmodel, FastAPI, etc.).
 */
function AboutTab() {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Sparkles className="h-4 w-4" />
            Why this exists
          </CardTitle>
          <CardDescription className="space-y-2">
            <p>
              A control assessment is a judgment call: does the evidence
              we have actually satisfy the requirement? But that judgment
              gets buried under the work around it — hunting for the right
              artifact across SharePoint and shared drives, reconciling
              what a prior assessor wrote, mapping CCIs to policies and
              STIGs, and retyping the same narratives a dozen ways.
            </p>
            <p>
              This app keeps the assessor doing the judgment and lets
              software do the rest.
            </p>
          </CardDescription>
        </CardHeader>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-4 w-4" />
            What makes it different
          </CardTitle>
          <CardDescription className="space-y-3">
            <div>
              <p className="font-medium text-foreground">
                Evidence-first, not template-first
              </p>
              <p>
                Drop a folder of evidence — PDFs, DOCX, PPTX, XLSX,
                STIG <span className="font-mono text-xs">.ckl</span> /{" "}
                <span className="font-mono text-xs">.cklb</span>, XCCDF,
                Nessus, ACAS — and the app indexes and tags each artifact
                against the CCIs it likely supports. By the time you open
                a control, the relevant evidence is already attached.
              </p>
            </div>
            <div>
              <p className="font-medium text-foreground">
                Works the way your team already works
              </p>
              <p>
                Edits the live catalog in place — comments, named
                ranges, merged cells, conditional formatting, and macros
                all survive a round-trip. No export-then-reimport step,
                no parallel copy that drifts from the source of truth,
                no rebuilding what the program already standardized on.
              </p>
            </div>
            <div>
              <p className="font-medium text-foreground">
                Knows the eMASS dialect
              </p>
              <p>
                Built-in rules recognize the recurring patterns —
                inheritance from a hosting provider, supersession of
                older STIGs, stock-language prior results — and resolve
                them deterministically without burning an LLM call.
                Surprising or ambiguous CCIs go to the model; everything
                else is fast and free.
              </p>
            </div>
            <div>
              <p className="font-medium text-foreground">
                POAMs that match how teams actually fix things
              </p>
              <p>
                Non-compliant findings cluster by remediation boundary —
                shared owner, shared fix, shared schedule — instead of
                exploding into one POAM per CCI. Round-trips through the
                eMASS RMF POAM template so what you ship is what
                stakeholders already know how to read.
              </p>
            </div>
            <div>
              <p className="font-medium text-foreground">
                Multi-framework on one engine
              </p>
              <p>
                The catalog and evidence model are framework-agnostic
                from day one. NIST 800-53 today; CSF 2.0, 800-171,
                FedRAMP, ISO 27001, CIS Controls, SOC 2 layer in without
                rewriting the rest of the app.
              </p>
            </div>
          </CardDescription>
        </CardHeader>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" />
            Built for CUI workflows from the start
          </CardTitle>
          <CardDescription className="space-y-2">
            <p>
              Everything runs locally. Evidence files never leave the
              machine. API keys live in Windows Credential Manager. The
              one external connector that ships today (SharePoint) is
              off by default and opt-in per session; planned connectors
              (Outlook, Tenable, eMASS) will follow the same model.
            </p>
            <p>
              When CUI is in scope — DoD baselines like 800-171
              or FedRAMP — the LLM endpoint is configurable so prompt
              traffic routes through an authorized gateway (Bedrock in
              GovCloud, Azure OpenAI in Gov) instead of the public API.
              See the <strong>Privacy</strong> tab for the full breakdown.
            </p>
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  );
}

function ArcherConnectorCard() {
  const settings = useSettings();
  const status = useArcherStatus();
  const update = useUpdateSettings({
    onSuccess: () => toast.success("Archer settings saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const test = useTestArcher({
    onError: (err) => toast.error("Test failed", humanize(err)),
  });
  const setPassword = useSetArcherPassword({
    onSuccess: () => {
      toast.success("Archer password saved");
      setPasswordInput("");
    },
    onError: (err) => toast.error("Couldn't save password", humanize(err)),
  });
  const clearPassword = useClearArcherPassword({
    onSuccess: (res) =>
      toast.success(
        "Archer password cleared",
        res.cleared ? "Removed from keyring" : "No stored password to remove",
      ),
    onError: (err) => toast.error("Couldn't clear password", humanize(err)),
  });

  // Feature-flag toggle. Defaults false; when off, the card body collapses
  // to a one-sentence notice. Header + pill stay visible so the user can
  // flip the switch without scrolling.
  const enabled = settings.data?.features?.archer ?? false;
  const toggleEnabled = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.enable_archer
          ? "Archer connector enabled"
          : "Archer connector disabled",
      ),
    onError: (err) => toast.error("Couldn't update connector", humanize(err)),
  });

  const conn = settings.data?.archer;
  const [instanceUrl, setInstanceUrl] = useState("");
  const [instanceName, setInstanceName] = useState("");
  const [username, setUsername] = useState("");
  const [domain, setDomain] = useState("");
  const [passwordInput, setPasswordInput] = useState("");

  useEffect(() => {
    if (!conn) return;
    setInstanceUrl(conn.instance_url ?? "");
    setInstanceName(conn.instance_name ?? "");
    setUsername(conn.username ?? "");
    setDomain(conn.domain ?? "");
  }, [conn]);

  const dirty =
    !!conn &&
    ((instanceUrl.trim().replace(/\/+$/, "") || null) !==
      (conn.instance_url ?? null) ||
      (instanceName.trim() || null) !== (conn.instance_name ?? null) ||
      (username.trim() || null) !== (conn.username ?? null) ||
      (domain.trim() || null) !== (conn.domain ?? null));

  async function save() {
    await update.mutateAsync({
      archer_instance_url: instanceUrl.trim(),
      archer_instance_name: instanceName.trim(),
      archer_username: username.trim(),
      archer_domain: domain.trim(),
    });
  }

  async function runTest() {
    try {
      // Empty fields fall back to saved config server-side via cfg.load_config().
      await test.mutateAsync({
        instance_url: instanceUrl.trim() || undefined,
        instance_name: instanceName.trim() || undefined,
        username: username.trim() || undefined,
        domain: domain.trim() || undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  async function savePassword() {
    if (!passwordInput) return;
    try {
      await setPassword.mutateAsync({
        password: passwordInput,
        instance_name: instanceName.trim() || undefined,
        username: username.trim() || undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  const result = test.data;
  const configured = !!status.data?.configured;
  const passwordSet = !!status.data?.password_set;
  const reachable = !!result?.ok;
  const detected = result?.detected;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" />
              Archer
              {!enabled ? (
                <Badge variant="outline" className="ml-1">
                  disabled
                </Badge>
              ) : reachable ? (
                <Badge variant="success" className="ml-1">
                  connected
                </Badge>
              ) : configured && passwordSet ? (
                <Badge variant="warning" className="ml-1">
                  configured, untested
                </Badge>
              ) : configured ? (
                <Badge variant="warning" className="ml-1">
                  password missing
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not configured
                </Badge>
              )}
              {enabled && detected?.username && detected?.instance_name && (
                <Badge variant="outline" className="ml-1">
                  {detected.username}@{detected.instance_name}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              RSA Archer (GRC) — pulls controls, findings, and POAM records as
              an evidence source via the Archer REST API.
            </CardDescription>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={enabled ? "Disable Archer connector" : "Enable Archer connector"}
            onClick={() => toggleEnabled.mutate({ enable_archer: !enabled })}
            disabled={toggleEnabled.isPending || settings.isLoading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      {!enabled ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Connector is off. Turn it on to point at an Archer instance and
            ingest GRC records as evidence.
          </p>
        </CardContent>
      ) : (
        <CardContent className="space-y-3">
          <Field label="Instance URL">
            <Input
              value={instanceUrl}
              onChange={(e) => setInstanceUrl(e.target.value)}
              placeholder="https://archer.example.gov"
              autoComplete="off"
            />
          </Field>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="Instance name">
              <Input
                value={instanceName}
                onChange={(e) => setInstanceName(e.target.value)}
                placeholder="PROD"
                autoComplete="off"
              />
            </Field>
            <Field label="Username">
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="svc-cyberassessor"
                autoComplete="off"
              />
            </Field>
          </div>

          <Field label="Domain (optional Active-Directory domain; most deployments leave blank)">
            <Input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder=""
              autoComplete="off"
            />
          </Field>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button onClick={save} disabled={!dirty || update.isPending}>
              {update.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={runTest}
              disabled={
                test.isPending ||
                !instanceUrl.trim() ||
                !instanceName.trim() ||
                !username.trim() ||
                !passwordSet
              }
              title={
                passwordSet
                  ? "Authenticate against Archer with the stored credentials."
                  : "Save a password below before testing the connection."
              }
            >
              {test.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
          </div>

          {/* Password card — kept separate from Save so the keyring write
              doesn't piggyback on the generic SettingsUpdate (which would
              push the password through GET responses on the round-trip). */}
          <div className="rounded-md border bg-muted/30 px-3 py-2 space-y-2">
            <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground flex items-center gap-1">
              <KeyRound className="h-3 w-3" />
              Password
              {passwordSet && (
                <Badge variant="success" className="ml-1 text-[10px]">
                  stored
                </Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Stored in the OS keyring under{" "}
              <span className="font-mono">cybersecurity-assessor.archer</span>{" "}
              keyed by <span className="font-mono">{username || "username"}@{instanceName || "instance"}</span>. Never written to config.toml.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                type="password"
                value={passwordInput}
                onChange={(e) => setPasswordInput(e.target.value)}
                placeholder={passwordSet ? "Replace stored password…" : "Enter password"}
                autoComplete="off"
                className="max-w-xs"
              />
              <Button
                size="sm"
                onClick={savePassword}
                disabled={
                  !passwordInput ||
                  !instanceName.trim() ||
                  !username.trim() ||
                  setPassword.isPending
                }
              >
                {setPassword.isPending ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Save className="h-3 w-3" />
                )}
                Save password
              </Button>
              {passwordSet && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => clearPassword.mutateAsync()}
                  disabled={clearPassword.isPending}
                  className="text-destructive hover:text-destructive"
                >
                  {clearPassword.isPending ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Trash2 className="h-3 w-3" />
                  )}
                  Clear
                </Button>
              )}
            </div>
          </div>

          {result && (
            <div
              className={
                result.ok
                  ? "rounded-md border border-emerald-300/60 bg-emerald-50 dark:border-emerald-700/60 dark:bg-emerald-950/30 px-3 py-2 text-sm space-y-1"
                  : "rounded-md border border-destructive/60 bg-destructive/5 px-3 py-2 text-sm space-y-1"
              }
            >
              <div
                className={
                  result.ok
                    ? "flex items-center gap-1 text-emerald-700 dark:text-emerald-400 text-xs font-semibold uppercase tracking-wide"
                    : "flex items-center gap-1 text-destructive text-xs font-semibold uppercase tracking-wide"
                }
              >
                {result.ok ? <Check className="h-3 w-3" /> : null}
                {result.ok ? "Connection OK" : "Connection problem"}
              </div>
              <p className="text-sm">{result.message}</p>
              {result.detected?.instance_url && (
                <Row
                  label="instance_url"
                  value={
                    <span className="font-mono text-xs">
                      {result.detected.instance_url}
                    </span>
                  }
                />
              )}
              {result.detected?.instance_name && (
                <Row
                  label="instance_name"
                  value={
                    <span className="font-mono text-xs">
                      {result.detected.instance_name}
                    </span>
                  }
                />
              )}
              {result.detected?.username && (
                <Row
                  label="username"
                  value={
                    <span className="font-mono text-xs">
                      {result.detected.username}
                    </span>
                  }
                />
              )}
              {result.disabled && (
                <p className="text-xs text-muted-foreground pt-1">
                  Connector feature flag is off — see{" "}
                  <span className="font-mono">
                    ARCHER_CONNECTOR_ENABLED
                  </span>{" "}
                  env-var or the toggle above.
                </p>
              )}
            </div>
          )}

          {!configured && (
            <p className="text-xs text-muted-foreground">
              Fill in the Archer instance URL, name, and username above, save,
              then enter a password and click{" "}
              <span className="font-medium">Test connection</span>.
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

function GitlabConnectorCard() {
  const settings = useSettings();
  const status = useGitlabStatus();
  const update = useUpdateSettings({
    onSuccess: () => toast.success("GitLab settings saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const test = useTestGitlab({
    onError: (err) => toast.error("Test failed", humanize(err)),
  });

  // Feature-flag toggle. Defaults false in backend Config (v0.1 ships
  // local-only). When off, we hide the entire configuration body — the
  // assessor doesn't want GitLab evidence ingest, so showing server URL /
  // project list / ref / globs is just noise.
  const enabled = settings.data?.features?.gitlab ?? false;
  const toggleEnabled = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.enable_gitlab
          ? "GitLab connector enabled"
          : "GitLab connector disabled",
      ),
    onError: (err) => toast.error("Couldn't update connector", humanize(err)),
  });

  // Local form state — initialized once settings load, edits diff against
  // saved values so Save knows there's something to commit. The PAT is NEVER
  // accepted over HTTP; the user pastes it into the GITLAB_TOKEN env var or
  // the OS keyring slot keyed by hostname. token_set on /status reflects only
  // whether a token is stored for the configured host.
  const gl = settings.data?.gitlab;
  const [serverUrl, setServerUrl] = useState("");
  const [projectPaths, setProjectPaths] = useState("");
  const [ref, setRef] = useState("");
  const [includeGlobs, setIncludeGlobs] = useState("");

  useEffect(() => {
    if (!gl) return;
    setServerUrl(gl.server_url ?? "");
    setProjectPaths((gl.project_paths ?? []).join("\n"));
    setRef(gl.ref ?? "");
    setIncludeGlobs((gl.include_globs ?? []).join("\n"));
  }, [gl]);

  // Parse multi-line textareas into trimmed string arrays; empty lines drop.
  const parsedProjectPaths = projectPaths
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  const parsedIncludeGlobs = includeGlobs
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);

  const savedProjectPaths = gl?.project_paths ?? [];
  const savedIncludeGlobs = gl?.include_globs ?? [];

  const dirty =
    !!gl &&
    ((serverUrl.trim() || null) !== (gl.server_url ?? null) ||
      JSON.stringify(parsedProjectPaths) !== JSON.stringify(savedProjectPaths) ||
      (ref.trim() || null) !== (gl.ref ?? null) ||
      JSON.stringify(parsedIncludeGlobs) !== JSON.stringify(savedIncludeGlobs));

  async function save() {
    await update.mutateAsync({
      gitlab_server_url: serverUrl.trim(),
      gitlab_project_paths: parsedProjectPaths,
      gitlab_ref: ref.trim(),
      gitlab_include_globs: parsedIncludeGlobs,
    });
  }

  async function runTest() {
    try {
      // Send the in-form values so the user can probe a candidate config
      // without saving first. Anything empty falls back to the saved value
      // server-side via cfg.load_config().
      await test.mutateAsync({
        server_url: serverUrl.trim() || undefined,
        project_paths: parsedProjectPaths.length ? parsedProjectPaths : undefined,
        ref: ref.trim() || undefined,
        include_globs: parsedIncludeGlobs.length ? parsedIncludeGlobs : undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  const result = test.data;
  const configured = !!status.data?.configured;
  const tokenSet = !!status.data?.token_set;
  const detectedUser = result?.detected?.user;
  const detectedHost = result?.detected?.host;
  const projects = result?.detected?.projects ?? [];

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <GitBranch className="h-4 w-4" />
              GitLab
              {!enabled ? (
                <Badge variant="outline" className="ml-1">
                  disabled
                </Badge>
              ) : configured && result?.ok ? (
                <Badge variant="success" className="ml-1">
                  connected
                </Badge>
              ) : configured ? (
                <Badge variant="warning" className="ml-1">
                  configured, untested
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not configured
                </Badge>
              )}
              {enabled && detectedUser && (
                <Badge variant="outline" className="ml-1">
                  {detectedUser}
                </Badge>
              )}
              {enabled && detectedHost && !detectedUser && (
                <Badge variant="outline" className="ml-1">
                  {detectedHost}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Walks GitLab repositories as an evidence source. Token comes from
              the <span className="font-mono text-xs">GITLAB_TOKEN</span> env
              var or the OS keyring (per host).
            </CardDescription>
          </div>
          {/* Inline pill-style toggle — bare button with role/aria-checked,
              no Radix dep. Click flips enable_gitlab via /api/settings. */}
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={enabled ? "Disable GitLab connector" : "Enable GitLab connector"}
            onClick={() => toggleEnabled.mutate({ enable_gitlab: !enabled })}
            disabled={toggleEnabled.isPending || settings.isLoading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      {!enabled ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Connector is off. Turn it on to configure a GitLab server, project
            list, and ref for evidence ingest.
          </p>
        </CardContent>
      ) : (
        <CardContent className="space-y-3">
          <Field label="Server URL">
            <Input
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
              placeholder="https://gitlab.example.com"
              autoComplete="off"
            />
          </Field>

          <Field label="Project paths (one per line)">
            <textarea
              value={projectPaths}
              onChange={(e) => setProjectPaths(e.target.value)}
              placeholder="sda-oi/example/mdp/tracking-handler"
              rows={3}
              className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
            />
          </Field>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="Ref (branch / tag / SHA, blank = HEAD)">
              <Input
                value={ref}
                onChange={(e) => setRef(e.target.value)}
                placeholder="main"
                autoComplete="off"
              />
            </Field>
            <Field label="Include globs (one per line, blank = all)">
              <textarea
                value={includeGlobs}
                onChange={(e) => setIncludeGlobs(e.target.value)}
                placeholder="**/*.md&#10;**/STIG*"
                rows={2}
                className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              />
            </Field>
          </div>

          {!tokenSet && serverUrl.trim() && (
            <p className="text-xs text-amber-700 dark:text-amber-400">
              No token found for this host. Set{" "}
              <span className="font-mono">GITLAB_TOKEN</span> in your
              environment, or store a PAT in the OS keyring keyed by the
              server's hostname.
            </p>
          )}

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button onClick={save} disabled={!dirty || update.isPending}>
              {update.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={runTest}
              disabled={test.isPending || !serverUrl.trim() || parsedProjectPaths.length === 0}
              title="Authenticate against the server and resolve each project to a commit SHA."
            >
              {test.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
          </div>

          {result && (
            <div
              className={
                result.ok
                  ? "rounded-md border border-emerald-300/60 bg-emerald-50 dark:border-emerald-700/60 dark:bg-emerald-950/30 px-3 py-2 text-sm space-y-1"
                  : "rounded-md border border-destructive/60 bg-destructive/5 px-3 py-2 text-sm space-y-1"
              }
            >
              <div
                className={
                  result.ok
                    ? "flex items-center gap-1 text-emerald-700 dark:text-emerald-400 text-xs font-semibold uppercase tracking-wide"
                    : "flex items-center gap-1 text-destructive text-xs font-semibold uppercase tracking-wide"
                }
              >
                {result.ok ? <Check className="h-3 w-3" /> : null}
                {result.ok ? "Connection OK" : "Connection problem"}
              </div>
              {result.message && (
                <p className="text-xs">{result.message}</p>
              )}
              {projects.length > 0 && (
                <div className="space-y-0.5 pt-1">
                  {projects.map((p) => (
                    <Row
                      key={p.project_path}
                      label={p.project_path}
                      value={
                        p.ok ? (
                          <span className="font-mono text-xs text-emerald-700 dark:text-emerald-400">
                            {p.commit_sha ? p.commit_sha.slice(0, 12) : "ok"}
                          </span>
                        ) : (
                          <span className="font-mono text-xs text-destructive">
                            {p.error ?? "failed"}
                          </span>
                        )
                      }
                    />
                  ))}
                </div>
              )}
            </div>
          )}

          {!configured && (
            <p className="text-xs text-muted-foreground">
              Paste a server URL and at least one project path above, save, then
              click <span className="font-medium">Test connection</span>.
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

/**
 * Jira connector. The main pill (`features.jira`, top-right) opts the connector
 * in; once on, configure the server URL, PAT, and allowed JQL queries.
 *
 * Status is config + keyring only — never a network call (recipe gotcha #6).
 * The Test button does the real /rest/api/2/myself round-trip via
 * JiraSource.test_connection() in the route layer.
 *
 * JQL is CONFIG-BOUND. The card edits a list of `{name, jql}` pairs that the
 * connector is allowed to run; no free-form JQL ever flows from the UI to the
 * wire. Names are human-facing for the future Sweep UI; jql is what hits Jira.
 */
function JiraConnectorCard() {
  const settings = useSettings();
  const status = useJiraStatus();

  const update = useUpdateSettings({
    onSuccess: () => toast.success("Jira settings saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const test = useTestJira({
    onError: (err) => toast.error("Test failed", humanize(err)),
  });
  const setPat = useSetJiraPat({
    onSuccess: () => {
      toast.success("Jira PAT saved");
      setPat_field("");
    },
    onError: (err) => toast.error("Couldn't save PAT", humanize(err)),
  });
  const clearPat = useClearJiraPat({
    onSuccess: () => toast.success("Jira PAT cleared"),
    onError: (err) => toast.error("Couldn't clear PAT", humanize(err)),
  });

  const enabled = settings.data?.features?.jira ?? false;
  const toggleEnabled = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.enable_jira ? "Jira connector enabled" : "Jira connector disabled",
      ),
    onError: (err) => toast.error("Couldn't update connector", humanize(err)),
  });

  // Local form state — seeded from settings.data?.jira so the user can edit
  // a candidate value before saving. The PAT field is separate (different
  // endpoint; keyring write).
  const jira = settings.data?.jira;
  const [serverUrl, setServerUrl] = useState("");
  const [queries, setQueries] = useState<JiraAllowedQuery[]>([]);
  const [patField, setPat_field] = useState("");

  useEffect(() => {
    if (!jira) return;
    setServerUrl(jira.server_url ?? "");
    setQueries(jira.allowed_jql_queries ?? []);
  }, [jira]);

  // Dirty calc uses JSON.stringify on queries since identity differs after
  // every edit but content may not. Avoids enabling Save on every keystroke
  // when the user types and then backspaces back to the saved value.
  const savedQueries = jira?.allowed_jql_queries ?? [];
  const queriesDirty = JSON.stringify(queries) !== JSON.stringify(savedQueries);
  const dirty =
    !!jira &&
    ((serverUrl.trim() || null) !== (jira.server_url ?? null) || queriesDirty);

  function updateRow(idx: number, patch: Partial<JiraAllowedQuery>) {
    setQueries((prev) =>
      prev.map((q, i) => (i === idx ? { ...q, ...patch } : q)),
    );
  }
  function addRow() {
    setQueries((prev) => [...prev, { name: "", jql: "" }]);
  }
  function removeRow(idx: number) {
    setQueries((prev) => prev.filter((_, i) => i !== idx));
  }

  async function save() {
    await update.mutateAsync({
      jira_server_url: serverUrl.trim(),
      // Send the cleaned list; server-side PUT will drop empty-name/empty-jql
      // rows and trim whitespace. Empty array explicitly clears the saved list.
      jira_allowed_jql_queries: queries,
    });
  }

  async function runTest() {
    try {
      // Send the in-form values so the user can probe candidate config without
      // saving first. Omitted fields fall back to the saved value server-side.
      await test.mutateAsync({
        server_url: serverUrl.trim() || undefined,
        allowed_jql_queries: queries.length > 0 ? queries : undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  async function savePat() {
    const trimmed = patField.trim();
    if (trimmed.length < 8) {
      toast.error("PAT is too short", "Jira PATs are typically 24+ characters.");
      return;
    }
    await setPat.mutateAsync(trimmed);
  }

  const result = test.data;
  const patSet = !!status.data?.pat_set;
  const configured = !!status.data?.configured;
  const gateOpen = !!status.data?.gate_open;
  const detected = result?.detected;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <Ticket className="h-4 w-4" />
              Jira
              {!enabled ? (
                <Badge variant="outline" className="ml-1">
                  disabled
                </Badge>
              ) : gateOpen && configured ? (
                <Badge variant="success" className="ml-1">
                  ready
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not configured
                </Badge>
              )}
              {enabled && detected?.account && (
                <Badge variant="outline" className="ml-1">
                  {detected.account}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Pulls Jira Data Center issues as evidence via a config-bound list
              of named JQL queries.
            </CardDescription>
          </div>
          {/* Main pill — flips features.jira. */}
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={enabled ? "Disable Jira connector" : "Enable Jira connector"}
            onClick={() => toggleEnabled.mutate({ enable_jira: !enabled })}
            disabled={toggleEnabled.isPending || settings.isLoading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      {!enabled ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Connector is off. Turn it on to configure a Jira Data Center server,
            store a Personal Access Token, and define the named JQL queries the
            assessor is allowed to run.
          </p>
        </CardContent>
      ) : (
        <CardContent className="space-y-3">
          <Field label="Server URL">
            <Input
              value={serverUrl}
              onChange={(e) => setServerUrl(e.target.value)}
              placeholder="https://jira.example.com"
              autoComplete="off"
            />
          </Field>

          <Field
            label={
              <span className="inline-flex items-center gap-1.5">
                Personal Access Token
                {patSet && (
                  <Badge variant="success" className="text-[10px]">
                    stored
                  </Badge>
                )}
              </span>
            }
          >
            <div className="flex gap-2">
              <Input
                type="password"
                value={patField}
                onChange={(e) => setPat_field(e.target.value)}
                placeholder={patSet ? "•••••••• (stored in OS keyring)" : "Paste PAT"}
                autoComplete="off"
              />
              <Button
                variant="outline"
                onClick={savePat}
                disabled={setPat.isPending || patField.trim().length < 8}
              >
                {setPat.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <KeyRound className="h-4 w-4" />
                )}
                {setPat.isPending ? "Saving…" : "Save PAT"}
              </Button>
              {patSet && (
                <Button
                  variant="outline"
                  onClick={() => clearPat.mutateAsync()}
                  disabled={clearPat.isPending}
                  className="text-destructive hover:text-destructive"
                  title="Remove the stored PAT from the OS keyring"
                >
                  {clearPat.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4" />
                  )}
                </Button>
              )}
            </div>
          </Field>

          <div className="space-y-2 pt-1">
            <div className="flex items-center justify-between">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Allowed JQL queries
              </div>
              <Button size="sm" variant="outline" onClick={addRow}>
                <Plus className="h-3 w-3" />
                Add query
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Config-bound: the connector only ever runs these named queries.
              No free-form JQL flows from the UI. Empty entries are dropped on
              save.
            </p>
            {queries.length === 0 && (
              <p className="text-xs italic text-muted-foreground py-2">
                No queries defined. Add at least one before testing.
              </p>
            )}
            <div className="space-y-2">
              {queries.map((q, idx) => (
                <div
                  key={idx}
                  className="grid grid-cols-1 md:grid-cols-[200px_1fr_auto] gap-2 items-start"
                >
                  <Input
                    value={q.name}
                    onChange={(e) => updateRow(idx, { name: e.target.value })}
                    placeholder="Name (e.g. Open security tickets)"
                    autoComplete="off"
                  />
                  <Input
                    value={q.jql}
                    onChange={(e) => updateRow(idx, { jql: e.target.value })}
                    placeholder="JQL (e.g. project = SEC AND status != Done)"
                    autoComplete="off"
                    className="font-mono text-xs"
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => removeRow(idx)}
                    className="text-destructive hover:text-destructive"
                    title="Remove this query"
                  >
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button onClick={save} disabled={!dirty || update.isPending}>
              {update.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={runTest}
              disabled={
                test.isPending ||
                !serverUrl.trim() ||
                !patSet ||
                queries.length === 0
              }
              title={
                !patSet
                  ? "Save a PAT first"
                  : queries.length === 0
                  ? "Add at least one JQL query first"
                  : "Round-trip /rest/api/2/myself to verify auth + reachability."
              }
            >
              {test.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
          </div>

          {result && (
            <div
              className={
                result.ok
                  ? "rounded-md border border-emerald-300/60 bg-emerald-50 dark:border-emerald-700/60 dark:bg-emerald-950/30 px-3 py-2 text-sm space-y-1"
                  : "rounded-md border border-destructive/60 bg-destructive/5 px-3 py-2 text-sm space-y-1"
              }
            >
              <div
                className={
                  result.ok
                    ? "flex items-center gap-1 text-emerald-700 dark:text-emerald-400 text-xs font-semibold uppercase tracking-wide"
                    : "flex items-center gap-1 text-destructive text-xs font-semibold uppercase tracking-wide"
                }
              >
                {result.ok ? <Check className="h-3 w-3" /> : null}
                {result.ok ? "Connection OK" : "Connection problem"}
              </div>
              <p className="text-sm">{result.message}</p>
              {result.detected?.server_url && (
                <Row
                  label="server"
                  value={
                    <span className="font-mono text-xs">
                      {result.detected.server_url}
                    </span>
                  }
                />
              )}
              {result.detected?.account && (
                <Row
                  label="account"
                  value={
                    <span className="font-mono text-xs">
                      {result.detected.account}
                    </span>
                  }
                />
              )}
              {result.detected?.queries_configured != null && (
                <Row
                  label="queries"
                  value={
                    <span className="font-mono text-xs">
                      {result.detected.queries_configured}
                    </span>
                  }
                />
              )}
            </div>
          )}

          {!configured && (
            <p className="text-xs text-muted-foreground">
              Paste a server URL, save a PAT, and add at least one named JQL
              query above, then click <span className="font-medium">Test connection</span>.
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

/**
 * eMASS REST connector card — DOUBLE-GATED (main pill + inner ISSM gate).
 *
 * Mirrors the SharePointConnectorCard shape: status polled cheaply on mount,
 * Save flushes the four connection fields, Test fires a real mTLS probe via
 * /api/emass/test. The wrinkle is the per-tenant gate: even with the main
 * pill on AND fields saved, the connector refuses to load until the user
 * confirms ISSM sign-off by flipping the inner toggle. That inner toggle is
 * an INLINE switch inside the card body (not a second pill in the header) to
 * keep the per-recipe convention for double-gated connectors.
 */
function EmassConnectorCard() {
  const settings = useSettings();
  const status = useEmassStatus();
  const update = useUpdateSettings({
    onSuccess: () => toast.success("eMASS settings saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const test = useTestEmass({
    onError: (err) => toast.error("Test failed", humanize(err)),
  });

  // Main pill — controls card body visibility. Default false (v0.1 ships
  // local-only and the REST API is DISA-restricted).
  const enabled = settings.data?.features?.emass ?? false;
  const toggleEnabled = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.enable_emass
          ? "eMASS connector enabled"
          : "eMASS connector disabled",
      ),
    onError: (err) => toast.error("Couldn't update connector", humanize(err)),
  });

  // Form state — initialized once settings load. Cert/key live as PATHS;
  // bytes never enter UI memory or get round-tripped to the sidecar.
  const conn = settings.data?.emass;
  const [baseUrl, setBaseUrl] = useState("");
  const [systemId, setSystemId] = useState("");
  const [certPath, setCertPath] = useState("");
  const [keyPath, setKeyPath] = useState("");

  useEffect(() => {
    if (!conn) return;
    setBaseUrl(conn.base_url ?? "");
    setSystemId(conn.system_id ?? "");
    setCertPath(conn.cert_path ?? "");
    setKeyPath(conn.key_path ?? "");
  }, [conn]);

  const dirty =
    !!conn &&
    ((baseUrl.trim() || null) !== (conn.base_url ?? null) ||
      (systemId.trim() || null) !== (conn.system_id ?? null) ||
      (certPath.trim() || null) !== (conn.cert_path ?? null) ||
      (keyPath.trim() || null) !== (conn.key_path ?? null));

  async function save() {
    await update.mutateAsync({
      emass_base_url: baseUrl.trim(),
      emass_system_id: systemId.trim(),
      emass_cert_path: certPath.trim(),
      emass_key_path: keyPath.trim(),
    });
  }

  async function runTest() {
    try {
      await test.mutateAsync({
        base_url: baseUrl.trim() || undefined,
        system_id: systemId.trim() || undefined,
        cert_path: certPath.trim() || undefined,
        key_path: keyPath.trim() || undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  const result = test.data;
  const configured = !!status.data?.configured;
  const reachable = !!result?.ok;
  const detectedSystem = result?.detected?.system_name;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" />
              eMASS
              {!enabled ? (
                <Badge variant="outline" className="ml-1">
                  disabled
                </Badge>
              ) : reachable ? (
                <Badge variant="success" className="ml-1">
                  connected
                </Badge>
              ) : configured ? (
                <Badge variant="warning" className="ml-1">
                  configured, untested
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not configured
                </Badge>
              )}
              {enabled && detectedSystem && (
                <Badge variant="outline" className="ml-1">
                  {detectedSystem}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              DISA eMASS REST API via mTLS — pulls package metadata, CCIs, and
              POAMs.
            </CardDescription>
          </div>
          {/* Main pill (same shape as SharePoint card). */}
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={enabled ? "Disable eMASS connector" : "Enable eMASS connector"}
            onClick={() => toggleEnabled.mutate({ enable_emass: !enabled })}
            disabled={toggleEnabled.isPending || settings.isLoading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      {!enabled ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Connector is off — flip the switch to configure mTLS credentials
            and the eMASS system ID.
          </p>
        </CardContent>
      ) : (
        <CardContent className="space-y-4">
          <Field label="API base URL">
            <Input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://emass.disa.mil/api"
              autoComplete="off"
            />
          </Field>

          <Field label="System ID">
            <Input
              value={systemId}
              onChange={(e) => setSystemId(e.target.value)}
              placeholder="The eMASS package GUID assigned to your system"
              autoComplete="off"
            />
          </Field>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="Client cert path (.pem or .pfx)">
              <Input
                value={certPath}
                onChange={(e) => setCertPath(e.target.value)}
                placeholder="C:\certs\emass-client.pem"
                autoComplete="off"
              />
            </Field>
            <Field label="Client key path (.pem, optional for .pfx)">
              <Input
                value={keyPath}
                onChange={(e) => setKeyPath(e.target.value)}
                placeholder="C:\certs\emass-client.key"
                autoComplete="off"
              />
            </Field>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button onClick={save} disabled={!dirty || update.isPending}>
              {update.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={runTest}
              disabled={
                test.isPending ||
                !baseUrl.trim() ||
                !systemId.trim() ||
                !certPath.trim()
              }
              title="Open an mTLS connection to eMASS and verify the system_id resolves."
            >
              {test.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
          </div>

          {result && (
            <div
              className={
                result.ok
                  ? "rounded-md border border-emerald-300/60 bg-emerald-50 dark:border-emerald-700/60 dark:bg-emerald-950/30 px-3 py-2 text-sm space-y-1"
                  : "rounded-md border border-destructive/60 bg-destructive/5 px-3 py-2 text-sm space-y-1"
              }
            >
              <div
                className={
                  result.ok
                    ? "flex items-center gap-1 text-emerald-700 dark:text-emerald-400 text-xs font-semibold uppercase tracking-wide"
                    : "flex items-center gap-1 text-destructive text-xs font-semibold uppercase tracking-wide"
                }
              >
                {result.ok ? <Check className="h-3 w-3" /> : null}
                {result.ok ? "Connection OK" : "Connection problem"}
              </div>
              <p className="text-xs">{result.message}</p>
              {result.detected?.system_id && (
                <Row
                  label="system_id"
                  value={
                    <span className="font-mono text-xs">
                      {result.detected.system_id}
                    </span>
                  }
                />
              )}
              {result.detected?.system_name && (
                <Row
                  label="system_name"
                  value={
                    <span className="font-mono text-xs">
                      {result.detected.system_name}
                    </span>
                  }
                />
              )}
            </div>
          )}

          {!configured && (
            <p className="text-xs text-muted-foreground">
              Configure all four fields, then click{" "}
              <span className="font-medium">Test connection</span> to verify the
              cert + system_id resolve against eMASS.
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

function SharePointConnectorCard() {
  const settings = useSettings();
  // Poll status while a device-code sign-in is in flight so the card auto-flips
  // to "signed in" the moment the background thread writes the token cache —
  // no second manual click required. Polling stops as soon as `pending` clears.
  const [polling, setPolling] = useState(false);
  const status = useSharePointStatus(polling ? 2000 : 0);
  const update = useUpdateSettings({
    onSuccess: () => toast.success("SharePoint settings saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const test = useTestSharePoint({
    onError: (err) => toast.error("Test failed", humanize(err)),
  });
  const signOut = useSignOutSharePoint({
    onSuccess: (res) =>
      toast.success(
        "Signed out of SharePoint",
        res.cache_removed ? "Token cache removed" : "No cached token to remove",
      ),
    onError: (err) => toast.error("Sign-out failed", humanize(err)),
  });
  const cancelSignIn = useCancelSharePointSignIn({
    onError: (err) => toast.error("Couldn't cancel sign-in", humanize(err)),
  });

  // Feature-flag toggle. Defaults false in backend Config (v0.1 ships
  // local-only). When off, we hide the entire configuration body — the
  // assessor doesn't want SharePoint, so showing site URL / library /
  // sign-in buttons is just noise. Also drives the conditional hide of
  // the "Sweep Context" sidebar entry in App.tsx (boundary docs only
  // exist to bias the SP sweep — useless if SP is off).
  const enabled = settings.data?.features?.sharepoint ?? false;
  const toggleEnabled = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.enable_sharepoint
          ? "SharePoint connector enabled"
          : "SharePoint connector disabled",
      ),
    onError: (err) => toast.error("Couldn't update connector", humanize(err)),
  });

  // Local form state — initialized once settings load, edits diff against
  // the saved values so the Save button knows there's something to commit.
  // Tenant / client / authority intentionally absent: the Graph PowerShell
  // client_id is hardcoded server-side and the cloud (Commercial / GovCloud /
  // DoD) is auto-detected from the site URL hostname. Pasting a URL + signing
  // in is the whole setup.
  const sp = settings.data?.sharepoint;
  const [siteUrl, setSiteUrl] = useState("");
  const [library, setLibrary] = useState("");
  const [folderPath, setFolderPath] = useState("");

  useEffect(() => {
    if (!sp) return;
    setSiteUrl(sp.site_url ?? "");
    setLibrary(sp.library ?? "");
    setFolderPath(sp.folder_path ?? "");
  }, [sp]);

  const dirty =
    !!sp &&
    ((siteUrl.trim() || null) !== (sp.site_url ?? null) ||
      (library.trim() || null) !== (sp.library ?? null) ||
      (folderPath.trim() || null) !== (sp.folder_path ?? null));

  async function save() {
    await update.mutateAsync({
      sharepoint_site_url: siteUrl.trim(),
      sharepoint_library: library.trim(),
      sharepoint_folder_path: folderPath.trim(),
    });
  }

  async function runTest() {
    try {
      // Send the in-form values so the user can probe a candidate config
      // without saving first. Anything empty falls back to the saved value
      // server-side via cfg.load_config().
      await test.mutateAsync({
        site_url: siteUrl.trim() || undefined,
        library: library.trim() || undefined,
        folder_path: folderPath.trim() || undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  const result = test.data;
  const configured = !!status.data?.configured;
  const tokenCached = !!status.data?.token_cache_exists;
  // Detected cloud comes from the site URL hostname (server-side); status
  // refreshes on save so editing the URL → Save flips the badge.
  const detectedCloud = status.data?.cloud_name ?? null;
  const pending = result?.pending && result.user_code && result.verification_uri;

  // Turn polling on while a device-code prompt is showing; turn it off as soon
  // as the user finishes signing in (token cache appears) or the prompt is
  // cancelled / replaced by a final result.
  useEffect(() => {
    setPolling(!!pending);
  }, [pending]);

  // When polling detects the cache has landed mid-prompt, drop the stale
  // "Sign in to continue" panel so the card visibly flips to signed-in.
  useEffect(() => {
    if (tokenCached && pending) {
      test.reset();
      setPolling(false);
    }
  }, [tokenCached, pending, test]);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <Cloud className="h-4 w-4" />
              SharePoint
              {!enabled ? (
                <Badge variant="outline" className="ml-1">
                  disabled
                </Badge>
              ) : tokenCached ? (
                <Badge variant="success" className="ml-1">
                  signed in
                </Badge>
              ) : configured ? (
                <Badge variant="warning" className="ml-1">
                  not signed in
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not configured
                </Badge>
              )}
              {enabled && detectedCloud && (
                <Badge variant="outline" className="ml-1">
                  {detectedCloud}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Walks a SharePoint document library as an evidence source. Cloud is
              auto-detected from the site URL.
            </CardDescription>
          </div>
          {/* Inline pill-style toggle. Avoids pulling in @radix-ui/react-switch
              for one switch — same a11y semantics via role/aria-checked on a
              <button>. Click flips enable_sharepoint via /api/settings. */}
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={enabled ? "Disable SharePoint connector" : "Enable SharePoint connector"}
            onClick={() =>
              toggleEnabled.mutate({ enable_sharepoint: !enabled })
            }
            disabled={toggleEnabled.isPending || settings.isLoading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      {!enabled ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Connector is off. Turn it on to configure a site URL, sign in, and
            enable SharePoint sweeps + Sweep Context.
          </p>
        </CardContent>
      ) : (
      <CardContent className="space-y-3">
        <Field label="Site URL">
          <Input
            value={siteUrl}
            onChange={(e) => setSiteUrl(e.target.value)}
            placeholder="https://collab.example.com/sites/PRGM-EXAMPLE"
            autoComplete="off"
          />
        </Field>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="Library (display name, blank = Documents)">
            <Input
              value={library}
              onChange={(e) => setLibrary(e.target.value)}
              placeholder="Documents"
              autoComplete="off"
            />
          </Field>
          <Field label="Folder path (optional, scopes the scan)">
            <Input
              value={folderPath}
              onChange={(e) => setFolderPath(e.target.value)}
              placeholder="e.g. CCIS/Evidence"
              autoComplete="off"
            />
          </Field>
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <Button onClick={save} disabled={!dirty || update.isPending}>
            {update.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Save className="h-4 w-4" />
            )}
            {update.isPending ? "Saving…" : "Save"}
          </Button>
          <Button
            variant="outline"
            onClick={runTest}
            disabled={test.isPending || !siteUrl.trim()}
            title="Authenticate via device-code and verify the site URL + folder are reachable."
          >
            {test.isPending ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <PlugZap className="h-4 w-4" />
            )}
            {test.isPending ? "Testing…" : tokenCached ? "Test connection" : "Sign in & test"}
          </Button>
          {tokenCached && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => signOut.mutateAsync()}
              disabled={signOut.isPending}
              className="text-destructive hover:text-destructive"
            >
              {signOut.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <LogOut className="h-4 w-4" />
              )}
              {signOut.isPending ? "Signing out…" : "Sign out"}
            </Button>
          )}
        </div>

        {pending && (
          <div className="rounded-md border border-amber-300/60 bg-amber-50 dark:border-amber-700/60 dark:bg-amber-950/30 px-3 py-2 space-y-2">
            <div className="text-xs font-semibold uppercase tracking-wide text-amber-700 dark:text-amber-400">
              Sign in to continue
            </div>
            <p className="text-sm">
              Open{" "}
              <a
                href={result!.verification_uri ?? "#"}
                target="_blank"
                rel="noreferrer"
                className="underline inline-flex items-center gap-1"
              >
                {result!.verification_uri}
                <ExternalLink className="h-3 w-3" />
              </a>{" "}
              and enter this code:
            </p>
            <div className="flex items-center gap-2">
              <code className="text-base font-mono font-semibold px-2 py-1 rounded bg-background border tracking-widest">
                {result!.user_code}
              </code>
              <Button
                size="sm"
                variant="outline"
                onClick={() => navigator.clipboard.writeText(result!.user_code ?? "")}
                title="Copy code to clipboard"
              >
                <Copy className="h-3 w-3" />
                Copy
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              After signing in, click <span className="font-medium">Sign in &amp; test</span>{" "}
              again to finish. Code expires in ~15 min.
            </p>
            <div>
              <Button
                size="sm"
                variant="outline"
                disabled={cancelSignIn.isPending || test.isPending}
                onClick={async () => {
                  // Drop the stuck flow + reset device-code state, then
                  // immediately respin so the user lands on a fresh code
                  // without having to click twice.
                  await cancelSignIn.mutateAsync();
                  test.reset();
                  await runTest();
                }}
              >
                {cancelSignIn.isPending || test.isPending ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : null}
                Get a new code
              </Button>
            </div>
          </div>
        )}

        {result && !pending && (
          <div
            className={
              result.ok
                ? "rounded-md border border-emerald-300/60 bg-emerald-50 dark:border-emerald-700/60 dark:bg-emerald-950/30 px-3 py-2 text-sm space-y-1"
                : "rounded-md border border-destructive/60 bg-destructive/5 px-3 py-2 text-sm space-y-1"
            }
          >
            <div
              className={
                result.ok
                  ? "flex items-center gap-1 text-emerald-700 dark:text-emerald-400 text-xs font-semibold uppercase tracking-wide"
                  : "flex items-center gap-1 text-destructive text-xs font-semibold uppercase tracking-wide"
              }
            >
              {result.ok ? <Check className="h-3 w-3" /> : null}
              {result.ok ? "Connection OK" : "Connection problem"}
            </div>
            {/* SharePointSource.test_connection() returns auth/site/library/
                scan-root health as separate fields; render them all so the
                user can see which step failed (e.g. library_ok=true but
                scan_root_ok=false ⇒ folder path typo). */}
            {Object.entries(result as unknown as Record<string, unknown>)
              .filter(
                ([k]) =>
                  !["ok", "pending", "device_code", "user_code", "verification_uri", "expires_in", "interval", "message", "detail"].includes(
                    k,
                  ),
              )
              .map(([k, v]) => (
                <Row
                  key={k}
                  label={k}
                  value={
                    <span className="font-mono text-xs">
                      {typeof v === "string" ? v : JSON.stringify(v)}
                    </span>
                  }
                />
              ))}
            {!result.ok && result.detail ? (
              <p className="text-xs text-destructive pt-1">{result.detail}</p>
            ) : null}
          </div>
        )}

        {!configured && (
          <p className="text-xs text-muted-foreground">
            Paste your SharePoint site URL above, save, then click{" "}
            <span className="font-medium">Sign in &amp; test</span> and follow the
            sign-in prompt.
          </p>
        )}

        <SharePointPriorityLinksEditor />
      </CardContent>
      )}
    </Card>
  );
}

/**
 * ServiceNow GRC connector card.
 *
 * Mirrors SharePointConnectorCard's shape: pill toggle for the feature flag,
 * config fields gated behind it, /test button that probes the SN Table API
 * without committing the form, secret-set/clear flows that store the OAuth
 * client_secret or Basic password in the OS keyring. The card defers ingest
 * wiring — v0.4 connector spec gives the route + /test plumbing; evidence
 * ingestion will land as a separate slice once the source-spec discriminator
 * is added to /api/evidence/ingest.
 */
function ServicenowGrcConnectorCard() {
  const settings = useSettings();
  const status = useServicenowGrcStatus();
  const update = useUpdateSettings({
    onSuccess: () => toast.success("ServiceNow GRC settings saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const test = useTestServicenowGrc({
    onError: (err) => toast.error("Test failed", humanize(err)),
  });
  const setOauthSecret = useSetServicenowGrcOauthSecret({
    onSuccess: () => toast.success("OAuth client_secret saved"),
    onError: (err) => toast.error("Couldn't save secret", humanize(err)),
  });
  const clearOauthSecret = useClearServicenowGrcOauthSecret({
    onSuccess: () => toast.success("OAuth client_secret cleared"),
    onError: (err) => toast.error("Couldn't clear secret", humanize(err)),
  });
  const setBasicPassword = useSetServicenowGrcBasicPassword({
    onSuccess: () => toast.success("Basic password saved"),
    onError: (err) => toast.error("Couldn't save password", humanize(err)),
  });
  const clearBasicPassword = useClearServicenowGrcBasicPassword({
    onSuccess: () => toast.success("Basic password cleared"),
    onError: (err) => toast.error("Couldn't clear password", humanize(err)),
  });

  // Feature-flag toggle. Backend flag is enable_snow_grc but surfaced under
  // features.servicenow_grc to keep the UI slug consistent with the route
  // prefix and DEFAULT_TABLES discoverability.
  const enabled = settings.data?.features?.servicenow_grc ?? false;
  const toggleEnabled = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.enable_servicenow_grc
          ? "ServiceNow GRC connector enabled"
          : "ServiceNow GRC connector disabled",
      ),
    onError: (err) => toast.error("Couldn't update connector", humanize(err)),
  });

  // Local form state — initialized once settings load. allowedTables is
  // stored as a textarea string so the user can paste comma/newline-separated
  // table names; we split on save.
  const sn = settings.data?.servicenow_grc;
  const [instanceUrl, setInstanceUrl] = useState("");
  const [authMethod, setAuthMethod] = useState<"oauth" | "basic">("oauth");
  const [username, setUsername] = useState("");
  const [allowedTablesText, setAllowedTablesText] = useState("");
  // Secret input is write-only; we never read back the stored value. Cleared
  // on successful set so the field doesn't carry plaintext around.
  const [secretInput, setSecretInput] = useState("");

  useEffect(() => {
    if (!sn) return;
    setInstanceUrl(sn.instance_url ?? "");
    setAuthMethod(
      (sn.auth_method === "basic" ? "basic" : "oauth") as "oauth" | "basic",
    );
    setUsername(sn.username ?? "");
    setAllowedTablesText((sn.allowed_tables ?? []).join("\n"));
  }, [sn]);

  // Parse the textarea: split on commas + newlines, strip whitespace, drop
  // empties. Empty list = backend falls back to DEFAULT_TABLES.
  function parseTables(): string[] {
    return allowedTablesText
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  const parsedTables = parseTables();
  const dirty =
    !!sn &&
    ((instanceUrl.trim() || null) !== (sn.instance_url ?? null) ||
      authMethod !== (sn.auth_method === "basic" ? "basic" : "oauth") ||
      (username.trim() || null) !== (sn.username ?? null) ||
      JSON.stringify(parsedTables) !==
        JSON.stringify(sn.allowed_tables ?? []));

  async function save() {
    await update.mutateAsync({
      servicenow_grc_instance_url: instanceUrl.trim(),
      servicenow_grc_auth_method: authMethod,
      servicenow_grc_username: username.trim(),
      servicenow_grc_allowed_tables: parsedTables,
    });
  }

  async function runTest() {
    try {
      // Send in-form values so the user can probe without saving first.
      await test.mutateAsync({
        instance_url: instanceUrl.trim() || undefined,
        auth_method: authMethod,
        username: username.trim() || undefined,
        allowed_tables: parsedTables.length ? parsedTables : undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  async function saveSecret() {
    if (!secretInput.trim()) return;
    if (authMethod === "oauth") {
      await setOauthSecret.mutateAsync({ secret: secretInput });
    } else {
      await setBasicPassword.mutateAsync({ secret: secretInput });
    }
    setSecretInput("");
  }

  async function clearSecret() {
    if (authMethod === "oauth") {
      await clearOauthSecret.mutateAsync();
    } else {
      await clearBasicPassword.mutateAsync();
    }
  }

  const result = test.data;
  const configured = !!status.data?.configured;
  const secretSet = !!status.data?.secret_set;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" />
              ServiceNow GRC
              {!enabled ? (
                <Badge variant="outline" className="ml-1">
                  disabled
                </Badge>
              ) : configured && secretSet ? (
                <Badge variant="success" className="ml-1">
                  configured
                </Badge>
              ) : configured ? (
                <Badge variant="warning" className="ml-1">
                  secret missing
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not configured
                </Badge>
              )}
              {enabled && authMethod && (
                <Badge variant="outline" className="ml-1">
                  {authMethod}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Pulls policy/control/risk records from ServiceNow GRC tables. OAuth
              uses client_credentials; Basic uses a service-account password.
            </CardDescription>
          </div>
          {/* Inline pill toggle — same a11y semantics as the SharePoint card. */}
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={
              enabled
                ? "Disable ServiceNow GRC connector"
                : "Enable ServiceNow GRC connector"
            }
            onClick={() =>
              toggleEnabled.mutate({ enable_servicenow_grc: !enabled })
            }
            disabled={toggleEnabled.isPending || settings.isLoading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      {!enabled ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Connector is off. Turn it on to configure the instance URL,
            credentials, and the GRC tables to read from.
          </p>
        </CardContent>
      ) : (
        <CardContent className="space-y-3">
          <Field label="Instance URL">
            <Input
              value={instanceUrl}
              onChange={(e) => setInstanceUrl(e.target.value)}
              placeholder="https://acme.service-now.com"
              autoComplete="off"
            />
          </Field>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="Auth method">
              <Select
                value={authMethod}
                onValueChange={(v) => setAuthMethod(v as "oauth" | "basic")}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="oauth">OAuth (client_credentials)</SelectItem>
                  <SelectItem value="basic">Basic (username/password)</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field
              label={
                authMethod === "oauth" ? "OAuth client_id" : "Service account username"
              }
            >
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={authMethod === "oauth" ? "client_id" : "svc.assessor"}
                autoComplete="off"
              />
            </Field>
          </div>

          <Field label="Allowed tables (one per line or comma-separated; blank = defaults)">
            <textarea
              value={allowedTablesText}
              onChange={(e) => setAllowedTablesText(e.target.value)}
              placeholder={"sn_grc_policy\nsn_grc_control\nsn_grc_risk"}
              rows={4}
              className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              autoComplete="off"
              spellCheck={false}
            />
          </Field>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button onClick={save} disabled={!dirty || update.isPending}>
              {update.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={runTest}
              disabled={test.isPending || !instanceUrl.trim() || !username.trim()}
              title="Probe the SN Table API using the current form values."
            >
              {test.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
          </div>

          {/* Secret block — write-only. The status endpoint reports whether a
              value is present in the keyring (secret_set), but never returns
              the value itself. */}
          <div className="rounded-md border bg-muted/30 px-3 py-3 space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              <KeyRound className="h-3 w-3" />
              {authMethod === "oauth" ? "OAuth client_secret" : "Basic password"}
              {secretSet ? (
                <Badge variant="success" className="ml-1">
                  stored
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not set
                </Badge>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                type="password"
                value={secretInput}
                onChange={(e) => setSecretInput(e.target.value)}
                placeholder={
                  authMethod === "oauth"
                    ? "Paste client_secret"
                    : "Paste password"
                }
                autoComplete="new-password"
                className="max-w-xs"
              />
              <Button
                size="sm"
                onClick={saveSecret}
                disabled={
                  !secretInput.trim() ||
                  setOauthSecret.isPending ||
                  setBasicPassword.isPending
                }
              >
                {(setOauthSecret.isPending || setBasicPassword.isPending) ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Save className="h-4 w-4" />
                )}
                Save secret
              </Button>
              {secretSet && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={clearSecret}
                  disabled={
                    clearOauthSecret.isPending || clearBasicPassword.isPending
                  }
                  className="text-destructive hover:text-destructive"
                >
                  {(clearOauthSecret.isPending || clearBasicPassword.isPending) ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4" />
                  )}
                  Clear
                </Button>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Stored in the OS keyring; never written to{" "}
              <span className="font-mono">config.toml</span> or returned by{" "}
              <span className="font-mono">GET /api/settings</span>.
            </p>
          </div>

          {result && (
            <div
              className={
                result.ok
                  ? "rounded-md border border-emerald-300/60 bg-emerald-50 dark:border-emerald-700/60 dark:bg-emerald-950/30 px-3 py-2 text-sm space-y-1"
                  : "rounded-md border border-destructive/60 bg-destructive/5 px-3 py-2 text-sm space-y-1"
              }
            >
              <div
                className={
                  result.ok
                    ? "flex items-center gap-1 text-emerald-700 dark:text-emerald-400 text-xs font-semibold uppercase tracking-wide"
                    : "flex items-center gap-1 text-destructive text-xs font-semibold uppercase tracking-wide"
                }
              >
                {result.ok ? <Check className="h-3 w-3" /> : null}
                {result.ok ? "Connection OK" : "Connection problem"}
              </div>
              {result.message && (
                <p className="text-xs">{result.message}</p>
              )}
              {result.detected &&
                Object.entries(result.detected as Record<string, unknown>).map(
                  ([k, v]) => (
                    <Row
                      key={k}
                      label={k}
                      value={
                        <span className="font-mono text-xs">
                          {typeof v === "string" ? v : JSON.stringify(v)}
                        </span>
                      }
                    />
                  ),
                )}
            </div>
          )}

          {!configured && (
            <p className="text-xs text-muted-foreground">
              Set the instance URL + username, save, then paste the OAuth
              client_secret (or Basic password) and click{" "}
              <span className="font-medium">Test connection</span>.
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

/**
 * Confluence Data Center connector — DOUBLE-GATED.
 *
 * Same shape as the eMASS card: a main pill in the header flips
 * ``enable_confluence`` (controls card body visibility), and an inner
 * amber-bordered panel inside the body holds the per-instance ISSM
 * authorization gate (``confluence_upcoming_gated``) and the shared v0.4
 * connector-cohort gate (``connectors_v04``). The backend
 * ``confluence_enabled()`` fast-path refuses to iterate unless BOTH inner
 * gates are flipped on, so we surface them visually distinct from the
 * main on/off switch.
 *
 * PAT is stored in the OS keyring (slot CONFLUENCE_PAT); never round-trips
 * through state or config.toml.
 */
function ConfluenceConnectorCard() {
  const settings = useSettings();
  const status = useConfluenceStatus();
  const update = useUpdateSettings({
    onSuccess: () => toast.success("Confluence settings saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const test = useTestConfluence({
    onError: (err) => toast.error("Test failed", humanize(err)),
  });
  const setPatMutation = useSetConfluencePat({
    onSuccess: () => toast.success("Confluence PAT saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const clearPat = useClearConfluencePat({
    onSuccess: () => toast.success("Confluence PAT cleared"),
    onError: (err) => toast.error("Clear failed", humanize(err)),
  });

  // Main pill — controls card body visibility. Default false (v0.1 ships
  // local-only and Confluence content frequently has sensitivity labels).
  const enabled = settings.data?.features?.confluence ?? false;
  const toggleEnabled = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.enable_confluence
          ? "Confluence connector enabled"
          : "Confluence connector disabled",
      ),
    onError: (err) => toast.error("Couldn't update connector", humanize(err)),
  });

  // Form state — initialized once settings load.
  const conn = settings.data?.confluence;
  const [baseUrl, setBaseUrl] = useState("");
  const [username, setUsername] = useState("");
  const [spaceKeys, setSpaceKeys] = useState("");
  const [maxPages, setMaxPages] = useState<string>("500");
  const [pat, setPat] = useState("");

  useEffect(() => {
    if (!conn) return;
    setBaseUrl(conn.base_url ?? "");
    setUsername(conn.username ?? "");
    setSpaceKeys(conn.space_keys ?? "");
    setMaxPages(String(conn.max_pages ?? 500));
  }, [conn]);

  const parsedMaxPages = Number.parseInt(maxPages, 10);
  const maxPagesValid = Number.isFinite(parsedMaxPages) && parsedMaxPages >= 1;

  const dirty =
    !!conn &&
    ((baseUrl.trim() || null) !== (conn.base_url ?? null) ||
      (username.trim() || null) !== (conn.username ?? null) ||
      (spaceKeys.trim() || null) !== (conn.space_keys ?? null) ||
      (maxPagesValid && parsedMaxPages !== conn.max_pages));

  async function save() {
    await update.mutateAsync({
      confluence_base_url: baseUrl.trim(),
      confluence_username: username.trim(),
      confluence_space_keys: spaceKeys.trim(),
      ...(maxPagesValid ? { confluence_max_pages: parsedMaxPages } : {}),
    });
  }

  async function runTest() {
    try {
      await test.mutateAsync({
        base_url: baseUrl.trim() || undefined,
        space_keys: spaceKeys.trim() || undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  async function savePat() {
    if (!pat.trim()) return;
    try {
      await setPatMutation.mutateAsync(pat.trim());
      setPat("");
    } catch {
      // toast handled by onError
    }
  }

  const result = test.data;
  const configured = !!status.data?.configured;
  const reachable = !!result?.ok;
  const patSet = !!status.data?.pat_set;
  const gatesSatisfied = !!status.data?.gates_satisfied;
  const sampleTitle = result?.detected?.sample_title;
  const spaceProbed = result?.detected?.space_probed;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <BookOpen className="h-4 w-4" />
              Confluence
              {!enabled ? (
                <Badge variant="outline" className="ml-1">
                  disabled
                </Badge>
              ) : reachable ? (
                <Badge variant="success" className="ml-1">
                  connected
                </Badge>
              ) : configured ? (
                <Badge variant="warning" className="ml-1">
                  configured, untested
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not configured
                </Badge>
              )}
              {enabled && spaceProbed && (
                <Badge variant="outline" className="ml-1">
                  {spaceProbed}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Confluence Data Center via PAT — walks the listed space keys
              and ingests pages as evidence.
            </CardDescription>
          </div>
          {/* Main pill (same shape as SharePoint/eMASS cards). */}
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={
              enabled
                ? "Disable Confluence connector"
                : "Enable Confluence connector"
            }
            onClick={() =>
              toggleEnabled.mutate({ enable_confluence: !enabled })
            }
            disabled={toggleEnabled.isPending || settings.isLoading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      {!enabled ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Connector is off — flip the switch to configure the instance
            URL, PAT, and space scope.
          </p>
        </CardContent>
      ) : (
        <CardContent className="space-y-4">
          <Field label="Base URL">
            <Input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="https://confluence.example.com/wiki"
              autoComplete="off"
            />
          </Field>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="Username (PAT owner)">
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="your.login"
                autoComplete="off"
              />
            </Field>
            <Field label="Max pages per space">
              <Input
                type="number"
                min={1}
                value={maxPages}
                onChange={(e) => setMaxPages(e.target.value)}
              />
            </Field>
          </div>

          <Field label="Space keys (comma-separated)">
            <Input
              value={spaceKeys}
              onChange={(e) => setSpaceKeys(e.target.value)}
              placeholder="PROG, DEV, SEC"
              autoComplete="off"
            />
          </Field>

          {/* PAT row — separate from the other fields because it never gets
              persisted to config.toml. Saved straight into the OS keyring. */}
          <Field
            label={
              <span className="flex items-center gap-2">
                Personal access token
                {patSet ? (
                  <Badge variant="success">stored</Badge>
                ) : (
                  <Badge variant="outline">not set</Badge>
                )}
              </span>
            }
          >
            <div className="flex flex-wrap items-center gap-2">
              <Input
                type="password"
                value={pat}
                onChange={(e) => setPat(e.target.value)}
                placeholder={
                  patSet ? "•••• (paste a new value to replace)" : "Paste PAT"
                }
                autoComplete="off"
                className="flex-1 min-w-[16rem]"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={savePat}
                disabled={!pat.trim() || setPatMutation.isPending}
              >
                <KeyRound className="h-4 w-4" />
                Save PAT
              </Button>
              {patSet && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => clearPat.mutate()}
                  disabled={clearPat.isPending}
                >
                  <Trash2 className="h-4 w-4" />
                  Clear
                </Button>
              )}
            </div>
          </Field>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button onClick={save} disabled={!dirty || update.isPending}>
              {update.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={runTest}
              disabled={
                test.isPending ||
                !baseUrl.trim() ||
                !spaceKeys.trim() ||
                !patSet ||
                !gatesSatisfied
              }
              title={
                !gatesSatisfied
                  ? "Both inner gates must be on before the probe will run."
                  : !patSet
                    ? "Paste and save a PAT first."
                    : "Hit the configured Confluence instance and list 1 page from the first space."
              }
            >
              {test.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
          </div>

          {result && (
            <div
              className={
                result.ok
                  ? "rounded-md border border-emerald-300/60 bg-emerald-50 dark:border-emerald-700/60 dark:bg-emerald-950/30 px-3 py-2 text-sm space-y-1"
                  : "rounded-md border border-destructive/60 bg-destructive/5 px-3 py-2 text-sm space-y-1"
              }
            >
              <div
                className={
                  result.ok
                    ? "flex items-center gap-1 text-emerald-700 dark:text-emerald-400 text-xs font-semibold uppercase tracking-wide"
                    : "flex items-center gap-1 text-destructive text-xs font-semibold uppercase tracking-wide"
                }
              >
                {result.ok ? <Check className="h-3 w-3" /> : null}
                {result.ok ? "Connection OK" : "Connection problem"}
              </div>
              <p className="text-xs">{result.message}</p>
              {spaceProbed && (
                <Row
                  label="space_probed"
                  value={
                    <span className="font-mono text-xs">{spaceProbed}</span>
                  }
                />
              )}
              {sampleTitle && (
                <Row
                  label="sample page"
                  value={
                    <span className="font-mono text-xs">{sampleTitle}</span>
                  }
                />
              )}
            </div>
          )}

          {!configured && (
            <p className="text-xs text-muted-foreground">
              Configure the base URL + space keys, paste a PAT, flip both
              inner gates, then click{" "}
              <span className="font-medium">Test connection</span> to verify
              the PAT resolves the first space.
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

/**
 * Quick-access bookmarks for SharePoint deep links. The user pastes URLs from
 * their browser address bar (typically a `?id=…` or `?RootFolder=…` link to a
 * specific folder); the Browse SharePoint dialog on the Evidence tab renders
 * the saved labels in a "Jump to…" sidebar so they can hop straight to the
 * folder instead of drilling from the library root every time.
 *
 * Server-side PUT trims whitespace and drops empty-URL rows, so we don't
 * bother validating client-side beyond "URL must look like a URL".
 */
function SharePointPriorityLinksEditor() {
  const query = useSharePointPriorityLinks();
  const save = useSetSharePointPriorityLinks({
    onSuccess: () => toast.success("Priority links saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  // Local editable array, seeded from the server. Re-seed on refetch so an
  // out-of-band change (e.g. the user edited config.toml directly) shows up
  // after the next invalidation.
  const [links, setLinks] = useState<SharePointPriorityLink[]>([]);
  useEffect(() => {
    if (query.data) setLinks(query.data.links);
  }, [query.data]);

  const dirty =
    JSON.stringify(links) !== JSON.stringify(query.data?.links ?? []);

  function updateRow(idx: number, patch: Partial<SharePointPriorityLink>) {
    setLinks((prev) => prev.map((l, i) => (i === idx ? { ...l, ...patch } : l)));
  }

  function addRow() {
    setLinks((prev) => [...prev, { label: "", url: "" }]);
  }

  function removeRow(idx: number) {
    setLinks((prev) => prev.filter((_, i) => i !== idx));
  }

  return (
    <div className="space-y-2 pt-3 border-t">
      <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        <Star className="h-3 w-3" />
        Priority links
      </div>
      <p className="text-xs text-muted-foreground">
        Paste deep links from your SharePoint browser address bar (the URL that
        appears when you're viewing a specific folder). They show up as
        "Jump to…" shortcuts in the Browse SharePoint dialog on the Evidence tab.
      </p>

      {query.isLoading && (
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      )}

      {!query.isLoading && (
        <div className="space-y-1.5">
          {links.length === 0 && (
            <p className="text-xs text-muted-foreground italic">
              No links saved yet.
            </p>
          )}
          {links.map((link, idx) => (
            <div key={idx} className="flex items-center gap-2">
              <Input
                value={link.label}
                onChange={(e) => updateRow(idx, { label: e.target.value })}
                placeholder="Label (e.g. SSP folder)"
                className="max-w-[200px]"
                autoComplete="off"
              />
              <Input
                value={link.url}
                onChange={(e) => updateRow(idx, { url: e.target.value })}
                placeholder="https://collab.example.com/sites/…?id=…"
                className="flex-1 font-mono text-xs"
                autoComplete="off"
              />
              <Button
                variant="ghost"
                size="sm"
                onClick={() => removeRow(idx)}
                disabled={save.isPending}
                className="text-destructive hover:text-destructive shrink-0"
                title="Remove"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center gap-2 pt-1">
        <Button
          variant="outline"
          size="sm"
          onClick={addRow}
          disabled={save.isPending}
        >
          <Plus className="h-3.5 w-3.5" />
          Add link
        </Button>
        <Button
          size="sm"
          onClick={() => save.mutate(links)}
          disabled={!dirty || save.isPending}
        >
          {save.isPending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Save className="h-3.5 w-3.5" />
          )}
          {save.isPending ? "Saving…" : "Save links"}
        </Button>
      </div>
    </div>
  );
}

/**
 * Tenable connector — supports two flavors:
 *
 * - **sc** (Tenable.sc / SecurityCenter on-prem): user supplies an FQDN host.
 * - **io** (Tenable.io SaaS): host is implicit (`cloud.tenable.com`); the host
 *   field is rendered read-only.
 *
 * Both flavors authenticate with an API access_key + secret_key pair stored
 * in the OS keyring (never in config.toml). The pill toggle gates the
 * connector entry on the Evidence picker; the test button runs a cheap
 * whoami probe via pyTenable to confirm credentials work.
 */
function TenableConnectorCard() {
  const settings = useSettings();
  const status = useTenableStatus();
  const update = useUpdateSettings({
    onSuccess: () => toast.success("Tenable settings saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const test = useTestTenable({
    onError: (err) => toast.error("Test failed", humanize(err)),
  });
  const setAccessKey = useSetTenableAccessKey({
    onSuccess: () => {
      toast.success("Access key saved");
      setAccessKeyInput("");
    },
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const clearAccessKey = useClearTenableAccessKey({
    onSuccess: () => toast.success("Access key cleared"),
    onError: (err) => toast.error("Clear failed", humanize(err)),
  });
  const setSecretKey = useSetTenableSecretKey({
    onSuccess: () => {
      toast.success("Secret key saved");
      setSecretKeyInput("");
    },
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const clearSecretKey = useClearTenableSecretKey({
    onSuccess: () => toast.success("Secret key cleared"),
    onError: (err) => toast.error("Clear failed", humanize(err)),
  });

  const enabled = settings.data?.features?.tenable ?? false;
  const toggleEnabled = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.enable_tenable
          ? "Tenable connector enabled"
          : "Tenable connector disabled",
      ),
    onError: (err) => toast.error("Couldn't update connector", humanize(err)),
  });

  // Form state — seeded from settings, edits diff against the saved values.
  const tn = settings.data?.tenable;
  const [flavor, setFlavor] = useState<"sc" | "io">("io");
  const [host, setHost] = useState("");
  const [accessKeyInput, setAccessKeyInput] = useState("");
  const [secretKeyInput, setSecretKeyInput] = useState("");

  useEffect(() => {
    if (!tn) return;
    setFlavor((tn.flavor as "sc" | "io" | null) ?? "io");
    setHost(tn.host ?? "");
  }, [tn]);

  // .io has an implicit host; only .sc edits matter for "dirty".
  const dirty =
    !!tn &&
    (flavor !== (tn.flavor ?? null) ||
      (flavor === "sc" && (host.trim() || null) !== (tn.host ?? null)));

  async function save() {
    await update.mutateAsync({
      tenable_flavor: flavor,
      // For .io we send empty-string to clear any stale host that might be
      // lingering in config.toml from a prior .sc selection. For .sc we send
      // the trimmed value (server-side strip handles trailing slash).
      tenable_host: flavor === "sc" ? host.trim() : "",
    });
  }

  async function runTest() {
    try {
      await test.mutateAsync({
        flavor,
        host: flavor === "sc" ? host.trim() || undefined : undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  const result = test.data;
  const configured = !!status.data?.configured;
  const accessKeySet = !!status.data?.access_key_set;
  const secretKeySet = !!status.data?.secret_key_set;
  const effectiveHost = status.data?.host ?? null;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <Radar className="h-4 w-4" />
              Tenable
              {!enabled ? (
                <Badge variant="outline" className="ml-1">
                  disabled
                </Badge>
              ) : configured ? (
                <Badge variant="success" className="ml-1">
                  configured
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not configured
                </Badge>
              )}
              {enabled && status.data?.flavor && (
                <Badge variant="outline" className="ml-1">
                  {status.data.flavor === "io" ? "Tenable.io" : "Tenable.sc"}
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Ingest ACAS / Nessus scan findings as evidence. Tenable.sc is the
              on-prem SecurityCenter; Tenable.io is the SaaS cloud at
              cloud.tenable.com.
            </CardDescription>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={enabled ? "Disable Tenable connector" : "Enable Tenable connector"}
            onClick={() => toggleEnabled.mutate({ enable_tenable: !enabled })}
            disabled={toggleEnabled.isPending || settings.isLoading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      {!enabled ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Connector is off. Turn it on to configure credentials and use
            Tenable as an evidence source.
          </p>
        </CardContent>
      ) : (
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="Flavor">
              <Select value={flavor} onValueChange={(v) => setFlavor(v as "sc" | "io")}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="io">Tenable.io (SaaS)</SelectItem>
                  <SelectItem value="sc">Tenable.sc (on-prem)</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={flavor === "io" ? "Host (implicit)" : "Host (FQDN)"}>
              <Input
                value={flavor === "io" ? (effectiveHost ?? "cloud.tenable.com") : host}
                onChange={(e) => setHost(e.target.value)}
                placeholder={
                  flavor === "io"
                    ? "cloud.tenable.com"
                    : "securitycenter.example.mil"
                }
                disabled={flavor === "io"}
                autoComplete="off"
              />
            </Field>
          </div>

          <div className="rounded-md border bg-muted/30 px-3 py-2 space-y-2">
            <div className="text-xs font-medium text-muted-foreground">
              API credentials (stored in OS keyring)
            </div>

            <Field
              label={
                <span className="flex items-center gap-2">
                  <span>Access key</span>
                  {accessKeySet && (
                    <Badge variant="success" className="text-[10px] px-1.5 py-0">
                      stored
                    </Badge>
                  )}
                </span>
              }
            >
              <div className="flex gap-2">
                <Input
                  type="password"
                  value={accessKeyInput}
                  onChange={(e) => setAccessKeyInput(e.target.value)}
                  placeholder={accessKeySet ? "•••••••• (saved)" : "Paste access key"}
                  autoComplete="off"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setAccessKey.mutateAsync(accessKeyInput.trim())}
                  disabled={!accessKeyInput.trim() || setAccessKey.isPending}
                >
                  {setAccessKey.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <KeyRound className="h-4 w-4" />
                  )}
                  Save
                </Button>
                {accessKeySet && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => clearAccessKey.mutateAsync()}
                    disabled={clearAccessKey.isPending}
                    className="text-destructive hover:text-destructive"
                    title="Remove access key from keyring"
                  >
                    {clearAccessKey.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4" />
                    )}
                  </Button>
                )}
              </div>
            </Field>

            <Field
              label={
                <span className="flex items-center gap-2">
                  <span>Secret key</span>
                  {secretKeySet && (
                    <Badge variant="success" className="text-[10px] px-1.5 py-0">
                      stored
                    </Badge>
                  )}
                </span>
              }
            >
              <div className="flex gap-2">
                <Input
                  type="password"
                  value={secretKeyInput}
                  onChange={(e) => setSecretKeyInput(e.target.value)}
                  placeholder={secretKeySet ? "•••••••• (saved)" : "Paste secret key"}
                  autoComplete="off"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setSecretKey.mutateAsync(secretKeyInput.trim())}
                  disabled={!secretKeyInput.trim() || setSecretKey.isPending}
                >
                  {setSecretKey.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <KeyRound className="h-4 w-4" />
                  )}
                  Save
                </Button>
                {secretKeySet && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => clearSecretKey.mutateAsync()}
                    disabled={clearSecretKey.isPending}
                    className="text-destructive hover:text-destructive"
                    title="Remove secret key from keyring"
                  >
                    {clearSecretKey.isPending ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4" />
                    )}
                  </Button>
                )}
              </div>
            </Field>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button onClick={save} disabled={!dirty || update.isPending}>
              {update.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={runTest}
              disabled={
                test.isPending ||
                !accessKeySet ||
                !secretKeySet ||
                (flavor === "sc" && !host.trim())
              }
              title="Run a whoami probe against the Tenable API."
            >
              {test.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
          </div>

          {result && (
            <div
              className={
                result.ok
                  ? "rounded-md border border-emerald-300/60 bg-emerald-50 dark:border-emerald-700/60 dark:bg-emerald-950/30 px-3 py-2 text-sm space-y-1"
                  : "rounded-md border border-destructive/60 bg-destructive/5 px-3 py-2 text-sm space-y-1"
              }
            >
              <div
                className={
                  result.ok
                    ? "flex items-center gap-1 text-emerald-700 dark:text-emerald-400 text-xs font-semibold uppercase tracking-wide"
                    : "flex items-center gap-1 text-destructive text-xs font-semibold uppercase tracking-wide"
                }
              >
                {result.ok ? <Check className="h-3 w-3" /> : null}
                {result.ok ? "Connection OK" : "Connection problem"}
              </div>
              {result.ok ? (
                <>
                  <Row label="message" value={<span>{result.message}</span>} />
                  {result.detected && (
                    <>
                      <Row
                        label="flavor"
                        value={
                          <span className="font-mono text-xs">
                            {result.detected.flavor}
                          </span>
                        }
                      />
                      <Row
                        label="host"
                        value={
                          <span className="font-mono text-xs">
                            {result.detected.host}
                          </span>
                        }
                      />
                      <Row
                        label="username"
                        value={
                          <span className="font-mono text-xs">
                            {result.detected.username}
                          </span>
                        }
                      />
                    </>
                  )}
                </>
              ) : null}
            </div>
          )}

          {!configured && (
            <p className="text-xs text-muted-foreground">
              {flavor === "sc"
                ? "Enter the SecurityCenter host, save both API keys, then click Test connection."
                : "Save both API keys, then click Test connection. Tenable.io always uses cloud.tenable.com."}
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}


/**
 * Splunk connector card. Single-gated (the `enable_splunk` feature flag is
 * the only kill-switch — unlike Confluence/Jira/eMASS which double-gate on a
 * separate ack). Form mirrors the SharePoint card layout: header with badge +
 * inline toggle pill, body hidden when disabled, save/test buttons share a
 * row with token Set/Clear because the token is stored separately in the OS
 * keyring (POST/DELETE /api/splunk/token) and never round-trips through
 * /api/settings.
 *
 * Splunk is config-bound: only saved-search NAMES are accepted (raw SPL is
 * rejected at SplunkSource construction). The textarea takes one search name
 * per line; we trim + drop blanks before sending.
 */
function SplunkConnectorCard() {
  const settings = useSettings();
  const status = useSplunkStatus();
  const update = useUpdateSettings({
    onSuccess: () => toast.success("Splunk settings saved"),
    onError: (err) => toast.error("Save failed", humanize(err)),
  });
  const test = useTestSplunk({
    onError: (err) => toast.error("Test failed", humanize(err)),
  });
  const setToken = useSetSplunkToken({
    onSuccess: () => toast.success("Splunk token saved"),
    onError: (err) => toast.error("Couldn't save token", humanize(err)),
  });
  const clearToken = useClearSplunkToken({
    onSuccess: () => toast.success("Splunk token cleared"),
    onError: (err) => toast.error("Couldn't clear token", humanize(err)),
  });

  // Feature-flag toggle. Defaults false in backend Config — v0.4 ships off so
  // a fresh install never accidentally probes a corporate Splunk indexer just
  // because the user typed a hostname.
  const enabled = settings.data?.features?.splunk ?? false;
  const toggleEnabled = useUpdateSettings({
    onSuccess: (_res, vars) =>
      toast.success(
        vars.enable_splunk
          ? "Splunk connector enabled"
          : "Splunk connector disabled",
      ),
    onError: (err) => toast.error("Couldn't update connector", humanize(err)),
  });

  // Saved settings → form-state seed. Splunk-specific: saved_searches is an
  // array; we render it as a newline-separated textarea so the user can paste
  // a list straight out of Splunk Web's Search > Reports view.
  const sp = settings.data?.splunk;
  const [host, setHost] = useState("");
  const [port, setPort] = useState<string>("8089");
  const [scheme, setScheme] = useState<string>("https");
  const [app, setApp] = useState<string>("search");
  const [owner, setOwner] = useState<string>("-");
  const [verifyTls, setVerifyTls] = useState<boolean>(true);
  const [savedSearchesText, setSavedSearchesText] = useState("");
  const [tokenInput, setTokenInput] = useState("");

  useEffect(() => {
    if (!sp) return;
    setHost(sp.host ?? "");
    setPort(String(sp.port ?? 8089));
    setScheme(sp.scheme ?? "https");
    setApp(sp.app ?? "search");
    setOwner(sp.owner ?? "-");
    setVerifyTls(sp.verify_tls);
    setSavedSearchesText((sp.saved_searches ?? []).join("\n"));
  }, [sp]);

  // Parse the textarea into a clean list — trim + drop blanks. Same shape
  // the backend re-normalises on POST, so this is mostly UX clarity for the
  // dirty check below.
  const parsedSavedSearches = savedSearchesText
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

  const portNum = Number.parseInt(port, 10);
  const portValid = Number.isFinite(portNum) && portNum > 0 && portNum < 65536;

  const dirty =
    !!sp &&
    ((host.trim() || null) !== (sp.host ?? null) ||
      (portValid && portNum !== sp.port) ||
      scheme !== sp.scheme ||
      app.trim() !== sp.app ||
      owner.trim() !== sp.owner ||
      verifyTls !== sp.verify_tls ||
      parsedSavedSearches.join("\n") !== (sp.saved_searches ?? []).join("\n"));

  async function save() {
    await update.mutateAsync({
      splunk_host: host.trim(),
      splunk_port: portValid ? portNum : undefined,
      splunk_scheme: scheme,
      splunk_app: app.trim(),
      splunk_owner: owner.trim(),
      splunk_verify_tls: verifyTls,
      splunk_saved_searches: parsedSavedSearches,
    });
  }

  async function runTest() {
    try {
      // Probe the in-form values so the user can verify a candidate config
      // (host, scheme, saved-search names) before saving. Token comes from
      // the keyring server-side unless they've also pasted a fresh token in
      // the input below.
      await test.mutateAsync({
        host: host.trim() || undefined,
        port: portValid ? portNum : undefined,
        scheme,
        app: app.trim() || undefined,
        owner: owner.trim() || undefined,
        verify_tls: verifyTls,
        saved_searches: parsedSavedSearches,
        token: tokenInput.trim() || undefined,
      });
    } catch {
      // toast handled by onError
    }
  }

  async function saveToken() {
    const t = tokenInput.trim();
    if (!t) return;
    await setToken.mutateAsync(t);
    setTokenInput("");
  }

  const result = test.data;
  const tokenSet = !!status.data?.token_set;
  const configured = !!status.data?.configured;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Splunk
              {!enabled ? (
                <Badge variant="outline" className="ml-1">
                  disabled
                </Badge>
              ) : configured ? (
                <Badge variant="success" className="ml-1">
                  configured
                </Badge>
              ) : tokenSet ? (
                <Badge variant="warning" className="ml-1">
                  needs saved searches
                </Badge>
              ) : (
                <Badge variant="outline" className="ml-1">
                  not configured
                </Badge>
              )}
            </CardTitle>
            <CardDescription>
              Pulls evidence from named Splunk saved searches via the REST API.
              Token-only auth, stored in the OS keyring; raw SPL is intentionally
              not accepted.
            </CardDescription>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label={enabled ? "Disable Splunk connector" : "Enable Splunk connector"}
            onClick={() => toggleEnabled.mutate({ enable_splunk: !enabled })}
            disabled={toggleEnabled.isPending || settings.isLoading}
            className={cn(
              "relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50",
              enabled ? "bg-primary" : "bg-input",
            )}
          >
            <span
              className={cn(
                "pointer-events-none inline-block h-5 w-5 transform rounded-full bg-background shadow ring-0 transition-transform",
                enabled ? "translate-x-5" : "translate-x-0",
              )}
            />
          </button>
        </div>
      </CardHeader>
      {!enabled ? (
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Connector is off. Turn it on to configure a Splunk REST host, store
            an auth token, and enable saved-search evidence sweeps.
          </p>
        </CardContent>
      ) : (
        <CardContent className="space-y-3">
          <Field label="Host (Splunk REST endpoint, no scheme)">
            <Input
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="splunk.example.mil"
              autoComplete="off"
            />
          </Field>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Field label="Port">
              <Input
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="8089"
                inputMode="numeric"
                autoComplete="off"
              />
            </Field>
            <Field label="Scheme">
              <Select value={scheme} onValueChange={setScheme}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="https">https</SelectItem>
                  <SelectItem value="http">http</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label="Verify TLS">
              <label className="flex h-9 items-center gap-2 rounded-md border border-input bg-background px-3 text-sm">
                <input
                  type="checkbox"
                  checked={verifyTls}
                  onChange={(e) => setVerifyTls(e.target.checked)}
                  className="h-4 w-4"
                />
                <span className="text-muted-foreground">
                  {verifyTls ? "Strict" : "Skip (dev only)"}
                </span>
              </label>
            </Field>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <Field label="App namespace (default: search)">
              <Input
                value={app}
                onChange={(e) => setApp(e.target.value)}
                placeholder="search"
                autoComplete="off"
              />
            </Field>
            <Field label="Owner (default: -)">
              <Input
                value={owner}
                onChange={(e) => setOwner(e.target.value)}
                placeholder="-"
                autoComplete="off"
              />
            </Field>
          </div>

          <Field label="Saved searches (one name per line)">
            <textarea
              value={savedSearchesText}
              onChange={(e) => setSavedSearchesText(e.target.value)}
              placeholder={"CCIS - Failed Logons\nCCIS - Privileged Access"}
              rows={4}
              className="flex w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
              spellCheck={false}
            />
          </Field>

          <div className="rounded-md border border-input bg-muted/30 p-3 space-y-2">
            <div className="flex items-center justify-between">
              <SectionHeader>Auth token</SectionHeader>
              {tokenSet ? (
                <Badge variant="success">stored</Badge>
              ) : (
                <Badge variant="outline">missing</Badge>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Splunk auth tokens live in the OS keyring, never on disk or in
              this form. Paste a token to store it; clear removes it from the
              keyring entirely.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <Input
                type="password"
                value={tokenInput}
                onChange={(e) => setTokenInput(e.target.value)}
                placeholder="Paste Splunk auth token"
                autoComplete="off"
                className="max-w-md"
              />
              <Button
                size="sm"
                onClick={saveToken}
                disabled={setToken.isPending || tokenInput.trim().length < 16}
                title="Minimum 16 chars — typo guard."
              >
                {setToken.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <KeyRound className="h-4 w-4" />
                )}
                {setToken.isPending ? "Saving…" : "Save token"}
              </Button>
              {tokenSet && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => clearToken.mutateAsync()}
                  disabled={clearToken.isPending}
                  className="text-destructive hover:text-destructive"
                >
                  {clearToken.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Trash2 className="h-4 w-4" />
                  )}
                  {clearToken.isPending ? "Clearing…" : "Clear"}
                </Button>
              )}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <Button onClick={save} disabled={!dirty || !portValid || update.isPending}>
              {update.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {update.isPending ? "Saving…" : "Save"}
            </Button>
            <Button
              variant="outline"
              onClick={runTest}
              disabled={
                test.isPending ||
                !host.trim() ||
                (!tokenSet && !tokenInput.trim()) ||
                parsedSavedSearches.length === 0
              }
              title="Live service.info() probe against the Splunk REST endpoint."
            >
              {test.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <PlugZap className="h-4 w-4" />
              )}
              {test.isPending ? "Testing…" : "Test connection"}
            </Button>
          </div>

          {result && (
            <div
              className={
                result.ok
                  ? "rounded-md border border-emerald-300/60 bg-emerald-50 dark:border-emerald-700/60 dark:bg-emerald-950/30 px-3 py-2 text-sm space-y-1"
                  : "rounded-md border border-destructive/60 bg-destructive/5 px-3 py-2 text-sm space-y-1"
              }
            >
              <div
                className={
                  result.ok
                    ? "flex items-center gap-1 text-emerald-700 dark:text-emerald-400 text-xs font-semibold uppercase tracking-wide"
                    : "flex items-center gap-1 text-destructive text-xs font-semibold uppercase tracking-wide"
                }
              >
                {result.ok ? <Check className="h-3 w-3" /> : null}
                {result.ok ? "Connection OK" : "Connection problem"}
              </div>
              <p className="text-sm">{result.message}</p>
              {result.detected?.host && (
                <Row
                  label="host"
                  value={<span className="font-mono text-xs">{result.detected.host}</span>}
                />
              )}
              {result.detected?.version && (
                <Row
                  label="version"
                  value={<span className="font-mono text-xs">{result.detected.version}</span>}
                />
              )}
              {typeof result.detected?.saved_searches === "number" && (
                <Row
                  label="saved searches"
                  value={
                    <span className="font-mono text-xs">{result.detected.saved_searches}</span>
                  }
                />
              )}
            </div>
          )}

          {!configured && enabled && (
            <p className="text-xs text-muted-foreground">
              Fill in the host, save at least one Splunk auth token, add the saved
              searches you want to harvest, then click{" "}
              <span className="font-medium">Test connection</span> to verify.
            </p>
          )}
        </CardContent>
      )}
    </Card>
  );
}

function Field({
  label,
  children,
}: {
  // ReactNode (not just string) so callers can decorate the label with
  // badges/icons — e.g. the "Active" tag next to whichever model field
  // matches the current llm_provider selection in DefaultsCard.
  label: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <label className="block space-y-1.5">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}

// ---------------------------------------------------------------------------
// AutomationTab — per-workbook evidence-pull schedule management
// ---------------------------------------------------------------------------

/** Convert interval_minutes to a concise human label. */
function fmtInterval(minutes: number): string {
  if (minutes < 60) return `every ${minutes}m`;
  const h = minutes / 60;
  if (Number.isInteger(h)) return `every ${h}h`;
  return `every ${minutes}m`;
}

/** Format an ISO timestamp as "YYYY-MM-DD HH:MM" or "—". */
function fmtTs(ts: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

const SOURCE_TYPE_OPTIONS = [
  { value: "all", label: "All sources" },
  { value: "local", label: "Local" },
  { value: "sharepoint", label: "SharePoint" },
  { value: "gitlab", label: "GitLab" },
  { value: "splunk", label: "Splunk" },
  { value: "tenable", label: "Tenable" },
  { value: "servicenow_grc", label: "ServiceNow GRC" },
  { value: "archer", label: "Archer" },
];

const DEFAULT_INTERVAL = 1440;

type ScheduleFormState = {
  name: string;
  source_type: string;
  source_ref: string;
  interval_minutes: number;
  run_assessment: boolean;
  enabled: boolean;
};

const BLANK_FORM: ScheduleFormState = {
  name: "",
  source_type: "local",
  source_ref: "",
  interval_minutes: DEFAULT_INTERVAL,
  run_assessment: false,
  enabled: true,
};

function AutomationTab() {
  const workbooks = useWorkbooks();
  const allWorkbooks = workbooks.data ?? [];

  // Let the user pick which workbook's schedules to manage — default to the
  // most-recently-opened one.
  const [selectedWbId, setSelectedWbId] = useState<number | undefined>(
    () => allWorkbooks.sort((a, b) =>
      new Date(b.last_opened).getTime() - new Date(a.last_opened).getTime()
    )[0]?.id,
  );

  // Re-default when workbooks load for the first time
  useEffect(() => {
    if (selectedWbId === undefined && allWorkbooks.length > 0) {
      const sorted = [...allWorkbooks].sort(
        (a, b) => new Date(b.last_opened).getTime() - new Date(a.last_opened).getTime(),
      );
      setSelectedWbId(sorted[0].id);
    }
  }, [allWorkbooks, selectedWbId]);

  const schedulesQuery = useAutomationSchedules(selectedWbId);
  const schedules = schedulesQuery.data ?? [];

  const createMut = useCreateAutomationSchedule();
  const updateMut = useUpdateAutomationSchedule();
  const deleteMut = useDeleteAutomationSchedule();
  const runNowMut = useRunAutomationScheduleNow();

  // New-schedule dialog
  const [newOpen, setNewOpen] = useState(false);
  const [newForm, setNewForm] = useState<ScheduleFormState>(BLANK_FORM);

  // Edit dialog
  const [editTarget, setEditTarget] = useState<AutomationSchedule | null>(null);
  const [editForm, setEditForm] = useState<ScheduleFormState>(BLANK_FORM);

  // Delete confirm
  const [deleteTarget, setDeleteTarget] = useState<AutomationSchedule | null>(null);

  function openEdit(s: AutomationSchedule) {
    setEditTarget(s);
    setEditForm({
      name: s.name ?? "",
      source_type: s.source_type,
      source_ref: s.source_ref ?? "",
      interval_minutes: s.interval_minutes,
      run_assessment: s.run_assessment,
      enabled: s.enabled,
    });
  }

  async function handleCreate() {
    if (!selectedWbId) return;
    try {
      await createMut.mutateAsync({
        workbook_id: selectedWbId,
        source_type: newForm.source_type,
        name: newForm.name.trim() || null,
        source_ref: newForm.source_ref.trim() || null,
        interval_minutes: newForm.interval_minutes,
        run_assessment: newForm.run_assessment,
        enabled: newForm.enabled,
      });
      toast.success("Schedule created");
      setNewOpen(false);
      setNewForm(BLANK_FORM);
    } catch (e) {
      toast.error(humanize(e as Error));
    }
  }

  async function handleEdit() {
    if (!editTarget) return;
    try {
      await updateMut.mutateAsync({
        id: editTarget.id,
        workbookId: editTarget.workbook_id,
        patch: {
          name: editForm.name.trim() || null,
          source_type: editForm.source_type,
          source_ref: editForm.source_ref.trim() || null,
          interval_minutes: editForm.interval_minutes,
          run_assessment: editForm.run_assessment,
          enabled: editForm.enabled,
        },
      });
      toast.success("Schedule updated");
      setEditTarget(null);
    } catch (e) {
      toast.error(humanize(e as Error));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await deleteMut.mutateAsync({
        id: deleteTarget.id,
        workbookId: deleteTarget.workbook_id,
      });
      toast.success("Schedule deleted");
      setDeleteTarget(null);
    } catch (e) {
      toast.error(humanize(e as Error));
    }
  }

  async function handleRunNow(s: AutomationSchedule) {
    try {
      await runNowMut.mutateAsync({ id: s.id, workbookId: s.workbook_id });
      toast.success(`Schedule "${s.name ?? s.source_type}" queued`);
    } catch (e) {
      toast.error(humanize(e as Error));
    }
  }

  async function handleToggleEnabled(s: AutomationSchedule) {
    try {
      await updateMut.mutateAsync({
        id: s.id,
        workbookId: s.workbook_id,
        patch: { enabled: !s.enabled },
      });
    } catch (e) {
      toast.error(humanize(e as Error));
    }
  }

  // Empty state: no workbooks in DB at all
  if (!workbooks.isLoading && allWorkbooks.length === 0) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-sm text-muted-foreground">
          Open a workbook to configure its automation queue.
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-4">
            <div className="space-y-1">
              <CardTitle className="flex items-center gap-2">
                <Clock className="h-4 w-4" />
                Automation schedules
              </CardTitle>
              <CardDescription>
                Schedules pull evidence from a connector on a cadence and,
                optionally, chain a re-assessment immediately after.
              </CardDescription>
            </div>
            <Button
              size="sm"
              variant="outline"
              disabled={!selectedWbId}
              onClick={() => { setNewForm(BLANK_FORM); setNewOpen(true); }}
            >
              <Plus className="h-4 w-4 mr-1" />
              New schedule
            </Button>
          </div>
          {/* Workbook selector */}
          <div className="pt-3">
            <Select
              value={selectedWbId !== undefined ? String(selectedWbId) : ""}
              onValueChange={(v) => setSelectedWbId(v ? Number(v) : undefined)}
            >
              <SelectTrigger className="max-w-xs">
                <SelectValue placeholder="Select workbook…" />
              </SelectTrigger>
              <SelectContent>
                {allWorkbooks
                  .slice()
                  .sort((a, b) => new Date(b.last_opened).getTime() - new Date(a.last_opened).getTime())
                  .map((w) => (
                    <SelectItem key={w.id} value={String(w.id)}>
                      {w.filename}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
          </div>
        </CardHeader>

        <CardContent>
          {schedulesQuery.isLoading ? (
            <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading schedules…
            </div>
          ) : schedules.length === 0 ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No schedules yet — add one to auto-pull evidence on a cadence.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name / source</TableHead>
                  <TableHead>Interval</TableHead>
                  <TableHead>Re-assess</TableHead>
                  <TableHead>Last run</TableHead>
                  <TableHead>Next run</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Enabled</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {schedules.map((s) => (
                  <TableRow key={s.id} className={cn(!s.enabled && "opacity-50")}>
                    <TableCell className="font-medium">
                      <div>{s.name ?? <span className="italic text-muted-foreground">(unnamed)</span>}</div>
                      <div className="text-xs text-muted-foreground">
                        {SOURCE_TYPE_OPTIONS.find((o) => o.value === s.source_type)?.label ?? s.source_type}
                        {" · "}
                        {s.source_ref ?? "all roots"}
                      </div>
                    </TableCell>
                    <TableCell className="tabular-nums">{fmtInterval(s.interval_minutes)}</TableCell>
                    <TableCell>
                      {s.run_assessment ? (
                        <Badge variant="secondary">yes</Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">no</span>
                      )}
                    </TableCell>
                    <TableCell className="tabular-nums text-xs">{fmtTs(s.last_run_at)}</TableCell>
                    <TableCell className="tabular-nums text-xs">{fmtTs(s.next_run_at)}</TableCell>
                    <TableCell>
                      {s.last_status ? (
                        <Badge
                          variant={
                            s.last_status === "ok" ? "success"
                            : s.last_status === "running" ? "secondary"
                            : "warning"
                          }
                        >
                          {s.last_status}
                        </Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <Switch
                        checked={s.enabled}
                        disabled={updateMut.isPending}
                        aria-label={`${s.enabled ? "Disable" : "Enable"} schedule`}
                        onCheckedChange={() => handleToggleEnabled(s)}
                      />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1 justify-end">
                        <Button
                          size="icon"
                          variant="ghost"
                          title="Run now"
                          disabled={runNowMut.isPending}
                          onClick={() => handleRunNow(s)}
                        >
                          <Play className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="Edit"
                          onClick={() => openEdit(s)}
                        >
                          <Pencil className="h-3.5 w-3.5" />
                        </Button>
                        <Button
                          size="icon"
                          variant="ghost"
                          title="Delete"
                          className="text-destructive hover:text-destructive"
                          onClick={() => setDeleteTarget(s)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* New schedule dialog */}
      <Dialog open={newOpen} onOpenChange={setNewOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>New automation schedule</DialogTitle>
          </DialogHeader>
          <ScheduleForm form={newForm} onChange={setNewForm} />
          <DialogFooter>
            <DialogClose asChild>
              <Button variant="ghost">Cancel</Button>
            </DialogClose>
            <Button onClick={handleCreate} disabled={createMut.isPending}>
              {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit dialog */}
      <Dialog open={!!editTarget} onOpenChange={(o) => { if (!o) setEditTarget(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit schedule</DialogTitle>
          </DialogHeader>
          <ScheduleForm form={editForm} onChange={setEditForm} />
          <DialogFooter>
            <Button variant="ghost" onClick={() => setEditTarget(null)}>Cancel</Button>
            <Button onClick={handleEdit} disabled={updateMut.isPending}>
              {updateMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm dialog */}
      <Dialog open={!!deleteTarget} onOpenChange={(o) => { if (!o) setDeleteTarget(null); }}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Delete schedule?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This will permanently remove the schedule
            {deleteTarget?.name ? ` "${deleteTarget.name}"` : ""}.
            Running jobs are not interrupted.
          </p>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setDeleteTarget(null)}>Cancel</Button>
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={deleteMut.isPending}
            >
              {deleteMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** Reusable form body for create + edit dialogs. */
function ScheduleForm({
  form,
  onChange,
}: {
  form: ScheduleFormState;
  onChange: (next: ScheduleFormState) => void;
}) {
  function set<K extends keyof ScheduleFormState>(k: K, v: ScheduleFormState[K]) {
    onChange({ ...form, [k]: v });
  }
  return (
    <div className="space-y-4 py-2">
      <Field label="Name (optional)">
        <Input
          placeholder="e.g. Daily SP pull"
          value={form.name}
          onChange={(e) => set("name", e.target.value)}
        />
      </Field>
      <Field label="Source type">
        <Select value={form.source_type} onValueChange={(v) => set("source_type", v)}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {SOURCE_TYPE_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </Field>
      <Field label="Source ref (leave blank for all roots)">
        <Input
          placeholder="e.g. /sites/MySite/Shared Documents/Evidence"
          value={form.source_ref}
          onChange={(e) => set("source_ref", e.target.value)}
        />
      </Field>
      <Field label="Interval (minutes)">
        <Input
          type="number"
          min={5}
          step={60}
          value={form.interval_minutes}
          onChange={(e) => set("interval_minutes", Math.max(5, Number(e.target.value)))}
        />
        <span className="text-xs text-muted-foreground">
          {fmtInterval(form.interval_minutes)} · default 1440 (24 h)
        </span>
      </Field>
      <div className="flex items-center justify-between rounded-md border px-3 py-2">
        <div>
          <p className="text-sm font-medium">Chain re-assessment</p>
          <p className="text-xs text-muted-foreground">
            Run a re-assessment immediately after each successful pull.
          </p>
        </div>
        <Switch
          checked={form.run_assessment}
          onCheckedChange={(v) => set("run_assessment", v)}
        />
      </div>
      <div className="flex items-center justify-between rounded-md border px-3 py-2">
        <div>
          <p className="text-sm font-medium">Enabled</p>
          <p className="text-xs text-muted-foreground">Uncheck to pause without deleting.</p>
        </div>
        <Switch
          checked={form.enabled}
          onCheckedChange={(v) => set("enabled", v)}
        />
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  // Items-start (not center) so when the value side stacks vertically
  // (Badge above a long descriptor) the label aligns with the top row
  // instead of floating to the visual centerline. gap-4 keeps the label
  // away from the right column even on narrower viewports.
  return (
    <div className="flex items-start justify-between gap-4 border-b last:border-0 py-2">
      <span className="text-muted-foreground shrink-0 pt-0.5">{label}</span>
      <div className="text-right min-w-0">{value}</div>
    </div>
  );
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground/80 pt-2 pl-1">
      {children}
    </h2>
  );
}

import { useEffect, useMemo, useState, type FormEvent } from "react";
import { CheckCircle2, RefreshCw, RotateCcw, Save, AlertTriangle } from "lucide-react";
import { CopyButton } from "./CopyButton.tsx";
import type { Lang } from "../proxy/i18n.ts";
import { TRANSLATIONS } from "../proxy/i18n.ts";
import type { PanelStateData } from "../types/proxy.ts";

interface ConfigViewProps {
  data: PanelStateData;
  adminBasePath: string;
  lang: Lang;
  onConfigSaved: (nextAdminBasePath: string, nextState: PanelStateData) => void;
}

type SecretAction = "keep" | "set" | "derive";
type AdTagAction = "keep" | "set" | "clear";

// 在浏览器端生成 24 字符的随机高强度 ADMIN_KEY
function generateAdminKeyClient(): string {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "x").replace(/\//g, "y").replace(/=+$/, "");
}

// 在浏览器端生成 dd + 32 位十六进制固定 Secret
function generateSecretHexClient(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let hex = "dd";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

// 在浏览器端生成标准 UUID v4
function generateUuidV4Client(): string {
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0"));
  return `${h.slice(0, 4).join("")}-${h.slice(4, 6).join("")}-${h.slice(6, 8).join("")}-${h.slice(8, 10).join("")}-${h.slice(10, 16).join("")}`;
}

// 动态运行配置编辑器（无需重启进程，实时持久化到 storage/runtime.json 并热更新）
export function ConfigView({ data, adminBasePath, lang, onConfigSaved }: ConfigViewProps) {
  const t = TRANSLATIONS[lang];
  const currentAdminKey = decodeURIComponent(adminBasePath.replace(/^\//, ""));

  const [adminKey, setAdminKey] = useState(currentAdminKey);
  const [secretAction, setSecretAction] = useState<SecretAction>("keep");
  const [secretInput, setSecretInput] = useState("");
  const [carrier, setCarrier] = useState<"websocket-lanes" | "websocket">(data.config.carrier);
  const [maxStreams, setMaxStreams] = useState(String(data.config.maxStreams));
  const [allowedHosts, setAllowedHosts] = useState(data.config.allowedHosts.join(", ") || "*");
  const [extraHosts, setExtraHosts] = useState(data.config.extraHosts.join(", "));
  const [decoyUrl, setDecoyUrl] = useState(data.config.decoyUrl || "");
  const [sessionPath, setSessionPath] = useState(data.config.sessionPath);
  const [wsPath, setWsPath] = useState(data.config.wsPath);
  const [dcPorts, setDcPorts] = useState((data.config.dcPorts || [443, 80, 5222]).join(", "));
  const [adTagAction, setAdTagAction] = useState<AdTagAction>("keep");
  const [adTagInput, setAdTagInput] = useState("");
  const [debug, setDebug] = useState(Boolean(data.config.debug));
  const [generatorEnabled, setGeneratorEnabled] = useState(Boolean(data.config.generatorEnabled));
  const [acceptGenerated, setAcceptGenerated] = useState(Boolean(data.config.acceptGenerated));
  const [vlessEnabled, setVlessEnabled] = useState(data.config.vlessEnabled !== false);
  const [vlessUuid, setVlessUuid] = useState(
    data.config.vlessUuid || "03267b72-5095-44be-8af1-a511b692832b"
  );
  const [vlessPath, setVlessPath] = useState(
    data.config.vlessPath || "/helloss-jsusyxystsdsahysy"
  );
  const [vlessDisguisedDomain, setVlessDisguisedDomain] = useState(
    data.config.vlessDisguisedDomain || "https://example.com"
  );

  const [saving, setSaving] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [confirmReset, setConfirmReset] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // 外部数据刷新或重置后同步表单默认值
  useEffect(() => {
    setAdminKey(decodeURIComponent(adminBasePath.replace(/^\//, "")));
    setSecretAction("keep");
    setSecretInput("");
    setCarrier(data.config.carrier);
    setMaxStreams(String(data.config.maxStreams));
    setAllowedHosts(data.config.allowedHosts.join(", ") || "*");
    setExtraHosts(data.config.extraHosts.join(", "));
    setDecoyUrl(data.config.decoyUrl || "");
    setSessionPath(data.config.sessionPath);
    setWsPath(data.config.wsPath);
    setDcPorts((data.config.dcPorts || [443, 80, 5222]).join(", "));
    setAdTagAction("keep");
    setAdTagInput("");
    setDebug(Boolean(data.config.debug));
    setGeneratorEnabled(Boolean(data.config.generatorEnabled));
    setAcceptGenerated(Boolean(data.config.acceptGenerated));
    setVlessEnabled(data.config.vlessEnabled !== false);
    setVlessUuid(data.config.vlessUuid || "03267b72-5095-44be-8af1-a511b692832b");
    setVlessPath(data.config.vlessPath || "/helloss-jsusyxystsdsahysy");
    setVlessDisguisedDomain(data.config.vlessDisguisedDomain || "https://example.com");
  }, [adminBasePath, data]);

  const envSnippet = useMemo(() => {
    const lines = [
      `ADMIN_KEY="${adminKey.trim()}"`,
      secretAction === "set" && secretInput.trim()
        ? `SECRET="${secretInput.trim()}"`
        : secretAction === "derive"
        ? `SECRET=""`
        : data.config.secretMode === "fixed"
        ? `# SECRET="<保留当前固定 Secret>"`
        : `SECRET=""`,
      `CARRIER="${carrier}"`,
      `MAX_STREAMS=${maxStreams.trim() || "16"}`,
      `ALLOWED_HOSTS="${allowedHosts.trim() || "*"}"`,
      `EXTRA_HOSTS="${extraHosts.trim()}"`,
      `DECOY_URL="${decoyUrl.trim()}"`,
      `DC_PORTS="${dcPorts.trim() || "443,80,5222"}"`,
      `SESSION_PATH="${sessionPath.trim() || "/api/v1/session"}"`,
      `WS_PATH="${wsPath.trim() || "/api/v1/ws"}"`,
      `VLESS_ENABLED=${vlessEnabled ? "true" : "false"}`,
      `UUID="${vlessUuid.trim()}"`,
      `VLESS_PATH="${vlessPath.trim() || "/helloss-jsusyxystsdsahysy"}"`,
      `DISGUISED_DOMAIN="${vlessDisguisedDomain.trim() || "https://example.com"}"`,
      `DEBUG=${debug ? "true" : "false"}`,
    ];
    return lines.join("\n");
  }, [
    adminKey,
    secretAction,
    secretInput,
    data.config.secretMode,
    carrier,
    maxStreams,
    allowedHosts,
    extraHosts,
    decoyUrl,
    dcPorts,
    sessionPath,
    wsPath,
    vlessEnabled,
    vlessUuid,
    vlessPath,
    vlessDisguisedDomain,
    debug,
  ]);

  const handleSave = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    setConfirmReset(false);
    setSaving(true);

    try {
      const resp = await fetch(`${adminBasePath}/api/config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "save",
          adminKey: adminKey.trim(),
          secretAction,
          secret: secretAction === "set" ? secretInput.trim() : "",
          carrier,
          maxStreams: Number(maxStreams),
          allowedHosts,
          extraHosts,
          decoyUrl: decoyUrl.trim(),
          sessionPath: sessionPath.trim(),
          wsPath: wsPath.trim(),
          dcPorts,
          adTagAction,
          adTag: adTagAction === "set" ? adTagInput.trim() : "",
          debug,
          generatorEnabled,
          acceptGenerated,
          vlessEnabled,
          vlessUuid: vlessUuid.trim(),
          vlessPath: vlessPath.trim(),
          vlessDisguisedDomain: vlessDisguisedDomain.trim(),
        }),
      });
      const json = (await resp.json()) as {
        ok?: boolean;
        panelPath?: string;
        state?: PanelStateData;
        error?: string;
      };
      if (!resp.ok || !json.ok || !json.state || !json.panelPath) {
        setError(json.error || `HTTP ${resp.status}`);
        return;
      }
      setSuccessMsg(t.cfgSavedOk);
      onConfigSaved(json.panelPath, json.state);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.networkError);
    } finally {
      setSaving(false);
    }
  };

  const handleReset = async () => {
    setError(null);
    setSuccessMsg(null);
    setResetting(true);
    try {
      const resp = await fetch(`${adminBasePath}/api/config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "reset" }),
      });
      const json = (await resp.json()) as {
        ok?: boolean;
        panelPath?: string;
        state?: PanelStateData;
        error?: string;
      };
      if (!resp.ok || !json.ok || !json.state || !json.panelPath) {
        setError(json.error || `HTTP ${resp.status}`);
        return;
      }
      setConfirmReset(false);
      setSuccessMsg(t.cfgResetOk);
      onConfigSaved(json.panelPath, json.state);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.networkError);
    } finally {
      setResetting(false);
    }
  };

  const persistenceNote = data.runtimePersisted
    ? t.cfgPersistenceFile
    : data.ephemeralSetup
    ? t.cfgPersistenceMemory
    : t.cfgPersistenceEnv;

  return (
    <div className="space-y-8">
      <div className="space-y-2 max-w-3xl">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900">
          {t.configPageTitle}
        </h1>
        <p className="text-sm sm:text-base text-slate-600">{t.configPageSubtitle}</p>
      </div>

      <div className="bg-slate-100 border border-slate-200 rounded-lg px-4 py-3 text-xs text-slate-700">
        {persistenceNote}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        <form onSubmit={handleSave} className="lg:col-span-8 space-y-6">
          {/* 1. 访问密钥与代理凭证 */}
          <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
            <h2 className="text-base font-semibold text-slate-900 border-b border-slate-200 pb-3">
              {t.cfgSectionAccess}
            </h2>

            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-slate-800">
                {t.adminKeyLabel}
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={adminKey}
                  onChange={(e) => setAdminKey(e.target.value)}
                  required
                  minLength={16}
                  pattern="[A-Za-z0-9_-]+"
                  className="flex-1 min-w-0 font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
                <button
                  type="button"
                  onClick={() => setAdminKey(generateAdminKeyClient())}
                  className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>{t.regenerate}</span>
                </button>
              </div>
              <p className="text-xs text-slate-500">{t.cfgAdminKeyHelp}</p>
            </div>

            <div className="space-y-2">
              <label className="block text-sm font-medium text-slate-800">
                {t.cfgSecretModeLabel}
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {(
                  [
                    { id: "keep", label: t.cfgSecretKeep },
                    { id: "set", label: t.cfgSecretSet },
                    { id: "derive", label: t.cfgSecretDerive },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setSecretAction(opt.id)}
                    className={`px-3 py-2 text-xs font-medium rounded-md border text-left transition-colors whitespace-nowrap truncate cursor-pointer ${
                      secretAction === opt.id
                        ? "bg-slate-900 text-white border-slate-900"
                        : "bg-white text-slate-700 border-slate-200 hover:bg-slate-50"
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              <p className="text-xs text-slate-500">
                {data.config.secretMode === "fixed"
                  ? t.cfgSecretCurrentHint
                  : t.cfgSecretDerivedHint}
              </p>

              {secretAction === "set" && (
                <div className="pt-2 space-y-1.5">
                  <label className="block text-xs font-medium text-slate-700">
                    {t.cfgSecretInputLabel}
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={secretInput}
                      onChange={(e) => setSecretInput(e.target.value)}
                      required
                      placeholder="dd3c875b4bf30975923526d92d4eacc4f7"
                      className="flex-1 min-w-0 font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                    />
                    <button
                      type="button"
                      onClick={() => setSecretInput(generateSecretHexClient())}
                      className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>{t.cfgSecretGenerate}</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </section>

          {/* 2. 域名与加速回源设置 */}
          <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
            <h2 className="text-base font-semibold text-slate-900 border-b border-slate-200 pb-3">
              {t.cfgSectionDomains}
            </h2>

            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-slate-800">
                {t.cfgAllowedHostsInputLabel}
              </label>
              <input
                type="text"
                value={allowedHosts}
                onChange={(e) => setAllowedHosts(e.target.value)}
                placeholder="*"
                className="w-full font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-slate-800">
                {t.cfgExtraHostsInputLabel}
              </label>
              <input
                type="text"
                value={extraHosts}
                onChange={(e) => setExtraHosts(e.target.value)}
                placeholder="ehddff6630.openlist.dpdns.org, cdn.example.com"
                className="w-full font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
              />
              <p className="text-xs text-slate-500 leading-relaxed">{t.cfgExtraHostsHelp}</p>
            </div>
          </section>

          {/* 3. 传输协议、伪装与出站策略 */}
          <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
            <h2 className="text-base font-semibold text-slate-900 border-b border-slate-200 pb-3">
              {t.cfgSectionTransport}
            </h2>

            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-slate-800">
                {t.cfgCarrierInputLabel}
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {(
                  [
                    { id: "websocket-lanes", desc: t.cfgCarrierLanesDesc },
                    { id: "websocket", desc: t.cfgCarrierSingleDesc },
                  ] as const
                ).map((mode) => (
                  <button
                    key={mode.id}
                    type="button"
                    onClick={() => setCarrier(mode.id)}
                    className={`px-3.5 py-2.5 rounded-md border text-left transition-colors cursor-pointer ${
                      carrier === mode.id
                        ? "bg-slate-900 text-white border-slate-900"
                        : "bg-white text-slate-700 border-slate-200 hover:bg-slate-50"
                    }`}
                  >
                    <div className="font-mono text-xs font-semibold">{mode.id}</div>
                    <div
                      className={`text-xs mt-0.5 ${
                        carrier === mode.id ? "text-slate-300" : "text-slate-500"
                      }`}
                    >
                      {mode.desc}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="block text-sm font-medium text-slate-800">
                  {t.cfgMaxStreamsInputLabel}
                </label>
                <input
                  type="number"
                  min={1}
                  max={64}
                  value={maxStreams}
                  onChange={(e) => setMaxStreams(e.target.value)}
                  required
                  className="w-full font-mono tabular-nums text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-sm font-medium text-slate-800">
                  {t.cfgDcPortsInputLabel}
                </label>
                <input
                  type="text"
                  value={dcPorts}
                  onChange={(e) => setDcPorts(e.target.value)}
                  placeholder="443, 80, 5222"
                  className="w-full font-mono tabular-nums text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
                <p className="text-xs text-slate-500">{t.cfgDcPortsHelp}</p>
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-slate-800">
                {t.cfgDecoyInputLabel}
              </label>
              <input
                type="url"
                value={decoyUrl}
                onChange={(e) => setDecoyUrl(e.target.value)}
                placeholder={t.decoyPlaceholder}
                className="w-full text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
              />
            </div>

            <div className="space-y-2">
              <label className="block text-sm font-medium text-slate-800">
                {t.cfgEndpointsGroupLabel}
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1">
                  <span className="text-xs text-slate-600">{t.cfgSessionPathLabel}</span>
                  <input
                    type="text"
                    value={sessionPath}
                    onChange={(e) => setSessionPath(e.target.value)}
                    className="w-full font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  />
                </div>
                <div className="space-y-1">
                  <span className="text-xs text-slate-600">{t.cfgWsPathLabel}</span>
                  <input
                    type="text"
                    value={wsPath}
                    onChange={(e) => setWsPath(e.target.value)}
                    className="w-full font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                  />
                </div>
              </div>
              <p className="text-xs text-slate-500">{t.cfgWsPathHelp}</p>
            </div>

            <div className="space-y-2">
              <label className="block text-sm font-medium text-slate-800">
                {t.cfgAdTagLabel}
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {(
                  [
                    { id: "keep", label: t.cfgAdTagKeep },
                    { id: "set", label: t.cfgAdTagSet },
                    { id: "clear", label: t.cfgAdTagClear },
                  ] as const
                ).map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setAdTagAction(opt.id)}
                    className={`px-3 py-2 text-xs font-medium rounded-md border text-left transition-colors whitespace-nowrap truncate cursor-pointer ${
                      adTagAction === opt.id
                        ? "bg-slate-900 text-white border-slate-900"
                        : "bg-white text-slate-700 border-slate-200 hover:bg-slate-50"
                    }`}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
              {adTagAction === "set" && (
                <input
                  type="text"
                  value={adTagInput}
                  onChange={(e) => setAdTagInput(e.target.value)}
                  required
                  placeholder="32 位十六进制字符串"
                  className="w-full font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
              )}
            </div>

            <div className="space-y-2 pt-2 border-t border-slate-200">
              <div className="text-sm font-medium text-slate-800">{t.cfgFlagsLabel}</div>
              <div className="space-y-2 text-sm text-slate-700">
                <label className="flex items-center gap-2.5 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={debug}
                    onChange={(e) => setDebug(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-600"
                  />
                  <span>{t.cfgDebugToggle}</span>
                </label>
                <label className="flex items-center gap-2.5 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={generatorEnabled}
                    onChange={(e) => setGeneratorEnabled(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-600"
                  />
                  <span>{t.cfgGeneratorToggle}</span>
                </label>
                <label className="flex items-center gap-2.5 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={acceptGenerated}
                    onChange={(e) => setAcceptGenerated(e.target.checked)}
                    className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-600"
                  />
                  <span>{t.cfgAcceptGeneratedToggle}</span>
                </label>
              </div>
            </div>
          </section>

          {/* 4. V2Ray / v2rayN (VLESS) 代理配置 */}
          <section className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
            <h2 className="text-base font-semibold text-slate-900 border-b border-slate-200 pb-3">
              {t.cfgSectionVless}
            </h2>

            <label className="flex items-center gap-2.5 text-sm text-slate-800 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={vlessEnabled}
                onChange={(e) => setVlessEnabled(e.target.checked)}
                className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-600"
              />
              <span className="font-medium">{t.cfgVlessEnabledToggle}</span>
            </label>

            <div className="space-y-1.5">
              <label className="block text-sm font-medium text-slate-800">
                {t.cfgVlessUuidLabel}
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={vlessUuid}
                  onChange={(e) => setVlessUuid(e.target.value)}
                  required
                  className="flex-1 min-w-0 font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
                <button
                  type="button"
                  onClick={() => setVlessUuid(generateUuidV4Client())}
                  className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100 whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>{t.cfgVlessGenerateUuid}</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="block text-sm font-medium text-slate-800">
                  {t.cfgVlessPathLabel}
                </label>
                <input
                  type="text"
                  value={vlessPath}
                  onChange={(e) => setVlessPath(e.target.value)}
                  required
                  className="w-full font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
                <p className="text-xs text-slate-500">{t.cfgVlessPathHelp}</p>
              </div>

              <div className="space-y-1.5">
                <label className="block text-sm font-medium text-slate-800">
                  {t.cfgVlessDisguisedLabel}
                </label>
                <input
                  type="url"
                  value={vlessDisguisedDomain}
                  onChange={(e) => setVlessDisguisedDomain(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
                />
              </div>
            </div>
          </section>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3 text-xs text-red-800 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-600" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="bg-emerald-50 border border-emerald-200 rounded-lg px-4 py-3 text-xs text-emerald-900 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
              <span>{successMsg}</span>
            </div>
          )}

          {confirmReset && (
            <div className="bg-amber-50 border border-amber-300 rounded-lg px-4 py-3 flex flex-wrap items-center justify-between gap-3">
              <span className="text-xs text-amber-900">{t.cfgResetConfirm}</span>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => setConfirmReset(false)}
                  className="px-3 py-1.5 text-xs font-medium rounded-md border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 whitespace-nowrap cursor-pointer"
                >
                  {t.cancel}
                </button>
                <button
                  type="button"
                  onClick={() => void handleReset()}
                  disabled={resetting}
                  className="px-3 py-1.5 text-xs font-semibold rounded-md bg-red-600 text-white hover:bg-red-700 disabled:opacity-60 whitespace-nowrap cursor-pointer"
                >
                  {resetting ? t.cfgResettingBtn : t.cfgResetBtn}
                </button>
              </div>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3">
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-2 px-5 py-2.5 text-sm font-semibold rounded-md bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Save className="w-4 h-4" />
              <span>{saving ? t.cfgSavingBtn : t.cfgSaveBtn}</span>
            </button>

            {data.hasRuntimeOverride && data.baseEnvConfigured && (
              <button
                type="button"
                onClick={() => setConfirmReset(true)}
                disabled={resetting}
                className="inline-flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium rounded-md border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>{t.cfgResetBtn}</span>
              </button>
            )}
          </div>
        </form>

        {/* 右侧 .env 配置快照与复制 */}
        <aside className="lg:col-span-4 bg-white border border-slate-200 rounded-lg p-5 space-y-3">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-slate-900">{t.cfgPreviewEnvTitle}</h3>
            <CopyButton value={envSnippet} label={t.copy} copiedLabel={t.copied} />
          </div>
          <pre className="bg-slate-50 border border-slate-200 text-slate-800 rounded-md p-3.5 text-xs overflow-x-auto leading-relaxed font-mono">
            {envSnippet}
          </pre>
        </aside>
      </div>
    </div>
  );
}

import { useState, type FormEvent } from "react";
import { RefreshCw, ArrowRight } from "lucide-react";
import { CopyButton } from "./CopyButton.tsx";
import type { Lang } from "../proxy/i18n.ts";
import { TRANSLATIONS } from "../proxy/i18n.ts";
import type { SetupStatusData } from "../types/proxy.ts";

interface SetupViewProps {
  data: SetupStatusData;
  lang: Lang;
  onActivated: (panelPath: string) => void;
}

// 在浏览器端生成 24 字符的随机高强度 ADMIN_KEY
function generateKeyClient(): string {
  const bytes = new Uint8Array(18);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "x").replace(/\//g, "y").replace(/=+$/, "");
}

// 首次启动初始化向导页面（仅在尚未配置 ADMIN_KEY/SECRET 时显示）
export function SetupView({ data, lang, onActivated }: SetupViewProps) {
  const t = TRANSLATIONS[lang];
  const [adminKey, setAdminKey] = useState(data.suggestedKey);
  const [secret, setSecret] = useState("");
  const [carrier, setCarrier] = useState<"websocket-lanes" | "websocket">("websocket-lanes");
  const [decoyUrl, setDecoyUrl] = useState("");
  const [extraHosts, setExtraHosts] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const envSnippet = [
    `PORT=3000`,
    `ADMIN_KEY="${adminKey}"`,
    secret.trim() ? `SECRET="${secret.trim()}"` : `# SECRET="" # 可选：固定 32 位十六进制密钥`,
    `CARRIER="${carrier}"`,
    decoyUrl.trim() ? `DECOY_URL="${decoyUrl.trim()}"` : `# DECOY_URL=""`,
    extraHosts.trim() ? `EXTRA_HOSTS="${extraHosts.trim()}"` : `# EXTRA_HOSTS=""`,
  ].join("\n");

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const resp = await fetch("/api/setup/activate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          adminKey,
          secret,
          carrier,
          decoyUrl,
          extraHosts,
        }),
      });
      const json = (await resp.json()) as { ok?: boolean; panelPath?: string; error?: string };
      if (!resp.ok || !json.ok || !json.panelPath) {
        setError(json.error || t.activateFailed);
        return;
      }
      onActivated(json.panelPath);
    } catch (err) {
      setError(err instanceof Error ? err.message : t.networkError);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-10">
      <div className="max-w-2xl space-y-2">
        <h1 className="text-3xl font-bold tracking-tight text-slate-900">{t.setupTitle}</h1>
        <p className="text-base text-slate-600">{t.setupSubtitle}</p>
        <div className="flex items-center gap-2 text-xs text-slate-500 pt-1">
          <span>{data.version}</span>
          <span aria-hidden="true">·</span>
          <span>{t.setupMetaEngine}</span>
          <span aria-hidden="true">·</span>
          <span>
            {t.setupHostPrefix}: {data.host || "localhost"}
          </span>
        </div>
      </div>

      {data.adminKeyTooShort && (
        <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 text-sm text-amber-900">
          {t.adminKeyTooShortWarn}
        </div>
      )}

      <form
        onSubmit={handleSubmit}
        className="max-w-2xl bg-white border border-slate-200 rounded-lg p-6 space-y-5"
      >
          <div className="space-y-1.5">
            <label className="block text-sm font-medium text-slate-800">{t.adminKeyLabel}</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={adminKey}
                onChange={(e) => setAdminKey(e.target.value)}
                required
                minLength={16}
                className="flex-1 min-w-0 font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
              />
              <button
                type="button"
                onClick={() => setAdminKey(generateKeyClient())}
                className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium rounded-md border border-slate-200 bg-slate-50 text-slate-700 hover:bg-slate-100 whitespace-nowrap shrink-0 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>{t.regenerate}</span>
              </button>
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-sm font-medium text-slate-800">{t.secretLabel}</label>
            <input
              type="text"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              placeholder={t.secretPlaceholder}
              className="w-full font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-sm font-medium text-slate-800">{t.carrierLabel}</label>
            <div className="grid grid-cols-2 gap-2">
              {(["websocket-lanes", "websocket"] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setCarrier(mode)}
                  className={`px-3 py-2 text-xs font-mono rounded-md border text-left transition-colors cursor-pointer ${
                    carrier === mode
                      ? "bg-slate-900 text-white border-slate-900"
                      : "bg-white text-slate-700 border-slate-200 hover:bg-slate-50"
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-sm font-medium text-slate-800">{t.decoyLabel}</label>
            <input
              type="url"
              value={decoyUrl}
              onChange={(e) => setDecoyUrl(e.target.value)}
              placeholder={t.decoyPlaceholder}
              className="w-full text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
            />
          </div>

          <div className="space-y-1.5">
            <label className="block text-sm font-medium text-slate-800">{t.extraHostsLabel}</label>
            <input
              type="text"
              value={extraHosts}
              onChange={(e) => setExtraHosts(e.target.value)}
              placeholder="tg.example.com, cdn.example.com"
              className="w-full font-mono text-sm px-3 py-2 rounded-md border border-slate-300 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600 focus:border-blue-600"
            />
          </div>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-md px-3 py-2 text-xs text-red-700">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-semibold rounded-md bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-60 transition-colors cursor-pointer"
          >
            <span>{submitting ? t.activating : t.activateBtn}</span>
            <ArrowRight className="w-4 h-4" />
          </button>

          <div className="pt-4 border-t border-slate-200 space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-semibold text-slate-700">{t.envTitle}</span>
              <CopyButton value={envSnippet} label={t.copy} copiedLabel={t.copied} />
            </div>
            <pre className="bg-slate-50 border border-slate-200 text-slate-800 rounded-md p-3 text-xs overflow-x-auto leading-relaxed">
              {envSnippet}
            </pre>
          </div>
        </form>
    </div>
  );
}

import { CopyButton } from "./CopyButton.tsx";
import type { Lang } from "../proxy/i18n.ts";
import { TRANSLATIONS } from "../proxy/i18n.ts";
import type { TunnelStatusData } from "../types/proxy.ts";

interface TunnelGuideProps {
  lang: Lang;
  host: string;
  tunnel?: TunnelStatusData;
}

// Cloudflare 隧道 (cloudflared) 连接指南与配置示例组件
export function TunnelGuide({ lang, host, tunnel }: TunnelGuideProps) {
  const t = TRANSLATIONS[lang];
  const displayHost =
    host && host !== "localhost" && host !== "127.0.0.1" ? host : "tg.yourdomain.com";

  const quickCmd = `cloudflared tunnel --url http://127.0.0.1:3000`;
  const namedCmd = `cloudflared tunnel run --token <YOUR_CF_TUNNEL_TOKEN>`;
  const yamlSnippet = `tunnel: <TUNNEL_UUID>
credentials-file: /etc/cloudflared/<TUNNEL_UUID>.json

ingress:
  - hostname: ${displayHost}
    service: http://127.0.0.1:3000
    originRequest:
      noTLSVerify: true
      keepAliveConnections: 100
      keepAliveTimeout: 90s
  - service: http_status:404`;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-900">{t.tunnelGuideTitle}</h2>
          <p className="text-sm text-slate-600 mt-1">
            {tunnel?.requestsViaTunnel
              ? `${t.tunnelActive} · ${tunnel.requestsViaTunnel} ${t.tunnelRequestsUnit}${
                  tunnel.lastRayColo ? ` · ${t.tunnelPopPrefix} ${tunnel.lastRayColo}` : ""
                }`
              : t.tunnelWaiting}
          </p>
        </div>
        {tunnel && (
          <div className="text-xs font-mono text-slate-600">
            {tunnel.running
              ? `${t.tunnelProcessRunning} (PID ${tunnel.pid ?? "-"})`
              : t.tunnelExternal}
          </div>
        )}
      </div>

      <div className="space-y-5">
        <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
          <div className="flex items-center justify-between gap-4">
            <h3 className="text-sm font-semibold text-slate-900">{t.tunnelQuickTitle}</h3>
            <CopyButton value={quickCmd} label={t.copy} copiedLabel={t.copied} />
          </div>
          <pre className="bg-slate-950 text-slate-100 rounded-md p-3.5 text-xs overflow-x-auto leading-relaxed">
            {quickCmd}
          </pre>
          <p className="text-xs text-slate-500">{t.tunnelQuickDesc}</p>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5 space-y-3">
          <div className="flex items-center justify-between gap-4">
            <h3 className="text-sm font-semibold text-slate-900">{t.tunnelNamedTitle}</h3>
            <CopyButton value={namedCmd} label={t.copy} copiedLabel={t.copied} />
          </div>
          <pre className="bg-slate-950 text-slate-100 rounded-md p-3.5 text-xs overflow-x-auto leading-relaxed">
            {namedCmd}
          </pre>
          <div className="pt-2">
            <div className="flex items-center justify-between gap-4 mb-2">
              <span className="text-xs font-medium text-slate-700">cloudflared/config.yml</span>
              <CopyButton value={yamlSnippet} label={t.copy} copiedLabel={t.copied} />
            </div>
            <pre className="bg-slate-50 border border-slate-200 text-slate-800 rounded-md p-3.5 text-xs overflow-x-auto leading-relaxed">
              {yamlSnippet}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

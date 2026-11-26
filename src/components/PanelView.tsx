import { ExternalLink, AlertTriangle, KeyRound, ShieldCheck } from "lucide-react";
import { CopyButton } from "./CopyButton.tsx";
import type { Lang } from "../proxy/i18n.ts";
import { TRANSLATIONS } from "../proxy/i18n.ts";
import type { PanelStateData } from "../types/proxy.ts";

interface PanelViewProps {
  data: PanelStateData;
  lang: Lang;
}

// Telegram WEB 代理链接与 V2Ray/v2rayN VLESS 节点配置面板
export function PanelView({ data, lang }: PanelViewProps) {
  const t = TRANSLATIONS[lang];

  return (
    <div className="space-y-8">
      <div className="space-y-2 max-w-3xl">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900">
          {t.panelTitle}
        </h1>
        <p className="text-sm sm:text-base text-slate-600">{t.panelSubtitle}</p>
        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500 pt-1">
          <span className="font-mono">{data.version}</span>
          <span aria-hidden="true">·</span>
          <span className="font-mono">{data.config.carrier}</span>
          <span aria-hidden="true">·</span>
          <span>
            {data.config.secretMode === "derived"
              ? t.secretModeDerived
              : t.secretModeFixed}
          </span>
        </div>
      </div>

      <div className="space-y-3">
        <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 text-sm text-amber-900 flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-600" />
          <span>{t.panelWarn}</span>
        </div>

        {data.ephemeralSetup && (
          <div className="bg-slate-100 border border-slate-200 rounded-lg px-4 py-3 text-xs text-slate-700">
            {t.ephemeralWarn}
          </div>
        )}

        {data.unifiedSecret && (
          <div className="bg-white border border-slate-200 rounded-lg px-4 py-3.5 flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1 min-w-0">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-700">
                <KeyRound className="w-3.5 h-3.5 text-blue-600 shrink-0" />
                <span>{t.unifiedSecretLabel}</span>
              </div>
              <div className="font-mono text-sm font-semibold text-slate-900 break-all">
                {data.unifiedSecret}
              </div>
              <div className="text-xs text-slate-500">{t.unifiedSecretNote}</div>
            </div>
            <CopyButton
              value={data.unifiedSecret}
              label={t.copySecret}
              copiedLabel={t.copied}
            />
          </div>
        )}
      </div>

      {data.hostConfigs.map((hc) => (
        <section key={hc.host} className="space-y-4">
          <div className="flex flex-wrap items-baseline justify-between gap-4 border-b border-slate-200 pb-3">
            <div className="flex items-baseline gap-3">
              <h2 className="text-lg font-semibold font-mono text-slate-900">{hc.host}</h2>
              <span className="text-xs text-slate-500">
                {hc.ports.length} {t.portsCountSuffix}
              </span>
            </div>
            <CopyButton value={hc.host} label={t.copyHost} copiedLabel={t.copied} />
          </div>

          {hc.isLocalhost && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg px-4 py-3 text-xs text-blue-900">
              {t.localhostWarn}
            </div>
          )}

          {hc.isWorkersDev && (
            <div className="bg-amber-50 border border-amber-200 rounded-lg px-4 py-3 text-xs text-amber-900">
              {t.workersDevWarn}
            </div>
          )}

          <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                    <th className="py-2.5 px-4 whitespace-nowrap">{t.portCol}</th>
                    <th className="py-2.5 px-4 whitespace-nowrap">{t.secretCol}</th>
                    <th className="py-2.5 px-4 whitespace-nowrap hidden xl:table-cell">
                      {t.linkCol}
                    </th>
                    <th className="py-2.5 px-4 text-right whitespace-nowrap">{t.actionsCol}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 text-sm">
                  {hc.ports.map((entry) => (
                    <tr key={entry.port} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3 px-4 font-mono tabular-nums whitespace-nowrap text-slate-900 font-medium">
                        {entry.port}
                        {entry.isDefault && (
                          <span className="ml-2 text-xs font-sans font-normal text-slate-500">
                            ({t.defaultPort})
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-700 max-w-[260px] truncate">
                        {entry.secret}
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-500 max-w-[340px] truncate hidden xl:table-cell">
                        {entry.link}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center justify-end gap-2">
                          <CopyButton
                            value={entry.secret}
                            label={t.copySecret}
                            copiedLabel={t.copied}
                          />
                          <CopyButton
                            value={entry.link}
                            label={t.copyLink}
                            copiedLabel={t.copied}
                          />
                          <a
                            href={entry.link}
                            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md bg-blue-600 text-white hover:bg-blue-700 transition-colors whitespace-nowrap shrink-0"
                          >
                            <span>{t.connectTelegram}</span>
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      ))}

      {/* V2Ray / v2rayN (VLESS) 节点配置与一键导入链接 */}
      {data.vless && (
        <section className="space-y-4 pt-4 border-t border-slate-200">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1 max-w-3xl">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="w-5 h-5 text-blue-600 shrink-0" />
                <h2 className="text-xl font-bold tracking-tight text-slate-900">
                  {t.vlessPanelTitle}
                </h2>
                <span
                  className={`px-2 py-0.5 text-xs font-medium rounded border ${
                    data.vless.enabled
                      ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                      : "bg-slate-100 text-slate-600 border-slate-200"
                  }`}
                >
                  {data.vless.enabled ? t.vlessEnabledLabel : t.vlessDisabledLabel}
                </span>
              </div>
              <p className="text-sm text-slate-600">{t.vlessPanelSubtitle}</p>
            </div>
          </div>

          {data.vless.enabled && (
            <div className="space-y-4">
              {data.vless.hosts.map((vh) => (
                <div
                  key={vh.host}
                  className="bg-white border border-slate-200 rounded-lg overflow-hidden"
                >
                  <div className="px-5 py-3.5 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
                    <div className="font-mono text-sm font-semibold text-slate-900">
                      {vh.host}:{vh.port}
                    </div>
                    <CopyButton
                      value={vh.uri}
                      label={t.copyVlessUri}
                      copiedLabel={t.copied}
                    />
                  </div>
                  <div className="p-5 space-y-4">
                    <div className="bg-slate-50 border border-slate-200 rounded-md px-3.5 py-2.5 font-mono text-xs text-slate-800 break-all">
                      {vh.uri}
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
                      <div className="border border-slate-200 rounded-md p-3">
                        <div className="text-slate-500">{t.vlessAddressLabel}</div>
                        <div className="mt-1 font-mono font-semibold text-slate-900 break-all">
                          {vh.host}
                        </div>
                      </div>
                      <div className="border border-slate-200 rounded-md p-3">
                        <div className="text-slate-500">{t.vlessPortLabel}</div>
                        <div className="mt-1 font-mono font-semibold tabular-nums text-slate-900">
                          {vh.port}
                        </div>
                      </div>
                      <div className="border border-slate-200 rounded-md p-3">
                        <div className="text-slate-500">{t.vlessUuidLabel}</div>
                        <div className="mt-1 font-mono font-semibold text-slate-900 break-all">
                          {data.vless.uuid}
                        </div>
                      </div>
                      <div className="border border-slate-200 rounded-md p-3">
                        <div className="text-slate-500">{t.vlessPathLabel}</div>
                        <div className="mt-1 font-mono font-semibold text-slate-900 break-all">
                          {data.vless.path}
                        </div>
                      </div>
                      <div className="border border-slate-200 rounded-md p-3">
                        <div className="text-slate-500">{t.vlessTransportLabel} / {t.vlessSecurityLabel}</div>
                        <div className="mt-1 font-mono font-semibold text-slate-900">
                          ws / {vh.security}
                        </div>
                      </div>
                      <div className="border border-slate-200 rounded-md p-3">
                        <div className="text-slate-500">{t.vlessHttpFallbackLabel}</div>
                        <div className="mt-1 font-mono font-semibold text-slate-900 break-all">
                          {vh.httpUrl}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

import { ExternalLink, AlertTriangle } from "lucide-react";
import { CopyButton } from "./CopyButton.tsx";
import type { Lang } from "../proxy/i18n.ts";
import { TRANSLATIONS } from "../proxy/i18n.ts";
import type { PanelStateData } from "../types/proxy.ts";

interface PanelViewProps {
  data: PanelStateData;
  lang: Lang;
}

// Telegram WEB 代理链接与 6 端口密钥管理面板
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
    </div>
  );
}

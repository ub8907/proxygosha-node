import { useState } from "react";
import { Activity, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";
import type { Lang } from "../proxy/i18n.ts";
import { TRANSLATIONS } from "../proxy/i18n.ts";
import type { PanelStateData, ProbeResultData } from "../types/proxy.ts";

interface StatusViewProps {
  data: PanelStateData;
  adminBasePath: string;
  lang: Lang;
}

// 运行状态监控、Cloudflare 隧道统计与 Telegram DC 实时 TCP 探测面板
export function StatusView({ data, adminBasePath, lang }: StatusViewProps) {
  const t = TRANSLATIONS[lang];
  const [probing, setProbing] = useState(false);
  const [probeResults, setProbeResults] = useState<ProbeResultData[] | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  const runProbe = async () => {
    setProbing(true);
    setProbeError(null);
    try {
      const resp = await fetch(`${adminBasePath}/api/probe`, { method: "POST" });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      const json = (await resp.json()) as { results: ProbeResultData[] };
      setProbeResults(json.results);
    } catch (err) {
      setProbeError(err instanceof Error ? err.message : t.networkError);
    } finally {
      setProbing(false);
    }
  };

  return (
    <div className="space-y-8">
      <div className="space-y-2 max-w-3xl">
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900">
          {t.statusTitle}
        </h1>
        <p className="text-sm sm:text-base text-slate-600">{t.statusSubtitle}</p>
      </div>

      {/* 四栏核心运行指标 */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="text-xs font-medium text-slate-500">{t.activeSessions}</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900">
            {data.stats.sessionsActive}
          </div>
          <div className="mt-1 text-xs text-slate-500 font-mono tabular-nums">
            {t.totalSessions}: {data.stats.sessions} · {t.wsRejectsLabel}: {data.stats.wsRejects}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="text-xs font-medium text-slate-500">{t.streamsOpened}</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900">
            {data.stats.streams}
          </div>
          <div className="mt-1 text-xs text-slate-500 font-mono tabular-nums">
            {t.dcOkFailLabel}: {data.stats.dcSuccess} / {data.stats.dcFails}
            {(data.stats.dcEmptyCloses ?? 0) > 0 ? ` · EOF(0B): ${data.stats.dcEmptyCloses}` : ""}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="text-xs font-medium text-slate-500">{t.trafficUpDown}</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900">
            {data.stats.bytesUpFormatted} / {data.stats.bytesDownFormatted}
          </div>
          <div className="mt-1 text-xs text-slate-500">{t.fastModeNote}</div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="text-xs font-medium text-slate-500">{t.uptime}</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900">
            {data.stats.uptimeFormatted}
          </div>
          <div className="mt-1 text-xs text-slate-500 font-mono tabular-nums">
            {t.cfTunnelHitsLabel}: {data.tunnel.requestsViaTunnel}
          </div>
        </div>
      </div>

      {/* 运行配置与 Cloudflare 隧道状态双栏表格 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 font-semibold text-sm text-slate-900">
            {t.configSection}
          </div>
          <table className="w-full text-left border-collapse text-sm">
            <tbody className="divide-y divide-slate-200">
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600 w-44">{t.cfgVersion}</th>
                <td className="py-2.5 px-5 font-mono text-slate-900">{data.version}</td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">{t.cfgCarrier}</th>
                <td className="py-2.5 px-5 font-mono text-slate-900">{data.config.carrier}</td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">{t.cfgMaxStreams}</th>
                <td className="py-2.5 px-5 font-mono tabular-nums text-slate-900">
                  {data.config.maxStreams}
                </td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">{t.cfgEndpoints}</th>
                <td className="py-2.5 px-5 font-mono text-xs text-slate-900">
                  {data.config.sessionPath} · {data.config.wsPath}
                </td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">{t.cfgDecoy}</th>
                <td className="py-2.5 px-5 font-mono text-xs text-slate-900">
                  {data.config.decoyUrl || t.cfgDecoyBuiltin}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 font-semibold text-sm text-slate-900">
            {t.tunnelSection}
          </div>
          <table className="w-full text-left border-collapse text-sm">
            <tbody className="divide-y divide-slate-200">
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600 w-44">
                  {t.tunnelRequestsLabel}
                </th>
                <td className="py-2.5 px-5 font-mono tabular-nums text-slate-900">
                  {data.tunnel.requestsViaTunnel}
                </td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">
                  {t.tunnelLastHostLabel}
                </th>
                <td className="py-2.5 px-5 font-mono text-slate-900">
                  {data.tunnel.lastTunnelHost || "-"}
                </td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">
                  {t.tunnelLastRayLabel}
                </th>
                <td className="py-2.5 px-5 font-mono text-slate-900">
                  {data.tunnel.lastRayColo || "-"}
                </td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">
                  {t.tunnelSidecarLabel}
                </th>
                <td className="py-2.5 px-5 text-slate-900">
                  {data.tunnel.running
                    ? `${t.tunnelProcessRunning} (PID ${data.tunnel.pid ?? "-"})`
                    : data.tunnel.binaryAvailable
                    ? t.tunnelInstalledExternal
                    : t.tunnelExternal}
                </td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">
                  {t.tunnelLastErrLabel}
                </th>
                <td className="py-2.5 px-5 font-mono text-xs text-slate-600">
                  {data.tunnel.lastError || t.noneText}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {((data.stats.dcEmptyCloses ?? 0) > 0 ||
        (probeResults && probeResults.some((r) => r.dc !== 203 && r.ok && r.mtprotoOk === false))) && (
        <div className="bg-amber-50 border border-amber-300 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs text-amber-900">
            <div className="font-semibold text-sm">{t.dcEmptyWarnTitle}</div>
            <p className="leading-relaxed text-amber-800">{t.dcEmptyWarnBody}</p>
          </div>
        </div>
      )}

      {/* Telegram DC 连通性探测区域 */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-900">{t.probeSection}</h2>
            <p className="text-xs text-slate-500 mt-0.5">{t.probeEmpty}</p>
          </div>
          <button
            type="button"
            onClick={runProbe}
            disabled={probing}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-md bg-slate-900 text-white hover:bg-slate-800 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Activity className="w-3.5 h-3.5" />
            <span>{probing ? t.probing : t.runProbe}</span>
          </button>
        </div>

        {probeError && (
          <div className="px-5 py-3 text-xs text-red-700 bg-red-50 border-b border-red-200">
            {probeError}
          </div>
        )}

        {probeResults && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                  <th className="py-2.5 px-5">{t.probeColDc}</th>
                  <th className="py-2.5 px-5">{t.probeColIp}</th>
                  <th className="py-2.5 px-5">{t.probeColStatus}</th>
                  <th className="py-2.5 px-5">{t.probeColMtproto}</th>
                  <th className="py-2.5 px-5 text-right">{t.probeColRtt}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {probeResults.map((r) => (
                  <tr key={r.dc} className="hover:bg-slate-50/70">
                    <td className="py-2.5 px-5 font-mono font-medium text-slate-900">DC{r.dc}</td>
                    <td className="py-2.5 px-5 font-mono text-xs text-slate-700">
                      {r.ip}
                      {r.port ? `:${r.port}` : ""}
                    </td>
                    <td className="py-2.5 px-5">
                      {r.ok ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>{t.reachable}</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700">
                          <XCircle className="w-3.5 h-3.5" />
                          <span>{t.failed}</span>
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-5">
                      {r.mtprotoOk === true ? (
                        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>
                            {t.mtprotoOkLabel}
                            {r.mtprotoMs !== null && r.mtprotoMs !== undefined ? ` (${r.mtprotoMs} ms)` : ""}
                          </span>
                        </span>
                      ) : r.mtprotoOk === null ? (
                        <span className="text-xs text-slate-500 font-mono">{t.mtprotoCdnLabel}</span>
                      ) : (
                        <div className="space-y-1">
                          <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-700">
                            <XCircle className="w-3.5 h-3.5" />
                            <span>
                              {t.mtprotoFailLabel}
                              {r.reason ? ` (${r.reason})` : ""}
                            </span>
                          </span>
                          {r.altPorts && r.altPorts.length > 0 && (
                            <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
                              {r.altPorts.map((alt) => (
                                <span
                                  key={alt.port}
                                  className={
                                    alt.mtprotoOk
                                      ? "px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200"
                                      : "px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 border border-slate-200"
                                  }
                                >
                                  :{alt.port} {alt.mtprotoOk ? `OK (${alt.ms}ms)` : alt.reason}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 px-5 text-right font-mono tabular-nums text-xs text-slate-700">
                      {r.ms} ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 内存环形事件日志表格 */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
          <span className="text-sm font-semibold text-slate-900">{t.logsSection}</span>
          <span className="text-xs text-slate-500">{t.logsHint}</span>
        </div>
        {data.logs.length === 0 ? (
          <div className="px-5 py-8 text-center text-sm text-slate-500">{t.logsEmpty}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 font-semibold text-slate-600">
                  <th className="py-2.5 px-5">{t.logsColUtc}</th>
                  <th className="py-2.5 px-5">{t.logsColEvent}</th>
                  <th className="py-2.5 px-5">{t.logsColDetail}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 font-mono">
                {data.logs.map((entry, idx) => (
                  <tr key={`${entry.t}-${idx}`} className="hover:bg-slate-50/70">
                    <td className="py-2 px-5 text-slate-500 whitespace-nowrap tabular-nums">
                      {new Date(entry.t).toISOString().slice(11, 19)}
                    </td>
                    <td className="py-2 px-5 text-slate-900 whitespace-nowrap">{entry.event}</td>
                    <td className="py-2 px-5 text-slate-700">{entry.detail || "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

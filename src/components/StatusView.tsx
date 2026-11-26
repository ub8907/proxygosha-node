import { useState } from "react";
import { Activity, AlertTriangle, CheckCircle2, Wifi, XCircle } from "lucide-react";
import type { Lang } from "../proxy/i18n.ts";
import { TRANSLATIONS } from "../proxy/i18n.ts";
import type {
  PanelStateData,
  ProbeResultData,
  WsBrowserTestResult,
  WsProbeServerResponse,
} from "../types/proxy.ts";

interface StatusViewProps {
  data: PanelStateData;
  adminBasePath: string;
  lang: Lang;
  onOpenConfig?: () => void;
}

function runBrowserWebSocketEcho(wsTestPath: string): Promise<WsBrowserTestResult> {
  return new Promise((resolve) => {
    const wsScheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${wsScheme}//${window.location.host}${wsTestPath}`;
    const started = performance.now();
    let settled = false;
    let handshakeOk = false;
    let subprotocolOk = false;
    let negotiatedProtocol = "";
    let binaryEchoOk = false;
    let closeCode: number | null = null;
    let closeReason = "";
    let sawError = false;

    const pingBytes = new Uint8Array(32);
    crypto.getRandomValues(pingBytes);

    let ws: WebSocket;
    try {
      ws = new WebSocket(wsUrl, "tproxy-v1.probe");
      ws.binaryType = "arraybuffer";
    } catch (err) {
      resolve({
        ok: false,
        wsUrl,
        rttMs: null,
        handshakeOk: false,
        subprotocolOk: false,
        negotiatedProtocol: "",
        binaryEchoOk: false,
        closeCode: null,
        closeReason: "",
        error: err instanceof Error ? err.message : "WebSocket constructor failed",
      });
      return;
    }

    const finish = (ok: boolean, error: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
          ws.close();
        }
      } catch {
        // ignore
      }
      resolve({
        ok,
        wsUrl,
        rttMs: handshakeOk ? Math.round(performance.now() - started) : null,
        handshakeOk,
        subprotocolOk,
        negotiatedProtocol,
        binaryEchoOk,
        closeCode,
        closeReason,
        error,
      });
    };

    const timer = setTimeout(() => {
      finish(false, "timeout (6000ms)");
    }, 6000);

    ws.onopen = () => {
      handshakeOk = true;
      negotiatedProtocol = ws.protocol || "";
      subprotocolOk = negotiatedProtocol === "tproxy-v1.probe";
      try {
        ws.send(pingBytes.buffer);
      } catch (err) {
        finish(false, err instanceof Error ? err.message : "binary send failed");
      }
    };

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        const recv = new Uint8Array(event.data);
        if (recv.length === pingBytes.length && recv.every((b, i) => b === pingBytes[i])) {
          binaryEchoOk = true;
          finish(true, null);
        }
      }
    };

    ws.onerror = () => {
      sawError = true;
    };

    ws.onclose = (ev) => {
      closeCode = ev.code;
      closeReason = ev.reason || "";
      if (!settled) {
        finish(
          false,
          sawError
            ? `WebSocket handshake/connection rejected (code=${ev.code})`
            : `WebSocket closed unexpectedly (code=${ev.code}${ev.reason ? `: ${ev.reason}` : ""})`
        );
      }
    };
  });
}

// 运行状态监控、WebSocket 连通性诊断与 Telegram DC 实时探测面板
export function StatusView({ data, adminBasePath, lang, onOpenConfig }: StatusViewProps) {
  const t = TRANSLATIONS[lang];
  const [probing, setProbing] = useState(false);
  const [probeResults, setProbeResults] = useState<ProbeResultData[] | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  const [wsTesting, setWsTesting] = useState(false);
  const [wsServerResult, setWsServerResult] = useState<WsProbeServerResponse | null>(null);
  const [wsBrowserResult, setWsBrowserResult] = useState<WsBrowserTestResult | null>(null);
  const [wsTestError, setWsTestError] = useState<string | null>(null);

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

  const runWsConnectivityTest = async () => {
    setWsTesting(true);
    setWsTestError(null);
    setWsServerResult(null);
    setWsBrowserResult(null);
    try {
      const resp = await fetch(`${adminBasePath}/api/ws-probe`, { method: "POST" });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`);
      }
      const serverJson = (await resp.json()) as WsProbeServerResponse;
      setWsServerResult(serverJson);

      const browserRes = await runBrowserWebSocketEcho(serverJson.endpoints.wsTestPath);
      setWsBrowserResult(browserRes);
    } catch (err) {
      setWsTestError(err instanceof Error ? err.message : t.networkError);
    } finally {
      setWsTesting(false);
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
          <div className="mt-1 text-xs text-slate-500">
            {t.fastModeNote}
            {data.vless?.enabled && (
              <span className="block font-mono mt-0.5">
                {t.vlessStatsLabel}: {data.stats.vlessActive ?? 0} / {data.stats.vlessConnections ?? 0}
              </span>
            )}
          </div>
        </div>

        <div className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="text-xs font-medium text-slate-500">{t.uptime}</div>
          <div className="mt-2 text-2xl font-bold font-mono tabular-nums text-slate-900">
            {data.stats.uptimeFormatted}
          </div>
          <div className="mt-1 text-xs text-slate-500 font-mono tabular-nums">
            {t.cfgCarrier}: {data.config.carrier}
          </div>
        </div>
      </div>

      {/* 运行配置表格 */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
          <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between gap-3">
            <span className="font-semibold text-sm text-slate-900">{t.configSection}</span>
            {onOpenConfig && (
              <button
                type="button"
                onClick={onOpenConfig}
                className="text-xs font-medium text-blue-600 hover:text-blue-700 hover:underline whitespace-nowrap shrink-0 cursor-pointer"
              >
                {t.editConfigBtn}
              </button>
            )}
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
                  {data.vless?.enabled ? ` · VLESS:${data.vless.path}` : ""}
                </td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">{t.cfgDecoy}</th>
                <td className="py-2.5 px-5 font-mono text-xs text-slate-900">
                  {data.config.decoyUrl || t.cfgDecoyBuiltin}
                </td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">{t.cfgAllowedHosts}</th>
                <td className="py-2.5 px-5 font-mono text-xs text-slate-900">
                  {[...data.config.allowedHosts, ...data.config.extraHosts].filter(Boolean).join(", ") || "*"}
                </td>
              </tr>
              <tr>
                <th className="py-2.5 px-5 font-medium text-slate-600">DC_PORTS</th>
                <td className="py-2.5 px-5 font-mono tabular-nums text-xs text-slate-900">
                  {(data.config.dcPorts || [443, 80, 5222]).join(", ")}
                </td>
              </tr>
            </tbody>
          </table>
      </div>

      {/* WebSocket 连通性诊断测试卡片 */}
      <div className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-slate-200 flex flex-wrap items-center justify-between gap-4">
          <div className="max-w-2xl">
            <h2 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Wifi className="w-4 h-4 text-blue-600 shrink-0" />
              <span>{t.wsProbeSection}</span>
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">{t.wsProbeEmpty}</p>
          </div>
          <button
            type="button"
            onClick={() => void runWsConnectivityTest()}
            disabled={wsTesting}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-md bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Wifi className="w-3.5 h-3.5" />
            <span>{wsTesting ? t.wsProbingBtn : t.wsProbeRunBtn}</span>
          </button>
        </div>

        {wsTestError && (
          <div className="px-5 py-3 text-xs text-red-700 bg-red-50 border-b border-red-200">
            {wsTestError}
          </div>
        )}

        {wsServerResult && wsBrowserResult && (
          <div className="p-5 space-y-4">
            {/* 综合诊断结论 */}
            {wsServerResult.local.ok && wsBrowserResult.ok ? (
              <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-4 flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs text-emerald-900">
                  <div className="font-semibold text-sm">{t.wsProbePassTitle}</div>
                  <p className="text-emerald-800">{t.wsProbePassDesc}</p>
                </div>
              </div>
            ) : wsServerResult.local.ok && !wsBrowserResult.ok ? (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 flex items-start gap-3">
                <XCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs text-red-900">
                  <div className="font-semibold text-sm">{t.wsProbeBlockedTitle}</div>
                  <p className="text-red-800">{t.wsProbeBlockedDesc}</p>
                </div>
              </div>
            ) : (
              <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs text-amber-900">
                  <div className="font-semibold text-sm">{t.wsProbeLocalFailTitle}</div>
                  <p className="text-amber-800">{t.wsProbeLocalFailDesc}</p>
                </div>
              </div>
            )}

            {/* 本地环回 vs 浏览器端到端 对比明细 */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="border border-slate-200 rounded-md p-4 space-y-2">
                <div className="flex items-center justify-between font-semibold text-slate-900">
                  <span>{t.wsProbeLocalLabel} (:{wsServerResult.local.listeningPort})</span>
                  <span
                    className={
                      wsServerResult.local.ok ? "text-emerald-700" : "text-red-700"
                    }
                  >
                    {wsServerResult.local.ok
                      ? `${t.wsProbeOk} (${wsServerResult.local.rttMs} ms)`
                      : t.wsProbeFail}
                  </span>
                </div>
                <div className="font-mono text-slate-600 space-y-1">
                  <div>
                    {t.wsProbeSubprotoLabel}:{" "}
                    {wsServerResult.local.subprotocolOk ? "tproxy-v1.probe OK" : "Fail"}
                  </div>
                  <div>
                    {t.wsProbeBinaryLabel}:{" "}
                    {wsServerResult.local.binaryEchoOk ? "24B ArrayBuffer OK" : "Fail"}
                  </div>
                  {wsServerResult.local.error && (
                    <div className="text-red-700">Error: {wsServerResult.local.error}</div>
                  )}
                </div>
              </div>

              <div className="border border-slate-200 rounded-md p-4 space-y-2">
                <div className="flex items-center justify-between font-semibold text-slate-900">
                  <span>{t.wsProbeBrowserLabel}</span>
                  <span className={wsBrowserResult.ok ? "text-emerald-700" : "text-red-700"}>
                    {wsBrowserResult.ok
                      ? `${t.wsProbeOk}${wsBrowserResult.rttMs !== null ? ` (${wsBrowserResult.rttMs} ms)` : ""}`
                      : t.wsProbeFail}
                  </span>
                </div>
                <div className="font-mono text-slate-600 space-y-1 break-all">
                  <div>URL: {wsBrowserResult.wsUrl}</div>
                  <div>
                    {t.wsProbeSubprotoLabel}:{" "}
                    {wsBrowserResult.subprotocolOk
                      ? `${wsBrowserResult.negotiatedProtocol} OK`
                      : wsBrowserResult.negotiatedProtocol || "None / Stripped"}
                  </div>
                  <div>
                    {t.wsProbeBinaryLabel}:{" "}
                    {wsBrowserResult.binaryEchoOk ? "32B ArrayBuffer OK" : "Fail"}
                  </div>
                  {wsBrowserResult.error && (
                    <div className="text-red-700">Error: {wsBrowserResult.error}</div>
                  )}
                </div>
              </div>
            </div>

            <div className="bg-slate-50 border border-slate-200 rounded-md px-3.5 py-2.5 text-xs font-mono text-slate-600 flex flex-wrap gap-x-4 gap-y-1">
              <span className="font-sans font-semibold text-slate-700">{t.wsProbeHeadersLabel}:</span>
              <span>proto={wsServerResult.request.proto}</span>
              <span>host={wsServerResult.request.host || "-"}</span>
              {wsServerResult.request.forwardedProto && (
                <span>x-forwarded-proto={wsServerResult.request.forwardedProto}</span>
              )}
              {wsServerResult.request.via && <span>via={wsServerResult.request.via}</span>}
              {wsServerResult.request.cfRay && <span>cf-ray={wsServerResult.request.cfRay}</span>}
            </div>
          </div>
        )}
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

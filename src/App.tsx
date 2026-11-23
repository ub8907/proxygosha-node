import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { ConfigView } from "./components/ConfigView.tsx";
import { PanelView } from "./components/PanelView.tsx";
import { SetupView } from "./components/SetupView.tsx";
import { StatusView } from "./components/StatusView.tsx";
import type { Lang } from "./proxy/i18n.ts";
import { TRANSLATIONS } from "./proxy/i18n.ts";
import type { PanelStateData, SetupStatusData } from "./types/proxy.ts";

type ActiveTab = "panel" | "status" | "config";

// 根据当前浏览器路径解析视图模式（初始化页 / 管理面板 / 状态探测 / 运行配置）
function parseLocation(): { mode: "setup" | "admin"; adminBasePath: string; tab: ActiveTab } {
  const path = window.location.pathname.replace(/\/+$/, "") || "/";
  if (path === "/" || path === "/setup") {
    return { mode: "setup", adminBasePath: "", tab: "panel" };
  }
  const parts = path.slice(1).split("/");
  if (parts.length >= 2 && parts[1] === "status") {
    return { mode: "admin", adminBasePath: "/" + parts[0], tab: "status" };
  }
  if (parts.length >= 2 && parts[1] === "config") {
    return { mode: "admin", adminBasePath: "/" + parts[0], tab: "config" };
  }
  return { mode: "admin", adminBasePath: "/" + parts[0], tab: "panel" };
}

export default function App() {
  // 默认界面语言为中文（zh），可通过 URL 参数 ?lang=en|fa 或顶部切换按钮变更
  const [lang, setLang] = useState<Lang>(() => {
    const p = new URLSearchParams(window.location.search).get("lang");
    if (p === "zh" || p === "fa" || p === "en") return p;
    return "zh";
  });

  const [route, setRoute] = useState(parseLocation);
  const [setupData, setSetupData] = useState<SetupStatusData | null>(null);
  const [panelData, setPanelData] = useState<PanelStateData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // 拉取初始化状态或管理面板实时遥测数据
  const loadData = useCallback(async (target: ReturnType<typeof parseLocation>) => {
    setLoading(true);
    setError(null);
    try {
      if (target.mode === "setup") {
        const resp = await fetch("/api/setup/status");
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const json = (await resp.json()) as SetupStatusData;
        setSetupData(json);
        setPanelData(null);
      } else {
        const resp = await fetch(`${target.adminBasePath}/api/state`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const json = (await resp.json()) as PanelStateData;
        setPanelData(json);
        setSetupData(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "数据加载失败");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData(route);
  }, [route, loadData]);

  useEffect(() => {
    const onPop = () => setRoute(parseLocation());
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  // 在管理页签间平滑切换并同步浏览器地址栏
  const navigateTab = (tab: ActiveTab) => {
    if (route.mode !== "admin") return;
    const nextUrl =
      tab === "status"
        ? `${route.adminBasePath}/status`
        : tab === "config"
        ? `${route.adminBasePath}/config`
        : route.adminBasePath;
    if (window.location.pathname !== nextUrl) {
      window.history.pushState(null, "", nextUrl);
    }
    setRoute({ ...route, tab });
  };

  // 初始化激活成功后自动跳转至 /<ADMIN_KEY> 管理面板
  const handleActivated = (panelPath: string) => {
    window.history.pushState(null, "", panelPath);
    setRoute({ mode: "admin", adminBasePath: panelPath, tab: "panel" });
  };

  // 动态保存配置后同步最新状态并在 ADMIN_KEY 变更时自动更新路径
  const handleConfigSaved = (nextAdminBasePath: string, nextState: PanelStateData) => {
    setPanelData(nextState);
    if (nextAdminBasePath !== route.adminBasePath) {
      const nextUrl = `${nextAdminBasePath}/config`;
      window.history.replaceState(null, "", nextUrl);
      setRoute({ mode: "admin", adminBasePath: nextAdminBasePath, tab: "config" });
    }
  };

  const t = TRANSLATIONS[lang];
  const isRtl = lang === "fa";

  return (
    <div dir={isRtl ? "rtl" : "ltr"} className="min-h-screen bg-slate-50 text-slate-900 flex flex-col">
      {/* 顶部三段式导航栏：品牌标识 — 功能导航 — 语言切换与刷新 */}
      <header className="bg-white border-b border-slate-200 sticky top-0 z-20">
        <div className="max-w-[1200px] mx-auto px-6 h-16 flex items-center justify-between gap-8">
          <a
            href={route.mode === "admin" ? route.adminBasePath : "/"}
            onClick={(e) => {
              if (route.mode === "admin") {
                e.preventDefault();
                navigateTab("panel");
              }
            }}
            className="font-display text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0"
          >
            {t.brand}
          </a>

          <nav className="flex items-center gap-6 text-sm font-medium text-slate-600 overflow-x-auto">
            {route.mode === "admin" ? (
              <>
                <button
                  type="button"
                  onClick={() => navigateTab("panel")}
                  className={`py-1 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    route.tab === "panel"
                      ? "text-slate-950 font-semibold border-b-2 border-blue-600"
                      : "hover:text-slate-900"
                  }`}
                >
                  {t.navPanel}
                </button>
                <button
                  type="button"
                  onClick={() => navigateTab("status")}
                  className={`py-1 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    route.tab === "status"
                      ? "text-slate-950 font-semibold border-b-2 border-blue-600"
                      : "hover:text-slate-900"
                  }`}
                >
                  {t.navStatus}
                </button>
                <button
                  type="button"
                  onClick={() => navigateTab("config")}
                  className={`py-1 transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    route.tab === "config"
                      ? "text-slate-950 font-semibold border-b-2 border-blue-600"
                      : "hover:text-slate-900"
                  }`}
                >
                  {t.navConfig}
                </button>
              </>
            ) : (
              <span className="text-slate-500 whitespace-nowrap shrink-0">{t.navSetup}</span>
            )}
          </nav>

          <div className="flex items-center gap-3 shrink-0">
            <div className="inline-flex items-center bg-slate-100 p-0.5 rounded-md border border-slate-200">
              {(["zh", "en", "fa"] as const).map((code) => (
                <button
                  key={code}
                  type="button"
                  onClick={() => setLang(code)}
                  className={`px-2 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    lang === code
                      ? "bg-white text-slate-900 shadow-xs"
                      : "text-slate-600 hover:text-slate-900"
                  }`}
                >
                  {code === "zh" ? "中文" : code === "en" ? "EN" : "فارسی"}
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={() => void loadData(route)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-slate-200 bg-white text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
              <span>{t.refresh}</span>
            </button>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-[1200px] w-full mx-auto px-6 py-8">
        {loading && !setupData && !panelData ? (
          <div className="space-y-4">
            <div className="h-8 w-64 bg-slate-200 rounded animate-pulse" />
            <div className="h-4 w-96 bg-slate-200 rounded animate-pulse" />
            <div className="h-48 bg-white border border-slate-200 rounded-lg animate-pulse" />
          </div>
        ) : error ? (
          <div className="bg-red-50 border border-red-200 rounded-lg p-5 text-sm text-red-800">
            {t.loadErrorPrefix} {error}
          </div>
        ) : route.mode === "setup" && setupData ? (
          <SetupView data={setupData} lang={lang} onActivated={handleActivated} />
        ) : route.mode === "admin" && panelData ? (
          route.tab === "status" ? (
            <StatusView
              data={panelData}
              adminBasePath={route.adminBasePath}
              lang={lang}
              onOpenConfig={() => navigateTab("config")}
            />
          ) : route.tab === "config" ? (
            <ConfigView
              data={panelData}
              adminBasePath={route.adminBasePath}
              lang={lang}
              onConfigSaved={handleConfigSaved}
            />
          ) : (
            <PanelView data={panelData} lang={lang} />
          )
        ) : null}
      </main>
    </div>
  );
}

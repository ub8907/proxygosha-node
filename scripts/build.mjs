import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as esbuild from "esbuild";

const rootDir = process.cwd();
const clientOutDir = path.resolve(rootDir, "dist-client");
const clientAssetsDir = path.join(clientOutDir, "assets");
const serverOutFile = path.resolve(rootDir, "dist-server", "server.mjs");

function hashFile(filePath) {
  return createHash("sha256").update(fs.readFileSync(filePath)).digest("hex").slice(0, 10);
}

async function buildAll() {
  fs.rmSync(clientOutDir, { recursive: true, force: true });
  fs.rmSync(path.dirname(serverOutFile), { recursive: true, force: true });
  fs.mkdirSync(clientAssetsDir, { recursive: true });

  // 1. 编译前端 React + TypeScript 入口（esbuild 打包为浏览器 ESM）
  const jsOutFile = path.join(clientAssetsDir, "app.js");
  await esbuild.build({
    entryPoints: [path.resolve(rootDir, "src", "main.tsx")],
    bundle: true,
    minify: true,
    format: "esm",
    platform: "browser",
    target: ["es2022"],
    jsx: "automatic",
    outfile: jsOutFile,
    alias: {
      "@": rootDir,
    },
    define: {
      "process.env.NODE_ENV": '"production"',
    },
  });

  // 2. 使用 Tailwind CSS CLI 编译全局样式表
  const cssInFile = path.resolve(rootDir, "src", "index.css");
  const cssOutFile = path.join(clientAssetsDir, "app.css");
  const tailwindBin = path.resolve(rootDir, "node_modules", "@tailwindcss", "cli", "dist", "index.mjs");
  execFileSync(process.execPath, [tailwindBin, "-i", cssInFile, "-o", cssOutFile, "--minify"], {
    cwd: rootDir,
    stdio: "inherit",
  });

  // 3. 生成带内容哈希缓存标识的 dist-client/index.html
  const jsHash = hashFile(jsOutFile);
  const cssHash = hashFile(cssOutFile);
  const rawHtml = fs.readFileSync(path.resolve(rootDir, "index.html"), "utf8");
  const prodHtml = rawHtml.replace(
    /<script\s+type="module"\s+src="\/src\/main\.tsx"><\/script>/,
    `<link rel="stylesheet" href="/assets/app.css?v=${cssHash}" />\n    <script type="module" src="/assets/app.js?v=${jsHash}"></script>`
  );
  fs.writeFileSync(path.join(clientOutDir, "index.html"), prodHtml, "utf8");

  // 4. 打包服务端 server.ts 为纯 Node.js 可执行 ESM 产物（无需 tsx）
  await esbuild.build({
    entryPoints: [path.resolve(rootDir, "server.ts")],
    bundle: true,
    platform: "node",
    format: "esm",
    packages: "external",
    outfile: serverOutFile,
  });

  console.log("[build] 前端产物 -> dist-client/，服务端产物 -> dist-server/server.mjs");
}

buildAll().catch((err) => {
  console.error("[build] 构建失败:", err);
  process.exit(1);
});

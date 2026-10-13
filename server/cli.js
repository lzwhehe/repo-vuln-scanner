#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { scanTarget } from "./scanner.js";
import { failsThreshold, toCsv, toSarif } from "./report.js";

const USAGE = `用法: npm run scan -- <本地路径 | GitHub 仓库 URL | GitHub 用户名> [选项]

选项:
  --github              使用 GitHub API 模式（不克隆，扫描用户/组织/仓库）
  --history             同时扫描 Git 历史（本地 / 克隆模式）
  --max-commits=200     历史扫描的提交数上限
  --format=json         输出格式：json | sarif | csv
  --out=report.sarif    写入文件（默认输出到 stdout）
  --fail-on=low         达到该严重度（low|medium|high|critical）时退出码为 1

退出码: 0 = 没有达到阈值的结果，1 = 有达到阈值的结果，2 = 扫描出错`;

const args = process.argv.slice(2);
const flag = (name) => args.find((arg) => arg.startsWith(`--${name}=`))?.split("=")[1];
const target = args.find((arg) => !arg.startsWith("--"));
const format = (flag("format") || "json").toLowerCase();
const failOn = (flag("fail-on") || "low").toLowerCase();

if (!target || args.includes("--help") || !["json", "sarif", "csv"].includes(format)) {
  console.error(USAGE);
  process.exit(2);
}

try {
  const result = await scanTarget(target, {
    githubApiMode: args.includes("--github"),
    scanHistory: args.includes("--history"),
    maxHistoryCommits: Number(flag("max-commits") || 200)
  });

  const output =
    format === "sarif" ? JSON.stringify(toSarif(result), null, 2) : format === "csv" ? toCsv(result) : JSON.stringify(result, null, 2);

  const out = flag("out");
  if (out) {
    await writeFile(out, output, "utf8");
    const s = result.summary;
    console.error(
      `已写入 ${out}：${s.total} 条结果（严重 ${s.critical} / 高危 ${s.high} / 中危 ${s.medium} / 低危 ${s.low}），排除噪声 ${s.suppressed ?? 0} 条`
    );
  } else {
    console.log(output);
  }

  process.exit(failsThreshold(result, failOn) ? 1 : 0);
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(2);
}

#!/usr/bin/env node
import { scanTarget } from "./scanner.js";

const args = process.argv.slice(2);
const target = args.find((arg) => !arg.startsWith("--"));
const scanHistory = args.includes("--history");
const maxArg = args.find((arg) => arg.startsWith("--max-commits="));
const maxHistoryCommits = maxArg ? Number(maxArg.split("=")[1]) : 200;

if (!target) {
  console.error("Usage: npm run scan -- <path-or-github-url> [--history] [--max-commits=200]");
  process.exit(1);
}

try {
  const result = await scanTarget(target, { scanHistory, maxHistoryCommits });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.summary.total > 0 ? 2 : 0);
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}

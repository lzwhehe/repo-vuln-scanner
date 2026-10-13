# 漏洞扫描器

一个面向 GitHub 和本地仓库的静态漏洞扫描器。它会根据当前文件内容匹配可能存在的凭证泄露、依赖 CVE、CWE 风险代码模式和常见安全配置问题，并把结果按仓库、文件、规则、严重级别聚合展示。

## 功能

- 扫描当前文件中的常见密钥格式：GitHub、OpenAI、Anthropic、DeepSeek、Hugging Face、Replicate、Groq、Pinecone、LangSmith、AWS、Google、Azure、Slack、Stripe、Discord、Telegram、Twilio、GitLab、npm、PyPI、Docker Hub、Datadog、Sentry、Notion、Airtable、Stripe、PayPal、Supabase、MongoDB、Redis、数据库连接串、JWT、私钥等。
- 根据文件内容匹配可能 CVE/CWE 风险：Log4Shell、Spring4Shell、Fastjson 反序列化、lodash/minimist 原型污染，以及命令注入、SQL 注入、路径穿越、SSRF、XSS、不安全反序列化、过宽 CORS 等静态漏洞模式。
- 线上模式支持输入 GitHub 用户/组织主页，例如 `https://github.com/lzwhehe`，自动枚举最近更新的仓库并搜索风险文件。
- 扫描流程按阶段执行并返回聚合结果：风险文件名、token pattern、entropy/context、漏洞/CVE 规则、可插拔 validity check。
- 可选扫描 Git 历史补丁，发现曾经提交过又删除的 secret。
- 对疑似 `KEY=value` 形式的高熵字符串做启发式检测。
- 结果只返回脱敏片段；凭证类命中不会在前端显示完整 token。

## 运行

```bash
npm install
npm run dev
```

打开 Vite 输出的本地地址。默认后端 API 运行在 `http://localhost:8787`。

## 命令行扫描

```bash
npm run scan -- /path/to/repo --history
npm run scan -- https://github.com/owner/repo.git
```

线上 Vercel API 默认使用 GitHub API 模式，支持：

- `github:explore`
- `https://github.com`
- `https://github.com/owner`
- `https://github.com/org`
- `https://github.com/owner/repo`
- `owner/repo`

探索模式会用 GitHub public repository search 自主发现最近活跃的 AI 相关公开仓库，优先覆盖 `artificial-intelligence`、`machine-learning`、`llm`、`large-language-models`、`generative-ai`、`rag`、`ai-agent`、`langchain`、`openai`、`deepseek`、`huggingface`、`vector-database` 等 topic 和关键词查询，再按风险优先级扫描风险文件和可扫描源码文件。排序会优先选择低 star、小体量、最近活跃、demo/starter/tutorial 类型的 AI 项目，因为这类项目更容易出现真实凭证或 `.env` 误提交。它不是一次性全量扫完整个 GitHub，而是适合在 API 限制内按批次持续探索。

线上默认探索 60 个仓库、每仓库最多 80 个候选文件；页面上仓库上限可调到 500。建议配置 `GITHUB_TOKEN`，否则 GitHub 未认证 API 速率限制会明显影响覆盖量。

扫描结果会返回并展示已扫描仓库列表，包括仓库名、描述、语言、star 数、扫描文件数和跳过状态。

如果检测到真实 token、疑似 secret、密码型连接串、私钥内容或可定位的高危漏洞模式，后端会返回 `riskProjects`，前端会自动把对应项目收纳到“风险项目收纳”列表，并保存在浏览器本地存储中。风险文件名现在只作为候选扫描信号，不会单独把项目判定为高危。GitHub 扫描命中会附带 `fileUrl`，前端可以直接定位到问题文件或具体行号。

每条命中还会给出 `exploitability` 评估：根据泄漏文件类型、token 规则、上下文、熵值、CVE/CWE 映射和危险 API 模式列出可能利用模式、利用前提、置信度和非侵入式安全测试证据。默认不会调用第三方 API 验证他人 token，也不会对目标项目发起漏洞利用 payload。

## 规则来源

内置规则包含项目自研规则、CVE/CWE 静态漏洞规则，以及参考 [Coff0xc/Github-API-scan](https://github.com/Coff0xc/Github-API-scan) 的纯匹配规则整理。该项目使用 MIT License；本项目只吸收 regex/search matching 思路，不吸收 token 验证、余额查询或权限探测逻辑。扫描结果会给命中项标注 `provider`、`category`、`cwe`、`possibleCves`、`evidenceLevel` 和 `sourceRuleSet`，便于区分精确格式、上下文格式、泛高熵命中和静态漏洞模式。

## 漏洞持久化

扫描 API 会把脱敏后的风险项目、漏洞命中、定位 URL、利用模式评估和扫描摘要写入漏洞仓库。线上优先使用 Vercel Blob 的私有对象 `token-guardian/vulnerability-vault.json`，本地开发会回退到 `.scanner-data/vault.json`。

可用接口：

- `GET /api/vault`：读取已保存的漏洞仓库
- `DELETE /api/vault`：清空漏洞仓库

如果线上没有配置 Vercel Blob，扫描仍会正常运行，但页面会显示“未配置持久化”。在 Vercel 项目中添加 Blob 存储后，`BLOB_READ_WRITE_TOKEN` 会自动注入，重新部署即可跨会话、跨部署保存结果。

## 高风险文件与 AI 深度分析

“高风险文件”页面会单独列出已持久化漏洞仓库中具备内容证据的高风险文件，包括严重/高危 token pattern、高熵 secret、密码型连接串、私钥内容、依赖 CVE 和高危代码漏洞模式。仅命中文件名的候选风险会保留在扫描结果和流水线聚合里，但不会进入高风险页或风险项目收纳。

点击“深度分析”会调用 `POST /api/analyze`，读取已保存的 GitHub 文件定位，抓取有限的公开代码上下文，并在发送给 AI 前做脱敏。当前支持 OpenAI 和 DeepSeek 两种 provider。API Key 有两种方式：

- 在页面临时输入 OpenAI / DeepSeek API Key：只随本次请求发送，不写入 vault。
- 在 Vercel 环境变量配置 `OPENAI_API_KEY`、`AI_SECURITY_API_KEY`、`DEEPSEEK_API_KEY` 或 `AI_SECURITY_DEEPSEEK_API_KEY`。

“API可用性测试”只会调用当前选择的 AI provider 和模型做一次最小化健康检查，不读取漏洞文件，也不保存 API Key。

AI 分析结果会保存回漏洞仓库，包含静态证据、可利用前提、影响、误报信号、安全验证计划和修复建议。分析不会验证或使用泄露凭证。

私有仓库需要在 Vercel 项目环境变量里配置 `GITHUB_TOKEN`。

当前 validity check 默认关闭，避免对第三方 token 发起验证请求。后续如果只验证你自己服务的 token，可以为对应 provider 单独接入安全验证器。

## 重要提醒

如果确认已经泄露 token，请立即到对应平台撤销/轮换。删除提交记录并不能让已经泄露的凭证重新安全。

# cloudflare-runaway-bill-audit

防止您的 Cloudflare 账单爆炸的检查 skill，由 Astra 撰写，并致谢 [serverlesshorrors.com](https://serverlesshorrors.com/)。

[English](README.md)

这是一个 agent skill，用于检查 Cloudflare 项目是否可能产生意外的高额账单。它查找真实失控账单事故背后的错误（不断重新设置自身的 Durable Object alarm、把消息重新放回自己队列的 queue consumer、为每一个 favicon 请求都启动容器的 catch-all 路由），并生成一个单文件 HTML 报告，外加一份交给编码 agent 的 Markdown 交接文档。

它分两部分工作：确定性的 `scan` 收集配置和账户事实，运行该 skill 的 agent 阅读应用源码并记录发现。仅支持 Cloudflare：Workers、Durable Objects、Queues、R2、Containers/Sandbox、Browser Run、Images 和 Workers AI。

审计是**只读**的：从不部署，从不更改账户，从不向被扫描项目写入任何内容，也从不调用会执行付费操作的应用端点。

**致谢。** 本 skill 由 Astra（GPT-6 Astra）撰写。事故案例来自 [serverlesshorrors.com](https://serverlesshorrors.com/)，一个收集 serverless 账单故事的网站；感谢其维护者。

**推荐模型。** 建议使用 GPT-6 Astra（`gpt-6-astra`）并将推理强度设为 `xhigh` 来运行本 skill。

## 安装

使用 [skills CLI](https://github.com/vercel-labs/skills)：

```bash
npx skills add pc418/cloudflare-runaway-bill-audit
```

或者把本仓库克隆到 agent 的 skills 目录（Claude Code 为 `~/.claude/skills/cloudflare-runaway-bill-audit` 或 `<project>/.claude/skills/...`）。只需要 Python 3.11+，无其他依赖（仅使用标准库）。

## 使用

向您的 agent 提问 "can this project blow up my Cloudflare bill?"（这个项目会不会让我的 Cloudflare 账单爆炸？）。agent 按照 [SKILL.md](SKILL.md) 执行：

```
scan (deterministic facts)  ->  agent audit (edits findings.json)  ->  render (HTML + Markdown)
```

1. **扫描。**

   ```bash
   python3 scripts/audit.py scan path/to/project                 # config + source context, no network
   python3 scripts/audit.py scan path/to/project --account       # + read-only account checks
   python3 scripts/audit.py scan path/to/project --account-wide  # account checks for every Worker / bucket
   ```

   扫描会读取项目中每一个 `wrangler.toml` / `wrangler.json` / `wrangler.jsonc`（`node_modules` 和点目录之外，包括每个 `[env.*]` 覆盖配置）、每个 Worker 声明的入口路径及其是否存在，以及 Git HEAD 和未提交改动状态。它不读取应用源码。加上 `--account` 时，还会对 Cloudflare 账户运行实时的只读检查。它会写出 `findings.json` 和第一版报告，标记为 **unreviewed**（未审阅）。

2. **Agent 审计。** agent 在源码中梳理入口和付费消耗点，借助[事故机制指南](references/agent-detection.md)追踪每条付费路径（准入、付费尝试、交付、重试），将疑似风险与实际控制措施对照检验，并在 `findings.json` 中修正或补充有证据的发现。[带日期的运行时说明](references/runtime-evidence.md)涵盖缓存层和取消行为。完成这些之后，它才会把 `audit_status` 设为 `reviewed`。

3. **校验并渲染。**

   ```bash
   python3 scripts/audit.py validate /tmp/nobill-report-xxxx/findings.json
   python3 scripts/audit.py render /tmp/nobill-report-xxxx/findings.json
   ```

单独的扫描不等于审计：它空的清单和零告警对应用本身说明不了任何问题。`reviewed` 表示 agent 的调查已经发生，并记录了其范围；它并不证明项目是安全的。

选项与行为：

- 项目需要有 wrangler 配置或 Cloudflare 依赖才会被扫描。对没有这些标记的项目，使用 `--provider cloudflare` 扫描。如果扫描拒绝执行且有路径无法读取，错误信息会列出这些路径（该项目仍可能是 Cloudflare 项目）。
- `--out DIR` 指定输出目录，必须位于项目之外。默认会在系统临时目录下新建一个目录；如果该目录位于项目内部，扫描会停止并要求提供 `--out`。`render --out FILE.html` 会在旁边写出 `FILE.md`。
- 当凭据可以读取多个账户时，用 `--account-id`（或 `CLOUDFLARE_ACCOUNT_ID`）指定账户。
- 写入任何内容之前都会检查输出：如果某个输出路径解析到项目内部（例如通过符号链接），或者 `--out` 与另一个输出或 findings 文件指向同一文件（仅大小写不同的名称视为相同），命令会停止。文件先写入临时文件再移动到位，因此目标位置已有的链接会被替换，而不会被写穿。
- `scan` 和 `render` 都会从三个输出中屏蔽已知的本地 Cloudflare 凭据（`CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_API_KEY`、wrangler 登录的 OAuth 和 refresh token，无论是否有效）。这不是通用的密钥检测器：第三方凭据和签名 URL 必须在进入审计证据之前先做脱敏。

## 输出

三个文件并列写在输出目录中；两个命令最后都会打印这三个带标签的绝对路径。

- `report.html`：给人看的完整报告（支持浅色/深色、适配手机宽度、自包含）。
- `report.md`：交给负责修复的编码 agent 的精简交接文档。它与 HTML 包含相同的发现、顺序相同：每条都带有 finding id、规则、目标、证据（`file:line` 及代码片段、API 字段及取值）、审阅结论、原因、修复方法和文档 URL。其中的项目文本会被中和处理（不会注入标题、链接、自动链接的 URL 或邮箱，也不会注入 HTML）。
- `findings.json`：两份报告的数据来源；agent 编辑的就是它。格式见 [references/findings-schema.md](references/findings-schema.md)。

报告包含：

- **Alarms（告警）**：必须修复。有证据表明存在可重复或被放大的成本，且没有有效的上限。
- **Suggestions（建议）**：最好修复，每条都附带最佳实践说明和文档链接。
- **Unknowns（未知项）**：无法检查的内容，以及能够确定结论所需的具体权限或事实。
- **已通过的检查**、**范围要求**表、agent 的**付费工作清单**（含每条路径上的控制措施）、**审计状态和审阅摘要**，以及发现所引用的**事故参考**。

## 检查内容

### Agent 调查的内容

[事故机制指南](references/agent-detection.md)为每一类给出因果问题、对比案例和决定性证据。其他云服务商的事故用于说明机制，而不代表 Cloudflare 的价格。Moltbot 是一个 Cloudflare Sandbox 事故：catch-all 路由为每个静态资源都启动了一个容器（这是用户提供的摘要；原帖未被抓取）。

| 类别 | 机制 | 事故 |
|---|---|---|
| C1 | 自主与跨服务重复：重新设置自身的 Durable Object alarm、重新入队的 queue consumer、自调用、workflow、定时器和后台任务 | [cloudflare-108k](https://serverlesshorrors.com/all/cloudflare-108k), [cloudflare-88k](https://serverlesshorrors.com/all/cloudflare-88k), [cloudflare-36k](https://serverlesshorrors.com/all/cloudflare-36k), [firebase-cloudrun-72k](https://serverlesshorrors.com/all/firebase-cloudrun-72k), [vercel-3k](https://serverlesshorrors.com/all/vercel-3k) |
| C2 | 工作量放大与存储增长：逐项操作、无界的列表和扫描、保留的数据 | cloudflare-36k, [firebase-70k](https://serverlesshorrors.com/all/firebase-70k), [bigquery-22k](https://serverlesshorrors.com/all/bigquery-22k) |
| C3/C6 | 可重复调用的付费端点与预算竞态：匿名或普通用户可触达的 AI、邮件/短信、浏览器、容器和外部付费 API；豁免、失败即放行的守卫、工作完成后才扣费 | [mailgun-11k](https://serverlesshorrors.com/all/mailgun-11k), [vercel-23k](https://serverlesshorrors.com/all/vercel-23k), cloudflare-36k |
| C4 | 公开对象与替代交付路径：绕过缓存、公开的存储桶域名、签名 URL、上传、图片变换 | [firebase-100k](https://serverlesshorrors.com/all/firebase-100k), [netlify-104k](https://serverlesshorrors.com/all/netlify-104k), [aws-13k](https://serverlesshorrors.com/all/aws-13k) |
| C5/C10 | Catch-all 与重复计算：零散请求启动容器、在 GET/SSR 上进行昂贵生成而没有提前命中缓存 | Moltbot（用户提供的摘要）, [vercel-620](https://serverlesshorrors.com/all/vercel-620), [vercel-96k](https://serverlesshorrors.com/all/vercel-96k), [vercel-46k](https://serverlesshorrors.com/all/vercel-46k) |
| C6 | 资源生命周期与执行上限：容器/浏览器/sandbox 的清理与空闲、实例上限、输出上限、Gateway 覆盖范围 | Moltbot, firebase-cloudrun-72k |
| C7 | 客户端生命周期、分析与恢复：每次渲染/挂载触发的事件、浏览器和原生客户端中的重连与重试 | [posthog-devin-1273](https://serverlesshorrors.com/all/posthog-devin-1273) |
| C8 | 可见性与强制刹车：告警只负责通知，上限才能停止工作 | 三起 Cloudflare 用量事故，都是从账单上才发现的 |
| C9 | 计费模型假设：SKU、套餐、包含额度、自动升级、外部计费单位 | [cloudflare-images-400](https://serverlesshorrors.com/all/cloudflare-images-400), [aws-103](https://serverlesshorrors.com/all/aws-103), [webflow-1k](https://serverlesshorrors.com/all/webflow-1k) |
| LOG | 日志与遥测倍增：逐项日志、写入计量存储的 tail consumer | 无事故；依据服务商的日志定价 |

### `scan` 检查的内容

这些规则来自配置和账户 API。每条规则都说明所检查的设置及其来源；配置事实并不能证明代码的实际行为。绑定成本表只覆盖已声明的 Cloudflare 产品，不包括外部 SDK/HTTP 支出。

| 类别 | 规则 | 严重程度 | 依据 |
|---|---|---|---|
| C1 | `CF-QUEUE-CONSUMER-BOUNDS`：consumer 没有显式设置 `max_retries` / `dead_letter_queue`（配置和实时 consumer 设置）。重试设置并不能限制应用自身的重新入队 | suggestion | cloudflare-36k |
| C1 | `CF-SELF-SERVICE-BINDING`：指向 Worker 自身的 service binding（需要审阅） | suggestion | firebase-cloudrun-72k |
| C3 | `CF-NO-RATELIMIT-BINDING`：有付费绑定但没有 Rate Limiting 绑定（声明了绑定并不证明它在付费路径上执行） | suggestion | cloudflare-36k, mailgun-11k |
| C3 | `CF-WORKERS-DEV-ON`：带付费绑定的 Worker 开启了 workers.dev / preview URL（配置和实时） | suggestion | cloudflare-36k, firebase-100k |
| C3 | `CF-AI-GATEWAY-SPEND`（账户）：没有设置支出上限的 AI Gateway；只要运行账户层就会收集，但不声称任何调用经过它。当配置声明了 AI 绑定或使用 `--account-wide` 时为确定，否则需要审阅 | suggestion | cloudflare-36k |
| C4 | `CF-R2-DEV-PUBLIC`（账户）：启用了 r2.dev 公开访问 | suggestion | firebase-100k, aws-13k |
| C5 | `CF-RUN-WORKER-FIRST`：`run_worker_first` 或 Pages `_routes.json` 覆盖了所有路径，因此每个静态资源请求都会运行 Worker；由 agent 判断这些请求是否会启动昂贵的工作（当 Worker 有 Containers、Browser Run 或 Durable Objects 时需要审阅） | suggestion | Moltbot, vercel-620 |
| C6 | `CF-CONTAINER-MAX-INSTANCES`（配置和已部署；从不升级为 alarm）、`CF-CONTAINER-SIZE`、`CF-CPU-LIMIT`、`CF-SUBREQUESTS-RAISED`、`CF-QUEUE-CONCURRENCY`。单次调用和实例上限并不能限制总支出 | suggestion | firebase-cloudrun-72k, Cloudflare 的定价指南 |
| C8 | `CF-NO-BILLING-ALERT`（账户；当没有列出已启用的成本告警策略或缺少 Notifications Read 时为 unknown）、`CF-USAGE-SNAPSHOT`（最近 24 小时用量） | unknown / suggestion | 三起 Cloudflare 用量事故都是从账单上才发现的 |
| C9 | `CF-COST-INVENTORY`：每个绑定按什么计费、免费额度在哪里用完；`CF-CONFIG-DRIFT`（已部署的绑定与配置不一致） | suggestion | cloudflare-images-400, aws-103, webflow-1k |
| LOG | `CF-LOG-SAMPLING`：100% 日志采样。Workers Logs 将于 2026-12-01 改为按 GB 计费的 Observability 定价（包含 50 GB，之后 $0.25/GB） | suggestion | 无事故；定价变更 |
| META | `CF-CONFIG-UNREADABLE`、`CF-NO-CONFIG`：没有可读的 wrangler 配置，配置检查就无法运行；任何失败的账户读取都是一个有范围的 unknown，并注明所需权限或错误 | unknown | 无 |

每条发现都带有证据（`file:line` 及该行内容，或 API 端点和字段）、置信度（`certain` / `heuristic`）、来源、对应的事故，以及附有 Cloudflare 文档链接的修复方法。价格截至 2026-10-13。

## 凭据与 token 权限范围

账户层优先使用 `CLOUDFLARE_API_TOKEN`，否则使用本地 `wrangler login` 的 OAuth token（从 wrangler 自己的配置文件读取：`~/.wrangler/config/default.toml`，macOS 上为 `~/Library/Preferences/.wrangler/config/default.toml`，Linux 上为 `~/.config/.wrangler/...`；优先使用未过期的 token）。审计从不登录或刷新凭据。token 的值从不被打印、记录到日志或写入报告。

| 检查 | 端点 | 权限（自定义 API token） | wrangler OAuth |
|---|---|---|---|
| 账单 / 预算 / 用量通知策略 | `GET /accounts/{id}/alerting/v3/policies`, `/available_alerts` | Notifications Read | 否 (403) |
| 实时 workers.dev / preview URL、绑定漂移、日志采样 | `GET /accounts/{id}/workers/scripts/{name}/subdomain`, `/settings` | Workers Scripts Read | 是 |
| Queue consumer（重试、DLQ） | `GET /accounts/{id}/queues` | Queues Read | 是 |
| r2.dev 公开访问 | `GET /accounts/{id}/r2/buckets/{b}/domains/managed`, `/custom` | Workers R2 Storage Read | 是 |
| 已部署容器的 `max_instances` | `GET /accounts/{id}/containers/applications` | Containers Read | 是 |
| AI Gateway 支出上限 | `GET /accounts/{id}/ai-gateway/gateways` | AI Gateway Read | 否 (403) |
| 最近 24 小时的请求 / 子请求 / CPU | `POST /graphql`（仅 query） | Account Analytics Read | 是（2026-10 观察到） |
| 查询账户 id | `GET /accounts` | Account Settings Read | 是 |

扫描的 API 客户端只能发送 GET 请求，以及经词法分析为 `query` 操作和 fragment 的 GraphQL 文档。

**创建只读 token**（覆盖所有检查）：dash.cloudflare.com > My Profile > API Tokens > Create Token > Create Custom Token。添加以下 Account 权限：*Account Settings Read, Notifications Read, Account Analytics Read, Workers Scripts Read, Queues Read, Workers R2 Storage Read, Containers Read, AI Gateway Read*；Account Resources：包含您的账户。然后执行 `export CLOUDFLARE_API_TOKEN=<token>`。这些全都是 Read 权限，因此该 token 无法更改任何内容。

如果只有 `wrangler login`，通知和 AI Gateway 检查会报告为 **unknown** 并注明缺少的权限，绝不会报告为通过。

## 它看不到什么

- **`scan` 不读取应用源码。** 它找不到路由、守卫、循环、客户端或付费调用；这些由 agent 来做。空的清单、零告警或缺少某条发现，都不能证明不存在付费工作。
- **Agent 审计是一次调查，而不是证明。** 它的结论附带证据和范围；`review_summary` 写明检查了什么、还有什么未解决。审阅之后 unknown 仍会保留在报告中。
- **配置事实不能证明代码行为。** 声明了 Rate Limiting 绑定并不证明它在付费路径上执行，queue 重试设置并不能限制应用的重新入队，实例或 CPU 上限也不能限制总支出。
- **声明的路径不等于已验证的部署。** source context 列出的是配置中声明的入口路径；它并不完整。
- **告警不是强制上限。** Cloudflare 的预算告警和用量通知只是提示性的；自 2026-07-20 起，符合条件的按量付费账户默认获得 $10 的预算告警，且告警在超过阈值的次日才触发（[运行时说明](references/runtime-evidence.md)）。根据 2026-10-13 的记录，Cloudflare 对付费用量没有账户级的硬性支出上限。强制性的限制存在于代码和服务商配置中：速率限制、配额、`max_instances`、`cpu_ms` 和 AI Gateway 支出上限。Gateway 支出上限只覆盖经过 Gateway、且模型定价已知的调用，并且是最终一致的，因此并发突发可能短暂超出上限。每种限制只覆盖一个维度；单独任何一种都不是账户级的总上限。
- 预算告警没有经过验证的 API；报告会请您在控制台中确认已设置。
- `scan` 不读取：zone WAF / 速率限制规则、bot 设置、Images Transformations 的 "Sources" 设置、Durable Object 存储分析、Logpush、Pages Functions 的具体细节。agent 可以通过项目记录或被允许的读取来确定这些内容。
- 通过需要正面证据。读取或解析失败，或者实时 API 的应答缺失、类型错误或不是 `success: true`，都会记为 **unknown** 并附原因，绝不会记为通过。

2026-10-20 之前由早期源码分析器写出的 `findings.json` 文件仍可加载，并按其保存的文本渲染。

## 测试

```bash
python3 -m unittest discover -s tests -t tests
```

测试在临时 `HOME` 下运行，不使用 Cloudflare 凭据，也不访问网络（账户检查针对本地的模拟 API 服务器运行）。

## 许可证

MIT；见 [LICENSE](LICENSE)。

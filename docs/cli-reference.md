# CLI 参考

可执行文件名为 `fileguard`，开发环境使用 `dotnet run --project src/FileGuard.Cli -- <参数>`。所有命令支持 `--help`（`-h` 也可）；帮助同样支持 `--json`。配置文件是 `GuardSettings` JSON；加载顺序为内置默认值 → `--config` 文件 → 命令行参数，后者优先。路径型配置按当前工作目录解析。示例使用生成数据的相对路径。

## 命令

```text
fileguard scan [root ...] [--root <root>] [--json] [--config <file>]
fileguard duplicates <scan-id> [--json]
fileguard scans list [--offset 0 --limit 50]
fileguard scans show <scan-id>
fileguard scans files <scan-id> [--state Unreadable] [--offset 0 --limit 50]
fileguard manifest create <root> --output <manifest.json> [--dry-run] [--json]
fileguard manifest verify <root> --manifest <manifest.json> [--json]
fileguard manifest diff --before <old.json> --after <new.json> [--json]
fileguard cleanup plan <scan-id> [--rule first|oldest|newest|preferred|explicit] [--json]
fileguard cleanup list [--offset 0 --limit 50]
fileguard cleanup show <plan-id>
fileguard cleanup apply <plan-id> [--confirm] [--json] [--dry-run]
fileguard quarantine list [--offset 0 --limit 50] [--json]
fileguard quarantine show <operation-id> [--json]
fileguard quarantine restore <operation-id> [--confirm] [--json] [--dry-run]
fileguard quarantine purge <operation-id> [--confirm --permanent] [--json] [--dry-run]
fileguard quarantine recover [--confirm] [--dry-run] [--json]
fileguard history [--offset 0 --limit 50] [--json]
fileguard serve [--urls http://localhost:5187] [--config <file>] [--web-path <FileGuard.Web.dll>]
```

`scan` 建立并运行任务，默认跳过链接；未传根时扫描配置中所有允许根。尚未配置允许列表时，CLI 的显式扫描根视为本次本地授权；已配置列表时，扫描参数不能扩展列表。执行清理时仍需传相同的 `--config` 或 `--allow-root`。Windows 根目录大小写拼写必须一致。

`duplicates` 展示完整 SHA-256 确认的组。`manifest create` 对全部普通文件哈希，输出必须在已存在的目录中且不能覆盖已有文件；建议放在扫描根外。`verify` 重新读取文件；`diff` 比较两份清单。`cleanup plan` 只生成并持久化计划，`cleanup show` 展示详细候选与 keeper。

`cleanup apply`、恢复和永久清除没有 `--confirm` 时返回 dry-run 预览；缺少 ID 是参数错误。`--dry-run` 总是优先于 `--confirm`。永久清除执行需同时 `--confirm --permanent`。`recover` 默认列出中断操作；显式确认才进行日志与实际状态核对及安全恢复。

`serve` 自动寻找相邻 Web 可执行文件或构建目录，支持显式 `--web-path`。它是持续运行的服务命令，不支持单结果 JSON 协议；使用 `--json` 会返回参数错误。只允许一个 loopback HTTP URL，远程监听拒绝。Web 凭据在 `<data>/web-private/startup-token.txt`，登录后消耗，会话有效期 8 小时。

## 全局与扫描参数

| 参数 | 默认值与语义 |
| --- | --- |
| `--config FILE` | 可选 schemaVersion 1 JSON 配置文件。 |
| `--data DIR` | 当前用户 LocalApplicationData 下的 FileGuard 目录；CLI 和 Web 指向同一目录可共享 SQLite。 |
| `--allow-root PATH` | 可重复；命令行一旦出现则覆盖配置中的整个允许根列表。服务会将相同列表转发到 Web。 |
| `--quarantine DIR` | 默认数据目录的 `quarantine` 子目录。 |
| `--concurrency N` | 默认 2，范围 1–64。 |
| `--capacity N` | 默认 64，每个有界 Channel 的容量，范围 1–4096。 |
| `--bytes-per-second N` | 默认 0（无限速），正整数为扫描哈希工作者共享的每秒读取字节预算。 |
| `--diagnostic-paths[=true\|false]` | 默认 false；只在本地诊断时启用敏感路径异常信息。`serve` 会把该设置转发给 Web。 |
| `--include GLOB` / `--exclude GLOB` | 可重复的根相对匹配；`*` 匹配单层名字，`**` 跨目录，`?` 单字符。 |
| `--extension .ext` | 可重复，按扩展名筛选。 |
| `--min-size N` / `--max-size N` | 包含边界的逻辑字节数范围。 |
| `--modified-after ISO8601` / `--modified-before ISO8601` | UTC 修改时间范围；建议显式 `Z` 或时区偏移。 |
| `--hash-all` | 对全部普通文件哈希；默认只对大小重复候选计算完整 SHA-256。 |
| `--offset N` / `--limit N` | 支持列表命令分页，默认 0 / 50，limit 1–10000。 |

计划保留规则为 `first`（Ordinal 路径最先）、`oldest`、`newest`、`preferred`（需 `--preferred-directory PATH`）和 `explicit`（可重复 `--keep-path PATH`，每个组至少命中一个）。`--valid-hours` 默认 24，范围 1–168。时间并列时按稳定路径顺序选择。多个显式 keep 路径都会保留。

配置示例：

```json
{
  "schemaVersion": 1,
  "dataDirectory": "./.local/fileguard-state",
  "allowedRoots": ["./.local/sample-data"],
  "quarantineDirectory": "./.local/quarantine",
  "concurrency": 2,
  "channelCapacity": 64,
  "bytesPerSecond": 0,
  "diagnosticPaths": false
}
```

JSON 模式下 stdout 只有一份含 `schemaVersion`、`command` 和 `data`（或 `error`）的协议 JSON；进度、日志和诊断在 stderr。没有 `--json` 时输出命令标题和缩进结果。结果中计划候选的完整路径用于本地审查，与普通日志的路径脱敏是不同的输出用途。Ctrl+C 触发有序取消，已开始操作会持久化结果。

## 退出码

| 码 | 意义 |
| --- | --- |
| 0 | 成功，且验证/执行没有差异或未处理项。 |
| 1 | 检测到清单内容变化、缺失或新增；重复组查询成功仍返回 0。 |
| 2 | 参数/配置无效、缺少必填 ID 或永久清除二次确认；未执行文件变更。 |
| 3 | 部分失败/跳过/需要复核；查看 JSON 中逐项结果和操作日志。 |
| 130 | 用户取消（Ctrl+C）；状态已持久化。 |

无法读取、计划过期、候选变化、keeper 失效、不存在的记录 ID 或损坏清单属于操作失败/部分结果，退出码为 3；清单验证发现内容变化、缺失、新增使用 1。无人值守调用不等待交互输入，调用方应捕获 stderr 并根据 `schemaVersion` 解析 stdout。

## 安全示例

```text
fileguard scan ./.local/sample-data --config ./.local/fileguard.json --json
fileguard cleanup plan SCAN_ID --config ./.local/fileguard.json --rule preferred --preferred-directory ./.local/sample-data/keep
fileguard cleanup show PLAN_ID --config ./.local/fileguard.json
fileguard cleanup apply PLAN_ID --config ./.local/fileguard.json
fileguard cleanup apply PLAN_ID --config ./.local/fileguard.json --confirm --json
fileguard quarantine restore OPERATION_ID --config ./.local/fileguard.json --confirm --json
fileguard quarantine purge OPERATION_ID --config ./.local/fileguard.json --confirm --permanent --json
```

清理命令先预览，确认每个保留副本和候选路径；计划生成后若文件变化，应重新扫描。不要把用户真实路径或包含敏感信息的 JSON/日志粘贴到公开 issue 或仓库。

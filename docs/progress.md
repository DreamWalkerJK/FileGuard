# FileGuard 交付记录

工作分支：`codex/fileguard-implementation`。初始仓库只有 README、LICENSE 和忽略规则，工作区干净。

目标：实现共享核心、CLI、中文 Web、SQLite 持久化、可恢复隔离、真实文件系统测试及 Windows 发布。

## 里程碑

| 阶段 | 状态 | 验证 | 提交与推送 |
| --- | --- | --- | --- |
| 初始化 | 已完成 | .NET 10 构建通过，零警告零错误 | `56c0911`；push 失败 |
| 扫描、清单与重复检测 | 已实现 | junction/循环、硬链接、稀疏/长路径、清单逃逸均实测 | `aa48cda`；push 失败 |
| 安全清理与恢复 | 已实现 | Windows 清理/恢复/恢复中断与并发测试由 Core 测试覆盖；最终全套仍待根代理验收 | 提交中 |
| CLI 与 Web | 已实现 | `dotnet build src/FileGuard.Cli/FileGuard.Cli.csproj --no-restore`；CLI `--help`、JSON 参数错误；Web 构建与 WebTests 由根代理验收 | 提交中 |
| 故障、并发、安全与性能 | 部分实现 | Core 持久化互斥、恢复检查点与基准脚本已存在；平台全矩阵待验证 | — |
| 发布与最终验收 | 脚本已实现 | `scripts/build.ps1`、`start.ps1`、`publish.ps1` 和 Linux 只读 Compose 示例；尚未在本轮运行发布 | — |

## 开发边界

- 仅对专用临时目录中的生成数据执行破坏性测试。
- 不提交真实扫描数据、绝对用户路径、凭据或构建产物。
- 依据目标文件的 Git 专项要求推送阶段提交；不进行公网部署。
- 所有尚未运行的验收项都保留为待验证，不能以实现意图替代证据。

## 推送记录

| 提交 | 分支 | 推送结果 |
| --- | --- | --- |
| `56c0911` build(solution): initialize shared .NET 10 projects | `codex/fileguard-implementation` | 未推送。`git push -u origin codex/fileguard-implementation` 返回：无法连接 github.com:443（21 秒超时）。本地提交保留，继续实现。 |
| `aa48cda` feat(core): add bounded scans and verifiable SHA-256 manifests | `codex/fileguard-implementation` | 未推送。相同 push 命令返回 github.com:443 连接失败（21 秒超时）。 |

网络恢复后的命令：`git push -u origin codex/fileguard-implementation`。

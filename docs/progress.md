# FileGuard 交付记录

工作分支：`codex/fileguard-implementation`。初始仓库只有 README、LICENSE 和忽略规则，工作区干净。

目标：实现共享核心、CLI、中文 Web、SQLite 持久化、可恢复隔离、真实文件系统测试及 Windows 发布。

## 里程碑

| 阶段 | 状态 | 验证 | 提交与推送 |
| --- | --- | --- | --- |
| 初始化 | 已完成 | .NET 10 构建通过，零警告零错误 | `56c0911`；push 失败 |
| 扫描、清单与重复检测 | 已实现 | junction/循环、硬链接、稀疏/长路径、清单逃逸均实测 | `aa48cda`；push 失败 |
| 安全清理与恢复 | 已完成 | Release Cleanup 测试 25 项通过；跨进程、跨卷、崩溃、冲突、容量和 ADS 场景覆盖 | 待提交 |
| CLI 与 Web | 已完成 | Release 全套 89 passed / 1 skipped；CLI/Web 测试和 Chromium 流程通过 | `b1f11cb`；已推送 |
| 故障、并发、安全与性能 | 已完成 | Ctrl+C 脚本通过；small/large 基准已记录；安全文档和恢复前缀核验完成 | `b1f11cb`；已推送 |
| 发布与最终验收 | 已完成 | Release 构建通过；Windows self-contained CLI/Web 与 ZIP 已生成；发布 Web `/login` 返回 200 | `b1f11cb`；已推送 |

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

| `efabf2e` feat(quarantine): add verified isolation and crash recovery | `codex/fileguard-implementation` | 已成功推送到 `origin/codex/fileguard-implementation`。 |

| `b1f11cb` feat(cli): add automation and Web management workspace | `codex/fileguard-implementation` | 已成功推送到 `origin/codex/fileguard-implementation`。包含 CLI/Web、测试、文档、基准、脚本和 Windows 发布配置。 |

最终工作树已审查并保持干净；当前分支跟踪 `origin/codex/fileguard-implementation`。

网络恢复后的命令：`git push -u origin codex/fileguard-implementation`。

# FileGuard

FileGuard 是一个 .NET 10 文件完整性、完全重复检测和可恢复隔离工具，提供共享核心库、CLI 和 ASP.NET Core + Blazor Web 管理界面。CLI 与 Web 调用相同的扫描、SHA-256、清单、计划和恢复规则。

工具面向由服务进程明确允许的服务端目录。浏览器客户端本地磁盘不会自动扫描。默认不跟随符号链接、junction 或其他 reparse point；清理前会重新验证路径、文件身份、大小、摘要和保留副本。隔离是可恢复移动，通常不会释放同卷空间；永久清除是独立且需要再次确认的动作。

Windows 本地卷支持隔离、恢复与独立永久清除。Linux 提供读取模式，但文件身份及物理容量未知，修改被拒绝；macOS 当前没有安全读取后端。无法可靠验证文件身份、链接或祖先边界时会保守拒绝。Windows UNC/设备路径不支持，大小写敏感目录只允许读取。稀疏/压缩/去重/快照存储可能使物理空间估算未知。首版没有远程 Web、清单签名或自动永久删除计划。见 [docs/security.md](docs/security.md)。

## 快速开始

```powershell
./scripts/build.ps1
dotnet run --project src/FileGuard.Cli -- --help

# 专用生成数据；不要用真实用户目录作为首次清理样本。
New-Item -ItemType Directory -Path .local/sample-data -Force
Set-Content -LiteralPath .local/sample-data/a.txt -Value 'generated example'
Copy-Item -LiteralPath .local/sample-data/a.txt -Destination .local/sample-data/b.txt
dotnet run --project src/FileGuard.Cli -- scan --config fileguard.example.json --json
dotnet run --project src/FileGuard.Cli -- manifest create ./.local/sample-data --config fileguard.example.json --output ./.local/sample-manifest.json
./scripts/start.ps1 -Config fileguard.example.json
```

`--config` 可以加载 `GuardSettings` JSON；命令行参数覆盖配置文件。`fileguard.example.json` 中的路径相对当前工作目录，示例数据、状态和隔离文件位于 Git 忽略的 `.local`。`serve` 默认绑定 [http://localhost:5187](http://localhost:5187)，浏览器登录需要读取 `.local/state/web-private/startup-token.txt` 并粘贴一次性 token；登录后 token 删除，会话有效期 8 小时，重启服务获得新 token。不能把 token 放入日志或提交到仓库。

清理始终从扫描开始：

```text
scan → duplicates → cleanup plan → preview → cleanup apply --confirm → quarantine restore/purge
```

计划生成只持久化候选。应用/恢复/清除命令没有 `--confirm` 时只预览，`--dry-run` 总是覆盖确认；永久清除还需 `--permanent`。保存首次扫描输出中的 `data.id`，然后逐步执行：

```powershell
dotnet run --project src/FileGuard.Cli -- duplicates SCAN_ID --config fileguard.example.json
dotnet run --project src/FileGuard.Cli -- cleanup plan SCAN_ID --config fileguard.example.json
dotnet run --project src/FileGuard.Cli -- cleanup show PLAN_ID --config fileguard.example.json
dotnet run --project src/FileGuard.Cli -- cleanup apply PLAN_ID --config fileguard.example.json
dotnet run --project src/FileGuard.Cli -- cleanup apply PLAN_ID --config fileguard.example.json --confirm
dotnet run --project src/FileGuard.Cli -- history --config fileguard.example.json
dotnet run --project src/FileGuard.Cli -- quarantine restore OPERATION_ID --config fileguard.example.json --confirm
Set-Content -LiteralPath .local/sample-data/a.txt -Value 'changed generated example'
dotnet run --project src/FileGuard.Cli -- manifest verify ./.local/sample-data --config fileguard.example.json --manifest ./.local/sample-manifest.json --json
```

把 SCAN_ID、PLAN_ID、OPERATION_ID 换成前一步结果中的真实 ID。最后的验证应返回退出码 1 和 ContentChanged。JSON 模式 stdout 只输出含 `schemaVersion` 的协议数据，进度和诊断写 stderr。完整参数、配置与退出码见 [docs/cli-reference.md](docs/cli-reference.md)。Web 的扫描、重复组、计划、隔离、清单、历史和设置标签可完成相同流程。

## 构建、测试与发布

需要 .NET SDK 10.0.102 或同功能带受允许的补丁版本，以及 Windows PowerShell/PowerShell。`scripts/build.ps1` 运行 restore、Release build 和全部测试。测试只创建项目 `.test-data` 中的生成数据，删除前校验测试根边界。

```powershell
./scripts/build.ps1
./scripts/publish.ps1
./artifacts/publish/win-x64/cli/fileguard.exe --help
./scripts/start.ps1 -Config fileguard.example.json -Published
```

发布为 Windows x64 自包含产物：`artifacts/publish/win-x64/cli/fileguard.exe` 与 `artifacts/publish/win-x64/web/FileGuard.Web.exe`，归档为 `artifacts/FileGuard-win-x64.zip`。部署后可直接从解压根运行 `cli/fileguard.exe serve --config fileguard.example.json`；先创建示例配置中的允许目录。发布脚本不推送、不安装系统服务、不部署公网。可选容器示例仅支持 Linux 只读 CLI 扫描，见 [docs/docker.md](docs/docker.md)。

## 目录

* [需求与验收矩阵](docs/requirements.md)
* [架构与技术决策](docs/architecture.md)
* [清单格式](docs/manifest-format.md)
* [隔离与恢复手册](docs/recovery-guide.md)
* [安全边界与平台限制](docs/security.md)
* [CLI 参考](docs/cli-reference.md)
* [测试报告](docs/test-report.md)
* [性能基准](docs/benchmarks.md)
* [Docker 只读扫描示例](docs/docker.md)
* [阶段进度与 Git 交付](docs/progress.md)

完整端到端验收必须使用项目专用临时目录和生成数据，不能对用户真实目录进行破坏性测试。测试、基准、发布产物和未验证平台能力必须如实记录；文档或演示数据不能代替真实文件操作证据。

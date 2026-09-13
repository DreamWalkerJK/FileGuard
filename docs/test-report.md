# FileGuard 测试报告

最后验证时间：2026-09-13；Windows 10.0.26200、.NET SDK 10.0.102 / runtime 10.0.2、x64、NVMe SSD。

## 自动化结果

命令：`dotnet test tests/FileGuard.Tests -c Release --no-restore`

结果：**89 passed, 1 skipped, 0 failed**。跳过项是文件符号链接创建测试：当前 Windows 测试账户没有 `SeCreateSymbolicLinkPrivilege`；junction、reparse point、链接循环和文件链接边界仍有实测覆盖。测试项目包含 Scanner、Manifest、Store、Cleanup、CLI 和 Web 测试。

专项命令及结果：

| 领域 | 结果 | 证据 |
| --- | ---: | --- |
| Scanner / Manifest / Store | 46 passed, 1 skipped | 过滤、大小写、Unicode、长路径、硬链接、junction、循环、文件变化/消失、阻塞目录、稀疏文件、清单逃逸/严格 JSON、迁移和未知版本 |
| Cleanup / Recovery | 25 passed | 预览、身份/摘要/字节核验、同卷 rename、跨卷复制、容量不足、冲突、崩溃检查点、恢复前缀核验、ADS 保守拒绝、跨进程锁 |
| CLI | 4 passed | help、JSON 错误、真实进程扫描/重复/清单/计划、默认 dry-run、取消和同计划并发 |
| Web | 13 passed | 未授权、一次性 token、Cookie、CSRF、Host/Origin、allowlist、任务取消/重试、真实扫描/计划/隔离/恢复/清单、过期计划、永久二次确认 |

额外真实进程验证：`python scripts/verify-console-cancel.py` 返回 `{"consoleSignal":"CTRL_C_EVENT","exitCode":130,"persistedState":"Cancelled","jsonStdout":true,"result":"passed"}`。它使用独立隐藏进程发送 Ctrl+C，避免测试宿主控制台句柄竞态。

## Web 浏览器验收

Playwright Chromium 实测扫描→重复组→显式保留计划→预览→隔离→恢复→清单创建→修改→验证差异→清单 diff→重复执行保护。`artifacts/web-evidence/browser-validation.json` 记录：`login=true`、`scan=true`、`duplicateGroups=1`、`quarantine=true`、`restore=true`、`manifestCreate=true`、`manifestVerify=true`、`manifestDiff=true`、`browserErrors=[]`、桌面和 390px 移动视口均无溢出。截图和 JSON 位于被忽略的 `artifacts/web-evidence/`。

## 性能基准

两组实测指标和复现命令见 [benchmarks.md](benchmarks.md)。原始 JSON 位于被忽略的 `artifacts/benchmarks/`，测试数据只位于被忽略的 `.test-data/benchmarks/`。

## 安全和破坏性边界

所有破坏性测试均先生成专用随机目录，并在清理前验证解析后的绝对路径仍位于测试根目录；没有对用户真实目录执行清理。真实文件内容、路径、数据库和 token 不入 Git。脚本发布只写入 `artifacts/`，并在删除旧发布目录前验证其路径边界。

macOS 安全读取后端未验证；Linux 读取使用 `O_NOFOLLOW`，清理/恢复明确拒绝。Windows 文件符号链接能力因账户权限跳过，不能据此宣称该权限场景已验证。

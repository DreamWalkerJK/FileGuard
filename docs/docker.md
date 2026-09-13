# 可选 Docker 扫描示例

Dockerfile 构建 Linux x64 CLI，Compose 示例只运行只读扫描。首版 Linux 不提供安全修改后端，因此隔离、恢复和永久清除被拒绝。Web 只允许 loopback 绑定，普通容器端口发布不适用于该限制，示例不提供容器 Web 服务。

先在项目内创建专用测试输入，再运行：

```powershell
New-Item -ItemType Directory -Path .local/sample-data -Force
Set-Content -LiteralPath .local/sample-data/a.txt -Value 'generated example'
Copy-Item -LiteralPath .local/sample-data/a.txt -Destination .local/sample-data/b.txt
docker compose build
docker compose run --rm scan
```

挂载边界：

| 位置 | 访问 | 用途 |
| --- | --- | --- |
| 主机 `.local/sample-data` → `/data` | 只读 bind | 仅作为扫描输入，目录必须预先存在。 |
| `fileguard-state` → `/state` | 可写 volume | SQLite、任务、索引和操作日志。 |
| `fileguard-quarantine` → `/quarantine` | 可写 volume | 展示隔离区必须独立授权写入；首版 Linux 不执行隔离。 |
| `/tmp` | 临时 tmpfs | .NET 运行时临时数据。 |

容器根文件系统只读，移除 Linux capabilities 并禁止取得新权限。Linux 文件身份/硬链接数无法可靠确认时返回未知容量；不能将该示例解读为跨平台清理验收。镜像构建需要访问 Microsoft .NET 镜像源与 NuGet。是否在交付环境实测成功，以测试报告为准。

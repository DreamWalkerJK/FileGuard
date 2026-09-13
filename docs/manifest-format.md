# 完整性清单格式（schemaVersion 1）

清单是用于内容一致性检查的公开 JSON 文档，不是签名容器。它证明生成时工具读取到的文件内容与摘要一致，不能证明文件来源、生成者身份或清单未被第三方修改。首版不提供数字签名；需要来源认证时，应在可信外部系统中签名并验证整个清单字节流。

## 规范

根对象必须包含：

```json
{
  "schemaVersion": 1,
  "algorithm": "SHA-256",
  "createdUtc": "2026-01-01T00:00:00Z",
  "files": [
    {
      "path": "docs/readme.txt",
      "size": 42,
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "modifiedUtc": "2026-01-01T00:00:00Z",
      "state": "Ready"
    }
  ]
}
```

`path` 是相对于扫描根的 `/` 分隔路径，禁止空路径、盘符、UNC、前导 `/`、`..`、NTFS alternate data stream 分隔符、控制字符及任何链接逃逸。排序使用 Ordinal 比较；写出使用 UTF-8（无 BOM）、LF 换行和稳定缩进。文件名大小写按运行平台文件系统语义处理，比较算法不能在 Linux 上统一折叠大小写。

`size` 是读取时的逻辑字节长度。`sha256` 是 64 个十六进制字符（256 位摘要），读取接受大小写，写出规范化为小写；`Unreadable`、`Missing`、`Unstable` 等非 `Ready` 状态可以为 null，并应填 `error`。`modifiedUtc` 为观测到的 UTC 时间。schema 1 拒绝未知字段、重复 JSON 属性、不完整必填字段、非法状态与不支持的 schemaVersion；增加字段需要新版本及相应解析器。

`isDirectory` 是可选布尔字段，默认 false。true 只允许用于 `Unreadable` 的目录条目（size 为 0、sha256 为 null），表示目录无法枚举。验证时该目录覆盖的基准后代应报告 Unreadable，避免把不能枚举的文件错误报告为 Missing。根目录本身不能枚举时创建/验证明确失败。

清单创建对根下普通文件使用流式 SHA-256；symlink/junction 条目被排除且不跟随。请把输出文件放在扫描根之外，否则它会成为下一次扫描的真实输入。输出目录必须已存在，已有目标文件被拒绝覆盖；工具先写同目录临时文件并刷新，再提交文件名。`--dry-run` 计算并预览清单但不写出文件。

清单验证重新读取根目录文件并复核路径、长度、身份和摘要。`diff` 的结果区分 `Added`、`Missing`、`ContentChanged`、`Unreadable`、`Unstable` 和 `Unchanged`。内容变化、新增、缺失退出码为 1；不可读取或不稳定退出码为 3。仅修改时间改变且内容相同不会报告 ContentChanged。两份清单的纯比较使用 Ordinal 路径语义；现场验证再按目标目录实际大小写规则匹配。

清单不是原子快照：文件在创建期间改变会被标记为不稳定或读取失败。缓存命中只能减少计算，不会授权清理。清单中的路径验证不能替代清理前的最终身份与链接检查。

## 机器消费

CLI JSON 结果最外层包含 `schemaVersion`，stdout 只写一份 JSON 文档；进度和诊断写 stderr，错误同时以结构化 `error` 字段返回。调用方应根据 `schemaVersion` 选择兼容解析器。清单解析器对输入字段严格验证，CLI 输出协议和清单文件是不同层次的格式。完整 CLI 退出码见 [cli-reference.md](cli-reference.md)。

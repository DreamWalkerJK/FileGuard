using FileGuard.Core;
namespace FileGuard.Web;
public static class Ui
{
    public static int Offset(int page) => Math.Clamp(page, 0, 1_000_000) * 25;
    public static string Bytes(long? value)
    {
        if (value is null) return "无法确定";
        double size = value.Value; var units = new[] { "B", "KiB", "MiB", "GiB", "TiB" }; var unit = 0;
        while (size >= 1024 && unit < units.Length - 1) { size /= 1024; unit++; }
        return $"{size:0.##} {units[unit]}";
    }
    public static string Time(DateTimeOffset time) => time.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
    public static bool Active(ScanState state) => state is ScanState.Queued or ScanState.Enumerating or ScanState.Hashing;
    public static string Tone(string state) => state switch { "Completed" or "Ready" or "Restored" or "Unchanged" => "success", "Failed" or "Unreadable" or "NeedsReview" or "Missing" => "error", "Unstable" or "PartialFailure" or "Skipped" or "Interrupted" => "warning", _ => "neutral" };
    public static string Label(object state) => state.ToString() switch
    {
        "Queued" => "排队中", "Enumerating" => "遍历中", "Hashing" => "读取校验中", "Completed" => "已完成", "PartialFailure" => "部分失败", "Cancelled" => "已取消", "Interrupted" => "已中断", "Failed" => "失败",
        "Indexed" => "已索引", "Ready" => "已校验", "Unreadable" => "无法读取", "Missing" => "缺失", "Unstable" => "文件不稳定", "SkippedLink" => "已跳过链接",
        "Planned" => "待执行", "Started" => "执行中", "Copied" => "已复制待提交", "Skipped" => "已跳过", "Restoring" => "恢复中", "Restored" => "已恢复", "Purging" => "清除中", "Purged" => "已永久清除", "NeedsReview" => "需要人工核对",
        "Added" => "新增", "ContentChanged" => "内容变化", "Unchanged" => "未变化", "FirstPath" => "路径排序第一份", "Oldest" => "修改时间最早", "Newest" => "修改时间最新", "PreferredDirectory" => "首选目录", "Explicit" => "显式选择", _ => state.ToString() ?? "未知"
    };
}

// Ipc/IpcLog.cs
//
// Diagnostic log for the IPC surface.
//
// Motivation: an agent self-update failed on a real endpoint with nothing but
// `PrivSvc timeout` on the Node side. The PrivSvc produced exactly ONE log file
// (grpcbridge-*.log) covering the gRPC bridge and nothing else, so there was no
// way to tell whether the IPC call had even arrived, which handler it hit, how
// long it ran, or what it answered. Every privileged primitive — signature
// verification, installs, patching — was invisible.
//
// Mirrors GrpcBridge's file conventions (same logs directory, daily stem, size
// roll, bounded retention) so operators collecting logs find both side by side.
//
// Volume discipline: the bridge drives a constant stream of acks/heartbeats/
// fact chunks. Logging every one of those would bury the interesting entries
// and burn disk, so high-frequency methods are logged ONLY when they fail. See
// Router for where that policy is applied.

using System;
using System.IO;
using System.Linq;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class IpcLog
{
    private static readonly string LogDir =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Tracenium",
            "PrivSvc",
            "logs");

    private const long MaxLogBytes = 5 * 1024 * 1024;
    private const int MaxLogFiles = 5;
    private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(5);
    private static DateTime _lastCleanupUtc = DateTime.MinValue;
    private static readonly object WriteLock = new();

    public static void Write(string message)
    {
        try
        {
            lock (WriteLock)
            {
                if (!Directory.Exists(LogDir)) Directory.CreateDirectory(LogDir);
                CleanupOldLogs();
                var line = $"[{DateTime.UtcNow:O}] {message}{Environment.NewLine}";
                File.AppendAllText(GetDailyLogPath(), line);
            }
        }
        catch
        {
            // Logging must never break a privileged operation.
        }
    }

    private static string GetDailyLogPath()
    {
        var stem = $"privsvc-{DateTime.UtcNow:yyyyMMdd}";
        var path = Path.Combine(LogDir, $"{stem}.log");
        try
        {
            if (new FileInfo(path) is { Exists: true, Length: > MaxLogBytes })
            {
                for (var i = 2; i < 100; i++)
                {
                    var rolled = Path.Combine(LogDir, $"{stem}.{i}.log");
                    var info = new FileInfo(rolled);
                    if (!info.Exists || info.Length <= MaxLogBytes) return rolled;
                }
            }
        }
        catch { }
        return path;
    }

    private static void CleanupOldLogs()
    {
        try
        {
            if (DateTime.UtcNow - _lastCleanupUtc < CleanupInterval) return;
            _lastCleanupUtc = DateTime.UtcNow;

            var files = Directory.GetFiles(LogDir, "privsvc-*.log")
                .Select(f => new FileInfo(f))
                .OrderByDescending(f => f.LastWriteTimeUtc)
                .Skip(MaxLogFiles)
                .ToList();

            foreach (var f in files)
            {
                try { f.Delete(); } catch { }
            }
        }
        catch { }
    }
}

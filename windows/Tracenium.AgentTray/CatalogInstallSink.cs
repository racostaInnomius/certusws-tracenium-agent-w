using System.Text.Json;

namespace Tracenium.AgentTray;

/// <summary>
/// Tray -&gt; core channel for the self-service Software Catalog tab.
///
/// This app has no control-plane credentials and no network access of
/// its own — every real capability (auth, the gRPC stream, PrivSvc)
/// lives in AgentCore, which runs as a LocalSystem service (see
/// windows/installer/wix/AgentCoreFiles.wxs). So "please install this"
/// travels the same file-mediated path the macOS tray uses (mirrors
/// CatalogInstallSink.swift): write a small JSON document into this
/// user's OWN AppData\Local\Tracenium — a location already writable by
/// this user without any ACL changes — and AgentCore, which can read
/// any user's profile as LocalSystem, polls for it (see
/// catalog-install-request-watcher.ts on the agent side).
/// </summary>
internal static class CatalogInstallSink
{
    private const string FileName = "catalog-install-request.json";

    private static string FilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Tracenium",
            FileName);

    /// <summary>
    /// Writes a fresh request. Overwrites any request already waiting —
    /// there is only ever one "next" self-install AgentCore should act
    /// on, and the UI already disables the Install button for the
    /// duration of a pending/running job, so a genuine double-write
    /// shouldn't happen in practice.
    /// </summary>
    public static void Write(string packageId)
    {
        try
        {
            var dir = Path.GetDirectoryName(FilePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var payload = new
            {
                packageId,
                requestedAtUtc = DateTime.UtcNow.ToString("O")
            };
            var json = JsonSerializer.Serialize(payload);

            // Write to a temp file then move — avoids AgentCore ever
            // reading a half-written file mid-poll (same atomic-write
            // posture as the macOS sink's `.atomic` write option).
            var tempPath = FilePath + ".tmp";
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, FilePath, overwrite: true);
        }
        catch
        {
            // Best-effort — a failed write just means this click's
            // install request never reaches AgentCore. Keep the tray
            // isolated from this failure the same way every other
            // sink/loader in this app already is.
        }
    }
}

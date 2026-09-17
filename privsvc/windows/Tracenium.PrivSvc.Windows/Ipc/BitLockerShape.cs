// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/BitLockerShape.cs
//
// El bloque `bitlocker` que evalúa windows.bitlocker.system_drive_encrypted,
// extraído de SecurityCompliance.cs para poder probarlo (el proyecto de
// pruebas es net8.0 multiplataforma, como DefenderStatusShape.cs).
//
// ── Por qué ──────────────────────────────────────────────────────────
//
// 1. El colector hacía `Get-BitLockerVolume | Select-Object MountPoint,
//    VolumeStatus | ConvertTo-Json` y buscaba "FullyEncrypted" en el texto.
//    PrivSvc lanza `powershell` = Windows PowerShell 5.1, cuyo ConvertTo-Json
//    serializa los enums como NÚMERO. Nunca contenía "FullyEncrypted": medido
//    el 16-sep, 47 de 47 estaciones de T111 y 8 de 8 de T1 salían "disabled"
//    con cero unidades, y el check fallaba en todas.
// 2. "Cualquier volumen cifrado" bastaba, y no se leía ProtectionStatus: un
//    BitLocker SUSPENDIDO pasaba (P1-6 de SCP-VALIDACION-PROD-2026-09-16.md).
//
// ── Qué emite ────────────────────────────────────────────────────────
//
//   volumes[]      cada volumen con sus estados como TEXTO (el script los
//                  convierte con [string] antes de serializar).
//   systemVolume   el de VolumeType OperatingSystem: encrypted =
//                  FullyEncrypted, protectionOn = ProtectionStatus On. Sin
//                  volumen de sistema identificable, se omite (not_applicable).
//   status/drives/coverage  como antes, para lectores que ya los usan.
//
// Un estado que no llega como texto conocido no se interpreta: no se
// adivinan los números de un enum.

using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class BitLockerShape
{
    public const string Script =
        "Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ " +
        "MountPoint = [string]$_.MountPoint; VolumeType = [string]$_.VolumeType; VolumeStatus = [string]$_.VolumeStatus; " +
        "ProtectionStatus = [string]$_.ProtectionStatus; EncryptionPercentage = $_.EncryptionPercentage } } | ConvertTo-Json -Depth 3";

    public static Dictionary<string, object?> Unknown() => new() { ["status"] = "unknown" };

    public static Dictionary<string, object?> Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Unknown();
        List<Dictionary<string, JsonElement>> rows;
        try
        {
            var trimmed = json.TrimStart();
            rows = trimmed.StartsWith("[")
                ? JsonSerializer.Deserialize<List<Dictionary<string, JsonElement>>>(json) ?? new()
                : new() { JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json) ?? new() };
        }
        catch (JsonException)
        {
            return Unknown();
        }
        rows = rows.Where(r => r.Count > 0).ToList();
        if (rows.Count == 0) return Unknown();

        var volumes = new List<Dictionary<string, object?>>();
        Dictionary<string, object?>? system = null;
        var encryptedMounts = new List<string>();
        foreach (var r in rows)
        {
            var mount = Str(r, "MountPoint");
            var type = Str(r, "VolumeType");
            var status = Str(r, "VolumeStatus");
            var protection = Str(r, "ProtectionStatus");
            var v = new Dictionary<string, object?>
            {
                ["mountPoint"] = mount,
                ["volumeType"] = type,
                ["volumeStatus"] = status,
                ["protectionStatus"] = protection,
                ["encryptionPercentage"] = Num(r, "EncryptionPercentage"),
            };
            volumes.Add(v);

            var encrypted = Is(status, "FullyEncrypted");
            if (encrypted == true && !string.IsNullOrWhiteSpace(mount)) encryptedMounts.Add(mount!);

            if (system == null && Is(type, "OperatingSystem") == true)
            {
                var protectionOn = Is(protection, "On");
                system = new Dictionary<string, object?> { ["mountPoint"] = mount };
                if (encrypted.HasValue) system["encrypted"] = encrypted.Value;
                if (protectionOn.HasValue) system["protectionOn"] = protectionOn.Value;
            }
        }

        var block = new Dictionary<string, object?>
        {
            ["status"] = encryptedMounts.Count > 0 ? "enabled" : "disabled",
            ["drives"] = encryptedMounts,
            ["coverage"] = (double)encryptedMounts.Count / rows.Count,
            ["volumes"] = volumes,
        };
        if (system != null) block["systemVolume"] = system;
        return block;
    }

    /// <summary>true/false si el estado llegó como texto; null si llegó vacío o como número (no se adivina).</summary>
    private static bool? Is(string? value, string expected)
    {
        if (string.IsNullOrWhiteSpace(value) || value.All(char.IsDigit)) return null;
        return string.Equals(value.Trim(), expected, StringComparison.OrdinalIgnoreCase);
    }

    private static string? Str(Dictionary<string, JsonElement> r, string key)
    {
        if (!r.TryGetValue(key, out var v)) return null;
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.GetRawText(),
            _ => null,
        };
    }

    private static double? Num(Dictionary<string, JsonElement> r, string key)
    {
        if (!r.TryGetValue(key, out var v)) return null;
        return v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d) ? d : null;
    }
}

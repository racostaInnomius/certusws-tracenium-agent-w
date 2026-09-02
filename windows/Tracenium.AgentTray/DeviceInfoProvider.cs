using Tracenium.AgentTray.Models;

namespace Tracenium.AgentTray;

/// <summary>
/// Builds the "Device Info" field list shown to end users during support
/// calls. Single source of truth shared by the StatusForm tab and the
/// top-center DeviceInfoFlyout so both always display the same fields in
/// the same order — and so "Copy all" produces identical text everywhere.
///
/// Data comes from two places:
///   * tray-status.json `device` block — hardware/network identity the
///     agent (SYSTEM service) collected via systeminformation.
///   * This process — logged-in user and screen resolution, which the
///     user-session tray knows better than the session-0 service.
/// </summary>
internal static class DeviceInfoProvider
{
    internal readonly record struct Field(string Label, string Value);

    public static List<Field> BuildFields(TrayStatus? status)
    {
        var d = status?.Device;

        var osText = JoinNonEmpty(" ", d?.OsName, d?.OsVersion);
        if (!string.IsNullOrWhiteSpace(osText) && !string.IsNullOrWhiteSpace(d?.OsBuild))
        {
            osText = $"{osText} (build {d!.OsBuild})";
        }

        var fields = new List<Field>
        {
            new Field("Logged user", LoggedUser()),
            new Field("Computer name", FirstNonEmpty(d?.Fqdn, d?.Hostname, status?.Hostname, Environment.MachineName)),
            new Field("Domain", FirstNonEmpty(d?.Domain, DomainFromEnvironment())),
            new Field("IP address", FirstNonEmpty(d?.Ipv4, d?.Ipv6)),
            new Field("MAC address", FirstNonEmpty(d?.Mac)),
            new Field("Operating system", FirstNonEmpty(osText)),
            new Field("Model", JoinNonEmpty(" ", d?.Manufacturer, d?.Model) is { Length: > 0 } m ? m : "—"),
            new Field("Serial number", FirstNonEmpty(d?.Serial)),
            new Field("Processor", FirstNonEmpty(d?.Cpu)),
            new Field("Memory", d?.MemoryGb is { } gb ? $"{gb:0.0} GB" : "—"),
            new Field("Screen resolution", ScreenResolution()),
            new Field("Tracenium device ID", FirstNonEmpty(status?.DeviceId))
        };

        // ADR-0013 (A) — solo en un gateway.
        //
        // Condicional a propósito: esta pantalla es el widget de soporte que ve
        // un usuario final, y una huella de 64 caracteres no le dice nada a
        // nadie que no esté configurando el gateway. Enseñarla en toda la flota
        // sería ruido en la única pantalla que existe para reducirlo.
        var fp = status?.Gateway?.CredentialKeyFingerprint;
        if (!string.IsNullOrWhiteSpace(fp))
        {
            fields.Add(new Field("vCenter credential key", fp!));
        }

        return fields;
    }

    /// <summary>Plain-text block the user pastes into a support chat/ticket.</summary>
    public static string BuildCopyText(TrayStatus? status)
    {
        var lines = BuildFields(status)
            .Select(f => $"{f.Label}: {(f.Value == "—" ? "-" : f.Value)}");
        return string.Join(Environment.NewLine, lines);
    }

    private static string LoggedUser()
    {
        var user = Environment.UserName;
        var domain = Environment.UserDomainName;
        // DOMAIN\user reads naturally for domain-joined support flows;
        // for local accounts UserDomainName equals MachineName, which is
        // still the correct Windows way to write it.
        return string.IsNullOrWhiteSpace(domain) ? user : $"{domain}\\{user}";
    }

    private static string? DomainFromEnvironment()
    {
        // Only meaningful when actually domain-joined: for local accounts
        // USERDOMAIN is the machine name, which is NOT a domain — report
        // none instead of misleading support.
        var domain = Environment.UserDomainName;
        if (string.IsNullOrWhiteSpace(domain)) return null;
        return domain.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase) ? null : domain;
    }

    private static string ScreenResolution()
    {
        var bounds = Screen.PrimaryScreen?.Bounds;
        return bounds is { } b ? $"{b.Width} x {b.Height}" : "—";
    }

    private static string FirstNonEmpty(params string?[] candidates)
    {
        foreach (var c in candidates)
        {
            if (!string.IsNullOrWhiteSpace(c)) return c!;
        }
        return "—";
    }

    private static string JoinNonEmpty(string separator, params string?[] parts)
    {
        return string.Join(separator, parts.Where(p => !string.IsNullOrWhiteSpace(p)));
    }
}

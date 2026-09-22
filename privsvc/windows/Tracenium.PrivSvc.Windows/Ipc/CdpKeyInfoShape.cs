// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpKeyInfoShape.cs
//
// Ola 1.3b — lógica PURA de «dónde vive la clave y si se puede exportar»,
// separada de CdpKeyInfo.cs (que habla con crypt32/CNG) para poder
// probarla fuera de Windows, igual que CryptoKeyNames.
//
// El proveedor criptográfico de la clave dice dónde vive, sin abrirla:
//   · Microsoft Platform Crypto Provider → TPM.
//   · Smart Card KSP / Base Smart Card CSP (y minidrivers que se llaman
//     «... Smart Card ...») → tarjeta inteligente.
//   · Los KSP/CSP de software de Microsoft → software.
//   · Cualquier otro (un HSM de un fabricante, Windows Hello/Passport,
//     que puede ir o no sobre TPM) → unknown. Adivinar «software» ahí
//     sería afirmar que una clave de HSM es copiable.

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpKeyInfoShape
{
    public const string Software = "software";
    public const string Tpm = "tpm";
    public const string SmartCard = "smartcard";
    public const string Unknown = "unknown";

    /// <summary>NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG.</summary>
    private const int ExportFlags = 0x1 | 0x2;

    private static readonly HashSet<string> SoftwareProviders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Software Key Storage Provider",
        "Microsoft Enhanced RSA and AES Cryptographic Provider",
        "Microsoft Enhanced Cryptographic Provider v1.0",
        "Microsoft Base Cryptographic Provider v1.0",
        "Microsoft Strong Cryptographic Provider",
        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft DH SChannel Cryptographic Provider",
        "Microsoft RSA SChannel Cryptographic Provider"
    };

    public static string StorageFor(string? providerName)
    {
        if (string.IsNullOrWhiteSpace(providerName)) return Unknown;
        var p = providerName.Trim();
        if (p.Equals("Microsoft Platform Crypto Provider", StringComparison.OrdinalIgnoreCase)) return Tpm;
        if (p.Contains("Smart Card", StringComparison.OrdinalIgnoreCase)) return SmartCard;
        if (SoftwareProviders.Contains(p)) return Software;
        return Unknown;
    }

    /// <summary>
    /// La política de exportación de CNG (`NCRYPT_EXPORT_POLICY_PROPERTY`).
    /// Los bits de ARCHIVADO (0x4/0x8) solo valen en el momento de crear la
    /// clave, así que no la hacen exportable después.
    /// </summary>
    public static bool ExportableFromCngPolicy(int policy) => (policy & ExportFlags) != 0;

    /// <summary>TPM y tarjeta no exportan por diseño: no hace falta abrir la clave para saberlo.</summary>
    public static bool? ExportableByStorage(string storage) =>
        storage == Tpm || storage == SmartCard ? false : null;
}

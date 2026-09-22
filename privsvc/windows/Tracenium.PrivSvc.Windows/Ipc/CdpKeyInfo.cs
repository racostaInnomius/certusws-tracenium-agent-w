// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpKeyInfo.cs
//
// Ola 1.3b — exportabilidad y almacenamiento de la clave privada de un
// certificado de LocalMachine, SIN exportarla.
//
// ── Cómo, y por qué así ──────────────────────────────────────────────
//
// 1. `CERT_KEY_PROV_INFO_PROP_ID` es una PROPIEDAD del certificado en el
//    almacén: nombre del contenedor, proveedor y tipo. Leerla no abre la
//    clave. El proveedor dice dónde vive (CdpKeyInfoShape.StorageFor).
// 2. TPM y tarjeta: no exportables por diseño, y NO se abren. Abrir una
//    clave de tarjeta desde un servicio puede bloquear esperando al
//    lector — el mismo motivo por el que HasPrivateKey tiene presupuesto.
// 3. Software: se abre el contenedor en modo silencioso y se lee su
//    POLÍTICA de exportación (CNG: `ExportPolicy`; CAPI:
//    `CspKeyContainerInfo.Exportable`). Nunca se llama a Export*: saber
//    si se podría no exige hacerlo.
//
// Cualquier fallo → (null, unknown). Un dato que no se pudo leer no es
// «no exportable».

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpKeyInfo
{
    private const uint CERT_KEY_PROV_INFO_PROP_ID = 2;
    /// <summary>CRYPT_MACHINE_KEYSET (CAPI) y NCRYPT_MACHINE_KEY_FLAG (CNG) comparten el bit.</summary>
    private const uint MACHINE_KEYSET = 0x20;

    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_KEY_PROV_INFO
    {
        public IntPtr pwszContainerName;
        public IntPtr pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern bool CertGetCertificateContextProperty(
        IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData);

    public static (bool? exportable, string storage) Read(X509Certificate2 cert)
    {
        try
        {
            uint size = 0;
            if (!CertGetCertificateContextProperty(cert.Handle, CERT_KEY_PROV_INFO_PROP_ID, IntPtr.Zero, ref size) || size == 0)
            {
                return (null, CdpKeyInfoShape.Unknown);
            }

            var buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (!CertGetCertificateContextProperty(cert.Handle, CERT_KEY_PROV_INFO_PROP_ID, buf, ref size))
                {
                    return (null, CdpKeyInfoShape.Unknown);
                }
                var info = Marshal.PtrToStructure<CRYPT_KEY_PROV_INFO>(buf);
                var container = Marshal.PtrToStringUni(info.pwszContainerName);
                var provider = Marshal.PtrToStringUni(info.pwszProvName);

                var storage = CdpKeyInfoShape.StorageFor(provider);
                var byStorage = CdpKeyInfoShape.ExportableByStorage(storage);
                if (byStorage.HasValue) return (byStorage, storage);

                var machine = (info.dwFlags & MACHINE_KEYSET) != 0;
                return (ReadExportPolicy(container, provider, info.dwProvType, machine), storage);
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch
        {
            return (null, CdpKeyInfoShape.Unknown);
        }
    }

    private static bool? ReadExportPolicy(string? container, string? provider, uint provType, bool machine)
    {
        if (string.IsNullOrEmpty(container) || string.IsNullOrEmpty(provider)) return null;
        try
        {
            if (provType == 0)
            {
                // dwProvType 0 = clave CNG (KSP).
                var opts = CngKeyOpenOptions.Silent | (machine ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None);
                using var key = CngKey.Open(container, new CngProvider(provider), opts);
                return CdpKeyInfoShape.ExportableFromCngPolicy((int)key.ExportPolicy);
            }

            // CAPI (CSP heredado).
            var csp = new CspParameters((int)provType, provider, container)
            {
                Flags = CspProviderFlags.UseExistingKey | CspProviderFlags.NoPrompt |
                        (machine ? CspProviderFlags.UseMachineKeyStore : CspProviderFlags.NoFlags)
            };
            return new CspKeyContainerInfo(csp).Exportable;
        }
        catch
        {
            return null;
        }
    }
}

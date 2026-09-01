// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpKeys.cs
//
// ADR-0011 FASE 2 — `cdp.csr.generate` parametrizado, con almacen de
// clave SEPARADO y ciclo de vida completo (decision 9).
//
// Gemelo de `privsvc/macos/src/cdp-keys.ts` y `privsvc/linux/src/cdp-keys.ts`.
// Se mantienen paralelos a proposito: tres implementaciones de la misma
// regla que divergen son peores que una sola, porque nadie sabe cual
// manda. El CONTRATO —validacion del keyId, prefijo reservado, registro,
// destruccion en el mismo camino de codigo— es identico; solo cambia
// donde vive la clave.
//
// ── Por que un metodo NUEVO ────────────────────────────────────────
//
// La correccion medida de ADR-0004 (2026-08-13) desmonta la premisa de
// que generalizar el CSR fuera «cableado»: `crypto.csr.generate` esta
// atado a la identidad mTLS del propio agente.
//
// ⚠️ Y aqui hay un agujero REAL que este fichero viene a cerrar. En
// `CryptoCsr.cs:39` el `keyName` llega DEL LLAMANTE y no se valida:
//
//     string? requestedKeyName = GetString(p, "keyName");
//     string keyName = string.IsNullOrWhiteSpace(requestedKeyName)
//         ? $"tracenium-{deviceId}" : requestedKeyName;
//
// Una peticion con `keyName = "tracenium-<deviceId>"` y
// `reuseExistingKey: false` entra por `OpenOrCreateMachineRsaKey`, que
// hace `existingKey.Delete()` y recrea. Eso BORRA la clave privada de la
// identidad mTLS del agente: el equipo deja de poder hablar con el
// control plane y no hay forma remota de arreglarlo — es una visita
// presencial. Multiplicado por la flota, es la caida que la correccion
// de ADR-0004 describe.
//
// Aqui el llamante NO nombra nada: entrega un `keyId` opaco y este
// fichero DERIVA el nombre CNG con un prefijo reservado. Lo que se usa
// nunca es lo que mando.

using System.Formats.Asn1;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpKeys
{
    /// <summary>Prefijo reservado. El enrolamiento usa `tracenium-{deviceId}`, sin `cdp-`.</summary>
    private const string KeyPrefix = "tracenium-cdp-";

    private const int RsaKeyBits = 2048;

    /// <summary>
    /// `keyId` aceptable. Identico al de macOS y Linux a proposito.
    ///
    /// Deliberadamente estrecho: sin separadores de ruta, sin `..`, sin
    /// espacios, con tope de longitud. Minusculas porque los nombres de
    /// clave CNG no distinguen la caja de forma fiable, y dos `keyId`
    /// que solo difirieran en mayusculas serian dos claves en macOS y
    /// una aqui — una divergencia silenciosa entre sistemas operativos.
    /// </summary>
    private static readonly Regex KeyIdRe = new(@"^[a-z0-9][a-z0-9._-]{0,63}$", RegexOptions.Compiled);

    public static bool IsValidKeyId(string? keyId)
    {
        if (string.IsNullOrEmpty(keyId)) return false;
        if (keyId.Contains("..", StringComparison.Ordinal)) return false;
        return KeyIdRe.IsMatch(keyId);
    }

    /// <summary>Nombre CNG derivado. El llamante NUNCA lo elige.</summary>
    public static string CdpKeyName(string keyId)
    {
        if (!IsValidKeyId(keyId)) throw new ArgumentException("invalid_key_id");
        return KeyPrefix + keyId;
    }

    /// <summary>
    /// Ultima linea: que lo derivado no sea la identidad del agente.
    ///
    /// La derivacion ya lo impide —el enrolamiento no lleva el prefijo—,
    /// pero esta es la clase de invariante que conviene que falle
    /// ruidosamente el dia que alguien toque el prefijo.
    /// </summary>
    public static void AssertNotEnrollmentKey(string keyName, string? deviceId)
    {
        if (!keyName.StartsWith(KeyPrefix, StringComparison.Ordinal))
            throw new InvalidOperationException("refuses_to_touch_enrollment_key");
        if (!string.IsNullOrWhiteSpace(deviceId) &&
            string.Equals(keyName, $"tracenium-{deviceId}", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("refuses_to_touch_enrollment_key");
    }

    /// <summary>Los atributos de sujeto admitidos. Los mismos que macOS y Linux.</summary>
    private static readonly HashSet<string> SubjectAttrs =
        new(StringComparer.OrdinalIgnoreCase) { "CN", "O", "OU" };

    /// <summary>
    /// Comprueba el sujeto y lo devuelve normalizado.
    ///
    /// ⚠️ Existe por paridad, y la paridad aqui no es estetica. En las
    /// otras dos plataformas se midio que un atributo desconocido NO
    /// hace fallar a openssl: avisa y lo DESCARTA, emitiendo un CSR sin
    /// el. Si Windows aceptara lo que alli se rechaza —o al reves—, la
    /// misma peticion produciria certificados distintos segun el sistema
    /// operativo del endpoint, que es la divergencia que el ADR dice que
    /// no puede haber.
    /// </summary>
    public static string ValidateSubject(string subject)
    {
        var partes = subject.StartsWith("/", StringComparison.Ordinal)
            ? subject.Substring(1).Split('/')
            : subject.Split(',');

        var salida = new List<string>();
        foreach (var parte in partes)
        {
            var trozo = parte.Trim();
            if (trozo.Length == 0) continue;
            var i = trozo.IndexOf('=');
            if (i <= 0) throw new ArgumentException($"componente de subject invalido: {trozo}");
            var clave = trozo.Substring(0, i).Trim().ToUpperInvariant();
            var valor = trozo.Substring(i + 1).Trim();
            if (!SubjectAttrs.Contains(clave))
                throw new ArgumentException($"atributo de subject no soportado: {clave} (solo CN, O, OU)");
            if (valor.Length == 0)
                throw new ArgumentException($"atributo de subject sin valor: {clave}");
            salida.Add($"{clave}={valor}");
        }
        if (salida.Count == 0) throw new ArgumentException("subject vacio");
        return string.Join(",", salida);
    }

    // ── Registro: desde cuando y por que ───────────────────────────
    //
    // CNG sabe si una clave con un nombre existe (`CngKey.Exists`) pero
    // NO se puede enumerar por prefijo sin bajar a P/Invoke sobre
    // NCryptEnumKeys. Por eso el registro es aqui mas necesario que en
    // las otras dos plataformas.
    //
    // ⚠️ El registro se escribe ANTES de crear la clave, asi que es un
    // SUPERCONJUNTO: puede sobrar una entrada (intencion que no llego a
    // nada) pero nunca puede faltar una clave. La lista cruza cada
    // entrada contra `CngKey.Exists`, asi que el registro no puede
    // inventar claves — y la entrada sobrante se limpia sola.

    public sealed class LedgerEntry
    {
        public string keyId { get; set; } = "";
        public string subject { get; set; } = "";
        public string createdAt { get; set; } = "";
        public string? requestId { get; set; }
        public string? certInstalledAt { get; set; }
    }

    private static string LedgerDir()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Tracenium", "cdp-keys");
        Directory.CreateDirectory(dir);
        HardenDirectory(dir);
        return dir;
    }

    private static string LedgerPath() => Path.Combine(LedgerDir(), "ledger.json");

    /// <summary>SYSTEM + Administradores. Mismo endurecimiento que el credential store.</summary>
    private static void HardenDirectory(string dir)
    {
        try
        {
            var info = new DirectoryInfo(dir);
            var sec = info.GetAccessControl();
            // ProgramData concede lectura a Users por defecto, que es
            // exactamente lo que un directorio de claves no puede tener.
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)))
                sec.RemoveAccessRule(rule);
            foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            {
                sec.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(sid, null),
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
            }
            info.SetAccessControl(sec);
        }
        catch
        {
            // Un fallo de endurecimiento no puede dejar el servicio
            // inservible: aqui solo hay metadatos, la clave la guarda el
            // KSP y no es exportable.
        }
    }

    public static Dictionary<string, LedgerEntry> ReadLedger()
    {
        try
        {
            var json = File.ReadAllText(LedgerPath());
            return JsonSerializer.Deserialize<Dictionary<string, LedgerEntry>>(json)
                   ?? new Dictionary<string, LedgerEntry>();
        }
        catch
        {
            // Un registro ilegible no puede costar la operacion: es
            // metadato, la verdad la tiene el KSP.
            return new Dictionary<string, LedgerEntry>();
        }
    }

    private static void WriteLedger(Dictionary<string, LedgerEntry> data)
    {
        try
        {
            var tmp = LedgerPath() + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(tmp, LedgerPath(), overwrite: true);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[PrivSvc][CdpKeys] no se pudo persistir el registro: {ex.Message}");
        }
    }

    public static void RecordKey(LedgerEntry entry)
    {
        var l = ReadLedger();
        l[entry.keyId] = entry;
        WriteLedger(l);
    }

    public static void ForgetKey(string keyId)
    {
        var l = ReadLedger();
        if (l.Remove(keyId)) WriteLedger(l);
    }

    /// <summary>El certificado llego: la clave deja de ser huerfana.</summary>
    public static void MarkCertInstalled(string keyId, string? whenIso = null)
    {
        var l = ReadLedger();
        if (!l.TryGetValue(keyId, out var e)) return;
        e.certInstalledAt = whenIso ?? DateTime.UtcNow.ToString("o");
        WriteLedger(l);
    }

    // ── Clave CNG ──────────────────────────────────────────────────

    private static bool KeyExists(string keyName) =>
        CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey);

    /// <summary>
    /// Crea la clave, NO exportable.
    ///
    /// `ExportPolicy = None` es la propiedad entera de la decision 9.b:
    /// si la clave no se puede extraer, una huerfana es un hueco
    /// desperdiciado y no una fuga.
    ///
    /// ⚠️ NO hay rama de reutilizacion, a diferencia del de
    /// enrolamiento. Ahi reutilizar tiene sentido —hay UNA identidad por
    /// equipo y sobrevive a las rotaciones—; aqui cada emision es una
    /// clave nueva, y «abrir la que ya habia» seria firmar un CSR con
    /// material de otra peticion.
    /// </summary>
    private static RSA CreateMachineRsaKey(string keyName)
    {
        var creationParams = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing,
            KeyCreationOptions = CngKeyCreationOptions.MachineKey
        };
        creationParams.Parameters.Add(
            new CngProperty("Length", BitConverter.GetBytes(RsaKeyBits), CngPropertyOptions.None));
        return new RSACng(CngKey.Create(CngAlgorithm.Rsa, keyName, creationParams));
    }

    private static bool DeleteMachineKey(string keyName)
    {
        try
        {
            if (!KeyExists(keyName)) return false;
            using var key = CngKey.Open(
                keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey);
            key.Delete();
            return true;
        }
        catch
        {
            return false;
        }
    }

    // ── Handlers IPC ───────────────────────────────────────────────

    /// <summary>
    /// `cdp.csr.generate`.
    ///
    /// ⚠️ Decision 9.c: la destruccion va en el MISMO camino de codigo
    /// que la creacion. Si algo falla despues de crear la clave, se
    /// borra aqui antes de responder — un manejador aparte es lo que
    /// alguien se olvida de cablear.
    /// </summary>
    public static Task<PrivSvcResponse> HandleCsrGenerate(PrivSvcRequest req)
    {
        var p = req.Params ?? new Dictionary<string, object>();
        var keyId = GetString(p, "keyId") ?? "";

        if (!IsValidKeyId(keyId))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request",
                "keyId invalido (min: [a-z0-9][a-z0-9._-]{0,63})"));

        var subjectIn = (GetString(p, "subject") ?? "").Trim();
        if (string.IsNullOrWhiteSpace(subjectIn))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "subject requerido"));
        string subject;
        try
        {
            subject = ValidateSubject(subjectIn);
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", ex.Message));
        }

        var ekuIn = GetString(p, "eku") ?? "clientAuth";
        string ekuOid = ekuIn switch
        {
            "clientAuth" => "1.3.6.1.5.5.7.3.2",
            "serverAuth" => "1.3.6.1.5.5.7.3.1",
            _ => ""
        };
        if (ekuOid.Length == 0)
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request",
                $"eku no soportado: {ekuIn} (clientAuth|serverAuth)"));

        var keyAlgorithm = (GetString(p, "keyAlgorithm") ?? "RSA_2048").ToUpperInvariant();
        if (keyAlgorithm != "RSA_2048")
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request",
                $"keyAlgorithm no soportado: {keyAlgorithm}"));

        var dnsNames = GetStringList(p, "dnsNames");
        var uris = GetStringList(p, "uris");

        string keyName;
        try
        {
            keyName = CdpKeyName(keyId);
            AssertNotEnrollmentKey(keyName, GetString(p, "deviceId") ?? req.Meta?.DeviceId);
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", ex.Message));
        }

        if (KeyExists(keyName))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "key_exists",
                $"ya existe una clave para keyId {keyId}"));

        // Registro ANTES de crear: asi el registro es un superconjunto y
        // ninguna clave puede quedar invisible en el inventario. En
        // Windows importa mas que en las otras dos, porque aqui no se
        // puede enumerar el KSP por prefijo.
        RecordKey(new LedgerEntry
        {
            keyId = keyId,
            subject = subject,
            createdAt = DateTime.UtcNow.ToString("o"),
            requestId = GetString(p, "requestId"),
            certInstalledAt = null
        });

        RSA? rsa = null;
        var creada = false;
        try
        {
            rsa = CreateMachineRsaKey(keyName);
            creada = true;

            var csr = new CertificateRequest(
                new X500DistinguishedName(subject),
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            csr.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));

            var ekus = new OidCollection { new Oid(ekuOid) };
            csr.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(ekus, critical: false));

            if (dnsNames.Count > 0 || uris.Count > 0)
            {
                var san = new SubjectAlternativeNameBuilder();
                foreach (var d in dnsNames) san.AddDnsName(d);
                foreach (var u in uris) san.AddUri(new Uri(u));
                csr.CertificateExtensions.Add(san.Build(critical: false));
            }

            var csrPem = PemEncode("CERTIFICATE REQUEST", csr.CreateSigningRequest());

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                keyId,
                csrPem,
                keyAlgorithm = "RSA_2048",
                // Se DECLARA el almacen. Es lo que permite comprobar que
                // la clave no es exportable sin creerse la documentacion.
                keyStore = "cng-nonexportable"
            }));
        }
        catch (Exception ex)
        {
            if (creada) DeleteMachineKey(keyName);
            ForgetKey(keyId);
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "csr_failed", ex.Message));
        }
        finally
        {
            rsa?.Dispose();
        }
    }

    /// <summary>
    /// `cdp.key.destroy` — la ejecuta el AGENTE, no el control plane
    /// (decision 9.c): el control plane puede ser el adversario, puede
    /// estar caido, y no tiene acceso al almacen de claves.
    /// </summary>
    public static Task<PrivSvcResponse> HandleKeyDestroy(PrivSvcRequest req)
    {
        var keyId = GetString(req.Params ?? new(), "keyId") ?? "";
        if (!IsValidKeyId(keyId))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", "keyId invalido"));

        string keyName;
        try
        {
            keyName = CdpKeyName(keyId);
            AssertNotEnrollmentKey(keyName, req.Meta?.DeviceId);
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "bad_request", ex.Message));
        }

        var borrada = DeleteMachineKey(keyName);
        ForgetKey(keyId);

        // Se VERIFICA. «No lanzo» no es lo mismo que «ya no esta», y la
        // destruccion es una fase obligatoria del ciclo, no una limpieza
        // optimista.
        if (KeyExists(keyName))
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "key_delete_incomplete",
                "la clave sigue en el KSP tras el borrado"));

        return Task.FromResult(PrivSvcResponse.Success(req.Id, new { keyId, destroyed = borrada ? 1 : 0 }));
    }

    /// <summary>
    /// `cdp.key.list` — decision 9.d.
    ///
    /// El respaldo no puede ser solo un cron: un respaldo que nadie mira
    /// se pudre, y entonces el diseño PARECE completo mientras el
    /// residuo se acumula en silencio (`purge_after` en este mismo
    /// repositorio). Esto es lo que hace que una huerfana aparezca en el
    /// panel.
    ///
    /// ⚠️ Cada entrada se cruza contra `CngKey.Exists`: el registro no
    /// puede inventar claves. Y la entrada que sobra se limpia sola, que
    /// es lo que impide que este inventario se pudra a su vez.
    /// </summary>
    public static Task<PrivSvcResponse> HandleKeyList(PrivSvcRequest req)
    {
        var ledger = ReadLedger();
        var ahora = DateTime.UtcNow;
        var keys = new List<object>();
        var huerfanasDelRegistro = new List<string>();

        foreach (var (keyId, e) in ledger)
        {
            if (!IsValidKeyId(keyId) || !KeyExists(CdpKeyName(keyId)))
            {
                huerfanasDelRegistro.Add(keyId);
                continue;
            }
            int? ageDays = DateTime.TryParse(e.createdAt, out var creada)
                ? (int)(ahora - creada.ToUniversalTime()).TotalDays
                : null;
            keys.Add(new
            {
                keyId,
                subject = e.subject,
                createdAt = e.createdAt,
                requestId = e.requestId,
                certInstalledAt = e.certInstalledAt,
                orphan = string.IsNullOrEmpty(e.certInstalledAt),
                ageDays
            });
        }

        foreach (var k in huerfanasDelRegistro) ForgetKey(k);

        return Task.FromResult(PrivSvcResponse.Success(req.Id, new { keys, count = keys.Count }));
    }

    // ── Helpers ────────────────────────────────────────────────────

    private static string PemEncode(string label, byte[] der)
    {
        var b64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
        return $"-----BEGIN {label}-----\n{b64}\n-----END {label}-----\n";
    }

    private static string? GetString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var val) || val == null) return null;
        if (val is string s) return s;
        if (val is JsonElement je)
            return je.ValueKind == JsonValueKind.String ? je.GetString() : je.ToString();
        return val.ToString();
    }

    private static List<string> GetStringList(Dictionary<string, object> p, string key)
    {
        var outp = new List<string>();
        if (!p.TryGetValue(key, out var val) || val == null) return outp;
        if (val is JsonElement je && je.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in je.EnumerateArray())
            {
                var s = item.ValueKind == JsonValueKind.String ? item.GetString() : item.ToString();
                if (!string.IsNullOrWhiteSpace(s)) outp.Add(s!);
            }
            return outp;
        }
        if (val is IEnumerable<object> lista)
        {
            foreach (var item in lista)
            {
                var s = item?.ToString();
                if (!string.IsNullOrWhiteSpace(s)) outp.Add(s!);
            }
        }
        return outp;
    }
}

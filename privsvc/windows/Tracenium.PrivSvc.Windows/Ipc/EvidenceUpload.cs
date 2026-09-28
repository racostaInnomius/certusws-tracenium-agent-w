// Ipc/EvidenceUpload.cs
//
// ADR-0032 D3 — pide al control plane el destino de subida de un artefacto de
// evidencia, presentando el CERTIFICADO DEL EQUIPO.
//
// Por que vive aqui y no en AgentCore: el proceso de Node no puede hablar mTLS.
// En Windows la clave del certificado de cliente es del almacen de la maquina y
// no es extraible (ADR-0011/0015); quien la usa es este servicio. AgentCore
// recoge y sube, pero la llave de escritura tiene que pedirla alguien que pueda
// demostrar quien es.
//
// ⚠️ ESTE METODO NO ES "HAZ UNA PETICION HTTPS CON MI CERTIFICADO". Esa
// primitiva generica seria un regalo para cualquier cosa que consiguiera
// hablar por el pipe: podria autenticarse como el equipo contra cualquier ruta
// del control plane. Aqui:
//
//   · la RUTA la compone este fichero, no el llamante;
//   · el deviceId sale del puente gRPC (lo que el backend ya sabe de nosotros),
//     nunca de los parametros;
//   · captureId tiene que ser un UUID y el nombre del artefacto, un nombre de
//     fichero simple — sin separadores ni "..";
//   · la base tiene que ser un origen https limpio, sin ruta, sin credenciales
//     y sin puerto raro.
//
// Lo unico que el llamante elige es el HOST del control plane, y eso es
// deliberado: REST y gRPC viven en hosts distintos segun el entorno
// (produccion y pre-produccion no coinciden), asi que fijarlo aqui romperia
// pre-produccion. Un host falso solo consigue ver el saludo TLS y el nombre del
// artefacto; la clave privada no sale, y una sesion mTLS no se puede reusar
// contra otro servidor.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class EvidenceUpload
{
    /// <summary>Cuanto se espera al control plane. Es una peticion diminuta.</summary>
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(30);

    private static readonly Regex UuidRe = new(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        RegexOptions.Compiled);

    // El mismo nombre que acepta el backend (evidence-collectors.ts): letras,
    // digitos, punto, guion y guion bajo. Sin separadores de ruta.
    private static readonly Regex ArtifactNameRe = new(
        "^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$",
        RegexOptions.Compiled);

    private static readonly object ClientLock = new();
    private static HttpClient? _client;
    private static string? _clientThumbprint;

    /// <summary>
    /// Cliente con el certificado del equipo y validacion de servidor NORMAL.
    ///
    /// ⚠️ A diferencia del cliente del DP (Sdp.cs), aqui NO se desactiva la
    /// validacion del certificado del servidor. Alli se podia porque el hash
    /// del binario descargado manda sobre el transporte; aqui lo que viaja de
    /// vuelta es una llave de escritura, y aceptar cualquier servidor seria
    /// entregarsela a quien se ponga en medio.
    ///
    /// Se recrea si el equipo rota su certificado (cambia la huella).
    /// </summary>
    private static HttpClient? GetClient()
    {
        var thumbprint = GrpcBridgeSingleton.Instance.ClientCertThumbprint;
        if (string.IsNullOrWhiteSpace(thumbprint)) return null;

        lock (ClientLock)
        {
            if (_client is not null && string.Equals(_clientThumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                return _client;
            }

            try
            {
                using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadOnly);
                var normalized = new string(thumbprint.Where(char.IsLetterOrDigit).ToArray()).ToUpperInvariant();
                var matches = store.Certificates.Find(X509FindType.FindByThumbprint, normalized, validOnly: false);
                if (matches.Count == 0) return null;
                var clientCert = matches[0];
                if (!clientCert.HasPrivateKey) return null;

                var handler = new SocketsHttpHandler
                {
                    ConnectTimeout = TimeSpan.FromSeconds(10),
                    SslOptions = new SslClientAuthenticationOptions
                    {
                        ClientCertificates = new X509Certificate2Collection(clientCert),
                    },
                };

                _client?.Dispose();
                _client = new HttpClient(handler) { Timeout = RequestTimeout };
                _clientThumbprint = thumbprint;
                return _client;
            }
            catch
            {
                _client = null;
                _clientThumbprint = null;
                return null;
            }
        }
    }

    private static string? Param(PrivSvcRequest req, string name)
    {
        if (req.Params is null) return null;
        if (!req.Params.TryGetValue(name, out var raw) || raw is null) return null;
        var value = raw is JsonElement je ? (je.ValueKind == JsonValueKind.String ? je.GetString() : je.ToString()) : raw.ToString();
        return string.IsNullOrWhiteSpace(value) ? null : value!.Trim();
    }

    /// <summary>
    /// Valida la base del control plane: origen https limpio. Devuelve null si
    /// no lo es, con lo que el metodo contesta un error legible en vez de
    /// intentar una peticion a cualquier cosa.
    /// </summary>
    internal static Uri? ParseBaseUrl(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri)) return null;
        if (!string.Equals(uri.Scheme, "https", StringComparison.OrdinalIgnoreCase)) return null;
        if (!string.IsNullOrEmpty(uri.UserInfo)) return null;
        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment)) return null;
        // Sin ruta: la ruta la componemos nosotros. "/" es lo unico que se tolera.
        if (!string.IsNullOrEmpty(uri.AbsolutePath) && uri.AbsolutePath != "/") return null;
        return uri;
    }

    /// <summary>
    /// La ruta del control plane, compuesta AQUI. El llamante no la elige.
    /// </summary>
    internal static string BuildPath(string deviceId, string captureId)
        => $"/api/v1/security/devices/{Uri.EscapeDataString(deviceId)}/evidence/{Uri.EscapeDataString(captureId)}/upload-url";

    public static async Task<PrivSvcResponse> HandleAsync(PrivSvcRequest req)
    {
        var captureId = Param(req, "captureId");
        var name = Param(req, "name");
        var baseUrl = ParseBaseUrl(Param(req, "baseUrl"));

        if (captureId is null || !UuidRe.IsMatch(captureId))
        {
            return PrivSvcResponse.Fail(req.Id, "invalid_params", "captureId must be a uuid");
        }
        if (name is null || !ArtifactNameRe.IsMatch(name) || name.Contains(".."))
        {
            return PrivSvcResponse.Fail(req.Id, "invalid_params", "name must be a simple file name");
        }
        if (baseUrl is null)
        {
            return PrivSvcResponse.Fail(req.Id, "invalid_params", "baseUrl must be an https origin with no path");
        }

        // El equipo lo dice el puente, no los parametros: pedir el destino de
        // OTRO equipo no es un caso de uso, es un intento.
        var deviceId = GrpcBridgeSingleton.Instance.DeviceId;
        if (string.IsNullOrWhiteSpace(deviceId))
        {
            return PrivSvcResponse.Fail(req.Id, "not_enrolled", "this device has no enrolled identity yet");
        }

        var client = GetClient();
        if (client is null)
        {
            return PrivSvcResponse.Fail(req.Id, "no_client_certificate", "the device certificate is not usable for mTLS");
        }

        var url = new Uri(baseUrl, BuildPath(deviceId!, captureId));
        var body = JsonSerializer.Serialize(new { name });

        try
        {
            using var content = new StringContent(body, Encoding.UTF8, "application/json");
            using var cts = new CancellationTokenSource(RequestTimeout);
            using var res = await client.PostAsync(url, content, cts.Token).ConfigureAwait(false);
            var text = await res.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);

            if (!res.IsSuccessStatusCode)
            {
                // El motivo del backend viaja tal cual (CAPTURE_CLOSED,
                // CAPTURE_NOT_FOUND…): AgentCore lo escribe en el manifiesto y
                // acaba explicando en el informe por que falto un artefacto.
                var reason = ExtractError(text) ?? $"http_{(int)res.StatusCode}";
                return PrivSvcResponse.Fail(req.Id, "upload_url_refused", reason);
            }

            var uploadUrl = ExtractString(text, "uploadUrl");
            if (string.IsNullOrWhiteSpace(uploadUrl))
            {
                return PrivSvcResponse.Fail(req.Id, "upload_url_missing", "the control plane returned no upload url");
            }

            // ⚠️ La URL NO se registra: es una llave de escritura. Se dice que
            // hubo destino y para que artefacto, nada mas.
            IpcLog.Write($"[evidence] destino de subida concedido capture={captureId} artifact={name}");

            return PrivSvcResponse.Success(req.Id, new
            {
                uploadUrl,
                expiresAtUtc = ExtractString(text, "expiresAtUtc") ?? "",
            });
        }
        catch (OperationCanceledException)
        {
            return PrivSvcResponse.Fail(req.Id, "timeout", "the control plane did not answer in time");
        }
        catch (Exception ex)
        {
            return PrivSvcResponse.Fail(req.Id, "request_failed", ex.Message);
        }
    }

    private static string? ExtractString(string json, string property)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty(property, out var el) && el.ValueKind == JsonValueKind.String
                ? el.GetString()
                : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? ExtractError(string json)
    {
        var error = ExtractString(json, "error");
        var message = ExtractString(json, "message");
        if (error is null && message is null) return null;
        return message is null ? error : (error is null ? message : $"{error}: {message}");
    }
}

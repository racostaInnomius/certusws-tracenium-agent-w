// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/AcmeHttp01.cs
//
// ADR-0033 F2b — `cdp.acme.http01`: publicar y retirar el desafío HTTP-01 en
// el webroot de IIS (o de otro servidor que el administrador declare).
//
//   params: { action: "publish" | "remove", webroot, token, keyAuthorization? }
//
// Las reglas de forma están en AcmeHttp01Shape (probadas en cualquier
// plataforma). Aquí va lo que sólo puede hacerse contra el disco:
//
//   · el webroot tiene que EXISTIR y ser un directorio;
//   · ningún tramo de la ruta —webroot, `.well-known`, `acme-challenge`, el
//     fichero— puede ser un punto de reanálisis (enlace simbólico o
//     junction): por ahí una ruta permitida acabaría escribiendo en otra;
//   · retirar sólo borra un FICHERO normal con ese nombre, nunca un directorio.

using System.Text;
using System.Text.Json;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class AcmeHttp01
{
    /// <summary>Raíces extra que declara el administrador del equipo (no el control plane).</summary>
    public static string ExtraRootsFile() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Tracenium", "PrivSvc", "acme-webroots.txt");

    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        var p = req.Params ?? new Dictionary<string, object>();
        var action = GetString(p, "action") ?? "";
        var token = GetString(p, "token") ?? "";
        if (action != "publish" && action != "remove")
            return Fail(req, "bad_request", "action must be publish or remove");
        if (!AcmeHttp01Shape.IsValidToken(token))
            return Fail(req, "bad_request", "token invalido");

        var keyAuthorization = GetString(p, "keyAuthorization");
        if (action == "publish" && !AcmeHttp01Shape.IsValidKeyAuthorization(token, keyAuthorization))
            return Fail(req, "bad_request", "keyAuthorization invalido (se espera token.huella)");

        var webroot = AcmeHttp01Shape.NormalizeWebroot(GetString(p, "webroot"));
        if (webroot == null)
            return Fail(req, "bad_request", "webroot debe ser una ruta absoluta local");

        var roots = AcmeHttp01Shape.DefaultRoots(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:");
        try
        {
            var extra = ExtraRootsFile();
            if (File.Exists(extra)) roots.AddRange(AcmeHttp01Shape.ParseExtraRoots(File.ReadAllText(extra)));
        }
        catch
        {
            // Un fichero ilegible no amplía nada: se queda con las raíces por defecto.
        }
        if (!AcmeHttp01Shape.IsUnderAllowedRoot(webroot, roots))
            return Fail(req, "webroot_not_allowed",
                $"{webroot} no esta bajo una raiz permitida; el administrador puede añadirla en {ExtraRootsFile()}");

        if (!Directory.Exists(webroot))
            return Fail(req, "webroot_missing", $"{webroot} no existe");

        var dir = AcmeHttp01Shape.ChallengeDir(webroot);
        var file = Path.Combine(dir, token);
        try
        {
            if (IsReparse(webroot)) return Fail(req, "webroot_is_link", "el webroot es un enlace; no se sigue");

            if (action == "remove")
            {
                if (File.Exists(file) && !IsReparse(file)) File.Delete(file);
                return Task.FromResult(PrivSvcResponse.Success(req.Id, new { removed = true, path = file }));
            }

            var wellKnown = Path.Combine(webroot, ".well-known");
            foreach (var d in new[] { wellKnown, dir })
            {
                if (Directory.Exists(d))
                {
                    if (IsReparse(d)) return Fail(req, "path_is_link", $"{d} es un enlace; no se sigue");
                }
                else
                {
                    Directory.CreateDirectory(d);
                }
            }
            if (File.Exists(file) && IsReparse(file)) return Fail(req, "path_is_link", $"{file} es un enlace; no se sigue");

            File.WriteAllText(file, keyAuthorization!, new UTF8Encoding(false));
            // Se relee: «no lanzó» no es «está publicado».
            if (File.ReadAllText(file) != keyAuthorization)
                return Fail(req, "write_mismatch", "el fichero publicado no contiene lo esperado");
            return Task.FromResult(PrivSvcResponse.Success(req.Id, new { published = true, path = file }));
        }
        catch (Exception ex)
        {
            return Fail(req, "io_error", ex.Message);
        }
    }

    private static bool IsReparse(string path) =>
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) == FileAttributes.ReparsePoint;

    private static Task<PrivSvcResponse> Fail(PrivSvcRequest req, string code, string message) =>
        Task.FromResult(PrivSvcResponse.Fail(req.Id, code, message));

    private static string? GetString(Dictionary<string, object> p, string key)
    {
        if (!p.TryGetValue(key, out var val) || val == null) return null;
        if (val is string s) return s;
        if (val is JsonElement je)
            return je.ValueKind == JsonValueKind.String ? je.GetString() : je.ToString();
        return val.ToString();
    }
}

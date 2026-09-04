// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpAdcs.cs
//
// Conector AD CS (fase 4 del analisis de madurez de CDP, 2026-09).
//
// Un servidor con el rol Certification Authority tiene en su base de
// datos TODO lo que ha emitido — tambien lo que nunca se instalo en un
// equipo con agente, y la PLANTILLA con la que se emitio, que es donde de
// verdad se migra una PKI Windows a post-cuantico. Nada de eso se ve
// desde los almacenes de certificados de los equipos.
//
// ── Que hace este handler ────────────────────────────────────────────
//
// 1. Comprueba si ESTE equipo es una CA (clave `Active` de CertSvc en el
//    registro). Si no lo es, lo dice y no ejecuta nada.
// 2. Ejecuta `certutil -view -csv` acotado por RequestID (incremental) y
//    con presupuesto de tiempo y de bytes, y devuelve el CSV CRUDO.
//    El parseo va en Node, igual que con los almacenes: el PrivSvc
//    devuelve bytes, el agente interpreta. Asi un cambio de formato se
//    arregla en TypeScript, con tests, sin rebuild del MSI.
//
// ── Solo lectura ─────────────────────────────────────────────────────
//
// `certutil -view` lee la base de la CA; no toca nada. Corre como el
// servicio (SYSTEM), que en un CA server tiene permiso de lectura sobre
// la base por defecto.
//
// ⚠️ NO PROBADO EN UNA CA REAL AL ESCRIBIRLO. Se escribio desde una Mac
// contra la documentacion de certutil. Lo que puede fallar: el nombre
// exacto de las columnas en `-out` y la forma del CSV. Por eso el CSV
// viaja crudo y el parser de Node registra la cabecera que recibio.

using System.Diagnostics;
using System.Text;
using Microsoft.Win32;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpAdcs
{
    public const int HandlerBudgetMs = 90_000;
    // certutil escupe RawCertificate en base64 multilinea: ~2 KB por
    // certificado. 20 MB son ~8.000 filas, mas que el tope por lectura.
    public const int MaxOutputBytes = 20 * 1024 * 1024;
    public const int DefaultMaxRows = 2000;

    /// <summary>Nombre de la CA activa, o null si este equipo no es una CA.</summary>
    public static string? ActiveCaName()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\CertSvc\Configuration");
            var active = key?.GetValue("Active") as string;
            return string.IsNullOrWhiteSpace(active) ? null : active.Trim();
        }
        catch
        {
            return null;
        }
    }

    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        try
        {
            var caName = ActiveCaName();
            if (caName == null)
            {
                return Task.FromResult(PrivSvcResponse.Success(req.Id, new { isCa = false }));
            }

            var p = req.Params ?? new Dictionary<string, object>();
            long since = 0;
            if (p.TryGetValue("sinceRequestId", out var s) && s != null && long.TryParse(s.ToString(), out var parsed) && parsed > 0) since = parsed;
            int maxRows = DefaultMaxRows;
            if (p.TryGetValue("maxRows", out var m) && m != null && int.TryParse(m.ToString(), out var pm) && pm > 0) maxRows = Math.Min(pm, 5000);

            var psi = new ProcessStartInfo
            {
                FileName = "certutil.exe",
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            psi.ArgumentList.Add("-view");
            psi.ArgumentList.Add("-csv");
            // Incremental por RequestID. Sin `Disposition` en el filtro: se
            // quieren tambien las revocadas (21) y se distingue en Node.
            psi.ArgumentList.Add("-restrict");
            psi.ArgumentList.Add($"RequestID>{since}");
            psi.ArgumentList.Add("-out");
            psi.ArgumentList.Add("RequestID,Request.Disposition,Request.RequesterName,CertificateTemplate,RawCertificate");

            var clock = Stopwatch.StartNew();
            using var proc = Process.Start(psi);
            if (proc == null)
            {
                return Task.FromResult(PrivSvcResponse.Fail(req.Id, "certutil_unavailable", "could not start certutil.exe"));
            }

            var sb = new StringBuilder();
            var truncated = false;
            var rows = 0;
            // Se lee linea a linea para poder cortar por filas y por bytes
            // sin tragarse una base de 200.000 emisiones entera.
            string? line;
            while ((line = proc.StandardOutput.ReadLine()) != null)
            {
                if (clock.ElapsedMilliseconds > HandlerBudgetMs || sb.Length > MaxOutputBytes)
                {
                    truncated = true;
                    break;
                }
                sb.Append(line).Append('\n');
                // Una fila del CSV empieza por un RequestID entre comillas.
                // Las lineas del base64 no; las de cabecera tampoco.
                if (line.StartsWith("\"", StringComparison.Ordinal) && line.Length > 2 && char.IsDigit(line[1]))
                {
                    rows += 1;
                    if (rows >= maxRows)
                    {
                        // Se deja terminar la fila actual (el RawCertificate
                        // multilinea) leyendo hasta la linea que cierra.
                        while ((line = proc.StandardOutput.ReadLine()) != null)
                        {
                            sb.Append(line).Append('\n');
                            if (line.EndsWith("\"", StringComparison.Ordinal) && line.Contains("END CERTIFICATE")) break;
                        }
                        truncated = true;
                        break;
                    }
                }
            }
            try { if (!proc.HasExited) proc.Kill(true); } catch { /* ya salio */ }
            var stderr = "";
            try { stderr = proc.StandardError.ReadToEnd(); } catch { /* ignorado */ }
            proc.WaitForExit(5_000);

            return Task.FromResult(PrivSvcResponse.Success(req.Id, new
            {
                isCa = true,
                caName,
                sinceRequestId = since,
                csv = sb.ToString(),
                rows,
                truncated,
                elapsedMs = clock.ElapsedMilliseconds,
                exitCode = proc.HasExited ? proc.ExitCode : (int?)null,
                stderr = stderr.Length > 2000 ? stderr[..2000] : stderr
            }));
        }
        catch (Exception ex)
        {
            return Task.FromResult(PrivSvcResponse.Fail(req.Id, "adcs_read_failed", ex.Message));
        }
    }
}

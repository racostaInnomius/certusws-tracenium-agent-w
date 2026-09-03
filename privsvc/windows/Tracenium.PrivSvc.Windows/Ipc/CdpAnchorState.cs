// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/CdpAnchorState.cs
//
// ADR-0011 fase 0, paso 1 — sacar la observacion del equipo.
//
// ── Por que existe este metodo ──────────────────────────────────────
//
// El modo `observe` del pin de anclas tiene UN proposito: generar la
// evidencia con la que decidir el paso a `enforce`. Medido el
// 2026-09-03, esa evidencia no salia del endpoint — el backend no tenia
// una sola referencia a anchor-pin y agent-core no leia el veredicto.
// Un mecanismo que funciona y no produce nada visible es el fallo que
// este repositorio ya conoce por `purge_after` y por los guards de la
// fase 1, que se quedaron fuera del bundle por no tener llamador.
//
// Windows es la plataforma que MAS importa aqui: es donde se midio el
// hallazgo original —`rootStore.Add()` sobre `LocalMachine\Root` en la
// ruta de renovacion— y donde una raiz plantada afecta a todo lo que
// haya en el equipo, no solo al agente.
//
// ── Solo lectura ────────────────────────────────────────────────────
//
// No decide ni escribe nada. Devuelve las huellas fijadas completas: son
// publicas por definicion —el hash de un certificado que el equipo ya
// presenta en cada handshake— y sin ellas no se puede distinguir «vio la
// CA nueva de la rotacion» de «vio otra cosa», que es LA pregunta.

using System.Threading.Tasks;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class CdpAnchorState
{
    public static Task<PrivSvcResponse> Handle(PrivSvcRequest req)
    {
        var pinned = AnchorPin.Load();
        var last = AnchorPin.LoadState();

        return Task.FromResult(PrivSvcResponse.Success(req.Id, new
        {
            // `applicable` distingue las tres cosas que un panel
            // confundiria: «no aplica en esta plataforma» (Linux),
            // «aplica y nunca ha evaluado» (last nulo) y «aplica y esto
            // es lo que vio».
            applicable = true,
            platform = "windows",
            mode = AnchorPin.IsEnforcing() ? "enforce" : "observe",
            pinnedCount = pinned.Count,
            pinned = pinned,
            last = last
        }));
    }
}

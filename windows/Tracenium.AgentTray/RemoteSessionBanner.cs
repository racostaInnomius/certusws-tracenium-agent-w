using System;
using System.Drawing;
using System.Windows.Forms;
using Tracenium.AgentTray.Models;

namespace Tracenium.AgentTray;

/// <summary>
/// Indicador PERMANENTE de sesión de control remoto (ADR-0012, paso 1).
///
/// Franja superior, siempre encima, mientras alguien está viendo esta pantalla.
/// No es una notificación: una notificación se descarta y a los diez segundos
/// la persona ya no recuerda que la están mirando. Lo que protege es la
/// presencia continua — y el botón de cortar que lleva al lado.
///
/// De todo ADR-0012, esta es la pieza que más protege por unidad de esfuerzo.
/// Un diálogo de consentimiento sin capacidad de revocar da la apariencia de
/// control sin darlo; esta franja da el control aunque el diálogo no exista
/// todavía.
///
/// Decisiones de presentación y su porqué:
///
///  * Arriba y centrado, no en la bandeja. Un icono en la bandeja se pierde
///    entre otros veinte y se ve solo si miras. Esto tiene que verse SIN
///    mirar.
///  * ShowWithoutActivation + no TopMost-robando-foco: informa sin
///    interrumpir. La persona probablemente esté en mitad de la incidencia que
///    motivó la sesión; robarle el foco empeora justo lo que veníamos a
///    arreglar.
///  * Sin entrada en la barra de tareas ni en Alt-Tab, igual que
///    DeviceInfoFlyout — no es una ventana con la que se trabaja.
///  * Ámbar, no rojo. Rojo dice "error" y esto no lo es: es una sesión
///    legítima que la persona debe poder ver. El rojo se reserva para cuando
///    algo va mal de verdad.
/// </summary>
internal sealed class RemoteSessionBanner : Form
{
    private const int BannerHeight = 34;

    private readonly Label _text;
    private readonly Button _stopButton;
    private string _sessionId = "";

    // Ámbar de aviso, el mismo par que BrandAssets usa para los chips de
    // advertencia: la franja tiene que leerse como "atención", no como fallo.
    private static readonly Color BannerBack = BrandAssets.ChipWarningBackground;
    private static readonly Color BannerText = BrandAssets.ChipWarningText;

    public RemoteSessionBanner()
    {
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        ShowInTaskbar = false;
        TopMost = true;
        BackColor = BannerBack;
        Height = BannerHeight;

        _stopButton = new Button
        {
            Text = "Stop sharing",
            Dock = DockStyle.Right,
            Width = 120,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.White,
            ForeColor = BannerText,
            Cursor = Cursors.Hand
        };
        _stopButton.FlatAppearance.BorderColor = BannerText;
        _stopButton.Click += (_, _) => RequestStop();

        _text = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = BannerText,
            TextAlign = ContentAlignment.MiddleCenter,
            Font = new Font(SystemFonts.MessageBoxFont?.FontFamily ?? FontFamily.GenericSansSerif,
                            9f, FontStyle.Bold)
        };

        Controls.Add(_text);
        Controls.Add(_stopButton);
    }

    /// <summary>
    /// No robar el foco al aparecer. La franja informa; la persona sigue
    /// escribiendo donde estaba.
    /// </summary>
    protected override bool ShowWithoutActivation => true;

    /// <summary>
    /// Refleja el estado de la sesión. `null` o inactiva ⇒ se esconde.
    ///
    /// Que se esconda importa tanto como que aparezca: una franja que se queda
    /// encendida sin sesión enseña una alarma falsa y entrena a la gente a
    /// ignorar la siguiente, que sí será real.
    /// </summary>
    public void Render(TrayRemoteSession? session)
    {
        if (session is null || !session.Active || string.IsNullOrWhiteSpace(session.SessionId))
        {
            _sessionId = "";
            if (Visible) Hide();
            return;
        }

        _sessionId = session.SessionId;

        // Sin nombre decimos "an operator". Inventar uno sería peor que
        // admitir que no lo sabemos: la identidad es justo lo que hace
        // creíble al indicador.
        var who = string.IsNullOrWhiteSpace(session.Operator) ? "An operator" : session.Operator;
        var what = session.Controlling
            ? $"{who} is viewing and controlling this computer"
            : $"{who} is viewing this screen";
        if (session.Recording)
        {
            // El derecho a saber que te graban no se agota al aceptar: dura lo
            // que dure la grabación.
            what += " · this session is being recorded";
        }

        _text.Text = what;
        _stopButton.Text = session.Controlling ? "Stop session" : "Stop sharing";
        _stopButton.Enabled = true;

        Reposition();
        if (!Visible) Show();
        // La sesión puede empezar con otras ventanas ya al frente.
        BringToFront();
    }

    private void RequestStop()
    {
        if (string.IsNullOrWhiteSpace(_sessionId)) return;

        // Desactivar en el acto: la persona ya lo pidió y volver a pulsar no
        // acelera nada. El texto cambia para que se vea que se está actuando —
        // el corte tarda hasta medio segundo en llegar al agente.
        _stopButton.Enabled = false;
        _stopButton.Text = "Stopping…";
        RemoteSessionRevokeSink.Write(_sessionId);
    }

    private void Reposition()
    {
        var screen = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1280, 720);
        // Ancho generoso y centrado: tiene que leerse de un vistazo, sin
        // buscarlo.
        Width = Math.Min(screen.Width - 40, 720);
        Left = screen.Left + (screen.Width - Width) / 2;
        Top = screen.Top;
    }
}

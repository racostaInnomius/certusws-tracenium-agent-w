using System;
using System.Drawing;
using System.Drawing.Drawing2D;
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
///
/// ── Rediseño 25-sep-2026, igual en las tres plataformas ─────────────
///
/// Antes era una banda ámbar plana con el aspecto de un aviso del sistema.
/// Ahora es cromo oscuro de marca con el logo delante: se lee como una pieza
/// de Tracenium, y eso es lo que la hace creíble — un aviso que podría ser de
/// cualquiera se ignora como se ignora cualquiera.
///
/// El ámbar deja de ser el fondo para ser **el acento del estado**:
///
///   viendo       → cian  (#8FFDFF)
///   controlando  → ámbar (#F4D37D)
///
/// Los dos acentos se distinguen también por CLARIDAD, no solo por tono, así
/// que el cambio se ve aunque no se distingan los colores. Ámbar y no rojo,
/// como antes: rojo dice "error" y esto no lo es — es una sesión legítima que
/// la persona debe poder ver.
///
/// El alto y la posición NO cambian al escalar: una franja que salta de sitio
/// se lee como una ventana nueva y no como la misma que ya estaba avisando.
/// </summary>
internal sealed class RemoteSessionBanner : Form
{
    private const int BannerHeight = 52;
    private const int CornerRadius = 14;

    private readonly Label _text;
    private readonly Button _stopButton;
    private readonly PictureBox _logo;
    private readonly Panel _dot;
    private readonly Panel _recBadge;
    private readonly Label _recLabel;
    private readonly Panel _divider;
    private readonly Panel _accentBar;
    private string _sessionId = "";

    // Cromo de marca. Fijo, no adaptativo al tema del sistema: la franja se ve
    // igual en las capturas de un incidente independientemente de cómo tuviera
    // el equipo la persona.
    private static readonly Color ChromeViewing = Color.FromArgb(0x22, 0x28, 0x31);
    private static readonly Color ChromeControlling = Color.FromArgb(0x2A, 0x26, 0x20);
    private static readonly Color AccentViewing = Color.FromArgb(0x8F, 0xFD, 0xFF);
    private static readonly Color AccentControlling = Color.FromArgb(0xF4, 0xD3, 0x7D);
    private static readonly Color TextViewing = Color.FromArgb(0xF2, 0xF4, 0xF7);
    private static readonly Color TextControlling = Color.FromArgb(0xFB, 0xEF, 0xD2);
    private static readonly Color InkOnAmber = Color.FromArgb(0x3A, 0x2D, 0x07);

    public RemoteSessionBanner()
    {
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        ShowInTaskbar = false;
        TopMost = true;
        BackColor = ChromeViewing;
        Height = BannerHeight;
        DoubleBuffered = true;

        _logo = new PictureBox
        {
            Image = BrandAssets.LoadLogoOrNull(),
            SizeMode = PictureBoxSizeMode.Zoom,
            Size = new Size(24, 24),
            BackColor = Color.Transparent
        };

        _dot = new Panel { Size = new Size(9, 9), BackColor = AccentViewing };
        _dot.Paint += (s, e) => PaintCircle(e, _dot);

        _text = new Label
        {
            AutoSize = false,
            // ⚠️ El "&" de un Label es prefijo de tecla de acceso en WinForms.
            // El nombre de un operador puede llevarlo ("Ruiz & asociados"), y
            // sin esto se lo comería el parser de mnemónicos.
            UseMnemonic = false,
            ForeColor = TextViewing,
            TextAlign = ContentAlignment.MiddleLeft,
            AutoEllipsis = true,
            Font = new Font(SystemFonts.MessageBoxFont?.FontFamily ?? FontFamily.GenericSansSerif,
                            9.5f, FontStyle.Bold)
        };

        // La grabación sale como insignia y no dentro de la frase: es un hecho
        // distinto del de quién mira, y en la frase quedaba al final de una
        // línea larga, que es justo por donde se trunca.
        _recBadge = new Panel { Size = new Size(54, 20), BackColor = Color.Transparent };
        _recBadge.Paint += PaintRecBadge;
        _recLabel = new Label
        {
            Text = "REC",
            AutoSize = false,
            UseMnemonic = false,
            Size = new Size(54, 20),
            ForeColor = Color.FromArgb(0xF7, 0xDF, 0x9E),
            TextAlign = ContentAlignment.MiddleCenter,
            BackColor = Color.Transparent,
            Font = new Font(SystemFonts.MessageBoxFont?.FontFamily ?? FontFamily.GenericSansSerif,
                            7.5f, FontStyle.Bold)
        };
        _recBadge.Controls.Add(_recLabel);

        _divider = new Panel { Size = new Size(1, 22), BackColor = Color.FromArgb(52, 219, 224, 230) };

        _stopButton = new Button
        {
            Text = "Stop sharing",
            Size = new Size(126, 34),
            FlatStyle = FlatStyle.Flat,
            BackColor = ChromeViewing,
            ForeColor = TextViewing,
            Cursor = Cursors.Hand,
            UseMnemonic = false,
            Font = new Font(SystemFonts.MessageBoxFont?.FontFamily ?? FontFamily.GenericSansSerif,
                            9f, FontStyle.Bold)
        };
        _stopButton.FlatAppearance.BorderColor = Color.FromArgb(0x8A, 0x92, 0x9C);
        _stopButton.Click += (_, _) => RequestStop();

        _accentBar = new Panel { Height = 2, Dock = DockStyle.Bottom, BackColor = AccentViewing };

        Controls.Add(_logo);
        Controls.Add(_dot);
        Controls.Add(_text);
        Controls.Add(_recBadge);
        Controls.Add(_divider);
        Controls.Add(_stopButton);
        Controls.Add(_accentBar);
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

        var controlling = session.Controlling;
        var chrome = controlling ? ChromeControlling : ChromeViewing;
        var accent = controlling ? AccentControlling : AccentViewing;
        var ink = controlling ? TextControlling : TextViewing;

        BackColor = chrome;
        _accentBar.BackColor = accent;
        _dot.BackColor = accent;
        _text.ForeColor = ink;

        // Sin nombre decimos "an operator". Inventar uno sería peor que
        // admitir que no lo sabemos: la identidad es justo lo que hace
        // creíble al indicador.
        var who = string.IsNullOrWhiteSpace(session.Operator) ? "An operator" : session.Operator;
        _text.Text = controlling
            ? $"{who} is viewing and controlling this computer"
            : $"{who} is viewing this screen";

        _recBadge.Visible = session.Recording;

        _stopButton.Text = controlling ? "Stop session" : "Stop sharing";
        _stopButton.BackColor = controlling ? accent : chrome;
        _stopButton.ForeColor = controlling ? InkOnAmber : ink;
        _stopButton.FlatAppearance.BorderColor = controlling ? accent : Color.FromArgb(0x8A, 0x92, 0x9C);
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

    private static void PaintCircle(PaintEventArgs e, Control c)
    {
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using var brush = new SolidBrush(c.BackColor);
        e.Graphics.FillEllipse(brush, 0, 0, c.Width - 1, c.Height - 1);
    }

    private static void PaintRecBadge(object? sender, PaintEventArgs e)
    {
        if (sender is not Control c) return;
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        var r = new Rectangle(0, 0, c.Width - 1, c.Height - 1);
        using var path = RoundedRect(r, c.Height / 2);
        using var fill = new SolidBrush(Color.FromArgb(41, 0xF4, 0xD3, 0x7D));
        using var pen = new Pen(Color.FromArgb(115, 0xF4, 0xD3, 0x7D));
        e.Graphics.FillPath(fill, path);
        e.Graphics.DrawPath(pen, path);
        using var dot = new SolidBrush(AccentControlling);
        e.Graphics.FillEllipse(dot, 8, c.Height / 2 - 3, 7, 7);
    }

    /// <summary>
    /// Esquinas redondeadas SOLO abajo: la franja está pegada al borde
    /// superior, así que redondear arriba dibujaría un hueco contra el borde
    /// de la pantalla.
    /// </summary>
    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        LayoutChildren();
        using var path = new GraphicsPath();
        var r = new Rectangle(0, 0, Width, Height);
        var d = CornerRadius * 2;
        path.AddLine(r.Left, r.Top, r.Right, r.Top);
        path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        path.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        Region = new Region(path);
    }

    /// <summary>
    /// Posiciona a mano: los controles son de anchos distintos y el texto se
    /// estira con lo que quede, que es lo que permite que una frase larga se
    /// recorte por la derecha en vez de empujar al botón fuera de la franja.
    /// </summary>
    private void LayoutChildren()
    {
        const int pad = 14;
        var midY = (Height - 2) / 2; // -2: la barra de acento de abajo

        _logo.Location = new Point(pad, midY - _logo.Height / 2);
        _dot.Location = new Point(_logo.Right + 12, midY - _dot.Height / 2);

        _stopButton.Location = new Point(Width - 8 - _stopButton.Width, midY - _stopButton.Height / 2);
        _divider.Location = new Point(_stopButton.Left - 10, midY - _divider.Height / 2);
        _recBadge.Location = new Point(_divider.Left - 10 - _recBadge.Width, midY - _recBadge.Height / 2);

        var textLeft = _dot.Right + 10;
        var textRight = (_recBadge.Visible ? _recBadge.Left : _divider.Left) - 10;
        _text.Location = new Point(textLeft, 0);
        _text.Size = new Size(Math.Max(40, textRight - textLeft), Height - 2);
    }

    private void Reposition()
    {
        var screen = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1280, 720);
        // Ancho generoso y centrado: tiene que leerse de un vistazo, sin
        // buscarlo.
        Width = Math.Min(screen.Width - 40, 760);
        Height = BannerHeight;
        Left = screen.Left + (screen.Width - Width) / 2;
        Top = screen.Top;
        LayoutChildren();
    }

    private static GraphicsPath RoundedRect(Rectangle r, int radius)
    {
        var d = radius * 2;
        var path = new GraphicsPath();
        path.AddArc(r.Left, r.Top, d, d, 180, 90);
        path.AddArc(r.Right - d, r.Top, d, d, 270, 90);
        path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        path.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }
}

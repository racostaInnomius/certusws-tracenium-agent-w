using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace Tracenium.AgentTray;

/// <summary>
/// El diálogo de consentimiento de ADR-0012, con la cara de Tracenium.
///
/// ── Por qué NO es un MessageBox ─────────────────────────────────────
///
/// Lo era. Un MessageBox sale por encima de todo sin depender de que la
/// bandeja tenga el foco, y es la ventana que Windows ya sabe colocar bien en
/// cualquier DPI y cualquier tema. Por eso se eligió.
///
/// Lo que se perdía a cambio es lo que este diálogo necesita más que ningún
/// otro: **que se reconozca de un vistazo quién lo muestra**. Un aviso que
/// aparece de la nada diciendo que alguien quiere ver tu pantalla, con el
/// aspecto exacto de cualquier otro cuadro del sistema, es indistinguible de
/// un intento de estafa — y la reacción sana ante eso es pulsar lo que sea
/// para que desaparezca. Nombrar el producto en el texto ayuda; enseñarlo con
/// su cromo y su logo, más.
///
/// Todo lo que el MessageBox hacía bien se conserva a propósito:
///
///  * **Denegar es el botón por defecto** (Return) y Escape también deniega.
///    En un diálogo que concede acceso a la pantalla de alguien, la opción de
///    reposo no puede ser la que concede: un Return distraído no debe regalar
///    el control del equipo.
///  * **Modal de verdad**, no una ventana que se pueda dejar de lado.
///  * **TopMost**, porque la persona puede estar en pantalla completa.
///
/// Y se añade lo que no había: la cuenta atrás. El plazo existía —vencerlo
/// cuenta como negativa— pero no se veía, así que la persona no sabía que
/// estaba decidiendo contra reloj.
/// </summary>
internal sealed class ConsentWindow : Form
{
    private const int DialogWidth = 480;

    private static readonly Color Chrome = Color.FromArgb(0x22, 0x28, 0x31);
    private static readonly Color ChromeControl = Color.FromArgb(0x2A, 0x26, 0x20);
    private static readonly Color Cyan = Color.FromArgb(0x8F, 0xFD, 0xFF);
    private static readonly Color Amber = Color.FromArgb(0xF4, 0xD3, 0x7D);
    private static readonly Color Teal = Color.FromArgb(0x3C, 0x7C, 0x7C);
    private static readonly Color Ink = Color.FromArgb(0x1C, 0x20, 0x27);
    private static readonly Color InkSoft = Color.FromArgb(0x5C, 0x64, 0x6E);
    private static readonly Color InkOnAmber = Color.FromArgb(0x3A, 0x2D, 0x07);

    private readonly ConsentRequest _request;
    private readonly bool _control;
    private readonly Label _expiry = new();
    private readonly System.Windows.Forms.Timer _ticker = new() { Interval = 1000 };

    /// <summary>true = la persona concedió.</summary>
    public bool Approved { get; private set; }

    public ConsentWindow(ConsentRequest request)
    {
        _request = request;
        _control = string.Equals(request.Kind, "control", StringComparison.OrdinalIgnoreCase);

        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterScreen;
        ControlBox = false;
        ShowInTaskbar = false;
        TopMost = true;
        BackColor = Color.White;
        Width = DialogWidth;
        AutoScaleMode = AutoScaleMode.Dpi;

        var y = BuildHeader();
        y = BuildBody(y);
        BuildFooter(y);

        _ticker.Tick += (_, _) => Tick();
        Shown += (_, _) => { Tick(); _ticker.Start(); };
        FormClosed += (_, _) => _ticker.Stop();
    }

    /// <summary>Banda oscura con el logo y el eslogan: lo PRIMERO que se ve es
    /// de quién viene el aviso.</summary>
    private int BuildHeader()
    {
        var bar = new Panel
        {
            Location = new Point(0, 0),
            Size = new Size(DialogWidth, 46),
            BackColor = _control ? ChromeControl : Chrome
        };

        var logo = new PictureBox
        {
            Image = BrandAssets.LoadLogoOrNull(),
            SizeMode = PictureBoxSizeMode.Zoom,
            Size = new Size(22, 22),
            Location = new Point(18, 12),
            BackColor = Color.Transparent
        };

        var name = new Label
        {
            Text = "Tracenium",
            AutoSize = true,
            UseMnemonic = false,
            ForeColor = Color.FromArgb(0xF2, 0xF4, 0xF7),
            Location = new Point(50, 15),
            Font = new Font(Font.FontFamily, 9.5f, FontStyle.Bold)
        };

        // El eslogan, con el "&" en cian. Tres etiquetas porque WinForms no
        // pinta parte de un Label en otro color — y las tres con
        // UseMnemonic=false, porque si no el "&" desaparece: es el prefijo de
        // tecla de acceso. Ese mismo fallo tenía la ventana de estado.
        var sloganLeft = new Label
        {
            Text = BrandAssets.SloganLeft,
            AutoSize = true,
            UseMnemonic = false,
            ForeColor = Color.FromArgb(0x9A, 0xA3, 0xAE),
            Font = new Font(Font.FontFamily, 8f)
        };
        var sloganAccent = new Label
        {
            Text = BrandAssets.SloganAccent,
            AutoSize = true,
            UseMnemonic = false,
            ForeColor = Cyan,
            Font = new Font(Font.FontFamily, 8f, FontStyle.Bold)
        };
        var sloganRight = new Label
        {
            Text = BrandAssets.SloganRight,
            AutoSize = true,
            UseMnemonic = false,
            ForeColor = Color.FromArgb(0x9A, 0xA3, 0xAE),
            Font = new Font(Font.FontFamily, 8f)
        };

        bar.Controls.Add(logo);
        bar.Controls.Add(name);
        bar.Controls.Add(sloganLeft);
        bar.Controls.Add(sloganAccent);
        bar.Controls.Add(sloganRight);

        // Las etiquetas son AutoSize: sus anchos sólo se conocen tras medir el
        // texto, así que se encadenan de derecha a izquierda al mostrarse.
        bar.Resize += (_, _) => LayoutSlogan(bar, sloganLeft, sloganAccent, sloganRight);
        Shown += (_, _) => LayoutSlogan(bar, sloganLeft, sloganAccent, sloganRight);

        if (_control)
        {
            bar.Controls.Add(new Panel { Dock = DockStyle.Bottom, Height = 2, BackColor = Amber });
        }

        Controls.Add(bar);
        return bar.Bottom;
    }

    private static void LayoutSlogan(Control bar, Control left, Control accent, Control right)
    {
        var y = (bar.Height - left.Height) / 2;
        right.Location = new Point(bar.Width - 18 - right.Width, y);
        accent.Location = new Point(right.Left - accent.Width, y);
        left.Location = new Point(accent.Left - left.Width, y);
    }

    private int BuildBody(int top)
    {
        var y = top + 20;

        var title = new Label
        {
            Text = _request.Title,
            AutoSize = false,
            UseMnemonic = false,
            ForeColor = Ink,
            Location = new Point(24, y),
            Width = DialogWidth - 48,
            Font = new Font(Font.FontFamily, 12f, FontStyle.Bold)
        };
        title.Height = TextRenderer.MeasureText(title.Text, title.Font,
            new Size(title.Width, 0), TextFormatFlags.WordBreak).Height + 4;
        Controls.Add(title);
        y = title.Bottom + 14;

        // Las líneas vienen YA PARTIDAS del agente (`consent-text.ts`), que es
        // donde vive la redacción para las tres plataformas. Aquí se
        // presentan, no se reescriben: una copia distinta por sistema es una
        // copia que se desincroniza.
        foreach (var line in _request.Lines)
        {
            if (string.IsNullOrWhiteSpace(line)) continue;

            var bullet = new Label
            {
                Text = "•",
                AutoSize = true,
                UseMnemonic = false,
                ForeColor = _control ? Amber : Teal,
                Location = new Point(24, y),
                Font = new Font(Font.FontFamily, 10f, FontStyle.Bold)
            };
            var body = new Label
            {
                Text = line,
                AutoSize = false,
                UseMnemonic = false,
                ForeColor = Ink,
                Location = new Point(44, y),
                Width = DialogWidth - 68,
                Font = new Font(Font.FontFamily, 9.5f)
            };
            body.Height = TextRenderer.MeasureText(body.Text, body.Font,
                new Size(body.Width, 0), TextFormatFlags.WordBreak).Height + 2;

            Controls.Add(bullet);
            Controls.Add(body);
            y = body.Bottom + 10;
        }

        return y + 6;
    }

    private void BuildFooter(int top)
    {
        _expiry.AutoSize = true;
        _expiry.UseMnemonic = false;
        _expiry.ForeColor = InkSoft;
        _expiry.Location = new Point(24, top + 12);
        _expiry.Font = new Font(Font.FontFamily, 8f);
        Controls.Add(_expiry);

        var deny = Pill(_request.DenyLabel, Color.White, Ink, Ink, 2);
        var allow = Pill(_request.AllowLabel,
                         _control ? Amber : Color.FromArgb(0xEB, 0xF4, 0xF4),
                         _control ? InkOnAmber : Color.FromArgb(0x2F, 0x60, 0x60),
                         _control ? Color.FromArgb(0xB9, 0x8F, 0x17) : Teal,
                         1);

        deny.Location = new Point(DialogWidth - 24 - deny.Width, top + 6);
        allow.Location = new Point(deny.Left - 10 - allow.Width, top + 6);

        deny.Click += (_, _) => Decide(false);
        allow.Click += (_, _) => Decide(true);

        Controls.Add(deny);
        Controls.Add(allow);

        // ⚠️ Los dos atajos apuntan a DENEGAR. AcceptButton es el de Return —
        // aquí es el de negarse, a propósito— y CancelButton el de Escape: el
        // gesto universal de "sácame de aquí" no puede conceder acceso a la
        // pantalla de nadie.
        AcceptButton = deny;
        CancelButton = deny;

        ClientSize = new Size(DialogWidth, deny.Bottom + 20);
    }

    private Button Pill(string text, Color fill, Color ink, Color border, int borderWidth)
    {
        var b = new Button
        {
            Text = text,
            AutoSize = false,
            UseMnemonic = false,
            Size = new Size(Math.Max(96, TextRenderer.MeasureText(text, Font).Width + 36), 34),
            FlatStyle = FlatStyle.Flat,
            BackColor = fill,
            ForeColor = ink,
            Cursor = Cursors.Hand,
            Font = new Font(Font.FontFamily, 9.5f, FontStyle.Bold)
        };
        b.FlatAppearance.BorderColor = border;
        b.FlatAppearance.BorderSize = borderWidth;
        return b;
    }

    private void Decide(bool approved)
    {
        Approved = approved;
        DialogResult = approved ? DialogResult.Yes : DialogResult.No;
        Close();
    }

    private void Tick()
    {
        if (_request.ExpiresAtUtc is not DateTime expiry)
        {
            _expiry.Text = "";
            return;
        }
        var left = (int)Math.Round((expiry - DateTime.UtcNow).TotalSeconds);
        if (left <= 0)
        {
            // El plazo venció. No se concede nada: el agente ya lo cuenta como
            // negativa, y dejar la ventana abierta invitaría a contestar a algo
            // que ya no escucha nadie.
            _expiry.Text = "Expired";
            Decide(false);
            return;
        }
        _expiry.Text = $"Expires in {left} s";
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
    }
}

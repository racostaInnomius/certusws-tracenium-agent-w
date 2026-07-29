using Tracenium.AgentTray.Models;

namespace Tracenium.AgentTray;

/// <summary>
/// Always-on-top "tab" docked at the top-center of the primary screen.
/// Collapsed it is a thin dark strip; clicking it expands a panel with
/// the device info a support tech asks for, plus "Copy all". Clicking
/// the strip again (or anywhere outside) collapses it back.
///
/// Visibility is policy-gated: TrayApplicationContext shows this form
/// only while tray-status.json reports policy.features.deviceInfoWidget
/// == true, so tenants opt in per-policy instead of every desktop
/// getting a floating widget. The Device Info TAB in StatusForm is not
/// gated — this flyout is just the zero-clicks-to-find variant.
///
/// Implementation notes:
///  * ShowWithoutActivation + WS_EX_NOACTIVATE keep the collapsed strip
///    from stealing focus from whatever the user is doing — it must
///    never interrupt typing. Expansion DOES activate (we want
///    Deactivate to fire so click-outside collapses it).
///  * TopMost borderless Form, no taskbar entry, no Alt-Tab entry
///    (WS_EX_TOOLWINDOW via CreateParams).
/// </summary>
internal sealed class DeviceInfoFlyout : Form
{
    private const int CollapsedWidth = 160;
    private const int CollapsedHeight = 14;
    private const int ExpandedWidth = 400;
    private const int ExpandedHeight = 460;

    private const int WS_EX_TOOLWINDOW = 0x00000080;
    private const int WS_EX_NOACTIVATE = 0x08000000;

    private readonly List<Label> _valueLabels = new();
    private readonly Panel _expandedPanel;
    private readonly Label _stripLabel;
    private readonly Button _copyButton;
    private TrayStatus? _lastStatus;
    private bool _expanded;

    public DeviceInfoFlyout()
    {
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.Manual;
        ShowInTaskbar = false;
        TopMost = true;
        BackColor = Color.FromArgb(34, 40, 49);

        // Strip (siempre visible): franja delgada con el texto de marca.
        _stripLabel = new Label
        {
            Text = "▾ Device info",
            Dock = DockStyle.Top,
            Height = CollapsedHeight,
            TextAlign = ContentAlignment.MiddleCenter,
            ForeColor = Color.FromArgb(143, 253, 255),
            Font = new Font("Segoe UI", 7.5f, FontStyle.Bold),
            Cursor = Cursors.Hand
        };
        _stripLabel.Click += (_, _) => Toggle();

        // Panel expandido: grid de campos + Copy all.
        _expandedPanel = new Panel
        {
            Dock = DockStyle.Fill,
            Visible = false,
            Padding = new Padding(14, 6, 14, 10)
        };

        var grid = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            AutoScroll = true,
            BackColor = Color.Transparent
        };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        foreach (var field in DeviceInfoProvider.BuildFields(null))
        {
            AddRow(grid, field.Label);
        }

        var buttonStrip = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            AutoSize = true,
            BackColor = Color.Transparent,
            Padding = new Padding(0, 4, 0, 0)
        };
        _copyButton = new Button
        {
            Text = "Copy all",
            AutoSize = true,
            FlatStyle = FlatStyle.Flat,
            ForeColor = Color.White,
            BackColor = Color.FromArgb(90, 159, 159)
        };
        _copyButton.FlatAppearance.BorderSize = 0;
        _copyButton.Click += (_, _) => CopyAll();
        buttonStrip.Controls.Add(_copyButton);

        _expandedPanel.Controls.Add(grid);
        _expandedPanel.Controls.Add(buttonStrip);

        Controls.Add(_expandedPanel);
        Controls.Add(_stripLabel);

        Deactivate += (_, _) => Collapse();

        ApplyCollapsedBounds();
    }

    /// <summary>Sin activación al mostrarse — nunca robar el foco.</summary>
    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            // TOOLWINDOW: fuera de Alt-Tab. NOACTIVATE: click en la franja
            // colapsada no roba foco de la app activa del usuario.
            cp.ExStyle |= WS_EX_TOOLWINDOW;
            if (!_expanded)
            {
                cp.ExStyle |= WS_EX_NOACTIVATE;
            }
            return cp;
        }
    }

    public void Render(TrayStatus? status)
    {
        _lastStatus = status;
        var fields = DeviceInfoProvider.BuildFields(status);
        for (var i = 0; i < fields.Count && i < _valueLabels.Count; i++)
        {
            _valueLabels[i].Text = fields[i].Value;
        }
    }

    private void Toggle()
    {
        if (_expanded) Collapse();
        else Expand();
    }

    private void Expand()
    {
        if (_expanded) return;
        _expanded = true;
        _stripLabel.Text = "▴ Device info";
        _expandedPanel.Visible = true;
        ApplyExpandedBounds();
        // Activar para que Deactivate dispare el colapso al click-fuera.
        Activate();
    }

    private void Collapse()
    {
        if (!_expanded) return;
        _expanded = false;
        _stripLabel.Text = "▾ Device info";
        _expandedPanel.Visible = false;
        ApplyCollapsedBounds();
    }

    private void ApplyCollapsedBounds()
    {
        var screen = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1280, 720);
        Bounds = new Rectangle(
            screen.Left + (screen.Width - CollapsedWidth) / 2,
            screen.Top,
            CollapsedWidth,
            CollapsedHeight);
    }

    private void ApplyExpandedBounds()
    {
        var screen = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1280, 720);
        Bounds = new Rectangle(
            screen.Left + (screen.Width - ExpandedWidth) / 2,
            screen.Top,
            ExpandedWidth,
            ExpandedHeight);
    }

    private void AddRow(TableLayoutPanel grid, string label)
    {
        var row = grid.RowStyles.Count;
        grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var labelControl = new Label
        {
            Text = label,
            AutoSize = true,
            ForeColor = Color.FromArgb(190, 190, 190),
            Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
            Margin = new Padding(0, 0, 10, 7)
        };

        var valueControl = new Label
        {
            Text = "—",
            AutoSize = true,
            ForeColor = Color.White,
            Font = new Font("Segoe UI", 8.5f),
            MaximumSize = new Size(220, 0),
            Margin = new Padding(0, 0, 0, 7)
        };
        _valueLabels.Add(valueControl);

        grid.Controls.Add(labelControl, 0, row);
        grid.Controls.Add(valueControl, 1, row);
    }

    private void CopyAll()
    {
        try
        {
            Clipboard.SetText(DeviceInfoProvider.BuildCopyText(_lastStatus));
            _copyButton.Text = "Copied ✓";
            var revert = new System.Windows.Forms.Timer { Interval = 1500 };
            revert.Tick += (_, _) =>
            {
                _copyButton.Text = "Copy all";
                revert.Stop();
                revert.Dispose();
            };
            revert.Start();
        }
        catch
        {
            // Clipboard bloqueado por otro proceso — nunca crashear el tray.
        }
    }
}

using System.Drawing;
using Tracenium.AgentTray.Models;

namespace Tracenium.AgentTray;

internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly StatusReader _reader = new();
    private readonly StatusForm _statusForm = new();
    private readonly DeviceInfoFlyout _deviceFlyout = new();
    private readonly NotifyIcon _notifyIcon;
    private readonly System.Windows.Forms.Timer _timer;
    private readonly Icon _trayIcon;

    public TrayApplicationContext()
    {
        _trayIcon = TrayIconLoader.LoadOrFallback();
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Status", null, (_, _) => ShowStatus());
        menu.Items.Add("Open Agent Data Folder", null, (_, _) => OpenAgentFolder());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit Tray", null, (_, _) => ExitThread());

        _notifyIcon = new NotifyIcon
        {
            Text = "Tracenium Agent",
            Icon = _trayIcon,
            Visible = true,
            ContextMenuStrip = menu
        };
        _notifyIcon.DoubleClick += (_, _) => ShowStatus();
        _statusForm.Icon = _trayIcon;

        _statusForm.FormClosing += (_, e) =>
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                _statusForm.Hide();
            }
        };
        _statusForm.VisibleChanged += (_, _) =>
        {
            if (_statusForm.Visible)
            {
                RefreshStatus();
            }
        };

        _timer = new System.Windows.Forms.Timer
        {
            Interval = 5000
        };
        _timer.Tick += (_, _) => RefreshStatus();
        _timer.Start();

        RefreshStatus();
    }

    protected override void ExitThreadCore()
    {
        _timer.Stop();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _trayIcon.Dispose();
        _timer.Dispose();
        _statusForm.Dispose();
        _deviceFlyout.Dispose();
        base.ExitThreadCore();
    }

    private void RefreshStatus()
    {
        TrayStatus? status = _reader.Read();
        _statusForm.Render(status);
        _deviceFlyout.Render(status);

        // Flyout top-center gateado por policy: solo visible cuando el
        // tenant activó features.deviceInfoWidget. Show() sin robar foco
        // (ShowWithoutActivation en el form); Hide() cuando la policy lo
        // apaga — el toggle llega en el próximo refresh de 5s.
        var flyoutEnabled = status?.Policy.Features?.DeviceInfoWidget == true;
        if (flyoutEnabled && !_deviceFlyout.Visible)
        {
            _deviceFlyout.Show();
        }
        else if (!flyoutEnabled && _deviceFlyout.Visible)
        {
            _deviceFlyout.Hide();
        }

        if (status is null)
        {
            _notifyIcon.Icon = _trayIcon;
            _notifyIcon.Text = "Tracenium Agent - No local status";
            return;
        }

        _notifyIcon.Icon = _trayIcon;
        _notifyIcon.Text = status.Grpc.Connected
            ? $"Tracenium Agent - Online ({status.AgentVersion})"
            : $"Tracenium Agent - Offline ({status.AgentVersion})";
    }

    private void ShowStatus()
    {
        _statusForm.Render(_reader.Read());

        if (!_statusForm.Visible)
        {
            _statusForm.Show();
        }

        if (_statusForm.WindowState == FormWindowState.Minimized)
        {
            _statusForm.WindowState = FormWindowState.Normal;
        }

        _statusForm.BringToFront();
        _statusForm.Activate();
    }

    private void OpenAgentFolder()
    {
        var path = Path.GetDirectoryName(_reader.StatusPath);
        if (string.IsNullOrWhiteSpace(path) || !Directory.Exists(path))
        {
            return;
        }

        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
        catch
        {
            // keep tray isolated; folder-open failure must never crash it
        }
    }
}

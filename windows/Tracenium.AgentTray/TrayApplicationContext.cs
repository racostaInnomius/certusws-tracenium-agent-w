using System.Drawing;
using Tracenium.AgentTray.Models;

namespace Tracenium.AgentTray;

internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly StatusReader _reader = new();
    private readonly StatusForm _statusForm = new();
    private readonly NotifyIcon _notifyIcon;
    private readonly System.Windows.Forms.Timer _timer;

    public TrayApplicationContext()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Status", null, (_, _) => ShowStatus());
        menu.Items.Add("Open Agent Data Folder", null, (_, _) => OpenAgentFolder());
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit Tray", null, (_, _) => ExitThread());

        _notifyIcon = new NotifyIcon
        {
            Text = "Tracenium Agent",
            Icon = SystemIcons.Application,
            Visible = true,
            ContextMenuStrip = menu
        };
        _notifyIcon.DoubleClick += (_, _) => ShowStatus();

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
        _timer.Dispose();
        _statusForm.Dispose();
        base.ExitThreadCore();
    }

    private void RefreshStatus()
    {
        TrayStatus? status = _reader.Read();
        _statusForm.Render(status);

        if (status is null)
        {
            _notifyIcon.Icon = SystemIcons.Warning;
            _notifyIcon.Text = "Tracenium Agent - No local status";
            return;
        }

        _notifyIcon.Icon = status.Grpc.Connected ? SystemIcons.Information : SystemIcons.Warning;
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

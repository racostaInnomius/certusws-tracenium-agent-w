using System.Drawing;
using Tracenium.AgentTray.Models;

namespace Tracenium.AgentTray;

internal sealed class TrayApplicationContext : ApplicationContext
{
    private readonly StatusReader _reader = new();

    // ⚠️ Estos TRES ya no son inicializadores de campo, y el motivo es un fallo
    // de campo (25-sep-2026: «después del update el icono de la bandeja se
    // murió; reinicié y sigue sin salir, los dos servicios corren»).
    //
    // Los inicializadores de campo corren ANTES del cuerpo del constructor, o
    // sea antes de que exista `_notifyIcon`. Cualquier excepción construyendo
    // una ventana —la franja, el flyout, el formulario de estado— tiraba el
    // constructor entero, `Application.Run` no llegaba a arrancar y el proceso
    // moría SIN haber puesto nunca el icono. Determinista: el reinicio lo
    // reproduce igual, que es justo lo que se vio.
    //
    // Ahora el icono se crea primero y estas tres van después, dentro de un
    // try. Una ventana rota degrada la bandeja; ya no la borra.
    private StatusForm? _statusForm;
    // NOT readonly: see the disposed-instance recovery in RefreshStatus().
    private DeviceInfoFlyout? _deviceFlyout;
    private RemoteSessionBanner? _remoteBanner;
    private readonly NotifyIcon _notifyIcon;
    private System.Windows.Forms.Timer? _timer;
    private readonly Icon _trayIcon;

    /// Se montó el icono pero no el resto. El menú sigue respondiendo
    /// («Exit Tray», «Open Agent Data Folder») y el fallo está en
    /// tray-crash.log; lo que NO puede pasar es que no haya icono.
    private bool _degraded;

    // Vigilancia del fichero de estado, SOLO por el indicador de sesión remota.
    //
    // El resto de la bandeja vive perfectamente con el refresco de 5 s: que un
    // recuento de parches tarde unos segundos no le importa a nadie. El
    // indicador de "te están viendo la pantalla" sí: cinco segundos de alguien
    // mirando ANTES de que se encienda el aviso son exactamente el hueco que
    // ADR-0012 viene a cerrar, y ninguna cantidad de diálogos de
    // consentimiento lo tapa.
    //
    // Bajar el temporizador general a 500 ms costaría releer y repintar todo
    // el estado diez veces más a menudo para siempre. El watcher solo despierta
    // cuando el agente escribe, que fuera de sesión son unas pocas veces por
    // minuto.
    private FileSystemWatcher? _statusWatcher;

    // Antirrebote. El agente escribe el estado con temp+move y algunos editores
    // de fichero generan varios eventos por escritura; sin esto, un cambio se
    // convertiría en tres refrescos completos.
    private readonly System.Windows.Forms.Timer _watchDebounce;

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

        // ── A partir de aquí el icono YA está puesto ──────────────────
        //
        // Todo lo que sigue construye ventanas, y una ventana puede fallar por
        // motivos que no controlamos: un assembly que el single-file aún no
        // había cargado cuando el MSI reemplazó el .exe, una fuente del sistema
        // sin la variante que pedimos, un tema raro. Antes cualquiera de esos
        // se llevaba por delante el icono. Ahora se anota y la bandeja sigue.
        _watchDebounce = new System.Windows.Forms.Timer { Interval = 150 };
        try
        {
            _statusForm = new StatusForm { Icon = _trayIcon };
            _deviceFlyout = new DeviceInfoFlyout();
            _remoteBanner = new RemoteSessionBanner();

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
                if (_statusForm is { Visible: true })
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

            _watchDebounce.Tick += (_, _) =>
            {
                _watchDebounce.Stop();
                RefreshStatus();
            };
            StartStatusWatch();

            RefreshStatus();
        }
        catch (Exception ex)
        {
            // Se anota con el mismo detalle que un fallo mortal: atrapar sin
            // dejar rastro convertiría esto en un misterio permanente.
            TrayLog.Write("tray degraded at startup", ex);
            _degraded = true;
            _notifyIcon.Text = "Tracenium Agent (limited)";
        }
    }

    /// <summary>
    /// Despierta el refresco en cuanto cambia el fichero de estado.
    ///
    /// Falla en silencio a propósito: si no se puede vigilar el directorio
    /// —perfil móvil, ACL rara, límite de handles— la bandeja sigue funcionando
    /// con el temporizador de 5 s. Un indicador que llega tarde es peor que uno
    /// inmediato, pero MUCHO mejor que una bandeja que no arranca.
    /// </summary>
    private void StartStatusWatch()
    {
        try
        {
            var dir = Path.GetDirectoryName(_reader.StatusPath);
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;

            // ⚠️ Forzar el handle NO es opcional. Los eventos del watcher llegan
            // en un hilo del pool y hay que marshalarlos al hilo de UI con
            // BeginInvoke, que sobre un Form nunca mostrado lanza porque aún no
            // existe la ventana. _statusForm arranca oculto, así que sin esta
            // línea el IsHandleCreated de abajo sería false y CADA evento se
            // descartaría en silencio hasta que el usuario abriera la ventana
            // de estado — justo lo que nadie hace mientras le comparten la
            // pantalla. Tocar .Handle crea la ventana sin mostrarla.
            // `StartStatusWatch` solo se llama desde el try del constructor,
            // con `_statusForm` ya construido; el `?.` es para el compilador,
            // no para un caso real.
            _ = _statusForm?.Handle;

            // ⚠️ SIN filtro de nombre: se vigila el DIRECTORIO entero.
            //
            // La primera versión filtraba por tray-status.json, que era
            // correcto cuando el watcher existía solo para el indicador. Desde
            // ADR-0012 paso 2 en ese mismo directorio aparece también
            // consent-request.json, y con el filtro puesto la bandeja NO se
            // habría despertado al publicarse una petición de consentimiento:
            // el aviso habría esperado hasta 5 s, o hasta vencer, y el
            // resultado visible sería un permiso denegado por plazo que nadie
            // decidió.
            //
            // El directorio es de tráfico bajo —unos pocos ficheros del propio
            // agente—, así que vigilarlo entero no cuesta nada.
            _statusWatcher = new FileSystemWatcher(dir)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size
            };

            // Los eventos llegan en un hilo del pool; tocar controles desde ahí
            // es InvalidOperationException. El debounce es un Forms.Timer, que
            // corre en el hilo de UI, así que hay que saltar a él primero.
            void Bump(object? _, FileSystemEventArgs __)
            {
                try
                {
                    if (_statusForm is { IsHandleCreated: true })
                    {
                        _statusForm.BeginInvoke(() =>
                        {
                            _watchDebounce.Stop();
                            _watchDebounce.Start();
                        });
                    }
                }
                catch
                {
                    // Form en proceso de destrucción mientras llega un evento:
                    // el temporizador de 5 s cubre lo que quede de vida.
                }
            }

            _statusWatcher.Changed += Bump;
            _statusWatcher.Created += Bump;
            _statusWatcher.Renamed += (s, e) => Bump(s, e);
            _statusWatcher.EnableRaisingEvents = true;
        }
        catch
        {
            _statusWatcher = null;
        }
    }

    protected override void ExitThreadCore()
    {
        _timer?.Stop();
        // Cortar el watcher ANTES de destruir los forms: un evento en vuelo que
        // llegue después no tiene a quién marshalarse.
        if (_statusWatcher is not null)
        {
            _statusWatcher.EnableRaisingEvents = false;
            _statusWatcher.Dispose();
            _statusWatcher = null;
        }
        _watchDebounce.Stop();
        _watchDebounce.Dispose();
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _trayIcon.Dispose();
        _timer?.Dispose();
        // Pueden no existir si el arranque quedó degradado.
        _statusForm?.Dispose();
        _deviceFlyout?.Dispose();
        _remoteBanner?.Dispose();
        base.ExitThreadCore();
    }

    private void RefreshStatus()
    {
        // Confirmed via a real crash log (2026-08-18): an
        // ObjectDisposedException on DeviceInfoFlyout, thrown from
        // Show() -> SetVisibleCore -> CreateHandle, inside this exact
        // Timer tick. Nothing in this codebase disposes _deviceFlyout
        // outside ExitThreadCore (reachable only via the "Exit Tray"
        // menu item, which the user hadn't clicked) — the only other
        // candidate is Windows Restart Manager sending a close signal to
        // this always-live top-level window (no taskbar entry, but a
        // real HWND whenever policy shows it) while msiexec has this
        // .exe's file locked during an upgrade. Whatever the exact
        // trigger, the old instance is gone for good once it happens —
        // recreate rather than let one bad tick crash (and, per
        // Program.cs's restart-once guard, potentially permanently kill)
        // the whole tray.
        // Arranque degradado: no hay ventanas que refrescar y el icono ya está
        // puesto. Salir en silencio evita convertir un fallo de construcción en
        // una excepción cada 5 segundos.
        if (_degraded || _statusForm is null || _deviceFlyout is null || _remoteBanner is null)
        {
            return;
        }

        if (_deviceFlyout.IsDisposed)
        {
            _deviceFlyout = new DeviceInfoFlyout();
        }

        // Same external-close risk applies to _statusForm in principle,
        // but recreating it would also mean re-wiring FormClosing /
        // VisibleChanged / the NotifyIcon.DoubleClick handler — skip the
        // tick instead of guessing at that wiring untested.
        if (_statusForm.IsDisposed)
        {
            return;
        }

        TrayStatus? status = _reader.Read();
        _statusForm.Render(status);
        _deviceFlyout.Render(status);

        // El indicador de sesión remota NO se gatea por policy, al contrario
        // que el flyout de device info. Saber que te están viendo la pantalla
        // no es una función que un tenant pueda apagar: si se pudiera, el
        // primero en apagarla sería quien más motivos tiene para mirar sin que
        // se note. El único interruptor es que haya sesión o no la haya.
        _remoteBanner.Render(status?.RemoteSession);

        // ADR-0012 — las dos puertas de consentimiento. Va en el mismo
        // refresco que el indicador: el watcher del fichero de estado ya
        // despierta esto en ~150 ms cuando AgentCore publica la petición.
        // Handle() es idempotente, así que llamarlo en cada tick es lo
        // normal.
        ConsentPrompt.Handle(ConsentPrompt.Read(_reader.StatusPath));

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
        // Sin ventana (arranque degradado) el menú no puede reventar: sería
        // volver a matar la bandeja por el mismo camino que veníamos a cerrar.
        if (_statusForm is null || _statusForm.IsDisposed)
        {
            return;
        }

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

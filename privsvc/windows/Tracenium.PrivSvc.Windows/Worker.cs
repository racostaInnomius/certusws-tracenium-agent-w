using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Tracenium.PrivSvc.Windows.Ipc;

namespace Tracenium.PrivSvc.Windows;

public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly NamedPipeServer _pipeServer;

    public Worker(ILogger<Worker> logger)
    {
        _logger = logger;
        _pipeServer = new NamedPipeServer(
            pipeName: "tracenium.privsvc.v1",
            router: new Router(logger),
            logger: logger);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("TraceniumPrivSvc starting...");

        // Repair AgentCore's SCM restart policy before anything else. The MSI
        // is supposed to set this, but hosts have been found in the field with
        // no failure actions at all — one crash away from staying down forever.
        // We run as LocalSystem and start before AgentCore (it depends on us),
        // so this is the earliest point where the fix can land, and it reaches
        // already-deployed hosts without needing an upgrade.
        ServiceRecovery.EnsureConfigured(_logger);

        // Relight the DP blob server if this endpoint holds a cache. The
        // listener only ever started from a prefetch, so every restart left a
        // designated DP holding its files and serving none of them until the
        // next prefetch — up to 24 hours later. Same shape as the repair above:
        // earliest point it can land, and it reaches deployed hosts.
        Ipc.Dp.EnsureServerOnStartup(m => _logger.LogInformation("{Message}", m));

        _ = Task.Run(async () =>
        {
            try
            {
                await _pipeServer.RunAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                // normal on stop
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "PrivSvc crashed.");
            }
            finally
            {
                _logger.LogInformation("TraceniumPrivSvc stopped.");
            }
        }, stoppingToken);

        return Task.CompletedTask;
    }
}
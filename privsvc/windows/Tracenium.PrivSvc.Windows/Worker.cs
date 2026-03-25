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
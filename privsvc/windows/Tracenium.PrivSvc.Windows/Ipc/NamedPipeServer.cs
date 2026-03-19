using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Tracenium.PrivSvc.Windows.Ipc;

public sealed class NamedPipeServer
{
    private readonly string _pipeName;
    private readonly Router _router;
    private readonly ILogger _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    public NamedPipeServer(string pipeName, Router router, ILogger logger)
    {
        _pipeName = pipeName;
        _router = router;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _logger.LogInformation("NamedPipe server starting: \\\\.\\pipe\\{Pipe}", _pipeName);

        while (!ct.IsCancellationRequested)
        {
            // Each connection gets its own server instance
            var server = CreateServerStreamWithAcl();

            // Wait for client connection
            await server.WaitForConnectionAsync(ct);

            // Handle client without blocking accept loop
            _ = Task.Run(() => HandleClientAsync(server, ct), ct);
        }
    }

    private NamedPipeServerStream CreateServerStreamWithAcl()
    {
        // Allow only:
        // - LocalSystem (PrivSvc service)
        // - NT SERVICE\TraceniumAgentCore (AgentCore client service)
        // - Administrators (support / debugging)
        var ps = new PipeSecurity();

        ps.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));


        // Allow the AgentCore Windows service
        try
        {
            var agentCoreSid = (SecurityIdentifier)
                new NTAccount("NT SERVICE", "TraceniumAgentCore")
                .Translate(typeof(SecurityIdentifier));

            ps.AddAccessRule(new PipeAccessRule(
                agentCoreSid,
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to resolve SID for NT SERVICE\\TraceniumAgentCore");
        }

        ps.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.ReadWrite,
            AccessControlType.Allow));

        // Important: do NOT grant Everyone/Users.

        return NamedPipeServerStreamAcl.Create(
            pipeName: _pipeName,
            direction: PipeDirection.InOut,
            maxNumberOfServerInstances: NamedPipeServerStream.MaxAllowedServerInstances,
            transmissionMode: PipeTransmissionMode.Byte,
            options: PipeOptions.Asynchronous,
            inBufferSize: 64 * 1024,
            outBufferSize: 64 * 1024,
            pipeSecurity: ps
        );
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        try
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, bufferSize: 64 * 1024, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), bufferSize: 64 * 1024, leaveOpen: true)
            {
                AutoFlush = true
            };

            // Protocol: 1 JSON object per line (request), respond with 1 JSON per line
            while (pipe.IsConnected && !ct.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync();
                if (line is null) break; // client disconnected
                if (string.IsNullOrWhiteSpace(line)) continue;

                // Basic DoS protection: reject excessively large IPC messages
                string? reqId = null;
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    if (doc.RootElement.TryGetProperty("id", out var idProp))
                    {
                        reqId = idProp.GetString();
                    }
                }
                catch
                {
                    // best effort only; bad JSON will be handled below
                }

                if (line.Length > 64 * 1024) // 64KB limit
                {
                    _logger.LogWarning("IPC request too large, rejecting. reqId={ReqId}", reqId);
                    var err = PrivSvcResponse.Fail(reqId ?? "", "request_too_large", "IPC request exceeds allowed size.");
                    var errJson = JsonSerializer.Serialize(err, JsonOpts);

                    try
                    {
                        await writer.WriteLineAsync(errJson);
                    }
                    catch { }

                    break;
                }

                PrivSvcResponse resp;
                PrivSvcRequest? req = null;
                try
                {
                    req = JsonSerializer.Deserialize<PrivSvcRequest>(line, JsonOpts);
                    if (req is null)
                    {
                        resp = PrivSvcResponse.Fail(reqId ?? "", "bad_json", "Could not parse request.");
                    }
                    else
                    {
                        resp = await _router.HandleAsync(req, ct);
                    }
                }
                catch (JsonException jex)
                {
                    _logger.LogWarning(jex, "Bad JSON received. reqId={ReqId}", reqId);
                    resp = PrivSvcResponse.Fail(reqId ?? "", "bad_json", "Invalid JSON.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Handler error. reqId={ReqId}", req?.Id ?? reqId);
                    resp = PrivSvcResponse.Fail(req?.Id ?? reqId ?? "", "internal_error", "Unhandled server error.");
                }

                var respJson = JsonSerializer.Serialize(resp, JsonOpts);

                try
                {
                    await writer.WriteLineAsync(respJson);
                }
                catch (IOException)
                {
                    // client closed the pipe while we were responding
                    _logger.LogDebug("Client disconnected while writing response.");
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // normal on shutdown
        }
        catch (IOException)
        {
            // normal when client closes pipe early
            _logger.LogDebug("Pipe closed by client.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Client handler crashed.");
        }
        finally
        {
            try
            {
                if (pipe.IsConnected) pipe.Disconnect();
            }
            catch { }
            pipe.Dispose();
        }
    }
}
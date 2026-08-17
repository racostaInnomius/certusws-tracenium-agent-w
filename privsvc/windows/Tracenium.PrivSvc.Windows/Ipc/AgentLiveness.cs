// Ipc/AgentLiveness.cs
//
// Tracks whether AgentCore — the Node.js service on the other side of the
// named pipe — is actually alive, so the PrivSvc stops vouching for a process
// that is gone.
//
// Why this exists:
//
// GrpcBridge runs its own HeartbeatLoop on a 30s timer. That loop was added so
// an idle stream stays open (a receive-only stream false-fired as dead every
// 270s), and it writes to the control plane WITHOUT consulting AgentCore. The
// backend derives "online now" from device_sessions.last_heartbeat inside 90s.
//
// Put together: while the PrivSvc lives, the device reports online — even when
// AgentCore crashed days ago. In August 2026 that hid 12 of 22 endpoints whose
// AgentCore had died (WinSW's log appender killed it during midnight rotation).
// Operators saw a green fleet; jobs dispatched to those devices sat in `sent`
// forever, because the stream is held open by the PrivSvc but jobs are executed
// by AgentCore.
//
// The heartbeat has to mean "the agent is alive", not "the pipe server is
// alive". Every IPC call arriving from AgentCore stamps this class, and the
// heartbeat loop refuses to speak for an agent that has gone quiet.
//
// Deliberately NOT a process check: AgentCore can be running yet wedged (a
// blocked event loop still leaves the process listed). Traffic on the pipe is
// the honest signal — it proves the event loop is turning.

using System;

namespace Tracenium.PrivSvc.Windows.Ipc;

public static class AgentLiveness
{
    /// <summary>
    /// How long AgentCore may stay silent before the PrivSvc stops emitting
    /// heartbeats on its behalf.
    ///
    /// AgentCore drives grpc.heartbeat every 60s (HEARTBEAT_INTERVAL_MS in
    /// src/transport/grpc-stream.ts), so this is five consecutive misses —
    /// long enough to ride out a slow privileged call or a GC pause, short
    /// enough that the backend flips the device offline within minutes
    /// instead of never.
    /// </summary>
    private static readonly TimeSpan SilenceThreshold = TimeSpan.FromMinutes(5);

    private static long _lastSeenTicksUtc;

    /// <summary>Record that AgentCore just spoke to us. Called on every IPC request.</summary>
    public static void Touch()
    {
        Interlocked.Exchange(ref _lastSeenTicksUtc, DateTime.UtcNow.Ticks);
    }

    /// <summary>UTC of the last IPC call from AgentCore, or null if it has never called.</summary>
    public static DateTime? LastSeenUtc
    {
        get
        {
            var ticks = Interlocked.Read(ref _lastSeenTicksUtc);
            return ticks == 0 ? null : new DateTime(ticks, DateTimeKind.Utc);
        }
    }

    /// <summary>
    /// True when AgentCore has spoken recently enough to be considered alive.
    ///
    /// Returns false before the first call ever arrives: the gRPC stream is
    /// only opened by an AgentCore `grpc.connect`, so in practice this is
    /// already stamped by the time any heartbeat could fire.
    /// </summary>
    public static bool IsAlive
    {
        get
        {
            var last = LastSeenUtc;
            return last.HasValue && DateTime.UtcNow - last.Value < SilenceThreshold;
        }
    }

    /// <summary>Seconds of silence, for log lines. 0 when never seen.</summary>
    public static long SilenceSeconds
    {
        get
        {
            var last = LastSeenUtc;
            return last.HasValue ? (long)(DateTime.UtcNow - last.Value).TotalSeconds : 0;
        }
    }
}

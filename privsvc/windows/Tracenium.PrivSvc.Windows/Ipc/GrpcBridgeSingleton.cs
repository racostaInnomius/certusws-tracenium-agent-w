// privsvc/windows/Tracenium.PrivSvc.Windows/Ipc/GrpcBridgeSingleton.cs
using Tracenium.PrivSvc.Windows.Grpc;

namespace Tracenium.PrivSvc.Windows;

public static class GrpcBridgeSingleton
{
    public static readonly GrpcBridge Instance = new();
}
import Foundation

struct TrayStatus: Decodable {
    var updatedAtUtc: Date?
    var agentVersion: String
    var coreVersion: String
    var deviceId: String
    var tenantId: String
    var hostname: String
    var grpc: TrayGrpcStatus
    var policy: TrayPolicyStatus
    var jobs: TrayJobStatus
    var update: TrayUpdateStatus
    var patch: TrayPatchStatus
    // Device Info tab (support widget). Optional — older agents don't
    // write this block; the tab shows placeholders in that case.
    var device: TrayDeviceInfo?
}

/// Static device identity written by the agent at startup. The
/// logged-in user and screen resolution are NOT here — this app runs in
/// the user session, so it reads those live (NSUserName / NSScreen)
/// where the root agent's view would be wrong.
struct TrayDeviceInfo: Decodable {
    var hostname: String?
    var domain: String?
    var fqdn: String?
    var ipv4: String?
    var ipv6: String?
    var mac: String?
    var osName: String?
    var osVersion: String?
    var osBuild: String?
    var manufacturer: String?
    var model: String?
    var serial: String?
    var cpu: String?
    var memoryGb: Double?
}

struct TrayGrpcStatus: Decodable {
    var connected: Bool
    var lastConnectedAtUtc: Date?
    var lastDisconnectedAtUtc: Date?
    var lastHeartbeatAtUtc: Date?
}

struct TrayPolicyStatus: Decodable {
    var version: String
    var hash: String?
    var plugins: [String]
    var modules: [String]
    /// Optional so snapshots written by older agents still decode.
    var features: TrayPolicyFeatures?
}

/// Feature switches the user-session app acts on. The daemon owns the policy;
/// this is how it tells the app what it is allowed to do.
struct TrayPolicyFeatures: Decodable {
    var deviceInfoWidget: Bool?
    var locationTracking: Bool?
}

struct TrayJobStatus: Decodable {
    var lastJobType: String?
    var lastJobStatus: String?
    var lastJobAtUtc: Date?
}

struct TrayUpdateStatus: Decodable {
    var status: String?
    var lastCheckedAtUtc: Date?
    var lastCompletedAtUtc: Date?
    var lastError: String?
}

struct TrayPatchStatus: Decodable {
    var status: String?
    var lastScanAtUtc: Date?
    var rebootRequired: Bool?
    var lastError: String?
}

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

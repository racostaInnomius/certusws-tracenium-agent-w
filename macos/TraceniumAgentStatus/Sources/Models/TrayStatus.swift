import Foundation

/// The daemon's snapshot, decoded DEFENSIVELY.
///
/// ⚠️ Why the hand-written initializer instead of the synthesized one.
///
/// The daemon and this app ship as one package but evolve independently, and
/// the synthesized Decodable is all-or-nothing: one missing key, one renamed
/// block, one type that changed, and the WHOLE snapshot fails to decode. The
/// app then behaves as if no snapshot existed at all — no status, no device
/// info, and (the way we found this) no location, because the policy that
/// enables it never arrives.
///
/// That is exactly what happened in the field: a Mac retried every 5 seconds
/// for days, logging "isn't in the correct format", while the file on disk was
/// perfectly readable and had locationTracking: true right there in it.
///
/// So every field degrades on its own now. A block the daemon stopped writing
/// costs that block's panel, not the entire app.
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

    private enum CodingKeys: String, CodingKey {
        case updatedAtUtc, agentVersion, coreVersion, deviceId, tenantId
        case hostname, grpc, policy, jobs, update, patch, device
    }

    init(from decoder: Decoder) throws {
        // A container that is not even an object is a genuine failure — there
        // is nothing to salvage. Everything below it degrades individually.
        let c = try decoder.container(keyedBy: CodingKeys.self)

        updatedAtUtc = try? c.decodeIfPresent(Date.self, forKey: .updatedAtUtc)
        agentVersion = (try? c.decodeIfPresent(String.self, forKey: .agentVersion)) as? String ?? ""
        coreVersion  = (try? c.decodeIfPresent(String.self, forKey: .coreVersion)) as? String ?? ""
        deviceId     = (try? c.decodeIfPresent(String.self, forKey: .deviceId)) as? String ?? ""
        tenantId     = (try? c.decodeIfPresent(String.self, forKey: .tenantId)) as? String ?? ""
        hostname     = (try? c.decodeIfPresent(String.self, forKey: .hostname)) as? String ?? ""

        grpc   = ((try? c.decodeIfPresent(TrayGrpcStatus.self, forKey: .grpc)) ?? nil) ?? TrayGrpcStatus(connected: false)
        policy = ((try? c.decodeIfPresent(TrayPolicyStatus.self, forKey: .policy)) ?? nil)
            ?? TrayPolicyStatus(version: "", hash: nil, plugins: [], modules: [], features: nil)
        jobs   = ((try? c.decodeIfPresent(TrayJobStatus.self, forKey: .jobs)) ?? nil) ?? TrayJobStatus()
        update = ((try? c.decodeIfPresent(TrayUpdateStatus.self, forKey: .update)) ?? nil) ?? TrayUpdateStatus()
        patch  = ((try? c.decodeIfPresent(TrayPatchStatus.self, forKey: .patch)) ?? nil) ?? TrayPatchStatus()
        device = (try? c.decodeIfPresent(TrayDeviceInfo.self, forKey: .device)) ?? nil
    }
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

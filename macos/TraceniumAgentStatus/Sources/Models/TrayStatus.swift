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
    // Software Catalog tab (self-service installs). Optional for the
    // same reason as device: absent on snapshots from an agent that
    // predates this feature.
    var catalog: TrayCatalogStatus?
    // Sesión de control remoto viva (ADR-0012). Ausente en agentes
    // anteriores y —lo normal— siempre que nadie esté mirando.
    var remoteSession: TrayRemoteSession?

    private enum CodingKeys: String, CodingKey {
        case updatedAtUtc, agentVersion, coreVersion, deviceId, tenantId
        case hostname, grpc, policy, jobs, update, patch, device, catalog
        case remoteSession
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
        catalog = (try? c.decodeIfPresent(TrayCatalogStatus.self, forKey: .catalog)) ?? nil
        remoteSession = (try? c.decodeIfPresent(TrayRemoteSession.self, forKey: .remoteSession)) ?? nil
    }
}

/// Sesión de control remoto viva en este equipo (ADR-0012).
///
/// Alimenta el indicador PERMANENTE: no un aviso que se descarta, sino algo
/// que sigue ahí mientras dure. Lo que protege a la persona no es enterarse
/// una vez, sino poder ver en todo momento que la están mirando y cortarlo.
///
/// La decodificación degrada campo a campo como el resto del fichero, con una
/// asimetría deliberada: si `active` no se puede leer, vale `false`. Es el
/// único sitio del modelo donde el valor por defecto apaga una alarma, y es
/// correcto — encender la banda por un campo ilegible enseñaría un aviso falso
/// cada vez que el JSON cambie de forma, y una alarma falsa entrena a la gente
/// a ignorar la de verdad. El indicador se enciende porque el agente lo dice,
/// no porque no se le entienda.
struct TrayRemoteSession: Decodable {
    var active: Bool
    var sessionId: String
    var capability: String
    var startedAtUtc: Date?
    /// Quién está mirando. Vacío en backends anteriores al campo; la banda
    /// dice "un operador" antes que inventarse un nombre.
    var `operator`: String?
    var controlling: Bool
    var recording: Bool

    private enum CodingKeys: String, CodingKey {
        case active, sessionId, capability, startedAtUtc, `operator`, controlling, recording
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        active = ((try? c.decodeIfPresent(Bool.self, forKey: .active)) ?? nil) ?? false
        sessionId = ((try? c.decodeIfPresent(String.self, forKey: .sessionId)) ?? nil) ?? ""
        capability = ((try? c.decodeIfPresent(String.self, forKey: .capability)) ?? nil) ?? ""
        startedAtUtc = (try? c.decodeIfPresent(Date.self, forKey: .startedAtUtc)) ?? nil
        `operator` = (try? c.decodeIfPresent(String.self, forKey: .operator)) ?? nil
        controlling = ((try? c.decodeIfPresent(Bool.self, forKey: .controlling)) ?? nil) ?? false
        recording = ((try? c.decodeIfPresent(Bool.self, forKey: .recording)) ?? nil) ?? false
    }

    init(active: Bool, sessionId: String, capability: String = "rcp.screen",
         startedAtUtc: Date? = nil, operator op: String? = nil,
         controlling: Bool = false, recording: Bool = false) {
        self.active = active
        self.sessionId = sessionId
        self.capability = capability
        self.startedAtUtc = startedAtUtc
        self.`operator` = op
        self.controlling = controlling
        self.recording = recording
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

/// Lenient like TrayStatus, and for the same reason: replacing the whole block
/// on one bad field would throw away the good fields next to it.
struct TrayGrpcStatus: Decodable {
    var connected: Bool
    var lastConnectedAtUtc: Date?
    var lastDisconnectedAtUtc: Date?
    var lastHeartbeatAtUtc: Date?

    private enum CodingKeys: String, CodingKey { case connected, lastConnectedAtUtc, lastDisconnectedAtUtc, lastHeartbeatAtUtc }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        connected = ((try? c.decodeIfPresent(Bool.self, forKey: .connected)) ?? nil) ?? false
        lastConnectedAtUtc = (try? c.decodeIfPresent(Date.self, forKey: .lastConnectedAtUtc)) ?? nil
        lastDisconnectedAtUtc = (try? c.decodeIfPresent(Date.self, forKey: .lastDisconnectedAtUtc)) ?? nil
        lastHeartbeatAtUtc = (try? c.decodeIfPresent(Date.self, forKey: .lastHeartbeatAtUtc)) ?? nil
    }

    init(connected: Bool) {
        self.connected = connected
    }
}

struct TrayPolicyStatus: Decodable {
    var version: String
    var hash: String?
    var plugins: [String]
    var modules: [String]
    /// Optional so snapshots written by older agents still decode.
    var features: TrayPolicyFeatures?

    private enum CodingKeys: String, CodingKey { case version, hash, plugins, modules, features }

    /// ⚠️ `features` is the field the location pipeline hangs off. A policy
    /// block that fails to decode used to be swapped for a default with
    /// `features: nil`, which reads as "location off" — so one missing
    /// `version` string silently disabled positioning on the whole machine.
    /// Every field degrades on its own so that cannot happen again.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version  = ((try? c.decodeIfPresent(String.self, forKey: .version)) ?? nil) ?? ""
        hash     = (try? c.decodeIfPresent(String.self, forKey: .hash)) ?? nil
        plugins  = ((try? c.decodeIfPresent([String].self, forKey: .plugins)) ?? nil) ?? []
        modules  = ((try? c.decodeIfPresent([String].self, forKey: .modules)) ?? nil) ?? []
        features = (try? c.decodeIfPresent(TrayPolicyFeatures.self, forKey: .features)) ?? nil
    }

    init(version: String, hash: String?, plugins: [String], modules: [String], features: TrayPolicyFeatures?) {
        self.version = version
        self.hash = hash
        self.plugins = plugins
        self.modules = modules
        self.features = features
    }
}

/// Feature switches the user-session app acts on. The daemon owns the policy;
/// this is how it tells the app what it is allowed to do.
struct TrayPolicyFeatures: Decodable {
    var deviceInfoWidget: Bool?
    var locationTracking: Bool?
}

/// Lenient like TrayStatus, and for the same reason: a malformed
/// `current` block (e.g. a future agent version adding a field this
/// app doesn't know about yet, or a genuinely corrupt write) must not
/// take lastJobType/lastJobStatus/lastJobAtUtc down with it.
struct TrayJobStatus: Decodable {
    var lastJobType: String?
    var lastJobStatus: String?
    var lastJobAtUtc: Date?
    /// The job actively executing right now, if any — present only
    /// between markJobStarted() and its matching markJobFinished() on
    /// the agent side. Drives the "Active Job" tab and the menu-bar
    /// badge. Optional so snapshots from older agents (no `current`
    /// key at all) still decode.
    var current: TrayCurrentJob?

    private enum CodingKeys: String, CodingKey { case lastJobType, lastJobStatus, lastJobAtUtc, current }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        lastJobType = (try? c.decodeIfPresent(String.self, forKey: .lastJobType)) ?? nil
        lastJobStatus = (try? c.decodeIfPresent(String.self, forKey: .lastJobStatus)) ?? nil
        lastJobAtUtc = (try? c.decodeIfPresent(Date.self, forKey: .lastJobAtUtc)) ?? nil
        current = (try? c.decodeIfPresent(TrayCurrentJob.self, forKey: .current)) ?? nil
    }

    init(
        lastJobType: String? = nil,
        lastJobStatus: String? = nil,
        lastJobAtUtc: Date? = nil,
        current: TrayCurrentJob? = nil
    ) {
        self.lastJobType = lastJobType
        self.lastJobStatus = lastJobStatus
        self.lastJobAtUtc = lastJobAtUtc
        self.current = current
    }
}

/// No progress percentage here on purpose: RunJob over gRPC carries
/// only jobId/jobType/payload (see proto/controlplane.proto) — the
/// agent itself has no timeout or step-count signal to report. The UI
/// shows elapsed time (real, computed from startedAtUtc) plus an
/// indeterminate spinner instead of fabricating a percentage.
struct TrayCurrentJob: Decodable {
    var jobId: String
    var jobType: String
    var startedAtUtc: Date?
}

/// One entry in the self-service Software Catalog tab. Mirrors proto
/// SoftwareCatalogItem — see controlplane.proto's "SOFTWARE CATALOG
/// (self-service)" doc block for why the agent (not the tray) is the
/// one that asks the backend for this list.
struct TrayCatalogItem: Decodable {
    var packageId: String
    var name: String
    var vendor: String?
    var version: String
    var description: String?
    var requiresReboot: Bool?
}

/// Lenient like TrayJobStatus: a malformed entry in `items` degrading
/// the WHOLE catalog block would take every other, perfectly good,
/// package with it — worse than just dropping the one bad row.
struct TrayCatalogStatus: Decodable {
    var updatedAtUtc: Date?
    var catalogVersion: String?
    var items: [TrayCatalogItem]

    private enum CodingKeys: String, CodingKey { case updatedAtUtc, catalogVersion, items }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        updatedAtUtc = (try? c.decodeIfPresent(Date.self, forKey: .updatedAtUtc)) ?? nil
        catalogVersion = (try? c.decodeIfPresent(String.self, forKey: .catalogVersion)) ?? nil

        if let rawItems = try? c.decodeIfPresent([TrayCatalogItem].self, forKey: .items) {
            items = rawItems
        } else {
            // One malformed item throws for the whole array (Swift's
            // Decodable doesn't skip-and-continue on a heterogeneous
            // JSON array) — degrade to empty rather than losing the
            // rest of the snapshot over one bad catalog row.
            items = []
        }
    }

    init(updatedAtUtc: Date? = nil, catalogVersion: String? = nil, items: [TrayCatalogItem] = []) {
        self.updatedAtUtc = updatedAtUtc
        self.catalogVersion = catalogVersion
        self.items = items
    }
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

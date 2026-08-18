import XCTest
@testable import TraceniumAgentStatus

/// Coverage for TrayCatalogStatus/TrayCatalogItem decoding — the
/// Software Catalog tab's data model. Mirrors TrayStatusDecodingTests'
/// approach: build a full snapshot JSON per case and decode the real
/// TrayStatus type, rather than decoding TrayCatalogStatus in
/// isolation, so back-compat with older snapshots is exercised the
/// same way production actually sees it (one JSON document decoded
/// once, not a sub-document handed to a sub-decoder).
final class CatalogDecodingTests: XCTestCase {
    private func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    private func baseSnapshotJson(catalogBlock: String?) -> String {
        let catalogField = catalogBlock.map { "\"catalog\": \($0),\n  " } ?? ""
        return """
        {
          "updatedAtUtc": "2026-08-18T00:00:00Z",
          "agentVersion": "1.1.40",
          "coreVersion": "1.1.40",
          "deviceId": "7149a30a-1181-41ed-86a7-08c7a62f20b4",
          "tenantId": "1",
          "hostname": "MacBook-Air-de-Rodrigo.local",
          "grpc": { "connected": true },
          "policy": { "version": "1786994430666", "plugins": [], "modules": [] },
          "jobs": {},
          "update": {},
          "patch": {},
          \(catalogField)"__end": null
        }
        """
    }

    func testDecodesCatalogItemsWhenPresent() throws {
        let json = baseSnapshotJson(catalogBlock: """
        {
          "updatedAtUtc": "2026-08-18T00:05:00Z",
          "catalogVersion": "abc123",
          "items": [
            {
              "packageId": "1",
              "name": "Zoom",
              "vendor": "Zoom Video",
              "version": "6.1.0",
              "description": "Video conferencing",
              "requiresReboot": false
            },
            {
              "packageId": "2",
              "name": "Slack",
              "version": "4.40.0"
            }
          ]
        }
        """)

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertEqual(status.catalog?.catalogVersion, "abc123")
        XCTAssertEqual(status.catalog?.items.count, 2)
        XCTAssertEqual(status.catalog?.items.first?.packageId, "1")
        XCTAssertEqual(status.catalog?.items.first?.name, "Zoom")
        XCTAssertEqual(status.catalog?.items.first?.vendor, "Zoom Video")
        XCTAssertEqual(status.catalog?.items.first?.requiresReboot, false)
        // Slack has no vendor/description/requiresReboot in the JSON —
        // must decode with those as nil, not throw.
        XCTAssertEqual(status.catalog?.items.last?.packageId, "2")
        XCTAssertNil(status.catalog?.items.last?.vendor)
        XCTAssertNil(status.catalog?.items.last?.description)
        XCTAssertNil(status.catalog?.items.last?.requiresReboot)
    }

    func testMissingCatalogKeyDecodesAsNil() throws {
        // Snapshot from an agent that predates this feature — no
        // "catalog" key in the document at all.
        let json = baseSnapshotJson(catalogBlock: nil)

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertNil(status.catalog)
    }

    func testEmptyItemsArrayDecodesCleanly() throws {
        let json = baseSnapshotJson(catalogBlock: """
        { "catalogVersion": "empty", "items": [] }
        """)

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertEqual(status.catalog?.catalogVersion, "empty")
        XCTAssertEqual(status.catalog?.items, [])
    }

    func testMalformedItemsArrayDegradesToEmptyRatherThanThrowing() throws {
        // One malformed entry (missing required "name"/"version") fails
        // Swift's array decode for the WHOLE items array — there is no
        // per-element skip-and-continue for a homogeneous [T] the way
        // TrayStatus's own top-level fields degrade individually.
        // TrayCatalogStatus's custom init catches that and falls back
        // to items: [] rather than losing the surrounding snapshot
        // (device info, jobs, grpc status, etc. all still decode).
        let json = baseSnapshotJson(catalogBlock: """
        {
          "catalogVersion": "broken",
          "items": [ { "packageId": "1" } ]
        }
        """)

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertEqual(status.catalog?.items, [])
        // The catalogVersion field itself is a plain optional String
        // decode, independent of the items array — it should still
        // come through.
        XCTAssertEqual(status.catalog?.catalogVersion, "broken")
        // Prove the rest of the snapshot is unaffected.
        XCTAssertEqual(status.deviceId, "7149a30a-1181-41ed-86a7-08c7a62f20b4")
        XCTAssertTrue(status.grpc.connected)
    }

    func testExplicitNullCatalogDecodesAsNil() throws {
        let json = baseSnapshotJson(catalogBlock: "null")

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertNil(status.catalog)
    }
}

extension TrayCatalogItem: Equatable {
    public static func == (lhs: TrayCatalogItem, rhs: TrayCatalogItem) -> Bool {
        lhs.packageId == rhs.packageId
            && lhs.name == rhs.name
            && lhs.vendor == rhs.vendor
            && lhs.version == rhs.version
            && lhs.description == rhs.description
            && lhs.requiresReboot == rhs.requiresReboot
    }
}

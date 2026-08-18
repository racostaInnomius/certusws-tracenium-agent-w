import XCTest
@testable import TraceniumAgentStatus

final class TrayStatusDecodingTests: XCTestCase {
    private func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }

    private func baseSnapshotJson(jobsBlock: String) -> String {
        """
        {
          "updatedAtUtc": "2026-08-17T23:51:55Z",
          "agentVersion": "1.1.38",
          "coreVersion": "1.1.38",
          "deviceId": "7149a30a-1181-41ed-86a7-08c7a62f20b4",
          "tenantId": "1",
          "hostname": "MacBook-Air-de-Rodrigo.local",
          "grpc": { "connected": true },
          "policy": { "version": "1786994430666", "plugins": [], "modules": [] },
          "jobs": \(jobsBlock),
          "update": {},
          "patch": {}
        }
        """
    }

    func testDecodesJobsCurrentWhenAJobIsRunning() throws {
        let json = baseSnapshotJson(jobsBlock: """
        {
          "lastJobType": "patch_install",
          "lastJobStatus": "in_progress",
          "lastJobAtUtc": "2026-08-17T23:17:48Z",
          "current": {
            "jobId": "job-123",
            "jobType": "patch_install",
            "startedAtUtc": "2026-08-17T23:17:48Z"
          }
        }
        """)

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertEqual(status.jobs.current?.jobId, "job-123")
        XCTAssertEqual(status.jobs.current?.jobType, "patch_install")
        XCTAssertNotNil(status.jobs.current?.startedAtUtc)
    }

    func testDecodesAbsentCurrentAsNilWhenNoJobIsRunning() throws {
        let json = baseSnapshotJson(jobsBlock: """
        {
          "lastJobType": "patch_install",
          "lastJobStatus": "success",
          "lastJobAtUtc": "2026-08-17T16:23:25Z"
        }
        """)

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertNil(status.jobs.current)
    }

    func testDecodesOlderSnapshotsWithNoJobsCurrentKeyAtAll() throws {
        // Snapshots written by an agent from before this feature existed
        // have no "current" key in "jobs" whatsoever — must still decode
        // cleanly rather than throwing (an older agent shouldn't be able
        // to crash a newer tray app).
        let json = baseSnapshotJson(jobsBlock: "{}")

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertNil(status.jobs.current)
    }

    func testExplicitNullCurrentDecodesAsNil() throws {
        let json = baseSnapshotJson(jobsBlock: """
        { "current": null }
        """)

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertNil(status.jobs.current)
    }

    func testMalformedCurrentDoesNotTakeDownTheRestOfJobs() throws {
        // TrayJobStatus decodes defensively (matching TrayStatus/
        // TrayGrpcStatus/TrayPolicyStatus in this same file) — a
        // `current` block missing its required jobId/jobType must not
        // wipe out lastJobType/lastJobStatus/lastJobAtUtc next to it.
        let json = baseSnapshotJson(jobsBlock: """
        {
          "lastJobType": "patch_install",
          "lastJobStatus": "success",
          "lastJobAtUtc": "2026-08-17T16:23:25Z",
          "current": { "startedAtUtc": "2026-08-17T23:17:48Z" }
        }
        """)

        let status = try makeDecoder().decode(TrayStatus.self, from: Data(json.utf8))

        XCTAssertNil(status.jobs.current)
        XCTAssertEqual(status.jobs.lastJobType, "patch_install")
        XCTAssertEqual(status.jobs.lastJobStatus, "success")
    }
}

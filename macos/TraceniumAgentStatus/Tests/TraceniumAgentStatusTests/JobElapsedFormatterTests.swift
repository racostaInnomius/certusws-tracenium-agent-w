import XCTest
@testable import TraceniumAgentStatus

final class JobElapsedFormatterTests: XCTestCase {
    func testNilStartReturnsPlaceholder() {
        XCTAssertEqual(JobElapsedFormatter.format(startedAtUtc: nil), "—")
    }

    func testJustStarted() {
        let now = Date()
        XCTAssertEqual(JobElapsedFormatter.format(startedAtUtc: now, now: now), "just started")
    }

    func testSecondsOnly() {
        let now = Date()
        let started = now.addingTimeInterval(-42)
        XCTAssertEqual(JobElapsedFormatter.format(startedAtUtc: started, now: now), "42s")
    }

    func testMinutesAndSeconds() {
        let now = Date()
        let started = now.addingTimeInterval(-(2 * 60 + 14))
        XCTAssertEqual(JobElapsedFormatter.format(startedAtUtc: started, now: now), "2m 14s")
    }

    func testExactMinutesOmitsZeroSeconds() {
        let now = Date()
        let started = now.addingTimeInterval(-5 * 60)
        XCTAssertEqual(JobElapsedFormatter.format(startedAtUtc: started, now: now), "5m")
    }

    func testHoursAndMinutes() {
        let now = Date()
        let started = now.addingTimeInterval(-(3 * 3600 + 7 * 60))
        XCTAssertEqual(JobElapsedFormatter.format(startedAtUtc: started, now: now), "3h 07m")
    }

    func testFutureStartClampsToZero() {
        // Clock skew between the daemon and this process shouldn't
        // produce a negative elapsed time.
        let now = Date()
        let started = now.addingTimeInterval(10)
        XCTAssertEqual(JobElapsedFormatter.format(startedAtUtc: started, now: now), "just started")
    }
}

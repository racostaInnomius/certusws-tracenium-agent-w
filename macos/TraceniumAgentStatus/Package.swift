// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TraceniumAgentStatus",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "TraceniumAgentStatus", targets: ["TraceniumAgentStatus"])
    ],
    targets: [
        .executableTarget(
            name: "TraceniumAgentStatus",
            path: "Sources"
        ),
        .testTarget(
            name: "TraceniumAgentStatusTests",
            dependencies: ["TraceniumAgentStatus"],
            path: "Tests/TraceniumAgentStatusTests"
        )
    ]
)

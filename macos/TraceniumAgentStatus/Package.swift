// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "TraceniumAgentStatus",
    platforms: [
        // 12.3, como tracenium-keystore y tracenium-screencap. Estaba en 13 sin
        // usar nada de 13 (compila igual con 12), y con LSMinimumSystemVersion
        // 13.0 LaunchServices se negaba a abrirla en Monterey: el iMac Intel de
        // T1 (macOS 12.7.6) no veia nunca la ventana de permisos del `--setup`.
        .macOS("12.3")
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

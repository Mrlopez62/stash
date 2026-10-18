// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "StashApp",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "Stash",
            path: "Sources/Stash",
            exclude: ["Fonts"],
            linkerSettings: [
                .linkedFramework("Carbon"),
                .linkedFramework("ScreenCaptureKit"),
                .linkedFramework("Vision"),
            ]
        )
    ]
)

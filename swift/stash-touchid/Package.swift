// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "stash-touchid",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "stash-touchid", path: "Sources/stash-touchid")
    ]
)

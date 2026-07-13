// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Keygate",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "KeygateCore", targets: ["KeygateCore"]),
        .executable(name: "KeygateApp", targets: ["KeygateApp"]),
        .executable(name: "keygate", targets: ["keygate-cli"]),
        .executable(name: "keygate-selftest", targets: ["keygate-selftest"]),
    ],
    dependencies: [
        // Shared design system for the vstack macOS apps.
        .package(path: "../vkit"),
    ],
    targets: [
        .target(
            name: "CBcryptPBKDF",
            path: "Sources/CBcryptPBKDF",
            exclude: ["Package.swift"]
        ),
        .target(
            name: "KeygateCore",
            dependencies: ["CBcryptPBKDF"],
            path: "Sources/KeygateCore"
        ),
        .executableTarget(
            name: "KeygateApp",
            dependencies: [
                "KeygateCore",
                .product(name: "VKit", package: "vkit"),
            ],
            path: "Sources/KeygateApp"
        ),
        .executableTarget(
            name: "keygate-cli",
            dependencies: ["KeygateCore"],
            path: "Sources/keygate-cli"
        ),
        .executableTarget(
            name: "keygate-selftest",
            dependencies: ["KeygateCore"],
            path: "Sources/keygate-selftest"
        ),
    ]
)

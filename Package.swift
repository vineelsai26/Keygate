// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Keygate",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "KeygateCore", targets: ["KeygateCore"]),
        // The app's UI as a library, so it can be embedded (e.g. in PowerTools)
        // as well as run standalone.
        .library(name: "KeygateUI", targets: ["KeygateUI"]),
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
        .target(
            name: "KeygateUI",
            dependencies: [
                "KeygateCore",
                .product(name: "VKit", package: "vkit"),
            ],
            path: "Sources/KeygateUI"
        ),
        .executableTarget(
            name: "KeygateApp",
            dependencies: [
                "KeygateCore", "KeygateUI",
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

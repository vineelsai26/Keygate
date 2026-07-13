// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CBcryptPBKDF",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(name: "CBcryptPBKDF", targets: ["CBcryptPBKDF"]),
    ],
    targets: [
        .target(
            name: "CBcryptPBKDF",
            path: ".",
            exclude: ["Package.swift"],
            publicHeadersPath: "include"
        ),
    ]
)

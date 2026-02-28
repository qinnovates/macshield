// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "MacShield",
    platforms: [.macOS(.v14)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    ],
    targets: [
        .target(
            name: "MacShieldLib",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/MacShieldLib",
            linkerSettings: [
                .linkedFramework("Security"),
            ]
        ),
        .executableTarget(
            name: "MacShield",
            dependencies: [
                "MacShieldLib",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ],
            path: "Sources/MacShield"
        ),
        .testTarget(
            name: "MacShieldTests",
            dependencies: ["MacShieldLib"],
            path: "Tests/MacShieldTests"
        ),
    ]
)

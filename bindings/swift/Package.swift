// swift-tools-version: 5.10

import PackageDescription

let package = Package(
    name: "PQCB",
    platforms: [
        .macOS(.v13),
        .iOS(.v15),
    ],
    products: [
        .library(name: "PQCB", targets: ["PQCB"]),
    ],
    targets: [
        .target(name: "PQCB"),
    ]
)

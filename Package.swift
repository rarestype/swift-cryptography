// swift-tools-version: 6.2
import PackageDescription

let package: Package = .init(
    name: "swift-cryptography",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "Cryptography", targets: ["Cryptography"]),
    ],
    targets: [
        .systemLibrary(
            name: "OpenSSL",
            pkgConfig: "libcrypto",
            providers: [
                .apt(["libssl-dev"])
            ]
        ),
        .target(
            name: "Cryptography",
            dependencies: [
                .target(name: "OpenSSL"),
            ]
        ),
        .testTarget(
            name: "CryptographyTests",
            dependencies: [
                .target(name: "Cryptography"),
            ]
        )
    ]
)

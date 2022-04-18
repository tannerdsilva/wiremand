// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "wiremand",
    platforms: [
    	.macOS(.v12)
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url:"https://github.com/tannerdsilva/Commander.git", .branch("master")),
		.package(url:"https://github.com/tannerdsilva/SwiftSlash.git", .exact("3.1.0")),
		.package(url:"https://github.com/tannerdsilva/QuickLMDB.git", .revision("c4d866c0f3fbd0db5c2513d888c0706a8ca8e318")),
		.package(url:"https://github.com/tannerdsilva/AddressKit.git", .exact("1.1.0")),
		.package(url:"https://github.com/hummingbird-project/hummingbird.git", .exact("0.16.0")),
		.package(url:"https://github.com/tannerdsilva/SignalStack.git", .exact("1.1.1")),
		.package(url:"https://github.com/tannerdsilva/swift-smtp.git", .revision("09a0e2d8cedcc7d4121823ca6aa9cbd81ecb0e00"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .executableTarget(
            name: "wiremand",
            dependencies: [
            	.product(name:"SwiftSlash", package:"SwiftSlash"),
            	.product(name:"Commander", package:"Commander"),
            	.product(name:"QuickLMDB", package:"QuickLMDB"),
            	.product(name:"AddressKit", package:"AddressKit"),
            	.product(name:"Hummingbird", package:"hummingbird"),
            	.product(name:"SignalStack", package:"SignalStack"),
				.product(name:"SwiftSMTP", package:"swift-smtp"),
                "cblake2b"
            ]),
        .target(name:"cblake2b"),
        .testTarget(
            name: "wiremandTests",
            dependencies: ["wiremand"]),
    ]
)

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
		.package(url:"https://github.com/tannerdsilva/SwiftSlash.git", .upToNextMinor(from:"3.1.0")),
		.package(url:"https://github.com/tannerdsilva/QuickLMDB.git", .upToNextMinor(from:"1.0.3")),
		.package(url:"https://github.com/tannerdsilva/AddressKit.git", .upToNextMinor(from:"1.1.0")),
		.package(url:"https://github.com/hummingbird-project/hummingbird.git", .exact("0.16.0")),
		.package(url:"https://github.com/tannerdsilva/SignalStack.git", .upToNextMinor(from:"1.1.1")),
		.package(url:"https://github.com/tannerdsilva/swift-smtp.git", .revision("09a0e2d8cedcc7d4121823ca6aa9cbd81ecb0e00")),
		.package(url:"https://github.com/swift-server/async-http-client.git", .upToNextMinor(from:"1.11.5")),
		.package(url:"https://github.com/tannerdsilva/SwiftDate.git", .branch("master")),
		.package(url:"https://github.com/apple/swift-system.git", .upToNextMajor(from:"1.0.0")),
		.package(url:"https://github.com/tannerdsilva/SwiftBlake2.git", .upToNextMajor(from:"0.0.3"))
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
				.product(name:"AsyncHTTPClient", package:"async-http-client"),
				.product(name:"SwiftDate", package:"SwiftDate"),
				.product(name:"SystemPackage", package:"swift-system"),
				.product(name:"SwiftBlake2", package:"SwiftBlake2")
            ]),
        .testTarget(
            name: "wiremandTests",
            dependencies: ["wiremand"]),
    ]
)

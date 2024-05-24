// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "wiremand",
    platforms: [
    	.macOS(.v14)
    ],
    dependencies: [
        .package(url:"https://github.com/apple/swift-argument-parser.git", .upToNextMinor(from:"1.2.1")),
		.package(url:"https://github.com/tannerdsilva/SwiftSlash.git", .upToNextMinor(from:"3.1.0")),
		.package(url:"https://github.com/tannerdsilva/QuickLMDB.git", revision:"80cc709cb67e6bb6bd0e0ab7cc79f324c7fc4927"),
		// .package(url:"https://github.com/tannerdsilva/AddressKit.git", .upToNextMinor(from:"1.1.0")),
		.package(url:"https://github.com/hummingbird-project/hummingbird.git", exact:"2.0.0-beta.4"),
		// .package(url:"https://github.com/tannerdsilva/SignalStack.git", .upToNextMinor(from:"1.1.1")),
		// .package(url:"https://github.com/tannerdsilva/swift-smtp.git", .revision("ba82aa3b56e75a798b155524fcb083a9f012a844")),
		// .package(url:"https://github.com/swift-server/async-http-client.git", from:"1.0.0"),
		.package(url:"https://github.com/apple/swift-system.git", from:"1.0.0"),
		// .package(url:"https://github.com/tannerdsilva/bedrock.git", revision:"635009cee72326bf74691e472656907896eb23bf"),\
		.package(path:"../bedrock"),
		.package(url:"https://github.com/tannerdsilva/rawdog.git", from:"8.0.0"),
		.package(url:"https://github.com/apple/swift-log.git", from:"1.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        // .executableTarget(
        //     name: "wiremand",
        //     dependencies: [
        //     	.product(name:"SwiftSlash", package:"SwiftSlash"),
        //     	.product(name:"QuickLMDB", package:"QuickLMDB"),
        //     	.product(name:"AddressKit", package:"AddressKit"),
        //     	.product(name:"Hummingbird", package:"hummingbird"),
        //     	.product(name:"SignalStack", package:"SignalStack"),
		// 		.product(name:"SwiftSMTP", package:"swift-smtp"),
		// 		.product(name:"AsyncHTTPClient", package:"async-http-client"),
		// 		.product(name:"SystemPackage", package:"swift-system"),
		// 		.product(name:"SwiftBlake2", package:"SwiftBlake2"),
		// 		.product(name:"ArgumentParser", package:"swift-argument-parser"),
		// 		.product(name:"bedrock", package:"bedrock")
        //     ]),
		.target(name:"wireman-c"),
		.target(name:"wireguard-tools",
				path:"./wireguard-tools/src",
				exclude:["./wincompat", "./wg-quick", "./man", "./fuzz", "./systemd"],
				publicHeadersPath:"."),
		.executableTarget(name:"wireman-db", dependencies:[
			.product(name:"SwiftSlash", package:"SwiftSlash"),
			.product(name:"QuickLMDB", package:"QuickLMDB"),
			.product(name:"Hummingbird", package:"hummingbird"),
			.product(name:"bedrock", package:"bedrock"),
			.product(name:"bedrock-ipaddress", package:"bedrock"),
			.product(name:"RAW", package:"rawdog"),
			.product(name:"RAW_blake2", package:"rawdog"),
			.product(name:"Logging", package:"swift-log"),
			.product(name:"SystemPackage", package:"swift-system"),
			.product(name:"ArgumentParser", package:"swift-argument-parser"),
			"wireman-c"
		])
    ]
)

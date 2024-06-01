// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "wiremand",
    platforms: [
    	.macOS(.v14)
    ],
    dependencies: [
        .package(url:"https://github.com/apple/swift-argument-parser.git", "1.0.0"..<"2.0.0"),
		.package(url:"https://github.com/tannerdsilva/SwiftSlash.git", .upToNextMinor(from:"3.1.0")),
		.package(url:"https://github.com/tannerdsilva/QuickLMDB.git", "5.0.0"..<"6.0.0"),
		.package(url:"https://github.com/hummingbird-project/hummingbird.git", exact:"2.0.0-beta.5"),
		// .package(url:"https://github.com/tannerdsilva/SignalStack.git", .upToNextMinor(from:"1.1.1")),
		// .package(url:"https://github.com/tannerdsilva/swift-smtp.git", .revision("ba82aa3b56e75a798b155524fcb083a9f012a844")),
		// .package(url:"https://github.com/swift-server/async-http-client.git", from:"1.0.0"),
		.package(url:"https://github.com/apple/swift-system.git", "1.0.0"..<"2.0.0"),
		.package(url:"https://github.com/tannerdsilva/bedrock.git", revision:"2725d5899fc8786b4c79751ac165dd5aeda48be0"),
		.package(url:"https://github.com/tannerdsilva/rawdog.git", "11.0.0"..<"12.0.0"),
		.package(url:"https://github.com/apple/swift-log.git", "1.0.0"..<"2.0.0"),
		.package(url:"https://github.com/tannerdsilva/Crtnetlink.git", revision:"ffc78c736f1d82e5e5f85914a4bf492b9064db15"),
		.package(url:"https://github.com/tannerdsilva/CWireguardTools.git", branch:"wiremand-prep"),
		.package(url:"https://github.com/tannerdsilva/QuickJSON.git", from:"1.1.1"),
		.package(url:"https://github.com/tannerdsilva/ws-kit.git", revision:"56d73c7e64019c3f3b488b9221ab5b5d4d30b5be")

		// .package(path:"../CWireguardTools")
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
		.systemLibrary(name:"wireman-cnftables", pkgConfig:"libnftables", providers:[.apt(["libnftables-dev"])]),
		.target(name:"wireman-c"),
		.executableTarget(name:"wireman-wg",
			dependencies:[
				"CWireguardTools",
				"wireman-db",
				.product(name:"ArgumentParser", package:"swift-argument-parser"),
				"wireman-rtnetlink",
				.product(name: "QuickJSON", package:"QuickJSON"),
				.product(name:"Logging", package:"swift-log"),
				"wireman-cnftables",
				.product(name:"WebSocket", package:"ws-kit"),
				.product(name:"Hummingbird", package:"hummingbird"),
			]),
		.target(name:"wireman-rtnetlink",
			dependencies:[
				"Crtnetlink",
				"wireman-db",
				.product(name:"ArgumentParser", package:"swift-argument-parser"),
				.product(name:"bedrock_ip", package:"bedrock")
			]),
		.target(name:"wireman-db", dependencies:[
			.product(name:"SwiftSlash", package:"SwiftSlash"),
			.product(name:"QuickLMDB", package:"QuickLMDB"),
			.product(name:"bedrock", package:"bedrock"),
			.product(name:"bedrock_ip", package:"bedrock"),
			.product(name:"RAW", package:"rawdog"),
			.product(name:"RAW_blake2", package:"rawdog"),
			.product(name:"RAW_base64", package:"rawdog"),
			.product(name:"RAW_hex", package:"rawdog"),
			.product(name:"Logging", package:"swift-log"),
			.product(name:"SystemPackage", package:"swift-system"),
			.product(name:"ArgumentParser", package:"swift-argument-parser"),
			"wireman-c",
			"CWireguardTools",
		])
    ]
)

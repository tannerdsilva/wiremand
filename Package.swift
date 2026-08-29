// swift-tools-version:6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "wiremand",
    platforms: [
    	.macOS(.v15)
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url:"https://github.com/apple/swift-argument-parser.git", "1.5.1"..<"2.0.0"),
		//.package(path: "../SwiftSlash"),
		.package(url:"https://github.com/tannerdsilva/SwiftSlash.git", "4.0.5"..<"5.0.0"),
		// .package(url:"https://github.com/tannerdsilva/QuickLMDB.git", "14.0.0"..<"15.0.0"),
		.package(url:"https://github.com/tannerdsilva/QuickLMDB.git", branch:"master"),
		// .package(url:"https://github.com/tannerdsilva/bedrock.git", "7.0.1"..<"8.0.0"),
		.package(url:"https://github.com/tannerdsilva/bedrock.git", branch:"compare_amend"),
		.package(url:"https://github.com/hummingbird-project/hummingbird.git", "2.9.0"..<"3.0.0"),
		.package(url:"https://github.com/tannerdsilva/rawdog.git", "20.0.0"..<"21.0.0"),
		.package(url:"https://github.com/swift-server/async-http-client.git", "1.26.1"..<"2.0.0"),
		.package(url:"https://github.com/apple/swift-log.git", "1.6.0"..<"2.0.0"),
		
		.package(url:"https://github.com/swift-server/swift-service-lifecycle.git", "2.6.3"..<"3.0.0"),
		.package(url:"https://github.com/apple/swift-nio.git", "2.81.0"..<"3.0.0"),
		.package(path:"../swift-mcp"),
		// .package(url:"https://github.com/tannerdsilva/swift-mcp.git", exact:"1.0.0"), requires a follow-up release with the public transport/accessResolver initializers
    ],
    targets: [
    	.target(
    		name:"wiremand_databases",
    		dependencies: [
    			"QuickLMDB",
				"Clibnftables",
				.product(name:"RAW", package:"rawdog"),
				.product(name:"RAW_dh25519", package:"rawdog"),
				.product(name:"bedrock_ip", package:"bedrock"),
				.product(name:"RAW_blake2", package:"rawdog"),
				.product(name:"bedrock", package:"bedrock"),
				.product(name:"RAW_base64", package:"rawdog"),
				.product(name:"Logging", package:"swift-log"),
				.product(name:"ServiceLifecycle", package:"swift-service-lifecycle"),
				.product(name:"NIO", package:"swift-nio"),
				.product(name:"AsyncHTTPClient", package:"async-http-client"),
    		]
    	),
		.executableTarget(name:"wiremand",
			dependencies: [
    			.product(name:"RAW", package:"rawdog"),
    			.product(name:"RAW_dh25519", package:"rawdog"),
    			.product(name:"bedrock_ip", package:"bedrock"),
    			.product(name:"RAW_blake2", package:"rawdog"),
    			.product(name:"bedrock", package:"bedrock"),
				.product(name:"RAW_base64", package:"rawdog"),
				.product(name:"SwiftSlash", package:"SwiftSlash"),
				.product(name:"MCP", package:"swift-mcp"),
				.product(name:"QuickLMDB", package:"QuickLMDB"),
				.product(name:"ArgumentParser", package:"swift-argument-parser"),
				.product(name:"Logging", package:"swift-log"),
				.product(name:"Hummingbird", package:"hummingbird"),
				.product(name:"HummingbirdTLS", package:"hummingbird"),
				"wiremand_databases",
				"Crtnetlink"
			],
		),
		.target(name:"Crtnetlink", dependencies: []),
		.systemLibrary(name:"Clibnftables", pkgConfig:"libnftables", providers:[.apt(["libnftables-dev"])]),
		.testTarget(
			name: "wiremandTests",
			dependencies: [
				"wiremand_databases",
				"Clibnftables",
				"wiremand",
				.product(name:"SwiftSlash", package:"SwiftSlash"),
				.product(name:"bedrock", package:"bedrock"),
				.product(name:"RAW", package:"rawdog"),
			],
		)
    ]
)

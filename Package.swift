// swift-tools-version:6.1
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
		.package(url:"https://github.com/tannerdsilva/SwiftSlash.git", "4.0.0"..<"5.0.0"),
		.package(url:"https://github.com/tannerdsilva/QuickLMDB.git", "11.1.0"..<"12.0.0"),
		.package(url:"https://github.com/tannerdsilva/bedrock.git", "4.0.2"..<"5.0.0"),
		.package(url:"https://github.com/hummingbird-project/hummingbird.git", "2.14.1"..<"3.0.0"),
		.package(url:"https://github.com/tannerdsilva/rawdog.git", "17.0.1"..<"18.0.0"),
		.package(url:"https://github.com/swift-server/async-http-client.git", "1.26.1"..<"2.0.0"),
		.package(url:"https://github.com/apple/swift-system.git", "1.5.0"..<"2.0.0"),
		.package(url:"https://github.com/apple/swift-log.git", "1.6.0"..<"2.0.0"),
		/*
		.package(url:"https://github.com/tannerdsilva/swift-smtp.git", .revision("ba82aa3b56e75a798b155524fcb083a9f012a844")),
		.package(url:"https://github.com/tannerdsilva/SwiftDate.git", .branch("master")),
		.package(url:"https://github.com/apple/swift-system.git", .upToNextMajor(from:"1.0.0")),
		*/
    ],
    targets: [
    	.target(
    		name:"wiremand_databases",
    		dependencies: [
    			"QuickLMDB",
				.product(name:"RAW", package:"rawdog"),
				.product(name:"RAW_dh25519", package:"rawdog"),
				.product(name:"bedrock_ip", package:"bedrock"),
				.product(name:"RAW_blake2", package:"rawdog"),
				.product(name:"bedrock", package:"bedrock"),
				.product(name:"RAW_base64", package:"rawdog"),
				.product(name:"Logging", package:"swift-log"),
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
				.product(name:"QuickLMDB", package:"QuickLMDB"),
				.product(name:"ArgumentParser", package:"swift-argument-parser"),
				.product(name:"Logging", package:"swift-log"),
				"wiremand_databases"
			],
		)				
        /*.executableTarget(
            name: "wiremand",
            dependencies: [
            	.product(name:"SwiftSlash", package:"SwiftSlash"),
            	.product(name:"QuickLMDB", package:"QuickLMDB"),
            	.product(name:"AddressKit", package:"AddressKit"),
            	.product(name:"Hummingbird", package:"hummingbird"),
            	.product(name:"SignalStack", package:"SignalStack"),
				.product(name:"SwiftSMTP", package:"swift-smtp"),
				.product(name:"AsyncHTTPClient", package:"async-http-client"),
				.product(name:"SwiftDate", package:"SwiftDate"),
				.product(name:"SystemPackage", package:"swift-system"),
				.product(name:"SwiftBlake2", package:"SwiftBlake2"),
				.product(name:"ArgumentParser", package:"swift-argument-parser"),
				.product(name:"bedrock", package:"bedrock")
            ]),*/
    ]
)

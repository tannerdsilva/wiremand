import CWireguardTools
import ArgumentParser
import wireman_db
import bedrock_ip
import RAW_blake2
import wireman_rtnetlink
import SystemPackage
import QuickJSON
import bedrock
import RAW_hex
import class Foundation.JSONEncoder

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#endif

extension NetworkV4:ExpressibleByArgument {
	public init?(argument:String) {
		guard let asNet = NetworkV4(argument) else {
			return nil
		}
		self = asNet
	}
}

extension NetworkV6:ExpressibleByArgument {
	public init?(argument:String) {
		guard let asNet = NetworkV6(argument) else {
			return nil
		}
		self = asNet
	}
}

extension PublicKey:ExpressibleByArgument {
	public init?(argument:String) {
		guard let asKey = PublicKey(argument) else {
			return nil
		}
		self = asKey
	}
}

extension PresharedKey:ExpressibleByArgument {
	public init?(argument:String) {
		guard let asKey = PresharedKey(argument) else {
			return nil
		}
		self = asKey
	}
}

extension Configuration.TrustedNode.Endpoint:ExpressibleByArgument {
	public init?(argument:String) {
		if argument.first == "[" {
			let lastCloseBracket:String.Index? = argument.lastIndex(of:"]")
			guard lastCloseBracket != nil else {
				return nil
			}
			var remaining = argument.suffix(from:argument.index(after:lastCloseBracket!)).dropFirst()
			guard remaining.first == ":" else {
				return nil
			}
			remaining = remaining.dropFirst()
			let port = UInt16(remaining)
			let address = AddressV6(String(argument.prefix(upTo:lastCloseBracket!).dropFirst()))
			guard port != nil && address != nil else {
				return nil
			}
			self = Self(address:.v6(address!), port:port!)
		} else {
			let lastColon:String.Index? = argument.lastIndex(of:":")
			guard lastColon != nil else {
				return nil
			}
			let port = UInt16(argument.suffix(from:argument.index(after:lastColon!)).dropFirst())
			let address = AddressV4(String(argument.prefix(upTo:lastColon!)))
			guard port != nil && address != nil else {
				return nil
			}
			self = Self(address:.v4(address!), port:port!)
		}
	}
}

extension AddressV6:ExpressibleByArgument {
	public init?(argument:String) {
		guard let asAddr = AddressV6(argument) else {
			return nil
		}
		self = asAddr
	}
}


@main
struct CLI:AsyncParsableCommand {
	static let configuration = CommandConfiguration(
		commandName:"wireman-wg",
		abstract:"wireman tool helps you apply changes and build infrastructure on wireguard interfaces.",
		subcommands:[
			DaemonCLI.self,
			AddTrustedNode.self
		]
	)

	struct AddTrustedNode:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"add-trusted-node",
			abstract:"Trust a new node on the network"
		)

		@Option(help:"path to the configuration file")
		var configPath:String = "/etc/wireman.conf"

		@Argument(help:"public key of the new node")
		var publicKey:PublicKey

		@Option(help:"preshared key of the new node")
		var presharedKey:PresharedKey? = nil

		@Argument(help:"endpoint address of the new node")
		var physicalEndpoint:Configuration.TrustedNode.Endpoint

		@Argument(help:"allowed IP address (in tunnel) of the new node")
		var allowedIP:AddressV6

		mutating func run() async throws {
			let logger = makeDefaultLogger(label:"daemon", logLevel:.debug)

			// load the initial configuration file, or write a default configuration file if it does not exist
			var configFD:FileDescriptor
			do {
				configFD = try FileDescriptor.open(configPath, .readWrite, options:[], permissions:[.ownerReadWrite])
				logger.info("successfully opened existing configuration file at '\(configPath)'")
			} catch let error {
				logger.critical("failed to open configuration file at '\(configPath)': \(error)")
				throw error
			}
			defer {
				try! configFD.close()
			}

			var buildBytes = [UInt8]()
			let newBuffer = UnsafeMutableRawBufferPointer.allocate(byteCount:1024*4, alignment:1)
			defer {
				newBuffer.deallocate()
			}
			while try configFD.read(into:newBuffer) > 0 {
				buildBytes.append(contentsOf:newBuffer)
			}
			var decodedConfiguration = try QuickJSON.decode(Configuration.self, from:buildBytes, size:buildBytes.count, flags:[.stopWhenDone])
			var newNode = try Configuration.TrustedNode.generateNew(publicKey:publicKey, presharedKey:&presharedKey, endpoint:physicalEndpoint, allowedIP:allowedIP)

			// verify that this instance is already configured to operate on the same trust network
			for var trustObj in decodedConfiguration.trusted {
				// verify that the current instance has a trusted network scope that this IP falls within
				guard trustObj.network.contains(allowedIP) else {
					logger.trace("node with public key '\(publicKey)' not trusted on network '\(trustObj.network)'")
					continue
				}
				trustObj.nodes.update(with:newNode)

				if presharedKey == nil {
					let newPSK = PresharedKey()
					newNode.presharedKey = newPSK
					logger.critical("generating new preshared key for trust relationship: \(newPSK)")
				}

				decodedConfiguration.trusted.update(with:trustObj)

				let bytes = try QuickJSON.encode(decodedConfiguration, flags:[.pretty])
				try configFD.seek(offset:0, from:.start)
				try configFD.writeAll(bytes)
				logger.notice("successfully trusted new node with public key '\(publicKey)' on network '\(trustObj.network)'")
				return
			}
			logger.error("failed to trust new node with public key '\(publicKey)': no network found for allowed IP '\(allowedIP)'")
			throw DaemonCLI.Error.invalidConfiguration
		}
	}

	struct DaemonCLI:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"mock",
			abstract:"Mock a wireguard daemon"
		)

		@Option(help:"path to the configuration file")
		var configPath:String = "/etc/wireman.conf"

		@Option(help:"only valid if the configuration file does not exist. specify your existing trusted address space to use when initializing the daemon for the first time.")
		var initializeTrustNetwork:NetworkV6? = nil

		mutating func run() async throws {
			let logger = makeDefaultLogger(label:"daemon", logLevel:.debug)

			// load the initial configuration file, or write a default configuration file if it does not exist
			let configFD:FileDescriptor
			do {
				do {
					let localFD = try FileDescriptor.open(configPath, .readWrite, options:[], permissions:[.ownerReadWrite])
					logger.info("successfully opened existing configuration file at '\(configPath)'")
					guard initializeTrustNetwork == nil else {
						logger.error("trust network initialization flag used on environment with existing configuration file ('\(configPath)'). exiting...")
						throw Error.invalidConfiguration
					}
					configFD = localFD
				} catch Errno.noSuchFileOrDirectory {
					logger.warning("configuration file not found! creating a new one...")
					let localFD = try FileDescriptor.open(configPath, .readWrite, options:[.create], permissions:[.ownerReadWrite])
					configFD = localFD
					if initializeTrustNetwork == nil {
						initializeTrustNetwork = NetworkV6(address:try! NetworkV6("fd00::/8")!.randomAddress(), subnetPrefix:96)
					}
					initializeTrustNetwork = NetworkV6(address:try initializeTrustNetwork!.randomAddress(), subnetPrefix:initializeTrustNetwork!.subnetPrefix)
					logger.notice("successfully created template configuration file.", metadata:["trust_network":"\(initializeTrustNetwork!)"])
					var newConfiguration = try Configuration.generateNew()
					newConfiguration.trusted = [Configuration.TrustedNetworkScope(network:initializeTrustNetwork!, nodes:[])]
					let bytes = try QuickJSON.encode(newConfiguration, flags:[.pretty])
					try configFD.writeAll(bytes)
					try configFD.seek(offset:0, from:.start)
				}
			} catch let error {
				logger.critical("failed to open configuration file at '\(configPath)': \(error)")
				throw error
			}
			defer {
				try! configFD.close()
			}

			var buildBytes = [UInt8]()
			let newBuffer = UnsafeMutableRawBufferPointer.allocate(byteCount:1024*4, alignment:1)
			defer {
				newBuffer.deallocate()
			}
			while try configFD.read(into:newBuffer) > 0 {
				buildBytes.append(contentsOf:newBuffer)
			}
			let decodedConfiguration = try QuickJSON.decode(Configuration.self, from:buildBytes, size:buildBytes.count, flags:[.stopWhenDone])
			logger.debug("loaded configuration: \(decodedConfiguration)")
			let newDaemon = Daemon(configuration:decodedConfiguration)
			try await newDaemon.run()
		}
		
		enum Error:Swift.Error {
			case invalidConfiguration
		}
	}
}
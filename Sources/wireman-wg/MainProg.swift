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


@main
struct CLI:AsyncParsableCommand {
	static let configuration = CommandConfiguration(
		commandName:"wireman-wg",
		abstract:"wireman tool helps you apply changes and build infrastructure on wireguard interfaces.",
		subcommands:[
			MockDaemon.self,
			ConfigureInterface.self
		]
	)

	struct MockDaemon:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"mock",
			abstract:"Mock a wireguard daemon"
		)

		@Option(help:"The path to the configuration file")
		var configPath:String = "/etc/wireman.conf"

		mutating func run() async throws {
			let logger = makeDefaultLogger(label:"mock", logLevel:.debug)

			// load the initial configuration file, or write a default configuration file if it does not exist
			let configFD:FileDescriptor
			do {
				do {
					configFD = try FileDescriptor.open(configPath, .readWrite, options:[], permissions:[.ownerReadWrite])
					logger.info("successfully opened existing configuration file at '\(configPath)'")
				} catch Errno.noSuchFileOrDirectory {
					logger.warning("configuration file not found! creating a new one...")
					configFD = try FileDescriptor.open(configPath, .readWrite, options:[.create], permissions:[.ownerReadWrite])
					logger.notice("successfully created template configuration file.")
					let newConfiguration = try Configuration.generateNew()
					let encoder = try QuickJSON.encode(newConfiguration)
					try configFD.writeAll(encoder)
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
			try await Self.runDaemon(configuration:decodedConfiguration)
		}
		
		enum Error:Swift.Error {
			case invalidConfiguration
		}

		static func runDaemon(configuration:Configuration) async throws {
			let logger = makeDefaultLogger(label:"daemon", logLevel:.debug)
			
			// compute the master keys
			let masterPublicKey = PublicKey(privateKey:configuration.privateKey)
			let masterPrivateKey = configuration.privateKey

			logger.info("starting daemon", metadata:["publicKey":"\(masterPublicKey)"])

			// generate the interface patterns based on the public key
			var uniquePatternHasher = try RAW_blake2.Hasher<B, [UInt8]>(key:masterPublicKey, outputLength:3)
			try uniquePatternHasher.update(Array("trusted_interface_iname".utf8))
			let trustedInterfacePattern = try uniquePatternHasher.finish()
			uniquePatternHasher = try RAW_blake2.Hasher<B, [UInt8]>(key:masterPublicKey, outputLength:3)
			try uniquePatternHasher.update(Array("hosted_interface_iname".utf8))
			let hostedInterfacePattern = try uniquePatternHasher.finish()

			// generate the sub-keys for each interface based on the master private key
			var secureKeyHasher = try RAW_blake2.Hasher<B, PrivateKey>(key:masterPrivateKey, outputLength:32)
			try secureKeyHasher.update(Array("trusted_interface_privatekey".utf8))
			let trustedInterfaceKey = try secureKeyHasher.finish()
			secureKeyHasher = try RAW_blake2.Hasher<B, PrivateKey>(key:masterPrivateKey, outputLength:32)
			try secureKeyHasher.update(Array("hosted_interface_privatekey".utf8))
			let hostedInterfaceKey = try secureKeyHasher.finish()

			let trustedDevName = "wmanT_" + String(RAW_hex.encode(trustedInterfacePattern))
			let hostedDevName = "wmanH_" + String(RAW_hex.encode(hostedInterfacePattern))
			logger.info("trusted device name: \(trustedDevName)")

			// load the wireguard trust interface
			var trustInterface:Device
			var hostedInterface:Device
			do {
				let listedDeviceNames = Device.list()

				// initialize the trusted interface
				if listedDeviceNames.contains(trustedDevName) {
					trustInterface = try Device.load(name:trustedDevName)
					logger.info("loaded existing wireguard interface: \(trustedDevName)")
				} else {
					trustInterface = try Device.add(name:trustedDevName)
				}

				// initialize the hosted interface
				if listedDeviceNames.contains(hostedDevName) {
					hostedInterface = try Device.load(name:hostedDevName)
					logger.info("loaded existing wireguard interface: \(hostedDevName)")
				} else {
					hostedInterface = try Device.add(name:hostedDevName)
					logger.info("created new wireguard interface: \(hostedDevName)")
				}
			}
			trustInterface.privateKey = trustedInterfaceKey
			hostedInterface.privateKey = hostedInterfaceKey
			try trustInterface.set()
			try hostedInterface.set()
			trustInterface = try Device.load(name:trustedDevName)
			hostedInterface = try Device.load(name:hostedDevName)

			var existingAddressesH:Set<Network> = []
			var existingAddressesT:Set<Network> = []
			for curAdd in try getAddressesV4() {
				if curAdd.address != nil {
					if curAdd.interfaceIndex == trustInterface.interfaceIndex {
						existingAddressesT.update(with:.v4(NetworkV4(address:AddressV4(curAdd.address!)!, subnetPrefix:curAdd.prefix_length)))
					}
					if curAdd.interfaceIndex == hostedInterface.interfaceIndex {
						existingAddressesH.update(with:.v4(NetworkV4(address:AddressV4(curAdd.address!)!, subnetPrefix:curAdd.prefix_length)))
					}
				}
			}
			for curAdd in try getAddressesV6() {
				if curAdd.address != nil {
					if curAdd.interfaceIndex == trustInterface.interfaceIndex {
						existingAddressesT.update(with:.v6(NetworkV6(address:AddressV6(curAdd.address!)!, subnetPrefix:curAdd.prefix_length)))
					}
					if curAdd.interfaceIndex == hostedInterface.interfaceIndex {
						existingAddressesH.update(with:.v6(NetworkV6(address:AddressV6(curAdd.address!)!, subnetPrefix:curAdd.prefix_length)))
					}
				}
			}

			var addressModifications4 = Set<AddRemove<NetworkV4>>()
			var addressModifications6 = Set<AddRemove<NetworkV6>>()
			for (curTrustNetInternal, curNodes) in configuration.trustedNodes {
				logger.info("initializing trusted network: \(curTrustNetInternal)")
				for curNode in curNodes {
					let newPeer = Device.Peer(publicKey:curNode.publicKey, presharedKey:curNode.presharedKey)
					switch curNode.endpoint.address {
					case .v4(let asV4):
						newPeer.endpoint = .v4(asV4, curNode.endpoint.port)
					case .v6(let asV6):
						newPeer.endpoint = .v6(asV6, curNode.endpoint.port)
					}
					newPeer.update(with:Device.Peer.AllowedIPsEntry(NetworkV6(address:curNode.allowedIP, subnetPrefix:128)))
					trustInterface.update(with:newPeer)
				}
				if existingAddressesT.contains(.v6(curTrustNetInternal)) == false {
					logger.info("assigning address to trusted interface: \(curTrustNetInternal)")
					addressModifications6.update(with:.add(Int32(trustInterface.interfaceIndex), curTrustNetInternal))
				}
			}
			for curExisting in existingAddressesH {
				if configuration.hostedNetworks.contains(curExisting) == false {
					logger.info("removing address from hosted interface: \(curExisting)")
					switch curExisting {
						case .v4(let asV4):
							addressModifications4.update(with:.remove(Int32(hostedInterface.interfaceIndex), asV4))
						case .v6(let asV6):
							addressModifications6.update(with:.remove(Int32(hostedInterface.interfaceIndex), asV6))
					}
				}
			}
			for curHostedNet in configuration.hostedNetworks {
				if existingAddressesH.contains(curHostedNet) == false {
					logger.info("assigning address to hosted interface: \(curHostedNet)")
					switch curHostedNet {
						case .v4(let asV4):
							addressModifications4.update(with:.add(Int32(hostedInterface.interfaceIndex), asV4))
						case .v6(let asV6):
							addressModifications6.update(with:.add(Int32(hostedInterface.interfaceIndex), asV6))
					}
				}
			}
			if addressModifications6.count > 0 || addressModifications4.count > 0 {
				_ = try modifyInterface(addressV4:addressModifications4, addressV6:addressModifications6)
			}
		}
	}

	struct ConfigureInterface:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"configure",
			abstract:"Configure a wireguard interface"
		)

		@Argument(help:"The name of the wireguard interface to manage")
		var interfaceName:String

		@Flag(name:.long, help:"do not create or set the wireguard interface.")
		var wgReadOnly:Bool = false

		mutating func run() throws {
			let wireguardInterface:Device
			do {
				wireguardInterface = try Device.load(name:interfaceName)
			} catch  {
				wireguardInterface = try Device.add(name:interfaceName)
			}
			let intPK = wireguardInterface.publicKey
			print(" == Interface Information ==")
			print("Interface Name: \(wireguardInterface.name)")
			print("Interface Public Key: \(String(describing:intPK))")
			print("Interface Index: \(wireguardInterface.interfaceIndex)")
			let getInterface = try wireman_rtnetlink.getAddressesV4()
			var interfaceAddressV4 = Set<NetworkV4>()
			var remove4 = Set<AddRemove<NetworkV4>>()
			for address in getInterface {
				if address.interfaceIndex == wireguardInterface.interfaceIndex && address.address != nil {
					let asAddr = AddressV4(address.address!)
					guard asAddr != nil else {
						continue
					}
					let asNetwork = NetworkV4(address:asAddr!, subnetPrefix:address.prefix_length)
					interfaceAddressV4.update(with:asNetwork)
					remove4.update(with:.remove(Int32(address.interfaceIndex), asNetwork))
					print("found matching address: \(asNetwork)")
				}
			}
			var interfaceAddressV6 = Set<NetworkV6>()
			var remove6 = Set<AddRemove<NetworkV6>>()
			for address in try wireman_rtnetlink.getAddressesV6() {
				if address.interfaceIndex == wireguardInterface.interfaceIndex && address.address != nil{
					let asAddr = AddressV6(address.address!)
					guard asAddr != nil else {
						continue
					}

					let asNetwork = NetworkV6(address:asAddr!, subnetPrefix:address.prefix_length)
					interfaceAddressV6.update(with:asNetwork)
					remove6.update(with:.remove(Int32(address.interfaceIndex), asNetwork))
					print("found matching address: \(String(asNetwork.address))")
				}
			}
			if interfaceAddressV4.count > 0 || interfaceAddressV6.count > 0 {
				_ = try modifyInterface(addressV4:remove4, addressV6:remove6)
			} else {
				print("No existing addresses to remove")
			}
		}
	}
}

// extension Wireguard.Peer.AllowedIP:Hashable, Equatable {

// 			public static func == (lhs:Wireguard.Peer.AllowedIP, rhs:Wireguard.Peer.AllowedIP) -> Bool {
// 				switch (lhs, rhs) {
// 				case (.v4(let a), .v4(let b)):
// 					return a == b
// 				case (.v6(let a), .v6(let b)):
// 					return a == b
// 				default:
// 					return false
// 				}
// 			}

// 			public func hash(into hasher:inout Hasher) {
// 				switch self {
// 				case .v4(let a):
// 					hasher.combine("v4")
// 					hasher.combine(a)
// 				case .v6(let a):
// 					hasher.combine("v6")
// 					hasher.combine(a)
// 				}
// 			}

// }
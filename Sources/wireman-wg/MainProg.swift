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
			DaemonCLI.self
		]
	)
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

	struct DaemonCLI:AsyncParsableCommand {
		static let configuration = CommandConfiguration(
			commandName:"mock",
			abstract:"Mock a wireguard daemon"
		)

		@Option(help:"The path to the configuration file")
		var configPath:String = "/etc/wireman.conf"

		mutating func run() async throws {
			let logger = makeDefaultLogger(label:"daemon", logLevel:.debug)

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
			let newDaemon = Daemon(configuration:decodedConfiguration)
			try await newDaemon.run()
		}
		
		enum Error:Swift.Error {
			case invalidConfiguration
		}
	}
}
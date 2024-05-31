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


@main
struct CLI:AsyncParsableCommand {
	static let configuration = CommandConfiguration(
		commandName:"wireman-wg",
		abstract:"wireman tool helps you apply changes and build infrastructure on wireguard interfaces.",
		subcommands:[
			DaemonCLI.self
		]
	)

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
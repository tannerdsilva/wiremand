import Foundation
import wiremand_databases
import SwiftSlash
import Logging
import SystemPackage

/// Executor used for configuring the Wireguard interface and peers on the server. 
struct WireguardExecutor {
	enum Error:Swift.Error {
		case wireguardCmdError
		case wireguardQuickCmdError
	}
	struct VPNKey {
		let privateKey:String
		let publicKey:PublicKey
		let presharedKey:String
	}
	
	static func generateClient() async throws -> VPNKey {
		let makePriKey = try await Command("wg", arguments:["genkey"]).runSync()
		guard makePriKey.succeeded == true, let privateKey = makePriKey.stdout.compactMap({ String(data:Data($0), encoding:.utf8) }).first else {
			throw Error.wireguardCmdError
		}
		
		// wg pubkey only accepts the key on stdin, and SwiftSlash 4.0.5's stdin
		// data channel cannot deliver EOF on Linux: its writer fd is registered
		// with EPOLLET (edge-triggered), so after the single initial writability
		// event flushes the payload, no second event ever arrives and the write
		// task never closes the child's stdin — the child blocks on EOF forever.
		// (verified for every usage ordering; macOS kqueue does not have this
		// bug). Feed the key through a mkstemp file and one sh invocation
		// instead: the path is generated here (never client input) and quoted,
		// so there is no injection surface, and key material never appears in
		// argv. this matches the PSK-by-path convention used below in install().
		let tempPath = malloc(64);
		defer {
			free(tempPath)
		}
		strcpy(tempPath!, "/tmp/wg_genkey_XXXXXXXXX")
		mkstemp(tempPath!)
		let newData = Data(bytes:tempPath!, count:strlen(tempPath!))
		let pathAsString = String(data:newData, encoding:.utf8)!
		defer {
			remove(tempPath)
		}
		let newFD = try FileDescriptor.open(pathAsString, .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWriteExecute])
		_ = try newFD.closeAfter {
			try newFD.writeAll("\(privateKey)\n".utf8)
		}
		let makePubKey = try await Command(sh: "cat '\(pathAsString)' | /usr/bin/wg pubkey", environment: CurrentEnvironment.environmentVariables()).runSync()
		guard makePubKey.succeeded == true, let keyData = makePubKey.stdout.first, let pubKeyString = String(data:Data(keyData), encoding:.utf8) else {
			throw Error.wireguardCmdError
		}

		let publicKey = PublicKey(argument: pubKeyString)
		guard let publicKey = publicKey else {
			throw Error.wireguardCmdError
		}
		let makePsk = try await Command("wg", arguments: ["genpsk"]).runSync()
		guard makePsk.succeeded == true, let psk = makePsk.stdout.compactMap({ String(data:Data($0), encoding:.utf8) }).first else {
			throw Error.wireguardCmdError
		}
		
		return VPNKey(privateKey:privateKey, publicKey:publicKey, presharedKey:psk)
	}
    
	static func install(publicKey:PublicKey, presharedKey:String, addresses:[Address], interfaceName:EncodedString) async throws {
		// sensitive material (the PSK) is written to a mkstemp file and passed
		// by path, never on the command line
        let tempPath = malloc(64);
        defer {
            free(tempPath)
        }
        strcpy(tempPath!, "/tmp/wg_genkey_XXXXXXXXX")
        mkstemp(tempPath!)
        let newData = Data(bytes:tempPath!, count:strlen(tempPath!))
        let pathAsString = String(data:newData, encoding:.utf8)!
        let newFD = try FileDescriptor.open(pathAsString, .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWriteExecute])
        defer {
            remove(tempPath)
        }
        _ = try newFD.closeAfter {
            try newFD.writeAll(presharedKey.utf8)
        }
		
		// posix_spawn instead of shell: `wg set <iface> peer <key> allowed-ips <ips> preshared-key <file>`
		var args = ["set", String(interfaceName), "peer", publicKey.string, "allowed-ips"]
		args.append(contentsOf: addresses.map { $0.isV4 ? "\($0.string)/32" : "\($0.string)/128" })
		args += ["preshared-key", pathAsString]
		let installKey = try await Command(absolutePath: "/usr/bin/wg", arguments: args, environment: CurrentEnvironment.environmentVariables()).runSync()
        guard installKey.succeeded == true else {
            throw Error.wireguardCmdError
        }
    }
    
	static func updateExistingClient(publicKey:PublicKey, with addresses:[Address], interfaceName:EncodedString) async throws {
		// posix_spawn instead of shell: `wg set <iface> peer <key> allowed-ips <ips>`
		var args = ["set", String(interfaceName), "peer", publicKey.string, "allowed-ips"]
		args.append(contentsOf: addresses.map { $0.isV4 ? "\($0.string)/32" : "\($0.string)/128" })
		let installNewAddress = try await Command(absolutePath: "/usr/bin/wg", arguments: args, environment: CurrentEnvironment.environmentVariables()).runSync()
    	guard installNewAddress.succeeded == true else {
    		throw Error.wireguardCmdError
    	}
    }
    
    static func uninstall(publicKey:PublicKey, interfaceName:EncodedString) async throws {
		let removeKey = try await Command(absolutePath: "/usr/bin/wg", arguments: ["set", String(interfaceName), "peer", publicKey.string, "remove"], environment: CurrentEnvironment.environmentVariables()).runSync()
        guard removeKey.succeeded == true else {
            throw Error.wireguardCmdError
        }
    }
	
	static func saveConfiguration(interfaceName:EncodedString, logLevel:Logger.Level) async throws {
		var log = Logger(label: "wireguard-executor")
		log.logLevel = logLevel
		guard try await Command(absolutePath: "/usr/bin/wg-quick", arguments: ["save", String(interfaceName)], environment: CurrentEnvironment.environmentVariables()).runSync().succeeded == true else {
			log.error("unable to save current wireguard configuration with `wg-quick`")
			throw Error.wireguardQuickCmdError
		}
		log.trace("successfully saved wireguard configuration with `wg-quick`")
	}

	static func installDomain(subnet:wiremand_databases.Network, interfaceName:EncodedString) async throws {
		let installNewAddress = try await Command(absolutePath: "/sbin/ip", arguments: ["addr", "add", subnet.cidrstring, "dev", String(interfaceName)], environment: CurrentEnvironment.environmentVariables()).runSync()
    	guard installNewAddress.succeeded == true else {
    		throw Error.wireguardCmdError
    	}
	}

	static func uninstallDomain(subnet:wiremand_databases.Network, interfaceName:EncodedString) async throws {
		let installNewAddress = try await Command(absolutePath: "/sbin/ip", arguments: ["addr", "del", subnet.cidrstring, "dev", String(interfaceName)], environment: CurrentEnvironment.environmentVariables()).runSync()
    	guard installNewAddress.succeeded == true else {
    		throw Error.wireguardCmdError
    	}
	}
}

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
		
		let makePubKey = try await Command(sh: "echo \(privateKey) | wg pubkey", environment: CurrentEnvironment.environmentVariables()).runSync()
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
		let ipEntries = addresses.map { "\($0.isV4 ? "\($0.string)/32" : "\($0.string)/128")" }
		let allowedIPs = "allowed-ips \(ipEntries.joined(separator: ","))"
		
		let installKey = try await Command(sh: "sudo wg set \(String(interfaceName)) peer \(publicKey.string) \(allowedIPs) preshared-key \(pathAsString)", environment: CurrentEnvironment.environmentVariables()).runSync()
        guard installKey.succeeded == true else {
            throw Error.wireguardCmdError
        }
    }
    
	static func updateExistingClient(publicKey:PublicKey, with addresses:[Address], interfaceName:EncodedString) async throws {
		let ipEntries = addresses.map { "\($0.isV4 ? "\($0.string)/32" : "\($0.string)/128")" }
		let allowedIPs = "allowed-ips \(ipEntries.joined(separator: ","))"
		
		let installNewAddress = try await Command(sh: "sudo wg set \(String(interfaceName)) peer \(publicKey.string) \(allowedIPs)", environment: CurrentEnvironment.environmentVariables()).runSync()
    	guard installNewAddress.succeeded == true else {
    		throw Error.wireguardCmdError
    	}
    }
    
    static func uninstall(publicKey:PublicKey, interfaceName:EncodedString) async throws {
		let removeKey = try await Command(sh: "sudo wg set \(String(interfaceName)) peer \(publicKey.string) remove", environment: CurrentEnvironment.environmentVariables()).runSync()
        guard removeKey.succeeded == true else {
            throw Error.wireguardCmdError
        }
    }
	
	static func saveConfiguration(interfaceName:EncodedString, logLevel:Logger.Level) async throws {
		var log = Logger(label: "wireguard-executor")
		log.logLevel = logLevel
		guard try await Command(sh: "sudo wg-quick save \(String(interfaceName))", environment: CurrentEnvironment.environmentVariables()).runSync().succeeded == true else {
			log.error("unable to save current wireguard configuration with `wg-quick`")
			throw Error.wireguardQuickCmdError
		}
		log.trace("successfully saved wireguard configuration with `wg-quick`")
	}

	static func installDomain(subnet:wiremand_databases.Network, interfaceName:EncodedString) async throws {
		let installNewAddress = try await Command(sh: "sudo ip addr add \(subnet.cidrstring) dev \(String(interfaceName))", environment: CurrentEnvironment.environmentVariables()).runSync()
    	guard installNewAddress.succeeded == true else {
    		throw Error.wireguardCmdError
    	}
	}

	static func uninstallDomain(subnet:wiremand_databases.Network, interfaceName:EncodedString) async throws {
		let installNewAddress = try await Command(sh: "sudo ip addr del \(subnet.cidrstring) dev \(String(interfaceName))", environment: CurrentEnvironment.environmentVariables()).runSync()
    	guard installNewAddress.succeeded == true else {
    		throw Error.wireguardCmdError
    	}
	}
}

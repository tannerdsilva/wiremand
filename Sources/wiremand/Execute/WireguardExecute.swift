import Foundation
import SwiftSlash
import AddressKit
import SystemPackage

struct WireguardExecutor {
	enum Error:Swift.Error {
		case wireguardCmdError
		case wireguardQuickCmdError
	}
	struct VPNKey {
		let privateKey:String
		let publicKey:String
		let presharedKey:String 
	}
	
	static func generateClient() async throws -> VPNKey {
		let makePriKey = try await Command(bash:"wg genkey").runSync()
		guard makePriKey.succeeded == true, let privateKey = makePriKey.stdout.compactMap({ String(data:$0, encoding:.utf8) }).first else {
			throw Error.wireguardCmdError
		}
        
		let makePubKey = try await Command(bash:"echo \(privateKey) | wg pubkey").runSync()
        guard makePubKey.succeeded == true, let publicKey = makePubKey.stdout.compactMap({ String(data:$0, encoding:.utf8) }).first else {
			throw Error.wireguardCmdError
		}
		let makePsk = try await Command(bash:"wg genpsk").runSync()
		guard makePsk.succeeded == true, let psk = makePsk.stdout.compactMap({ String(data:$0, encoding:.utf8) }).first else {
			throw Error.wireguardCmdError
		}
		
		return VPNKey(privateKey:privateKey, publicKey:publicKey, presharedKey:psk)
	}
    
	static func install(publicKey:String, presharedKey:String, address:AddressV6, addressv4:AddressV4?, interfaceName:String) async throws {
        let tempPath = malloc(64);
        defer {
            free(tempPath)
        }
        strcpy(tempPath!, "/tmp/wg_genkey_XXXXXXXXX")
        mktemp(tempPath!)
        let newData = Data(bytes:tempPath!, count:strlen(tempPath!))
        let pathAsString = String(data:newData, encoding:.utf8)!
        let newFD = try FileDescriptor.open(pathAsString, .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWriteExecute])
        defer {
            remove(tempPath)
        }
        _ = try newFD.closeAfter {
            try newFD.writeAll(presharedKey.utf8)
        }
		var allowedIPs = "allowed-ips \(address.string)/128"
		if addressv4 != nil {
			allowedIPs += ",\(addressv4!.string)/32"
		}
        let installKey = try await Command(bash:"sudo wg set \(interfaceName) peer \(publicKey) \(allowedIPs) preshared-key \(pathAsString)").runSync()
        guard installKey.succeeded == true else {
            throw Error.wireguardCmdError
        }
    }
    
	static func updateExistingClient(publicKey:String, with newIPv6Address:AddressV6, and newIPv4Address:AddressV4? = nil, interfaceName:String) async throws {
		var allowedIPs = "allowed-ips \(newIPv6Address.string)/128"
		if (newIPv4Address != nil) {
			allowedIPs += ",\(newIPv4Address!.string)/32"
		}
    	let installNewAddress = try await Command(bash:"sudo wg set \(interfaceName) peer \(publicKey) \(allowedIPs)").runSync()
    	guard installNewAddress.succeeded == true else {
    		throw Error.wireguardCmdError
    	}
    }
    
    static func uninstall(publicKey:String, interfaceName:String) async throws {
        let removeKey = try await Command(bash:"sudo wg set \(interfaceName) peer \(publicKey) remove").runSync()
        guard removeKey.succeeded == true else {
            throw Error.wireguardCmdError
        }
    }
	
	static func saveConfiguration(interfaceName:String) async throws {
		guard try await Command(bash:"sudo wg-quick save \(interfaceName)").runSync().succeeded == true else {
			WiremanD.appLogger.error("unable to save current wireguard configuration with `wg-quick`")
			throw Error.wireguardQuickCmdError
		}
		WiremanD.appLogger.trace("successfully saved wireguard configuration with `wg-quick`")
	}
}

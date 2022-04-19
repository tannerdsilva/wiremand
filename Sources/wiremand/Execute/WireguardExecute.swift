import Foundation
import SwiftSlash
import AddressKit

struct WireguardExecutor {
	enum Error:Swift.Error {
		case wireguardCmdError
	}
	struct VPNKey {
		let privateKey:String
		let publicKey:String
		let presharedKey:String 
	}
	
	static func generateNewKey() async throws -> VPNKey {
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
    
    static func installNew(key:VPNKey, address:AddressV6) async throws {
        
    }
}

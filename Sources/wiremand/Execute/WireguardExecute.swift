import Foundation
import SwiftSlash
import AddressKit
import SystemPackage

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
    
    static func installNew(key:VPNKey, address:AddressV6, interfaceName:String) async throws {
        let tempPath = malloc(64);
        defer {
            free(tempPath)
        }
        strcpy(tempPath!, "/tmp/wg_genkey_XXXXXXXXX")
        mktemp(tempPath!)
        let newData = Data(bytes:tempPath!, count:strlen(tempPath!))
        let pathAsString = String(data:newData, encoding:.utf8)!
        let newFD = try FileDescriptor.open(pathAsString, .writeOnly, options:[.create, .truncate], permissions: [.ownerReadWriteExecute])
        _ = try newFD.closeAfter {
            try newFD.writeAll(key.presharedKey.utf8)
        }
        defer {
//            remove(tempPath)
        }
        //preshared-key \(pathAsString)
        print("sudo wg set \(interfaceName) peer \(key.publicKey) allowed-ips \(address.string)/128")
        let installKey = try await Command(bash:"sudo wg set \(interfaceName) peer \(key.publicKey) allowed-ips \(address.string)/128 preshared-key \(key.presharedKey)").runSync()
        guard installKey.succeeded == true else {
            let stderrLines = installKey.stderr.compactMap({ String(data:$0, encoding:.utf8) })
            for errLine in stderrLines {
                print(Colors.Red("\(errLine)"))
            }
            throw Error.wireguardCmdError
        }
    }
}

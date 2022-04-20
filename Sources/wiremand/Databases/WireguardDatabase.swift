import QuickLMDB
import AddressKit
import Foundation
import SystemPackage

class WireguardDatabase {
    static func createDatabase(directory:URL, wg_primaryInterfaceName:String, wg_serverPublicDomainName:String, wg_serverPublicListenPort:UInt16, serverIPv6Block:NetworkV6, publicKey:String, defaultSubnetMask:UInt8) throws {
		let wgDBPath = directory.appendingPathComponent("wireguard-dbi")
		let makeEnv = try Environment(path:wgDBPath.path, flags:[.noSubDir], mapSize:4000000000, maxReaders:128, maxDBs:32)
		
        try makeEnv.transact(readOnly: false) { someTransaction in
			let metadataDB = try makeEnv.openDatabase(named:Databases.metadata.rawValue, flags:[.create], tx:someTransaction)
			
			//make all the databases
			_ = try makeEnv.openDatabase(named:Databases.clientPub_ipv6.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.clientPub_clientName.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.clientPub_createdOn.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.clientPub_subnetName.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.subnetName_networkV6.rawValue, flags:[.create], tx:someTransaction)
            _ = try makeEnv.openDatabase(named:Databases.networkV6_subnetName.rawValue, flags:[.create], tx:someTransaction)
		
			//assign required metadata values
			try metadataDB.setEntry(value:wg_primaryInterfaceName, forKey:Metadatas.wg_primaryInterfaceName.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:wg_serverPublicDomainName, forKey:Metadatas.wg_serverPublicDomainName.rawValue, tx:someTransaction)
            try metadataDB.setEntry(value:wg_serverPublicListenPort, forKey:Metadatas.wg_serverPublicListenPort.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:serverIPv6Block, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:publicKey, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:someTransaction)
            try metadataDB.setEntry(value:defaultSubnetMask, forKey:Metadatas.wg_defaultSubnetMask.rawValue, tx:someTransaction)
		}
	}
	
	enum Metadatas:String {
		case wg_primaryInterfaceName = "wg_primaryWGInterfaceName" //String
		case wg_serverPublicDomainName = "wg_serverPublicDomainName" //String
        case wg_serverPublicListenPort = "wg_serverPublicListenPort" //UInt16
		case wg_serverIPv6Block = "wg_serverIPv6Subnet" //NetworkV6 where address == servers own internal IP
		case wg_serverPublicKey = "serverPublicKey" //String
		case wg_defaultSubnetMask = "defaultSubnetMask" //UInt8
	}
	func primaryInterfaceName(_ tx:Transaction? = nil) throws -> String {
		return try self.metadata.getEntry(type:String.self, forKey:Metadatas.wg_primaryInterfaceName.rawValue, tx:tx)!
	}
	func getPublicEndpointName(_ tx:Transaction? = nil) throws -> String {
		return try self.metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicDomainName.rawValue, tx:tx)!
	}
    func getPublicListenPort(_ tx:Transaction? = nil) throws -> UInt16 {
        return try self.metadata.getEntry(type:UInt16.self, forKey:Metadatas.wg_serverPublicListenPort.rawValue, tx:tx)!
    }
	func getServerInternalNetwork(_ tx:Transaction? = nil) throws -> NetworkV6 {
		return try self.metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:tx)!
	}
	func getServerPublicKey(_ tx:Transaction? = nil) throws -> String {
		return try self.metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:tx)!
	}
    
    func getWireguardConfigMetas() throws -> (String, UInt16, NetworkV6, String) {
        return try env.transact(readOnly:true) { someTrans -> (String, UInt16, NetworkV6, String) in
            let getDNSName = try metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicDomainName.rawValue, tx:someTrans)!
            let getPort = try metadata.getEntry(type:UInt16.self, forKey:Metadatas.wg_serverPublicListenPort.rawValue, tx:someTrans)!
            let ipv6Block = try metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTrans)!
            let serverPubKey = try metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:someTrans)!
            return (getDNSName, getPort, ipv6Block, serverPubKey)
        }
    }
	
    enum Databases:String {
        case metadata = "metadata"
        
        ///Maps a client public key to their respective ipv6 address assignment
        case clientPub_ipv6 = "clientPub_IPv6" //String:AddressV6
        
        ///Maps a client ipv6 address to their public key
        case ipv6_clientPub = "IPv6_clientPub" //AddressV6:String
        
        ///Maps a client public key to their respective client name
        case clientPub_clientName = "clientPub_clientName" //String:String

        ///Maps a client public key to their keys respective creation date
        case clientPub_createdOn = "clientPub_createDate" //String:Date
        
        ///Maps a client public key to their respective subnet
        case clientPub_subnetName = "clientPub_subnetName" //String:String
        
        ///Maps a given subnet name to its respective IPv6 network
        case subnetName_networkV6 = "subnetName_networkV6" //String:NetworkV6
        
        ///Maps a given subnet CIDR to its respective subnet name
        case networkV6_subnetName = "networkV6_subnetName" //NetworkV6:String
        
        ///Maps a given subnet name hash to its respective security key
        case subnetHash_securityKey = "subnetHash_securityKey" //String:String
    }
    // basics
	let env:Environment
	let metadata:Database
    
    // client info
	let clientPub_ipv6:Database
    let ipv6_clientPub:Database
	let clientPub_clientName:Database
	let clientPub_createdOn:Database
	let clientPub_subnetName:Database
	
    // subnet info
	let subnetName_networkV6:Database
    let networkV6_subnetName:Database
    let subnetHash_securityKey:Database
	
	init(directory:URL) throws {
		let wgDBPath = directory.appendingPathComponent("wireguard-dbi")
		let makeEnv = try Environment(path:wgDBPath.path, flags:[.noSubDir], mapSize:4000000000, maxReaders:128, maxDBs:32)
		
		let dbs = try makeEnv.transact(readOnly:false) { someTrans -> [Database] in
			// open all the databases
			let metadata = try makeEnv.openDatabase(named:Databases.metadata.rawValue, tx:someTrans)
			let clientPub_ipv6 = try makeEnv.openDatabase(named:Databases.clientPub_ipv6.rawValue, tx:someTrans)
            let ipv6_clientPub = try makeEnv.openDatabase(named:Databases.ipv6_clientPub.rawValue, tx:someTrans)
			let clientPub_clientName = try makeEnv.openDatabase(named:Databases.clientPub_clientName.rawValue, tx:someTrans)
			let clientPub_createdOn = try makeEnv.openDatabase(named:Databases.clientPub_createdOn.rawValue, tx:someTrans)
			let clientPub_subnetName = try makeEnv.openDatabase(named:Databases.clientPub_subnetName.rawValue, tx:someTrans)
			let subnetName_networkV6 = try makeEnv.openDatabase(named:Databases.subnetName_networkV6.rawValue, tx:someTrans)
            let networkV6_subnetName = try makeEnv.openDatabase(named:Databases.networkV6_subnetName.rawValue, tx:someTrans)
            let subnetName_securityKey = try makeEnv.openDatabase(named:Databases.subnetHash_securityKey.rawValue, tx:someTrans)
            return [metadata, clientPub_ipv6, ipv6_clientPub, clientPub_clientName, clientPub_createdOn, clientPub_subnetName, subnetName_networkV6, networkV6_subnetName, subnetName_securityKey]
		}
        self.env = makeEnv
        self.metadata = dbs[0]
        self.clientPub_ipv6 = dbs[1]
        self.ipv6_clientPub = dbs[2]
        self.clientPub_clientName = dbs[3]
        self.clientPub_createdOn = dbs[4]
        self.clientPub_subnetName = dbs[5]
        self.subnetName_networkV6 = dbs[6]
        self.networkV6_subnetName = dbs[7]
        self.subnetHash_securityKey = dbs[8]
	}
    
    func subnetMake(name:String) throws -> (NetworkV6, String) {
        let randomBuffer = malloc(512);
        defer {
            free(randomBuffer)
        }
        return try env.transact(readOnly:false) { someTrans in
            // get the default subnet mask size
            let maskNumber = try self.metadata.getEntry(type:UInt8.self, forKey:Metadatas.wg_defaultSubnetMask.rawValue, tx:someTrans)!
            // get the servers ipv6 block
            let ipv6Block = try self.metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTrans)!
            
            // find a vacant subnet (subnet cannot already exist and subnet cannot overlap with the servers own internal IPv6 address)
            var suggestedSubnet:NetworkV6
            repeat {
                suggestedSubnet = NetworkV6(cidr:ipv6Block.range.randomAddress().string + "/\(maskNumber)")!.maskingAddress()
            } while try self.networkV6_subnetName.containsEntry(key:suggestedSubnet, tx:someTrans) == true && suggestedSubnet.contains(ipv6Block.address)
            
            // write the subnet and name to the database
            try self.subnetName_networkV6.setEntry(value:suggestedSubnet, forKey:name, tx:someTrans)
            try self.networkV6_subnetName.setEntry(value:name, forKey:suggestedSubnet, tx:someTrans)
            
            // read 512 bytes of random data from the system
            let randomFD = try FileDescriptor.open("/dev/urandom", .readOnly)
            defer {
                try! randomFD.close()
            }
            var totalRead = 0
            repeat {
                totalRead += try randomFD.read(into:UnsafeMutableRawBufferPointer(start:randomBuffer!.advanced(by:totalRead), count:512))
            } while totalRead < 512
            
            let randomString = Data(bytes:randomBuffer!, count:64).base64EncodedString()
            try self.subnetHash_securityKey.setEntry(value:randomString, forKey:name, tx:someTrans)
            return (suggestedSubnet, randomString)
        }
    }
    struct SubnetInfo {
        let name:String
        let network:NetworkV6
    }
    func allSubnets() throws -> [SubnetInfo] {
        return try env.transact(readOnly:true) { someTrans in
            let subnetNameCursor = try subnetName_networkV6.cursor(tx:someTrans)
            var buildSubnets = [SubnetInfo]()
            for curKV in subnetNameCursor {
                buildSubnets.append(SubnetInfo(name:String(curKV.key)!, network:NetworkV6(curKV.value)!))
            }
            return buildSubnets
        }
    }
    
    func clientMake(name:String, publicKey:String, subnet:String) throws -> AddressV6 {
        return try env.transact(readOnly:false) { someTrans in
            // validate the subnet exists by retrieving its network
            let subnetNetwork = try subnetName_networkV6.getEntry(type:NetworkV6.self, forKey:subnet, tx:someTrans)!
            let serverInternalIP = try self.metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTrans)!.address
            
            // find a non-conflicting address
            var newAddress:AddressV6
            repeat {
                newAddress = subnetNetwork.range.randomAddress()
            } while try self.ipv6_clientPub.containsEntry(key:newAddress, tx:someTrans) == true && newAddress == serverInternalIP
            
            // write it to the database
            try self.clientPub_ipv6.setEntry(value:newAddress, forKey:publicKey, flags:[.noOverwrite], tx:someTrans)
            try self.ipv6_clientPub.setEntry(value:publicKey, forKey:newAddress, flags:[.noOverwrite], tx:someTrans)
            try self.clientPub_clientName.setEntry(value:name, forKey:publicKey, flags:[.noOverwrite], tx:someTrans)
            try self.clientPub_createdOn.setEntry(value:Date(), forKey:publicKey, flags:[.noOverwrite], tx:someTrans)
            try self.clientPub_subnetName.setEntry(value:subnet, forKey:publicKey, flags:[.noOverwrite], tx:someTrans)
            
            return newAddress
        }
    }
}

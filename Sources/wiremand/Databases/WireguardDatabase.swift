import QuickLMDB
import AddressKit
import Foundation
import SystemPackage

class WireguardDatabase {
    static func createDatabase(directory:URL, wg_primaryInterfaceName:String, wg_serverPublicDomainName:String, wg_serverPublicListenPort:UInt16, serverIPv6Block:NetworkV6, publicKey:String, defaultSubnetMask:UInt8, noHandshakeInvalidationInterval:TimeInterval = 900, handshakeInvalidationInterval:TimeInterval = 2629800) throws {
		let wgDBPath = directory.appendingPathComponent("wireguard-dbi")
		let makeEnv = try Environment(path:wgDBPath.path, flags:[.noSubDir], mapSize:4000000000, maxReaders:128, maxDBs:32)
		
        try makeEnv.transact(readOnly: false) { someTransaction in
			let metadataDB = try makeEnv.openDatabase(named:Databases.metadata.rawValue, flags:[.create], tx:someTransaction)
			
			//make all the databases
			_ = try makeEnv.openDatabase(named:Databases.clientPub_ipv6.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.ipv6_clientPub.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.clientPub_clientName.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.clientPub_createdOn.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.clientPub_subnetName.rawValue, flags:[.create], tx:someTransaction)
            _ = try makeEnv.openDatabase(named:Databases.clientPub_handshakeDate.rawValue, flags:[.create], tx:someTransaction)
			_ = try makeEnv.openDatabase(named:Databases.subnetName_networkV6.rawValue, flags:[.create], tx:someTransaction)
            _ = try makeEnv.openDatabase(named:Databases.networkV6_subnetName.rawValue, flags:[.create], tx:someTransaction)
            _ = try makeEnv.openDatabase(named:Databases.subnetHash_securityKey.rawValue, flags:[.create], tx:someTransaction)
            _ = try makeEnv.openDatabase(named:Databases.subnetName_clientPub.rawValue, flags:[.create, .dupSort], tx:someTransaction)
            
			//assign required metadata values
			try metadataDB.setEntry(value:wg_primaryInterfaceName, forKey:Metadatas.wg_primaryInterfaceName.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:wg_serverPublicDomainName, forKey:Metadatas.wg_serverPublicDomainName.rawValue, tx:someTransaction)
            try metadataDB.setEntry(value:wg_serverPublicListenPort, forKey:Metadatas.wg_serverPublicListenPort.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:serverIPv6Block, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTransaction)
			try metadataDB.setEntry(value:publicKey, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:someTransaction)
            try metadataDB.setEntry(value:defaultSubnetMask, forKey:Metadatas.wg_defaultSubnetMask.rawValue, tx:someTransaction)
            try metadataDB.setEntry(value:noHandshakeInvalidationInterval, forKey:Metadatas.wg_noHandshakeInvalidationInterval.rawValue, tx:someTransaction)
            try metadataDB.setEntry(value:handshakeInvalidationInterval, forKey:Metadatas.wg_handshakeInvalidationInterval.rawValue, tx:someTransaction)
		}
	}
	
	enum Metadatas:String {
		case wg_primaryInterfaceName = "wg_primaryWGInterfaceName" //String
		case wg_serverPublicDomainName = "wg_serverPublicDomainName" //String
        case wg_serverPublicListenPort = "wg_serverPublicListenPort" //UInt16
		case wg_serverIPv6Block = "wg_serverIPv6Subnet" //NetworkV6 where address == servers own internal IP
		case wg_serverPublicKey = "serverPublicKey" //String
		case wg_defaultSubnetMask = "defaultSubnetMask" //UInt8
        case wg_noHandshakeInvalidationInterval = "noHandshakeInvalidationInterval" //TimeInterval
        case wg_handshakeInvalidationInterval = "handshakeInvalidationInterval" //TimeInterval
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
    
    func getWireguardConfigMetas() throws -> (String, UInt16, NetworkV6, String, String) {
        return try env.transact(readOnly:true) { someTrans -> (String, UInt16, NetworkV6, String, String) in
            let getDNSName = try metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicDomainName.rawValue, tx:someTrans)!
            let getPort = try metadata.getEntry(type:UInt16.self, forKey:Metadatas.wg_serverPublicListenPort.rawValue, tx:someTrans)!
            let ipv6Block = try metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTrans)!
            let serverPubKey = try metadata.getEntry(type:String.self, forKey:Metadatas.wg_serverPublicKey.rawValue, tx:someTrans)!
            let publicInterfaceName = try metadata.getEntry(type:String.self, forKey:Metadatas.wg_primaryInterfaceName.rawValue, tx:someTrans)!
            return (getDNSName, getPort, ipv6Block, serverPubKey, publicInterfaceName)
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
        
        ///Maps a client public key to their respective handshake date
        case clientPub_handshakeDate = "clientPub_handshakeDate" //String:Date? (optional value)
        
        ///Maps a given subnet name to its respective IPv6 network
        case subnetName_networkV6 = "subnetName_networkV6" //String:NetworkV6
        
        ///Maps a given subnet CIDR to its respective subnet name
        case networkV6_subnetName = "networkV6_subnetName" //NetworkV6:String
        
        ///Maps a given subnet name hash to its respective security key
        case subnetHash_securityKey = "subnetHash_securityKey" //String:String
        
        ///Maps a given subnet name to the various public keys that it encompasses
        case subnetName_clientPub = "subnetName_clientPub"
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
    let clientPub_handshakeDate:Database
	
    // subnet info
	let subnetName_networkV6:Database
    let networkV6_subnetName:Database
    let subnetHash_securityKey:Database
    let subnetName_clientPub:Database
	
	init(directory:URL) throws {
		let wgDBPath = directory.appendingPathComponent("wireguard-dbi")
		let makeEnv = try Environment(path:wgDBPath.path, flags:[.noSubDir], mapSize:4000000000, maxReaders:128, maxDBs:32)
		
		let dbs = try makeEnv.transact(readOnly:false) { someTrans -> [Database] in
			// open all the databases
            let metadata = try makeEnv.openDatabase(named:Databases.metadata.rawValue, flags:[], tx:someTrans)
			let clientPub_ipv6 = try makeEnv.openDatabase(named:Databases.clientPub_ipv6.rawValue, flags:[], tx:someTrans)
            let ipv6_clientPub = try makeEnv.openDatabase(named:Databases.ipv6_clientPub.rawValue, flags:[], tx:someTrans)
			let clientPub_clientName = try makeEnv.openDatabase(named:Databases.clientPub_clientName.rawValue, flags:[], tx:someTrans)
			let clientPub_createdOn = try makeEnv.openDatabase(named:Databases.clientPub_createdOn.rawValue, flags:[], tx:someTrans)
			let clientPub_subnetName = try makeEnv.openDatabase(named:Databases.clientPub_subnetName.rawValue, flags:[], tx:someTrans)
            let clientPub_handshakeDate = try makeEnv.openDatabase(named:Databases.clientPub_handshakeDate.rawValue, flags:[], tx:someTrans)
			let subnetName_networkV6 = try makeEnv.openDatabase(named:Databases.subnetName_networkV6.rawValue, flags:[], tx:someTrans)
            let networkV6_subnetName = try makeEnv.openDatabase(named:Databases.networkV6_subnetName.rawValue, flags:[], tx:someTrans)
            let subnetName_securityKey = try makeEnv.openDatabase(named:Databases.subnetHash_securityKey.rawValue, flags:[], tx:someTrans)
            let subnetName_clientPub = try makeEnv.openDatabase(named:Databases.subnetName_clientPub.rawValue, flags:[.dupSort], tx:someTrans)
            return [metadata, clientPub_ipv6, ipv6_clientPub, clientPub_clientName, clientPub_createdOn, clientPub_subnetName, clientPub_handshakeDate, subnetName_networkV6, networkV6_subnetName, subnetName_securityKey, subnetName_clientPub]
		}
        self.env = makeEnv
        self.metadata = dbs[0]
        self.clientPub_ipv6 = dbs[1]
        self.ipv6_clientPub = dbs[2]
        self.clientPub_clientName = dbs[3]
        self.clientPub_createdOn = dbs[4]
        self.clientPub_subnetName = dbs[5]
        self.clientPub_handshakeDate = dbs[6]
        self.subnetName_networkV6 = dbs[7]
        self.networkV6_subnetName = dbs[8]
        self.subnetHash_securityKey = dbs[9]
        self.subnetName_clientPub = dbs[10]
	}
    
    // make a subnet
    struct SubnetInfo {
        let name:String
        let network:NetworkV6
        let securityKey:String
    }
    func subnetMake(name:String) throws -> (NetworkV6, String) {
        let randomBuffer = malloc(512);
        defer {
            free(randomBuffer)
        }
        return try env.transact(readOnly:false) { someTrans in
            // get the default subnet mask size
            let maskNumber = try! self.metadata.getEntry(type:UInt8.self, forKey:Metadatas.wg_defaultSubnetMask.rawValue, tx:someTrans)!
            // get the servers ipv6 block
            let ipv6Block = try! self.metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:someTrans)!
            
            // find a vacant subnet (subnet cannot already exist and subnet cannot overlap with the servers own internal IPv6 address)
            var suggestedSubnet:NetworkV6
            repeat {
                suggestedSubnet = NetworkV6(cidr:ipv6Block.range.randomAddress().string + "/\(maskNumber)")!.maskingAddress()
            } while try! self.networkV6_subnetName.containsEntry(key:suggestedSubnet, tx:someTrans) == true && suggestedSubnet.contains(ipv6Block.address)
            
            // write the subnet and name to the database
            try self.subnetName_networkV6.setEntry(value:suggestedSubnet, forKey:name, tx:someTrans)
            try self.networkV6_subnetName.setEntry(value:name, forKey:suggestedSubnet, tx:someTrans)
            
            // read 512 bytes of random data from the system
            let randomFD = try! FileDescriptor.open("/dev/urandom", .readOnly)
            defer {
                try! randomFD.close()
            }
            var totalRead = 0
            repeat {
                totalRead += try! randomFD.read(into:UnsafeMutableRawBufferPointer(start:randomBuffer!.advanced(by:totalRead), count:512))
            } while totalRead < 512
            
            let randomString = Data(bytes:randomBuffer!, count:64).base64EncodedString()
            let domainHash = try WiremanD.hash(domain:name)
            try! self.subnetHash_securityKey.setEntry(value:randomString, forKey:domainHash, tx:someTrans)
            return (suggestedSubnet, randomString)
        }
    }
    // validate the security keys for a given subnet
    func validateSecurity(dk subnetHash:String, sk securityKey:String) throws -> Bool {
        return try env.transact(readOnly:true) { someTrans in
            do {
                let currentSecurityKey = try self.subnetHash_securityKey.getEntry(type:String.self, forKey:subnetHash, tx:someTrans)
                if (currentSecurityKey == securityKey) {
                    return true
                } else {
                    return false
                }
            } catch LMDBError.notFound {
                return false
            }
        }
    }
    // get all the subnets in the database
    func allSubnets() throws -> [SubnetInfo] {
        return try env.transact(readOnly:true) { someTrans in
            let subnetNameCursor = try subnetName_networkV6.cursor(tx:someTrans)
            let securityKeyCursor = try subnetHash_securityKey.cursor(tx:someTrans)
            var buildSubnets = [SubnetInfo]()
            for curKV in subnetNameCursor {
                let name = String(curKV.key)!
                let hashed = try WiremanD.hash(domain:name)
                let securityKey = String(try securityKeyCursor.getEntry(.set, key:hashed).value)!
                buildSubnets.append(SubnetInfo(name:name, network:NetworkV6(curKV.value)!, securityKey:securityKey))
            }
            return buildSubnets
        }
    }
    func validateSubnet(name:String) throws -> Bool {
        try env.transact(readOnly:true) { someTrans in
            return try self.subnetName_networkV6.containsEntry(key:name, tx:someTrans)
        }
    }
    
    // make a client
    struct ClientInfo:Hashable {
        let publicKey:String
        let address:AddressV6
        let name:String
        let subnetName:String
    }
    fileprivate func _clientMake(name:String, publicKey:String, subnet:String, tx:Transaction) throws -> AddressV6 {
        // validate the subnet exists by retrieving its network
        let subnetNetwork = try subnetName_networkV6.getEntry(type:NetworkV6.self, forKey:subnet, tx:tx)!
        let serverInternalIP = try self.metadata.getEntry(type:NetworkV6.self, forKey:Metadatas.wg_serverIPv6Block.rawValue, tx:tx)!.address
        
        // find a non-conflicting address
        var newAddress:AddressV6
        repeat {
            newAddress = subnetNetwork.range.randomAddress()
        } while try self.ipv6_clientPub.containsEntry(key:newAddress, tx:tx) == true && newAddress == serverInternalIP
        
        // write it to the database
        try self.clientPub_ipv6.setEntry(value:newAddress, forKey:publicKey, flags:[.noOverwrite], tx:tx)
        try self.ipv6_clientPub.setEntry(value:publicKey, forKey:newAddress, flags:[.noOverwrite], tx:tx)
        try self.clientPub_clientName.setEntry(value:name, forKey:publicKey, flags:[.noOverwrite], tx:tx)
        try self.clientPub_createdOn.setEntry(value:Date(), forKey:publicKey, flags:[.noOverwrite], tx:tx)
        try self.clientPub_subnetName.setEntry(value:subnet, forKey:publicKey, flags:[.noOverwrite], tx:tx)
        
        try self.subnetName_clientPub.setEntry(value:publicKey, forKey:subnet, flags:[.noOverwrite], tx:tx)
        
        return newAddress
    }
    func clientMake(name:String, publicKey:String, subnet:String) throws -> AddressV6 {
        return try env.transact(readOnly:false) { someTrans in
            return try _clientMake(name:name, publicKey:publicKey, subnet:subnet, tx:someTrans)
        }
    }
    fileprivate func _clientRemove(publicKey:String, tx:Transaction) throws {
        // get the clients address
        let clientAddress = try self.clientPub_ipv6.getEntry(type:AddressV6.self, forKey:publicKey, tx:tx)!
        let clientSubnet = try self.clientPub_subnetName.getEntry(type:String.self, forKey:publicKey, tx:tx)!
        
        // with this info we can delete everything else from the database
        try self.clientPub_ipv6.deleteEntry(key:publicKey, tx:tx)
        try self.ipv6_clientPub.deleteEntry(key:clientAddress, tx:tx)
        try self.clientPub_clientName.deleteEntry(key:publicKey, tx:tx)
        try self.clientPub_subnetName.deleteEntry(key:publicKey, tx:tx)
        try self.subnetName_clientPub.deleteEntry(key:clientSubnet, value:publicKey, tx:tx)
        do {
            try self.clientPub_handshakeDate.deleteEntry(key:publicKey, tx:tx)
        } catch LMDBError.notFound {}
    }
    func clientRemove(publicKey:String, tx:Transaction) throws {
        try env.transact(readOnly:false) { someTrans in
            try self._clientRemove(publicKey:publicKey, tx:tx)
        }
    }
    fileprivate func _allClients(subnet:String? = nil, tx:Transaction) throws -> Set<ClientInfo> {
        var buildClients = Set<ClientInfo>()
        let clientAddressCursor = try self.clientPub_ipv6.cursor(tx:tx)
        let clientNameCursor = try self.clientPub_clientName.cursor(tx:tx)
        let clientSubnetCursor = try self.clientPub_subnetName.cursor(tx:tx)
        if (subnet == nil) {
            // all clients are requested
            for curClient in clientAddressCursor {
                let getName = String(try clientNameCursor.getEntry(.set, key:curClient.key).value)!
                let getSubnet = String(try clientSubnetCursor.getEntry(.set, key:curClient.key).value)!
                let publicKey = String(curClient.key)!
                let address = AddressV6(curClient.value)!
                buildClients.update(with:ClientInfo(publicKey:publicKey, address:address, name:getName, subnetName:getSubnet))
            }
            return buildClients
        } else {
            // only the clients of a certain subnet are requested
            let subnetNameCursor = try self.subnetName_clientPub.cursor(tx:tx)
            _ = try subnetNameCursor.getEntry(.set, key:subnet!)
            do {
                var operation = Cursor.Operation.firstDup
                repeat {
                    let getCurrentPub = try subnetNameCursor.getEntry(operation).value
                    let clientAddress = AddressV6(try clientAddressCursor.getEntry(.set, key:getCurrentPub).value)!
                    let clientName = String(try clientNameCursor.getEntry(.set, key:getCurrentPub).value)!
                    
                    buildClients.update(with:ClientInfo(publicKey:String(getCurrentPub)!, address:clientAddress, name:clientName, subnetName:subnet!))
                    
                    switch operation {
                    case .firstDup:
                        operation = .nextDup
                    default:
                        break;
                    }
                } while true
            } catch LMDBError.notFound {}
            return buildClients
        }
    }
    func allClients(subnet:String? = nil) throws -> Set<ClientInfo> {
        try env.transact(readOnly:true) { someTrans in
            return try _allClients(subnet:subnet, tx:someTrans)
        }
    }
    
    func processHandshakes(_ handshakes:[String:Date], zeros:Set<String>) throws -> Set<String> {
        //new readwrite
        return try env.transact(readOnly:false) { someTrans in
            
            let clientAddressCursor = try clientPub_ipv6.cursor(tx:someTrans)
            let clientHandshakeCursor = try clientPub_handshakeDate.cursor(tx:someTrans)
            
            let noHandshakeInterval = try self.metadata.getEntry(type:TimeInterval.self, forKey:Metadatas.wg_noHandshakeInvalidationInterval.rawValue, tx:someTrans)!
            let handshakeInterval = try self.metadata.getEntry(type:TimeInterval.self, forKey:Metadatas.wg_handshakeInvalidationInterval.rawValue, tx:someTrans)!
            
            // any public keys that need to be removed from the wireguard interface are passed into this variable
            var removeKeys = Set<String>()
            
            // iterate through every client with nonzero handshake data
            for curClient in handshakes {
                // validate that the client exists
                if try clientAddressCursor.containsEntry(key:curClient.key) == true {
                    // check what the existing handshake value is for this client
                    do {
                        let existingHandshake = Date(try clientHandshakeCursor.getEntry(.set, key:curClient.key).value)!
                        
                        if (existingHandshake < curClient.value) {
                            // update the handshake date because there is a newer date than what is stored in the database
                            try clientHandshakeCursor.setEntry(value:curClient.value, forKey:curClient.key)
                        } else {
                            // handshake has not been updated, so check and see if it has crossed the drop threshold for clients that have successfully made a handshake
                            if (existingHandshake.addingTimeInterval(handshakeInterval).timeIntervalSinceNow < 0) {
                                try _clientRemove(publicKey:curClient.key, tx:someTrans)
                                removeKeys.update(with:curClient.key)
                            }
                        }
                    } catch LMDBError.notFound {
                        // assign a handshake value if it cannot be found in the database
                        try clientHandshakeCursor.setEntry(value:curClient.value, forKey:curClient.key)
                    }
                } else {
                    // return the key as unfound if they cannot be found in the database
                    removeKeys.update(with:curClient.key)
                }
            }
            
            for curClient in zeros {
                // validate that the client exists
                if try clientAddressCursor.containsEntry(key:curClient) == true {
                    // if the client already has a handshake entry, it needs to be removed
                    if try clientHandshakeCursor.containsEntry(key:curClient) == true {
                        try clientHandshakeCursor.deleteEntry()
                    }
                    
                    // check the creation date of the client
                    let createDate = try self.clientPub_createdOn.getEntry(type:Date.self, forKey:curClient, tx:someTrans)!
                    
                    // if the creation date with the added `noHandshakeDropInterval` is behind present time, drop the client
                    if (createDate.addingTimeInterval(noHandshakeInterval).timeIntervalSinceNow < 0) {
                        removeKeys.update(with:curClient)
                        try _clientRemove(publicKey:curClient, tx:someTrans)
                    }
                } else {
                    // return the key as unfound if they cannot be found in the database
                    removeKeys.update(with:curClient)
                }
            }
            
            // if there are more keys in the database than were passed into this function, we must remove any of the outstanding keys from the db before returning
            if try (handshakes.count + zeros.count - removeKeys.count) < clientPub_clientName.getStatistics(tx:someTrans).entries {
                for curClient in clientAddressCursor {
                    let pubKey = String(curClient.key)!
                    if (handshakes[pubKey] == nil && zeros.contains(pubKey) == false) {
                        // remove the client from the database. this public key does not need to be added to the `removeKeys` because it never existed in the database
                        try _clientRemove(publicKey:pubKey, tx:someTrans)
                    }
                }
            }
            return removeKeys
        }
    }
}

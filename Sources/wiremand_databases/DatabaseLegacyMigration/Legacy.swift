import QuickLMDB
import RAW
import bedrock
import RAW_base64
import bedrock_ip
import struct Foundation.Date

struct DBLegacy {
	struct Wireguard {
		enum Names:String {
			case metadata = "wgdb_metadata_db"
	
			// Client Databases
			/// Maps a client public key to their respective ipv4 address assignment (intended for small uses)
			case clientPub_ipv4 = "wgdb_clientPub_IPv4"	//String:AddressV4
			/// Maps a client ipv4 address assignment to their respective public key (intended for infrequent uses)
			case ipv4_clientPub = "wgdb_IPv4_clientPub"	//AddressV4:String
			/// Maps a client public key to their respective ipv6 address assignment
			case clientPub_ipv6 = "wgdb_clientPub_IPv6" //String:AddressV6
			// Maps a client ipv6 address to their public key
			case ipv6_clientPub = "wgdb_IPv6_clientPub" //AddressV6:String
			/// Maps a client public key to their respective client name
			case clientPub_clientName = "wgdb_clientPub_clientName" //String:String
			/// Maps a client public key to their keys respective creation date
			case clientPub_createdOn = "wgdb_clientPub_createDate" //String:Date
			/// Maps a client public key to their respective subnet
			case clientPub_subnetName = "wgdb_clientPub_subnetName" //String:String
			// Maps a client public key to their respective handshake date
			case clientPub_handshakeDate = "wgdb_clientPub_handshakeDate" //String:Date? (optional value)
			/// Maps a client public key to their respective endpoint address
			case clientPub_endpointAddress = "wgdb_clientPub_endpointAddr" //String:String? (optional value)
			/// Maps a client public key to their respective invalidation date
			case clientPub_invalidDate = "wgdb_clientPub_invalidDate" //String:Date (non-optional but not specified for the servers own public key since the server cannot invalidate itself)
			
			/// Maps a given subnet name to its respective IPv6 network
			case subnetName_networkV6 = "wgdb_subnetName_networkV6" //String:NetworkV6
			
			/// Maps a given subnet CIDR to its respective subnet name
			case networkV6_subnetName = "wgdb_networkV6_subnetName" //NetworkV6:String
			
			/// Maps a given subnet name hash to its respective security key
			/// - not specified on subnets that do not have the public api activated
			case subnetHash_securityKey = "wgdb_subnetHash_securityKey" //String:String
			
			/// Maps a given subnet name to the various public keys that it encompasses
			case subnetName_clientPub = "wgdb_subnetName_clientPub" //String:String
			
			/// Maps a given subnet name to the various client name that reside within it. This prevents name conflicts
			case subnetName_clientNameHash = "wgdb_subnetName_clientNameHash" //String:Data
			
			/// Maps a given client public key to the config data that may be served
			case webServe__clientPub_configData = "wgdb___webserve_clientPub_configData" //String:String
		}
	}
}

extension WireguardDatabase_vX {
	public func migrate(oldWireguardDatabase:Environment) throws {
		let oldDBTrans = try Transaction(env:oldWireguardDatabase, readOnly:true)
		let oldClientPub_ipv4 = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.clientPub_ipv4.rawValue, flags:[], tx:oldDBTrans)

		// migrate the clientPub_ipv4 and ipv4_clientPub database to the new format
		let newDBTrans = try Transaction(env:env, readOnly:false)
		let newClientPub_ipv4 = try Database.Strict<PublicKey, AddressV4>(env:env, name:Databases.clientPub_ipv4.rawValue, flags:[], tx:newDBTrans)
		let newIpv4_clientPub = try Database.Strict<AddressV4, PublicKey>(env:env, name:Databases.ipv4_clientPub.rawValue, flags:[], tx:newDBTrans)
		try oldClientPub_ipv4.cursor(tx:oldDBTrans) { oldCursor in
			try newClientPub_ipv4.cursor(tx:newDBTrans) { newCursor in
				try newIpv4_clientPub.cursor(tx:newDBTrans) { newCursorInverted in
					for (curKey, curValue) in oldCursor {
						let oldKeyDecoded = PublicKey(RAW_decode:try RAW_base64.decode(EncodedString(curKey)!))!
						let a4 = AddressV4(bedrock_ip.AddressV4(String(EncodedString(curValue)!))!)
						try newCursor.setEntry(key:oldKeyDecoded, value:a4, flags:[])
						try newCursorInverted.setEntry(key:a4, value:oldKeyDecoded, flags:[])
					}
				}
			}
		}


		// migrate the clientPub_ipv6 and ipv6_clientPub database to the new format
		let oldClientPub_ipv6 = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.clientPub_ipv6.rawValue, flags:[], tx:oldDBTrans)
		let newClientPub_ipv6 = try Database.Strict<PublicKey, AddressV6>(env:env, name:Databases.clientPub_ipv6.rawValue, flags:[], tx:newDBTrans)
		let newIpv6_clientPub = try Database.Strict<AddressV6, PublicKey>(env:env, name:Databases.ipv6_clientPub.rawValue, flags:[], tx:newDBTrans)
		try oldClientPub_ipv6.cursor(tx:oldDBTrans) { oldCursor in
			try newClientPub_ipv6.cursor(tx:newDBTrans) { newCursor in
				try newIpv6_clientPub.cursor(tx:newDBTrans) { newCursorInverted in
					for (curKey, curValue) in oldCursor {
						let oldKeyDecoded = PublicKey(RAW_decode:try RAW_base64.decode(EncodedString(curKey)!))!
						let a6 = AddressV6(bedrock_ip.AddressV6(String(EncodedString(curValue)!))!)
						try newCursor.setEntry(key:oldKeyDecoded, value:a6, flags:[])
						try newCursorInverted.setEntry(key:a6, value:oldKeyDecoded, flags:[])
					}
				}
			}
		}

		// migrate the clientPub_clientName database to the new format
		let oldClientPub_clientName = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.clientPub_clientName.rawValue, flags:[], tx:oldDBTrans)
		let newClientPub_clientName = try Database.Strict<PublicKey, EncodedString>(env:env, name:Databases.clientPub_clientName.rawValue, flags:[], tx:newDBTrans)
		try oldClientPub_clientName.cursor(tx:oldDBTrans) { oldCursor in
			try newClientPub_clientName.cursor(tx:newDBTrans) { newCursor in
				for (curKey, curValue) in oldCursor {
					let oldKeyDecoded = PublicKey(RAW_decode:try RAW_base64.decode(EncodedString(curKey)!))!
					let clientName = EncodedString(curValue)!
					try newCursor.setEntry(key:oldKeyDecoded, value:clientName, flags:[])
				}
			}
		}

		// migrate the clientPub_createdOn database to the new format
		let oldClientPub_createdOn = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.clientPub_createdOn.rawValue, flags:[], tx:oldDBTrans)
		let newClientPub_createdOn = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_createdOn.rawValue, flags:[], tx:newDBTrans)
		try oldClientPub_createdOn.cursor(tx:oldDBTrans) { oldCursor in
			try newClientPub_createdOn.cursor(tx:newDBTrans) { newCursor in
				for (curKey, curValue) in oldCursor {
					let oldKeyDecoded = PublicKey(RAW_decode:try RAW_base64.decode(EncodedString(curKey)!))!
					let referenceIntervalString = EncodedString(curValue)!
					let referenceIntervalDuration = Double(String(referenceIntervalString))!
					let referenceDate = Foundation.Date(timeIntervalSinceReferenceDate:referenceIntervalDuration)
					let seconds = bedrock.Date.Seconds(RAW_native:UInt64(referenceDate.timeIntervalSince1970))
					try newCursor.setEntry(key:oldKeyDecoded, value:seconds, flags:[])
				}
			}
		}

		let oldClientPub_subnetName = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.clientPub_subnetName.rawValue, flags:[], tx:oldDBTrans)
		let newClientPub_subnetName = try Database.Strict<SubnetHash, EncodedString>(env:env, name:Databases.subnetNameHash_subnetName.rawValue, flags:[], tx:newDBTrans)
		let newClientPub_subnetNameHash = try Database.Strict<PublicKey, SubnetHash>(env:env, name:Databases.clientPub_subnetNameHash.rawValue, flags:[], tx:newDBTrans)
		try oldClientPub_subnetName.cursor(tx:oldDBTrans) { oldCursor in
			try newClientPub_subnetName.cursor(tx:newDBTrans) { newCursorName in
				try newClientPub_subnetNameHash.cursor(tx:newDBTrans) { newCursorHash in
					for (curKey, curValue) in oldCursor {
						let oldKeyDecoded = PublicKey(RAW_decode:try RAW_base64.decode(EncodedString(curKey)!))!
						let subnetName = EncodedString(curValue)!
						let subnetHash = try SubnetHash(subnetName:subnetName)
						try newCursorName.setEntry(key:subnetHash, value:subnetName, flags:[])
						try newCursorHash.setEntry(key:oldKeyDecoded, value:subnetHash, flags:[])
					}
				}
			}
		}

		let oldClientPub_handshakeDate = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.clientPub_handshakeDate.rawValue, flags:[], tx:oldDBTrans)
		let newClientPub_handshakeDate = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_handshakeDate.rawValue, flags:[], tx:newDBTrans)
		try oldClientPub_handshakeDate.cursor(tx:oldDBTrans) { oldCursor in
			try newClientPub_handshakeDate.cursor(tx:newDBTrans) { newCursor in
				for (curKey, curValue) in oldCursor {
					let oldKeyDecoded = PublicKey(RAW_decode:try RAW_base64.decode(EncodedString(curKey)!))!
					if let referenceIntervalString = EncodedString(curValue) {
						let referenceIntervalDuration = Double(String(referenceIntervalString))!
						let referenceDate = Foundation.Date(timeIntervalSinceReferenceDate:referenceIntervalDuration)
						let seconds = bedrock.Date.Seconds(RAW_native:UInt64(referenceDate.timeIntervalSince1970))
						try newCursor.setEntry(key:oldKeyDecoded, value:seconds, flags:[])
					} else {
						// if the value is nil, we just skip it
					}
				}
			}
		}

		let oldClientPub_endpointAddress = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.clientPub_endpointAddress.rawValue, flags:[], tx:oldDBTrans)
		let newClientPub_endpointAddress = try Database.Strict<PublicKey, Address>(env:env, name:Databases.clientPub_endpointAddress.rawValue, flags:[], tx:newDBTrans)
		try oldClientPub_endpointAddress.cursor(tx:oldDBTrans) { oldCursor in
			try newClientPub_endpointAddress.cursor(tx:newDBTrans) { newCursor in
				for (curKey, curValue) in oldCursor {
					let oldKeyDecoded = PublicKey(RAW_decode:try RAW_base64.decode(EncodedString(curKey)!))!
					let addressString = EncodedString(curValue)!
					let address = Address(String(addressString))!
					try newCursor.setEntry(key:oldKeyDecoded, value:address, flags:[])
				}
			}
		}

		let oldClientPub_invalidDate = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.clientPub_invalidDate.rawValue, flags:[], tx:oldDBTrans)
		let newClientPub_invalidDate = try Database.Strict<PublicKey, bedrock.Date.Seconds>(env:env, name:Databases.clientPub_invalidDate.rawValue, flags:[], tx:newDBTrans)
		try oldClientPub_invalidDate.cursor(tx:oldDBTrans) { oldCursor in
			try newClientPub_invalidDate.cursor(tx:newDBTrans) { newCursor in
				for (curKey, curValue) in oldCursor {
					let oldKeyDecoded = PublicKey(RAW_decode:try RAW_base64.decode(EncodedString(curKey)!))!
					let referenceIntervalString = EncodedString(curValue)!
					let referenceIntervalDuration = Double(String(referenceIntervalString))!
					let referenceDate = Foundation.Date(timeIntervalSinceReferenceDate:referenceIntervalDuration)
					let seconds = bedrock.Date.Seconds(RAW_native:UInt64(referenceDate.timeIntervalSince1970))
					try newCursor.setEntry(key:oldKeyDecoded, value:seconds, flags:[])
				}
			}
		}

		let oldSubnetName_networkV6 = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.subnetName_networkV6.rawValue, flags:[], tx:oldDBTrans)
		let newSubnetName_networkV6 = try Database.Strict<SubnetHash, NetworkV6>(env:env, name:Databases.subnetName_networkV6.rawValue, flags:[], tx:newDBTrans)
		let newNetworkV6_subnetName = try Database.Strict<NetworkV6, EncodedString>(env:env, name:Databases.networkV6_subnetName.rawValue, flags:[], tx:newDBTrans)
		try oldSubnetName_networkV6.cursor(tx:oldDBTrans) { oldCursor in
			try newSubnetName_networkV6.cursor(tx:newDBTrans) { newCursorName in
				try newNetworkV6_subnetName.cursor(tx:newDBTrans) { newCursorHash in
					for (curKey, curValue) in oldCursor {
						let subnetName = EncodedString(curKey)!
						let networkV6 = NetworkV6(String(EncodedString(curValue)!))!
						let subnetHash = try SubnetHash(subnetName:subnetName)
						try newCursorName.setEntry(key:subnetHash, value:networkV6, flags:[])
						try newCursorHash.setEntry(key:networkV6, value:subnetName, flags:[])
					}
				}
			}
		}

		let oldSubnetHash_securityKey = try Database(env:oldWireguardDatabase, name:DBLegacy.Wireguard.Names.subnetHash_securityKey.rawValue, flags:[], tx:oldDBTrans)
		let newSubnetHash_securityKey = try Database.Strict<SubnetHash, EncodedString>(env:env, name:Databases.subnetHash_securityKey.rawValue, flags:[], tx:newDBTrans)
		try oldSubnetHash_securityKey.cursor(tx:oldDBTrans) { oldCursor in
			try newSubnetHash_securityKey.cursor(tx:newDBTrans) { newCursor in
				for (curKey, curValue) in oldCursor {
					let subnetHash = SubnetHash(RAW_decode:try RAW_base64.decode(EncodedString(curKey)!))!
					let securityKey = EncodedString(curValue)!
					try newCursor.setEntry(key:subnetHash, value:securityKey, flags:[])
				}
			}
		}
	}
}
import QuickLMDB
import bedrock
import bedrock_ipaddress

extension WireguardDatabaseV2 {
	internal struct AddressDatabaseV6 {

		private enum Databases:String {
			case clientPub_ipv6 = "addrdb:pub_ipv6"
			case ipv6_clientPub = "addrdb:ipv6_pub"
		}

		private let env:Environment		
		
		// required IPv6 related databases
		internal let clientPub_ipv6:Database.DupFixed<PublicKey, AddressV6>
		internal let ipv6_clientPub:Database.Strict<AddressV6, PublicKey>

		internal init(environment:Environment, tx:borrowing Transaction) throws {
			let subTrans = try Transaction(env:environment, readOnly:false, parent:tx)
			env = environment
			clientPub_ipv6 = try Database.DupFixed(env:environment, name:Databases.clientPub_ipv6.rawValue, flags:[.create], tx:subTrans)
			ipv6_clientPub = try Database.Strict(env:environment, name:Databases.ipv6_clientPub.rawValue, flags:[.create], tx:subTrans)
			try subTrans.commit()
		}

		/// installs a client public key with any number of ipv6 addresses. the public key must not already exist in the database.
		/// - throws: `LMDBError.keyExists` if the client already has an entry in the database.
		internal func createClient(publicKey:PublicKey, ipv6 ipv6s:[AddressV6], tx:borrowing Transaction) throws {
			let subTrans = try Transaction(env:self.env, readOnly:false, parent:tx)
			try clientPub_ipv6.cursor(tx:subTrans) { pubCursor in
				do {
					// check if the client already has an entry in the database. this should throw LMDBError.notFound in order to continue with the write op.
					_ = try pubCursor.opSet(key:publicKey)
					throw LMDBError.keyExists
				} catch LMDBError.notFound {
					// write the data entries
					try ipv6_clientPub.cursor(tx:subTrans) { addyCursor in
						for curV6 in ipv6s {
							try pubCursor.setEntry(key:publicKey, value:curV6, flags:[.noDupData])
							try addyCursor.setEntry(key:curV6, value:publicKey, flags:[.noOverwrite])
						}
					}
				}
			}
			try subTrans.commit()
		}

		/// removes a client public key from the database, along with any number of their IPv6 addresses.
		/// - throws: `LMDBError.notFound` if the public key does not exist.
		/// - returns: a complete set of IPv6 addresses that were removed from the database.
		@discardableResult internal func removeClient(publicKey:PublicKey, tx:borrowing Transaction) throws -> Set<AddressV6> {
			let subTrans = try Transaction(env:self.env, readOnly:false, parent:tx)
			let returnValue = try clientPub_ipv6.cursor(tx:subTrans) { cursor in
				_ = try cursor.opSet(key:publicKey)
				var buildAddresses = Set<AddressV6>()
				for (_, curValue) in cursor.makeDupIterator(key:publicKey) {
					try ipv6_clientPub.deleteEntry(key:curValue, tx:subTrans)
					try cursor.deleteCurrentEntry(flags:[])
					buildAddresses.update(with:curValue)
				}
				return buildAddresses
			}
			try subTrans.commit()
			return returnValue
		}

		/// searches the database for all ipv6 addresses associated with.
		/// - throws: `LMDBError.notFound` if any of the public key do not exist.
		internal func getAddresses(publicKeys:Set<PublicKey>, tx:borrowing Transaction) throws -> [PublicKey:Set<AddressV6>] {
			let returnValue = try clientPub_ipv6.cursor(tx:tx) { cursor in
				var buildAddresses = [PublicKey:Set<AddressV6>]()
				for publicKey in publicKeys {
					_ = try cursor.opSet(key:publicKey)
					var curPubAddresses = Set<AddressV6>()
					for (_, curValue) in cursor.makeDupIterator(key:publicKey) {
						curPubAddresses.update(with:curValue)
					}
					buildAddresses[publicKey] = curPubAddresses
				}
				return buildAddresses
			}
			return returnValue
		}

		/// updates an existing public key with a new set of ipv6 addresses. the public key must already exist in the database.
		/// - throws: `LMDBError.notFound` if the public key does not exist.
		/// - throws: `LMDBError.keyExists` if the new ipv6 address already exists in the database.
		internal func addAddress(publicKey:PublicKey, ipv6:AddressV6, tx:borrowing Transaction) throws {
			let subTrans = try Transaction(env:self.env, readOnly:false, parent:tx)
			try clientPub_ipv6.cursor(tx:subTrans) { pubCursor in
				try ipv6_clientPub.cursor(tx:subTrans) { addyCursor in
					do {
						_ = try addyCursor.opSet(key:ipv6) // throws LMDBError.notFound if the address does not exist. this is the desired behavior.
						throw LMDBError.keyExists // the address already exists in the database.
					} catch LMDBError.notFound {
						_ = try pubCursor.opSet(key:publicKey) // will throw LMDBError.notFound if the public key does not exist
						try pubCursor.setEntry(key:publicKey, value:ipv6, flags:[.noDupData])
						try addyCursor.setEntry(key:ipv6, value:publicKey, flags:[.noOverwrite])
					}
				}
			}
			try subTrans.commit()
		}

		/// removes an ipv6 address from the database. the address must already exist with the specified public key.
		/// - if the specified address is the last address associated with the public key, the public key will also be removed, and the client will no longer exist in the database.
		/// - throws: `LMDBError.notFound` if the address does not exist.
		internal func removeAddress(publicKey:PublicKey, ipv6:AddressV6, tx:borrowing Transaction) throws {
			let subTrans = try Transaction(env:self.env, readOnly:false, parent:tx)
			try clientPub_ipv6.cursor(tx:subTrans) { pubCursor in
				try ipv6_clientPub.cursor(tx:subTrans) { addyCursor in
					_ = try pubCursor.opGetBoth(key:publicKey, value:ipv6)
					_ = try addyCursor.opSet(key:ipv6)
					try pubCursor.deleteCurrentEntry(flags:[])
					try addyCursor.deleteCurrentEntry(flags:[])
				}
			}
			try subTrans.commit()
		}
	}
}
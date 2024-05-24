import QuickLMDB
import bedrock_ipaddress

extension WireguardDatabaseV2 {
	internal struct AddressDatabaseV4 {
		private let env:Environment

		private enum Databases:String {
			case clientPub_ipv4 = "addrdb:pub_ipv4"
			case ipv4_clientPub = "addrdb:ipv4_pub"
		}

		internal let clientPub_ipv4:Database.Strict<PublicKey, AddressV4>
		internal let ipv4_clientPub:Database.Strict<AddressV4, PublicKey>

		internal init(environment:Environment, tx:borrowing Transaction) throws {
			let subTrans = try Transaction(env:environment, readOnly:false, parent:tx)
			self.env = environment
			self.clientPub_ipv4 = try Database.Strict<PublicKey, AddressV4>(env:environment, name:Databases.clientPub_ipv4.rawValue, flags:[.create], tx:subTrans)
			self.ipv4_clientPub = try Database.Strict<AddressV4, PublicKey>(env:environment, name:Databases.ipv4_clientPub.rawValue, flags:[.create], tx:subTrans)
			try subTrans.commit()
		}

		/// installs a client public key with an IPv4 address. the public key must not already exist in the database.
		/// - throws: `LMDBError.keyExists` if the client already has an entry in the database.
		internal func createClient(publicKey:PublicKey, ipv4:AddressV4, tx:borrowing Transaction) throws {
			let subTrans = try Transaction(env:self.env, readOnly:false, parent:tx)
			try self.clientPub_ipv4.setEntry(key:publicKey, value:ipv4, flags:[.noOverwrite], tx:subTrans)
			try self.ipv4_clientPub.setEntry(key:ipv4, value:publicKey, flags:[.noOverwrite], tx:subTrans)
			try subTrans.commit()
		}

		/// removes a client public key from the database, along with their IPv4 address.
		/// - returns: the IPv4 address that was removed from the database.
		/// - throws: `LMDBError.notFound` if the public key does not exist.
		@discardableResult internal func removeClient(publicKey:PublicKey, tx:borrowing Transaction) throws -> AddressV4 {
			let subTrans = try Transaction(env:self.env, readOnly:false, parent:tx)
			let ipv4 = try self.clientPub_ipv4.loadEntry(key:publicKey, tx:subTrans)
			try self.clientPub_ipv4.deleteEntry(key:publicKey, tx:subTrans)
			try self.ipv4_clientPub.deleteEntry(key:ipv4, tx:subTrans)
			try subTrans.commit()
			return ipv4
		}
	}
}
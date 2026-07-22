import ArgumentParser
import RAW_dh25519
import RAW_base64
import wiremand_databases

extension EncodedString: ExpressibleByArgument {
	public init?(argument: String) {
		self = EncodedString(argument)
	}
	public static var defaultValue: EncodedString {
		EncodedString("")
	}
}

extension wiremand_databases.PublicKey: ExpressibleByArgument {
	public init?(argument: String) {
		let rawBytes = try? RAW_base64.decode(argument)
		guard let bytes = rawBytes, bytes.count == 32 else {
			return nil
		}
		self = wiremand_databases.PublicKey(RAW_staticbuff:bytes)
	}
}

extension AddressV4: ExpressibleByArgument {
	public init?(argument: String) {
		guard let address = AddressV4(argument) else { return nil }
		self = address
	}
}

extension AddressV6: ExpressibleByArgument {
	public init?(argument: String) {
		guard let address = AddressV6(argument) else { return nil }
		self = address
	}
}

// extension NetworkV4: ExpressibleByArgument {
// 	public init?(argument: String) {
// 		guard let network = NetworkV4(argument) else { return nil }
// 		self = network
// 	}
// }

// extension NetworkV6: ExpressibleByArgument {
// 	public init?(argument: String) {
// 		guard let network = NetworkV6(argument) else { return nil }
// 		self = network
// 	}
// }

extension Network: ExpressibleByArgument {
	public init?(argument: String) {
		guard let network = Network(argument) else { return nil }
		self = network
	}
}
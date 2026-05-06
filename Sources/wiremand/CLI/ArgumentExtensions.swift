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

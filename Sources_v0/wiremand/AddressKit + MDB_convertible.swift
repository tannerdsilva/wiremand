import QuickLMDB
import Foundation
import AddressKit

extension AddressV4:LosslessStringConvertible, MDB_convertible {
	public var description: String {
		return self.string
	}
}

extension AddressV6:LosslessStringConvertible, MDB_convertible {
	public var description: String {
		return self.string
	}
}

extension RangeV4:LosslessStringConvertible, MDB_convertible {
	public var description: String {
		return self.string
	}
}

extension RangeV6:LosslessStringConvertible, MDB_convertible {
	public var description: String {
		return self.string
	}
}

extension NetworkV4:LosslessStringConvertible, MDB_convertible {
	public init?(_ description: String) {
		guard let makeSelf = Self(cidr:description) else {
			return nil
		}
		self = makeSelf
	}
	
	public var description: String {
		return self.cidrString
	}
}

extension NetworkV6:LosslessStringConvertible, MDB_convertible {
	public init?(_ description: String) {
		guard let makeSelf = Self(cidr:description) else {
			return nil
		}
		self = makeSelf
	}
	
	public var description: String {
		return self.cidrString
	}
}

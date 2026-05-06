import RAW
import Foundation
import QuickLMDB

/// the encoded date value type used for the pricedb engine. 8 byte integer, signed big endian.
@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<Int64>(bigEndian:true)
@MDB_comparable
@frozen public struct _int64_encoded:Sendable, Hashable, CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(RAW_native())"
	}
}

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian:true)
@MDB_comparable
@frozen public struct _uint64_encoded:Sendable, Hashable, CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(RAW_native())"
	}
}

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_binaryfloatingpoint_type<Double>()
@MDB_comparable
@frozen public struct _double_encoded:Sendable, Hashable, CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(RAW_native())"
	}
}

/// distinct date implementation. 64bit floating point.
@RAW_staticbuff(concat:_uint64_encoded.self)
@MDB_comparable
@frozen public struct DateUTC:Sendable, Comparable, Hashable {
	/// the number of seconds since 00:00:00 UTC on 1 January 1970
	internal let seconds_since_1970:_uint64_encoded
}

extension DateUTC {
	@RAW_staticbuff(concat:_double_encoded.self)
	@MDB_comparable
	@frozen public struct Precise:Sendable, Comparable, Hashable {
		internal let seconds_since_1970:_double_encoded
	}
}

extension DateUTC.Precise:CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(seconds_since_1970.RAW_native())"
	}
}

extension DateUTC:CustomDebugStringConvertible {
	public var debugDescription:String {
		return "\(seconds_since_1970.RAW_native())"
	}
}

extension DateUTC.Precise {
	public init(from decoder:Decoder) throws {
		let container = try decoder.singleValueContainer()
		let seconds = try container.decode(Double.self)
		self = DateUTC.Precise(unixInterval:seconds)
	}
	public func encode(to encoder:Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(seconds_since_1970.RAW_native())
	}
}

extension DateUTC:Codable {
	public init(from decoder:Decoder) throws {
		let container = try decoder.singleValueContainer()
		let seconds = try container.decode(Int64.self)
		self = DateUTC(unixInterval:seconds)
	}

	public func encode(to encoder:Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(seconds_since_1970.RAW_native())
	}
}

extension DateUTC {

	/// initialize a new date based in UTC
	public init() {
		seconds_since_1970 = _uint64_encoded(RAW_native:UInt64(Date().timeIntervalSince1970))
	}

	public init(timeIntervalSinceNow interval:UInt64) {
		self = DateUTC().addingTimeInterval(interval)
	}

	/// initialize with a Unix epoch interval (seconds since 00:00:00 UTC on 1 January 1970)
	public init(unixInterval:Double) {
		seconds_since_1970 = _uint64_encoded(RAW_native:UInt64(unixInterval))
	}

	public init(unixInterval:Int) {
		seconds_since_1970 = _uint64_encoded(RAW_native:UInt64(unixInterval))
	}

	public init(unixInterval:Int64) {
		seconds_since_1970 = _uint64_encoded(RAW_native:UInt64(unixInterval))
	}

	public init(unixInterval:UInt64) {
		seconds_since_1970 = _uint64_encoded(RAW_native:unixInterval)
	}

	/// returns the difference in time between the called instance and passed date
	public func timeIntervalSince(_ other:Self) -> UInt64 {
		#if DEBUG
		guard seconds_since_1970.RAW_native() >= other.seconds_since_1970.RAW_native() else {
			fatalError("cannot calculate time interval since other date is in the future: \(other.seconds_since_1970.RAW_native()) vs \(seconds_since_1970.RAW_native()). \(#file):\(#line)")
		}
		#endif
		return seconds_since_1970.RAW_native() - other.seconds_since_1970.RAW_native()
	}

	public func addingTimeInterval(_ interval:UInt64) -> Self {
		return self + interval
	}

	/// returns the time interval since Unix date
	public func timeIntervalSinceUnixDate() -> UInt64 {
		return seconds_since_1970.RAW_native()
	}

	public static func + (lhs:DateUTC, rhs:UInt64) -> DateUTC {
		return Self(unixInterval:lhs.seconds_since_1970.RAW_native() + rhs)
	}
	public static func - (lhs:DateUTC, rhs:UInt64) -> DateUTC {
		return Self(unixInterval:UInt64(lhs.seconds_since_1970.RAW_native() - rhs))
	}
}

extension DateUTC.Precise {
	/// initialize a new date based in UTC
	public init() {
		seconds_since_1970 = _double_encoded(RAW_native:Date().timeIntervalSince1970)
	}

	public init(unixInterval:Double) {
		seconds_since_1970 = _double_encoded(RAW_native:unixInterval)
	}

	public func timeIntervalSince(_ other:Self) -> Double {
		return seconds_since_1970.RAW_native() - other.seconds_since_1970.RAW_native()
	}

	public func addingTimeInterval(_ interval:Double) -> Self {
		return Self(unixInterval: seconds_since_1970.RAW_native() + interval)
	}

	public func addingTimeInterval(_ interval:Int64) -> Self {
		return Self(unixInterval:seconds_since_1970.RAW_native() + Double(interval))
	}

	public func timeIntervalSinceUnixDate() -> Double {
		return seconds_since_1970.RAW_native()
	}

	public func timeIntervalSinceReferenceDate() -> Double {
		return seconds_since_1970.RAW_native() - 978307200.0
	}
}


import Foundation
import RAW

@RAW_staticbuff(bytes:8)
@RAW_staticbuff_fixedwidthinteger_type<UInt64>(bigEndian: true)
public struct EncodedDate: Sendable, Hashable, Comparable, RAW_convertible {
	public init(date: Foundation.Date) {
		self = EncodedDate(RAW_native: UInt64(date.timeIntervalSince1970))
	}
	public init(_ date:UInt64) {
		self = EncodedDate(RAW_native: date)
	}
	public func currentTime() -> UInt64 {
		return self.RAW_native()
	}
	public func currentDate() -> Foundation.Date {
		Foundation.Date(timeIntervalSince1970: TimeInterval(self.RAW_native()))
	}
}

import Foundation
import bedrock

extension bedrock.Date.Seconds {
	public func iso8601String() -> String {
		let date = Date(timeIntervalSince1970: TimeInterval(self.timeIntervalSinceUnixDate()))
		let formatter = ISO8601DateFormatter()
		return formatter.string(from: date)
	}
	
	public func relativeTimeString(to later: bedrock.Date.Seconds) -> String {
		let referenceDate = Date(timeIntervalSince1970: TimeInterval(self.RAW_native()))
		let targetDate    = Date(timeIntervalSince1970: TimeInterval(later.RAW_native()))
		let formatter = RelativeDateTimeFormatter()
		formatter.unitsStyle = .full
		let raw = formatter.localizedString(for: targetDate, relativeTo: referenceDate)
		return raw.lowercased()
	}
}

extension bedrock.Date.Seconds {
	public func timeIntervalSince(other:bedrock.Date.Seconds) -> Int64{
		return Int64(self.RAW_native()) - Int64(other.RAW_native())
	}
	public var timeIntervalSinceNow:Int64 {
		let now = bedrock.Date.Seconds()
		return self.timeIntervalSince(other: now)
	}
	public func subtractingTimeInterval(_ interval:UInt64) -> Self {
		return Self(RAW_native: self.RAW_native() - interval)
	}
}

import Foundation
import bedrock

class LinuxRelativeDateFormatter {
    func formatRelative(from date: Foundation.Date, to referenceDate: Foundation.Date = Date()) -> String {
        let calendar = Calendar.current
        let components = calendar.dateComponents(
            [.year, .month, .day, .hour, .minute, .second],
            from: date,
            to: referenceDate
        )

        if let years = components.year, years > 0 {
            return "\(years) \(years == 1 ? "year" : "years") ago"
        } else if let months = components.month, months > 0 {
            return "\(months) \(months == 1 ? "month" : "months") ago"
        } else if let days = components.day, days > 0 {
            return "\(days) \(days == 1 ? "day" : "days") ago"
        } else if let hours = components.hour, hours > 0 {
            return "\(hours) \(hours == 1 ? "hour" : "hours") ago"
        } else if let minutes = components.minute, minutes > 0 {
            return "\(minutes) \(minutes == 1 ? "minute" : "minutes") ago"
        } else if let seconds = components.second, seconds > 0 {
            return "\(seconds) \(seconds == 1 ? "second" : "seconds") ago"
        } else {
            return "just now"
        }
    }
}

extension bedrock.Date.Seconds {
	public func iso8601String() -> String {
		let date = Date(timeIntervalSince1970: TimeInterval(self.timeIntervalSinceUnixDate()))
		let formatter = ISO8601DateFormatter()
		return formatter.string(from: date)
	}
	
	public func relativeTimeString(to later: bedrock.Date.Seconds) -> String {
		let referenceDate = Date(timeIntervalSince1970: TimeInterval(self.RAW_native()))
		let targetDate    = Date(timeIntervalSince1970: TimeInterval(later.RAW_native()))
		let formatter = LinuxRelativeDateFormatter()
		let raw = formatter.formatRelative(from: targetDate, to: referenceDate)
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

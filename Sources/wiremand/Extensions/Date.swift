import Foundation

extension Date {
	func relativeTimeString(to nowTime:Date = Date()) -> String {
		var time = self.timeIntervalSince(nowTime)
		if (time > 0) {
			switch time {
			case 0..<3600:
				return ("In \(Int(time/60)) Minutes")
			case 3600..<86399:
				return time <= 7200 ? ("In 1 Hour"): ("In \(Int(time/3600)) Hours")
			default:
				return time <= 172800 ? ("In 1 Day"): ("In \(Int(time/86400)) Days")
			}
		} else {
			time = abs(time)
			switch time {
			case 0..<3600:
				return ("\(Int(time/60)) Minutes Ago")
			case 3600..<86399:
				return time <= 7200 ? ("1 Hour Ago"): ("\(Int(time/3600)) Hours Ago")
			default:
				return time <= 172800 ? ("1 Day Ago"): ("\(Int(time/86400)) Days Ago")
			}
		}
	}
}

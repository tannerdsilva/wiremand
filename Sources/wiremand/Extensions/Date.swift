import Foundation

extension Date {
	func relativeTimeString() -> String {
		let nowTI = self.timeIntervalSinceNow
		if (nowTI < 0) {
			if (abs(nowTI) < 60) {
				return "\(floor(abs(nowTI))) seconds ago"
			} else if (abs(nowTI) < 3600) {
				return "\(floor(abs(nowTI / 60))) minute(s) ago"
			} else if (abs(nowTI) < 86400) {
				return "\(floor(abs(nowTI / 3600))) hour(s) ago"
			} else {
				return "\(floor(abs(nowTI / 86400))) day(s) ago"
			}
		} else {
			if (abs(nowTI) < 60) {
				return "In \(floor(abs(nowTI))) seconds"
			} else if (abs(nowTI) < 3600) {
				return "In \(floor(abs(nowTI / 60))) minute(s)"
			} else if (abs(nowTI) < 86400) {
				return "In \(floor(abs(nowTI / 3600))) hour(s)"
			} else {
				return "In \(floor(abs(nowTI / 86400))) day(s)"
			}
		}
	}
}

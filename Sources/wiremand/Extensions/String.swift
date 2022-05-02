import Foundation

extension String {
	//static function that creates a string of random length
	public static func random(length:Int = 32, separator:Character? = nil) -> String {
		let base = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%*?+="
		let baseLength = base.count
		var randomString = ""
		for i in 0..<length {
			if (i % 4 == 0 && separator != nil && i != 0) {
				randomString.append(separator!)
			}
			let randomIndex = Int.random(in:0..<baseLength)
			randomString.append(base[base.index(base.startIndex, offsetBy:randomIndex)])
		}
		return randomString
	}
}

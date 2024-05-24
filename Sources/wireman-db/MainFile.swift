import ArgumentParser
import bedrock_ipaddress

@main
struct CLI:ParsableCommand {
	
	@Argument(help:"The path to the database file")
	var address:String

	mutating func run() throws {
		let asNetwork = NetworkV6(address)
		print("Network: \(String(asNetwork!.range.lowerBound)) - \(String(asNetwork!.range.upperBound))")
	}
	
}
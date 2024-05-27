
public struct Configuration:Codable {
	public struct Node:Codable {
		public let nodeName:String
		public let operationOrder:UInt8
	}
	// public struct Network:Codable {
	// 	public let wg_interfaceName:String
	// 	public let networkV6:NetworkV6
	// }
}
import Foundation
import AsyncHTTPClient
import Logging
import NIO
import RAW
import QuickLMDB

@RAW_staticbuff(bytes: 1)
@RAW_staticbuff_fixedwidthinteger_type<UInt8>(bigEndian: true)
public struct EncodedBool: Sendable {
	public var bool:Bool {
		self.RAW_native() != 0
	}
	
	public init(_ bool:Bool) {
		self = bool ? EncodedBool(RAW_native: 1) : EncodedBool(RAW_native: 0)
	}
}
@RAW_staticbuff_fixedwidthinteger_type<UInt32>(bigEndian: true)
@RAW_staticbuff(bytes: 4)
public struct Bytes4:Sendable, Hashable, Equatable, Comparable { }

extension EncodedString: Codable {
	public init(from decoder: Decoder) throws {
		let container = try decoder.singleValueContainer()
		let rawString = try container.decode(String.self)
		self = EncodedString(rawString)
	}
	public func encode(to encoder: Encoder) throws {
		var container = encoder.singleValueContainer()
		try container.encode(String(self))
	}
}

extension IPDatabase {
	
	public struct ResolvedIPInfo:Codable {
		enum Error:Swift.Error {
			case unrecognizedHTTPResponse
			case unrecognizedHTTPBody
			case missingContinentInfo
			case missingRegionInfo
			case missingCountryInfo
			case missingISPInfo
			case missingThreatInfo
		}
		
		public struct ContinentInfo:Codable {
			public let code:EncodedString
			public let name:EncodedString
			init(apiResponse:[String:Any]) throws {
				guard let findName = apiResponse["continent_name"] as? String, let findCode = apiResponse["continent_code"] as? String else {
					throw ResolvedIPInfo.Error.missingContinentInfo
				}
				self.code = EncodedString(findCode)
				self.name = EncodedString(findName)
			}
		}
		
		public struct RegionInfo:Codable {
			public let code:EncodedString
			public let name:EncodedString
			init(apiResponse:[String:Any]) throws {
				guard let findName = apiResponse["region_name"] as? String, let findCode = apiResponse["region_code"] as? String else {
					throw ResolvedIPInfo.Error.missingContinentInfo
				}
				self.code = EncodedString(findCode)
				self.name = EncodedString(findName)
			}
		}
		
		public struct CountryInfo:Codable {
			public let code:EncodedString
			public let name:EncodedString
			init(apiResponse:[String:Any]) throws {
				guard let findName = apiResponse["country_name"] as? String, let findCode = apiResponse["country_code"] as? String else {
					throw ResolvedIPInfo.Error.missingCountryInfo
				}
				self.code = EncodedString(findCode)
				self.name = EncodedString(findName)
			}
		}
		
		public let continent:ContinentInfo?
		public let country:CountryInfo?
		public let region:RegionInfo?
		public let city:EncodedString?
		public let zip:EncodedString?
		public let isp:EncodedString
		
		public init(apiResponse:[String:Any]) throws {
			self.continent = try? ContinentInfo(apiResponse:apiResponse)
			self.country = try? CountryInfo(apiResponse:apiResponse)
			self.region = try? RegionInfo(apiResponse:apiResponse)
			let city = apiResponse["city"] as? String
			self.city = city == nil ? nil : EncodedString(city!)
			let zip = apiResponse["zip"] as? String
			self.zip = zip == nil ? nil : EncodedString(zip!)
			guard let hasConnectionInfo = apiResponse["connection"] as? [String:Any], let hasISP = hasConnectionInfo["isp"] as? String else {
				throw Error.missingISPInfo
			}
			self.isp = EncodedString(hasISP)
		}

		public static func from(addressString:String, accessKey:String) async throws -> ResolvedIPInfo {
			return try await withUnsafeThrowingContinuation({  (myCont:UnsafeContinuation<ResolvedIPInfo, Swift.Error>) in
				let logger = Logger(label:"resolved-ip-info")
				let client = HTTPClient()
				defer {
					do {
						try client.syncShutdown()
						logger.trace("successfully shut down HTTP client")
					} catch let error {
						logger.error("failed to shut down HTTP client", metadata:["error":"\(error)"])
					}
				}
				// build the URL
				var buildURL = URLComponents()
				buildURL.scheme = "https"
				buildURL.host = "api.ipstack.com"
				buildURL.path = "/\(addressString)"
				buildURL.queryItems = [URLQueryItem(name:"access_key", value:accessKey)]
				let clientRequest:HTTPClient.Request
				do {
					clientRequest = try HTTPClient.Request(url:buildURL.url!)
				} catch let error {
					logger.error("unable to resolve IPv4 metadata. unable to build HTTP request")
					myCont.resume(throwing:error)
					return
				}
				let launchtime = Date()
				let clientJob = client.execute(request:clientRequest, deadline: NIODeadline.now() + .seconds(5))
				clientJob.whenSuccess({ apiResponse in
					guard apiResponse.status == .ok, let responseBody = apiResponse.body, responseBody.readableBytes > 0 else {
						logger.error("unable to resolve IPv4 metadata. unrecognized response found", metadata:["address": "\(addressString)"])
						myCont.resume(throwing:Error.unrecognizedHTTPResponse)
						return
					}
					let responseBodyData = responseBody.withUnsafeReadableBytes { ptr in
						return Data(bytes: ptr.baseAddress!, count: ptr.count)
					}
					guard let jsonSerialization:[String:Any] = try? JSONSerialization.jsonObject(with:responseBodyData) as? [String:Any] else {
						logger.error("unable to resolve IPv4 metadata. unrecognized JSON data found", metadata:["address": "\(addressString)"])
						myCont.resume(throwing:Error.unrecognizedHTTPBody)
						return
					}
					do {
						let resolvedIPInfo = try ResolvedIPInfo(apiResponse:jsonSerialization)
						logger.info("successfully resolved IPv4 metadata", metadata:["address": "\(addressString)", "duration":"\(launchtime.timeIntervalSinceNow)"])
						myCont.resume(returning:resolvedIPInfo)
					} catch let error {
						logger.error("unable to resolve IPv4 metadata. incomplete API response.", metadata:["error": "\(error)"])
						myCont.resume(throwing:error)
					}
				})
				clientJob.whenFailure({ apiError in
					logger.error("unable to resolve IPv4 metadata. swift nio error thrown", metadata:["address": "\(addressString)", "error": "\(apiError)"])
					myCont.resume(throwing:apiError)
					return
				})
			})
		}
		
		
		public init(continent: ContinentInfo?, country: CountryInfo?, region: RegionInfo?, city: EncodedString?, zip: EncodedString?, isp: EncodedString) {
			self.continent = continent
			self.country = country
			self.region = region
			self.city = city
			self.zip = zip
			self.isp = isp
		}
		
		public init(continent: ContinentInfo?, country: CountryInfo?, region: RegionInfo?, cityNative: String?, zipNative: String?, ispNative: String) {
			self.continent = continent
			self.country = country
			self.region = region
			if let cityNative = cityNative {
				self.city = EncodedString(cityNative)
			} else {
				self.city = nil
			}
			if let zipNative = zipNative {
				self.zip = EncodedString(zipNative)
			} else {
				self.zip = nil
			}
			self.isp = EncodedString(ispNative)
		}
	}
}

extension IPDatabase.ResolvedIPInfo: RAW_convertible, RAW_accessible {
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		var inputPtr = inputPtr
		var dataCount = count
		var continent0: ContinentInfo?
		let continentExists = EncodedBool(RAW_staticbuff_seeking: &inputPtr)
		dataCount -= MemoryLayout<EncodedBool>.size
		if continentExists.bool {
			guard dataCount >= MemoryLayout<Bytes4>.size else {
				return nil
			}
			let continentLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
			dataCount -= MemoryLayout<Bytes4>.size
			guard dataCount >= continentLength else {
				return nil
			}
			guard let continent1 = ContinentInfo(RAW_decode: inputPtr, count: continentLength) else {
				return nil
			}
			inputPtr = inputPtr.advanced(by: continentLength)
			dataCount -= continentLength
			continent0 = continent1
		} else {
			continent0 = nil
		}
		self.continent = continent0
		var country0: CountryInfo?
		let countryExists = EncodedBool(RAW_staticbuff_seeking: &inputPtr)
		dataCount -= MemoryLayout<EncodedBool>.size
		if countryExists.bool {
			guard dataCount >= MemoryLayout<Bytes4>.size else {
				return nil
			}
			let countryLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
			dataCount -= MemoryLayout<Bytes4>.size
			guard dataCount >= countryLength else {
				return nil
			}
			guard let country1 = CountryInfo(RAW_decode: inputPtr, count: countryLength) else {
				return nil
			}
			inputPtr = inputPtr.advanced(by: countryLength)
			dataCount -= countryLength
			country0 = country1
		} else {
			country0 = nil
		}
		self.country = country0
		var region0: RegionInfo?
		let regionExists = EncodedBool(RAW_staticbuff_seeking: &inputPtr)
		dataCount -= MemoryLayout<EncodedBool>.size
		if regionExists.bool {
			guard dataCount >= MemoryLayout<Bytes4>.size else {
				return nil
			}
			let regionLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
			dataCount -= MemoryLayout<Bytes4>.size
			guard dataCount >= regionLength else {
				return nil
			}
			guard let region1 = RegionInfo(RAW_decode: inputPtr, count: regionLength) else {
				return nil
			}
			inputPtr = inputPtr.advanced(by: regionLength)
			dataCount -= regionLength
			region0 = region1
		} else {
			region0 = nil
		}
		self.region = region0
		var city0: EncodedString?
		let cityExists = EncodedBool(RAW_staticbuff_seeking: &inputPtr)
		dataCount -= MemoryLayout<EncodedBool>.size
		if cityExists.bool {
			guard dataCount >= MemoryLayout<Bytes4>.size else {
				return nil
			}
			let cityLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
			dataCount -= MemoryLayout<Bytes4>.size
			guard dataCount >= cityLength else {
				return nil
			}
			let city1 = EncodedString(RAW_decode: inputPtr, count: cityLength)
			inputPtr = inputPtr.advanced(by: cityLength)
			dataCount -= cityLength
			city0 = city1
		} else {
			city0 = nil
		}
		self.city = city0
		var zip0: EncodedString?
		let zipExists = EncodedBool(RAW_staticbuff_seeking: &inputPtr)
		dataCount -= MemoryLayout<EncodedBool>.size
		if zipExists.bool {
			guard dataCount >= MemoryLayout<Bytes4>.size else {
				return nil
			}
			let zipLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
			dataCount -= MemoryLayout<Bytes4>.size
			guard dataCount >= zipLength else {
				return nil
			}
			let zip1 = EncodedString(RAW_decode: inputPtr, count: zipLength)
			inputPtr = inputPtr.advanced(by: zipLength)
			dataCount -= zipLength
			zip0 = zip1
		} else {
			zip0 = nil
		}
		self.zip = zip0
		guard dataCount >= MemoryLayout<Bytes4>.size else {
			return nil
		}
		let ispLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		dataCount -= MemoryLayout<Bytes4>.size
		guard dataCount >= ispLength else {
			return nil
		}
		let isp0 = EncodedString(RAW_decode: inputPtr, count: ispLength)
		inputPtr = inputPtr.advanced(by: ispLength)
		dataCount -= ispLength
		self.isp = isp0
		guard dataCount == 0 else {
			return nil
		}
	}
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<EncodedBool>.size
		if let continent = continent {
			count += MemoryLayout<Bytes4>.size
			continent.RAW_encode(count: &count)
		}
		count += MemoryLayout<EncodedBool>.size
		if let country = country {
			count += MemoryLayout<Bytes4>.size
			country.RAW_encode(count: &count)
		}
		count += MemoryLayout<EncodedBool>.size
		if let region = region {
			count += MemoryLayout<Bytes4>.size
			region.RAW_encode(count: &count)
		}
		count += MemoryLayout<EncodedBool>.size
		if let city = city {
			count += MemoryLayout<Bytes4>.size
			city.RAW_encode(count: &count)
		}
		count += MemoryLayout<EncodedBool>.size
		if let zip = zip {
			count += MemoryLayout<Bytes4>.size
			zip.RAW_encode(count: &count)
		}
		count += MemoryLayout<Bytes4>.size
		isp.RAW_encode(count: &count)
	}
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var dest = dest
		if let continent = continent {
			dest = EncodedBool(true).RAW_encode(dest: dest)
			var continentLength = 0;
			continent.RAW_encode(count: &continentLength)
			let continentLengthBytes = Bytes4(RAW_native: UInt32(continentLength))
			dest = continentLengthBytes.RAW_encode(dest: dest)
			dest = continent.RAW_encode(dest: dest)
		} else {
			dest = EncodedBool(false).RAW_encode(dest: dest)
		}
		if let country = country {
			dest = EncodedBool(true).RAW_encode(dest: dest)
			var countryLength = 0;
			country.RAW_encode(count: &countryLength)
			let countryLengthBytes = Bytes4(RAW_native: UInt32(countryLength))
			dest = countryLengthBytes.RAW_encode(dest: dest)
			dest = country.RAW_encode(dest: dest)
		} else {
			dest = EncodedBool(false).RAW_encode(dest: dest)
		}
		if let region = region {
			dest = EncodedBool(true).RAW_encode(dest: dest)
			var regionLength = 0;
			region.RAW_encode(count: &regionLength)
			let regionLengthBytes = Bytes4(RAW_native: UInt32(regionLength))
			dest = regionLengthBytes.RAW_encode(dest: dest)
			dest = region.RAW_encode(dest: dest)
		} else {
			dest = EncodedBool(false).RAW_encode(dest: dest)
		}
		if let city = city {
			dest = EncodedBool(true).RAW_encode(dest: dest)
			var cityLength = 0;
			city.RAW_encode(count: &cityLength)
			let cityLengthBytes = Bytes4(RAW_native: UInt32(cityLength))
			dest = cityLengthBytes.RAW_encode(dest: dest)
			dest = city.RAW_encode(dest: dest)
		} else {
			dest = EncodedBool(false).RAW_encode(dest: dest)
		}
		if let zip = zip {
			dest = EncodedBool(true).RAW_encode(dest: dest)
			var zipLength = 0;
			zip.RAW_encode(count: &zipLength)
			let zipLengthBytes = Bytes4(RAW_native: UInt32(zipLength))
			dest = zipLengthBytes.RAW_encode(dest: dest)
			dest = zip.RAW_encode(dest: dest)
		} else {
			dest = EncodedBool(false).RAW_encode(dest: dest)
		}
		var ispLength = 0;
		isp.RAW_encode(count: &ispLength)
		let ispLengthBytes = Bytes4(RAW_native: UInt32(ispLength))
		dest = ispLengthBytes.RAW_encode(dest: dest)
		dest = isp.RAW_encode(dest: dest)
		return dest
	}
}

extension RAW_accessible where Self: RAW_encodable & RAW_decodable {
	public func RAW_access<R, E>(_ body: (UnsafeBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E : Error {
		var count: RAW.size_t = 0
		self.RAW_encode(count: &count)
		
		return try! withUnsafeTemporaryAllocation(
			byteCount: count,
			alignment: MemoryLayout<UInt8>.alignment
		) { rawBuffer in
			let base = rawBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
			_ = self.RAW_encode(dest: base)

			let buffer = UnsafeBufferPointer(start: base, count: count)
			return try body(buffer)
		}
	}
	
	public mutating func RAW_access_mutating<R, E>(_ body: (UnsafeMutableBufferPointer<UInt8>) throws(E) -> R) throws(E) -> R where E : Error {
		var count: RAW.size_t = 0
		self.RAW_encode(count: &count)

		return try! withUnsafeTemporaryAllocation(
			byteCount: count,
			alignment: MemoryLayout<UInt8>.alignment
		) { rawBuffer in
			let base = rawBuffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
			_ = self.RAW_encode(dest: base)

			let buffer = UnsafeMutableBufferPointer(start: base, count: count)
			let result = try body(buffer)

			let readPtr = UnsafeRawPointer(base)
			guard let decoded = Self(
				RAW_decode: readPtr,
				count: count
			) else {
				fatalError("RAW_access_mutating produced invalid state")
			}

			self = decoded
			return result
		}
	}
}

extension IPDatabase.ResolvedIPInfo.CountryInfo: RAW_convertible {
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		var inputPtr = inputPtr
		var dataCount = count
		guard dataCount >= MemoryLayout<Bytes4>.size else {
			return nil
		}
		let codeLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		dataCount -= MemoryLayout<Bytes4>.size
		guard dataCount >= codeLength else {
			return nil
		}
		let code0 = EncodedString(RAW_decode: inputPtr, count: codeLength)
		inputPtr = inputPtr.advanced(by: codeLength)
		dataCount -= codeLength
		self.code = code0
		guard dataCount >= MemoryLayout<Bytes4>.size else {
			return nil
		}
		let nameLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		dataCount -= MemoryLayout<Bytes4>.size
		guard dataCount >= nameLength else {
			return nil
		}
		let name0 = EncodedString(RAW_decode: inputPtr, count: nameLength)
		inputPtr = inputPtr.advanced(by: nameLength)
		dataCount -= nameLength
		self.name = name0
		guard dataCount == 0 else {
			return nil
		}
	}
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<Bytes4>.size
		code.RAW_encode(count: &count)
		count += MemoryLayout<Bytes4>.size
		name.RAW_encode(count: &count)
	}
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var dest = dest
		var codeLength = 0;
		code.RAW_encode(count: &codeLength)
		let codeLengthBytes = Bytes4(RAW_native: UInt32(codeLength))
		dest = codeLengthBytes.RAW_encode(dest: dest)
		dest = code.RAW_encode(dest: dest)
		var nameLength = 0;
		name.RAW_encode(count: &nameLength)
		let nameLengthBytes = Bytes4(RAW_native: UInt32(nameLength))
		dest = nameLengthBytes.RAW_encode(dest: dest)
		dest = name.RAW_encode(dest: dest)
		return dest
	}
}

extension IPDatabase.ResolvedIPInfo.RegionInfo: RAW_convertible {
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		var inputPtr = inputPtr
		var dataCount = count
		guard dataCount >= MemoryLayout<Bytes4>.size else {
			return nil
		}
		let codeLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		dataCount -= MemoryLayout<Bytes4>.size
		guard dataCount >= codeLength else {
			return nil
		}
		let code0 = EncodedString(RAW_decode: inputPtr, count: codeLength)
		inputPtr = inputPtr.advanced(by: codeLength)
		dataCount -= codeLength
		self.code = code0
		guard dataCount >= MemoryLayout<Bytes4>.size else {
			return nil
		}
		let nameLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		dataCount -= MemoryLayout<Bytes4>.size
		guard dataCount >= nameLength else {
			return nil
		}
		let name0 = EncodedString(RAW_decode: inputPtr, count: nameLength)
		inputPtr = inputPtr.advanced(by: nameLength)
		dataCount -= nameLength
		self.name = name0
		guard dataCount == 0 else {
			return nil
		}
	}
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<Bytes4>.size
		code.RAW_encode(count: &count)
		count += MemoryLayout<Bytes4>.size
		name.RAW_encode(count: &count)
	}
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var dest = dest
		var codeLength = 0;
		code.RAW_encode(count: &codeLength)
		let codeLengthBytes = Bytes4(RAW_native: UInt32(codeLength))
		dest = codeLengthBytes.RAW_encode(dest: dest)
		dest = code.RAW_encode(dest: dest)
		var nameLength = 0;
		name.RAW_encode(count: &nameLength)
		let nameLengthBytes = Bytes4(RAW_native: UInt32(nameLength))
		dest = nameLengthBytes.RAW_encode(dest: dest)
		dest = name.RAW_encode(dest: dest)
		return dest
	}
}

extension IPDatabase.ResolvedIPInfo.ContinentInfo: RAW_convertible {
	public init?(RAW_decode inputPtr: consuming UnsafeRawPointer, count: RAW.size_t) {
		var inputPtr = inputPtr
		var dataCount = count
		guard dataCount >= MemoryLayout<Bytes4>.size else {
			return nil
		}
		let codeLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		dataCount -= MemoryLayout<Bytes4>.size
		guard dataCount >= codeLength else {
			return nil
		}
		let code0 = EncodedString(RAW_decode: inputPtr, count: codeLength)
		inputPtr = inputPtr.advanced(by: codeLength)
		dataCount -= codeLength
		self.code = code0
		guard dataCount >= MemoryLayout<Bytes4>.size else {
			return nil
		}
		let nameLength = Int(Bytes4(RAW_staticbuff_seeking: &inputPtr).RAW_native())
		dataCount -= MemoryLayout<Bytes4>.size
		guard dataCount >= nameLength else {
			return nil
		}
		let name0 = EncodedString(RAW_decode: inputPtr, count: nameLength)
		inputPtr = inputPtr.advanced(by: nameLength)
		dataCount -= nameLength
		self.name = name0
		guard dataCount == 0 else {
			return nil
		}
	}
	public func RAW_encode(count: inout RAW.size_t) {
		count += MemoryLayout<Bytes4>.size
		code.RAW_encode(count: &count)
		count += MemoryLayout<Bytes4>.size
		name.RAW_encode(count: &count)
	}
	public func RAW_encode(dest: UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8> {
		var dest = dest
		var codeLength = 0;
		code.RAW_encode(count: &codeLength)
		let codeLengthBytes = Bytes4(RAW_native: UInt32(codeLength))
		dest = codeLengthBytes.RAW_encode(dest: dest)
		dest = code.RAW_encode(dest: dest)
		var nameLength = 0;
		name.RAW_encode(count: &nameLength)
		let nameLengthBytes = Bytes4(RAW_native: UInt32(nameLength))
		dest = nameLengthBytes.RAW_encode(dest: dest)
		dest = name.RAW_encode(dest: dest)
		return dest
	}
}

extension IPDatabase.ResolvedIPInfo:LosslessStringConvertible {
	public var description: String {
		let jsonData = try! JSONEncoder().encode(self)
		let jsonString = String(data:jsonData, encoding:.utf8)!
		return jsonString
	}
	
	public init?(_ string:String) {
		let logger = Logger(label:"resolved-ip-info")
		let stringData = Data(string.utf8)
		do {
			self = try JSONDecoder().decode(Self.self, from:stringData)
		} catch let error {
			logger.error("unable to decode IPDatabase.ResolvedIPInfo", metadata:["error": "\(error)"])
			return nil
		}
	}
}

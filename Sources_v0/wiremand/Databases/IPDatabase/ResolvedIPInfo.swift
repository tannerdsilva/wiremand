import Foundation
import AsyncHTTPClient
import Logging
import NIO
import AddressKit
import QuickLMDB

extension IPDatabase {
	struct ResolvedIPInfo:Codable {
		enum Error:Swift.Error {
			case unrecognizedHTTPResponse
			case unrecognizedHTTPBody
			case missingContinentInfo
			case missingRegionInfo
			case missingCountryInfo
			case missingISPInfo
			case missingThreatInfo
		}
		struct ContinentInfo:Codable {
			let code:String
			let name:String
			init(apiResponse:[String:Any]) throws {
				guard let findName = apiResponse["continent_name"] as? String, let findCode = apiResponse["continent_code"] as? String else {
					throw ResolvedIPInfo.Error.missingContinentInfo
				}
				self.code = findCode
				self.name = findName
			}
		}
		struct RegionInfo:Codable {
			let code:String
			let name:String
			init(apiResponse:[String:Any]) throws {
				guard let findName = apiResponse["region_name"] as? String, let findCode = apiResponse["region_code"] as? String else {
					throw ResolvedIPInfo.Error.missingContinentInfo
				}
				self.code = findCode
				self.name = findName
			}
		}
		struct CountryInfo:Codable {
			let code:String
			let name:String
			init(apiResponse:[String:Any]) throws {
				guard let findName = apiResponse["country_name"] as? String, let findCode = apiResponse["country_code"] as? String else {
					throw ResolvedIPInfo.Error.missingCountryInfo
				}
				self.code = findCode
				self.name = findName
			}
		}
		
		let continent:ContinentInfo?
		let country:CountryInfo?
		let region:RegionInfo?
		let city:String?
		let zip:String?
		let isp:String
		
		init(apiResponse:[String:Any]) throws {
			self.continent = try? ContinentInfo(apiResponse:apiResponse)
			self.country = try? CountryInfo(apiResponse:apiResponse)
			self.region = try? RegionInfo(apiResponse:apiResponse)
			self.city = apiResponse["city"] as? String
			self.zip = apiResponse["zip"] as? String
			guard let hasConnectionInfo = apiResponse["connection"] as? [String:Any], let hasISP = hasConnectionInfo["isp"] as? String else {
				throw Error.missingISPInfo
			}
			self.isp = hasISP
		}

		static func from(addressString:String, accessKey:String, client:HTTPClient) async throws -> ResolvedIPInfo {
			return try await withUnsafeThrowingContinuation({  (myCont:UnsafeContinuation<ResolvedIPInfo, Swift.Error>) in
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
					guard let jsonSerialization:[String:Any] = try? JSONSerialization.jsonObject(with:responseBody) as? [String:Any] else {
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
	}
}

extension IPDatabase.ResolvedIPInfo:LosslessStringConvertible {
	var description: String {
		let jsonData = try! JSONEncoder().encode(self)
		let jsonString = String(data:jsonData, encoding:.utf8)!
		return jsonString
	}
	
	init?(_ string:String) {
		let stringData = Data(string.utf8)
		do {
			self = try JSONDecoder().decode(Self.self, from:stringData)
		} catch let error {
			IPDatabase.logger.error("unable to decode IPDatabase.ResolvedIPInfo", metadata:["error": "\(error)"])
			return nil
		}
	}
}

extension IPDatabase.ResolvedIPInfo:MDB_convertible {}

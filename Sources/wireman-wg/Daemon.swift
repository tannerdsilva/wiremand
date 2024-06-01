import CWireguardTools
import ArgumentParser
import wireman_db
import bedrock_ip
import bedrock
import RAW_blake2
import wireman_rtnetlink
import SystemPackage
import QuickJSON
import bedrock
import RAW_hex
import ServiceLifecycle
import Logging

#if os(Linux)
import Glibc
#elseif os(macOS)
import Darwin
#endif

internal struct Daemon:Service {
	internal let configuration:Configuration
 	internal func run() async throws {
		let logger = makeDefaultLogger(label:"daemon", logLevel:.trace)
		
		// compute the master keys
		let masterPublicKey = PublicKey(privateKey:configuration.privateKey)
		let masterPrivateKey = configuration.privateKey

		logger.info("starting daemon", metadata:["publicKey":"\(masterPublicKey)"])

		// generate the interface patterns based on the public key
		var uniquePatternHasher = try RAW_blake2.Hasher<B, [UInt8]>(key:masterPublicKey, outputLength:3)
		try uniquePatternHasher.update(Array("trusted_interface_iname".utf8))
		let trustedInterfacePattern = try uniquePatternHasher.finish()
		uniquePatternHasher = try RAW_blake2.Hasher<B, [UInt8]>(key:masterPublicKey, outputLength:3)
		try uniquePatternHasher.update(Array("hosted_interface_iname".utf8))
		let hostedInterfacePattern = try uniquePatternHasher.finish()

		// assemble interface names
		let trustedDevName = "wmanT_" + String(RAW_hex.encode(trustedInterfacePattern))
		let hostedDevName = "wmanH_" + String(RAW_hex.encode(hostedInterfacePattern))
		logger.debug("trusted device name: \(trustedDevName)")
		logger.debug("hosted device name: \(hostedDevName)")

		// generate the sub-keys for each interface based on the master private key
		var secureKeyHasher = try RAW_blake2.Hasher<B, PrivateKey>(key:masterPrivateKey, outputLength:32)
		try secureKeyHasher.update(Array("trusted_interface_privatekey".utf8))
		let trustedInterfaceKey = try secureKeyHasher.finish()
		secureKeyHasher = try RAW_blake2.Hasher<B, PrivateKey>(key:masterPrivateKey, outputLength:32)
		try secureKeyHasher.update(Array("hosted_interface_privatekey".utf8))
		let hostedInterfaceKey = try secureKeyHasher.finish()

		// load the wireguard interfaces
		var trustInterface:Device
		var hostedInterface:Device
		do {
			let listedDeviceNames = Device.list()

			// trust interface
			if listedDeviceNames.contains(trustedDevName) {
				trustInterface = try Device.load(name:trustedDevName)
				logger.info("loaded existing wireguard interface: \(trustedDevName)")
			} else {
				trustInterface = try Device.add(name:trustedDevName)
				logger.info("created new wireguard interface: \(trustedDevName)")
			}

			// hosted interface
			if listedDeviceNames.contains(hostedDevName) {
				hostedInterface = try Device.load(name:hostedDevName)
				logger.info("loaded existing wireguard interface: \(hostedDevName)")
			} else {
				hostedInterface = try Device.add(name:hostedDevName)
				logger.info("created new wireguard interface: \(hostedDevName)")
			}
		}

		trustInterface.privateKey = trustedInterfaceKey
		hostedInterface.privateKey = hostedInterfaceKey
		try trustInterface.set()
		try hostedInterface.set()

		repeat {
			trustInterface = try Device.load(name:trustedDevName)
			hostedInterface = try Device.load(name:hostedDevName)

			// poll the system and take tabs on any addresses that are assigned to the interfaces
			var existingAddressesH:Set<Network> = []
			var existingAddressesT:Set<Network> = []
			// v4
			for curAdd in try getAddressesV4() {
				if curAdd.address != nil {
					if curAdd.interfaceIndex == trustInterface.interfaceIndex {
						existingAddressesT.update(with:.v4(NetworkV4(address:AddressV4(curAdd.address!)!, subnetPrefix:curAdd.prefix_length)))
					}
					if curAdd.interfaceIndex == hostedInterface.interfaceIndex {
						existingAddressesH.update(with:.v4(NetworkV4(address:AddressV4(curAdd.address!)!, subnetPrefix:curAdd.prefix_length)))
					}
				}
			}
			// v6
			for curAdd in try getAddressesV6() {
				if curAdd.address != nil {
					if curAdd.interfaceIndex == trustInterface.interfaceIndex {
						existingAddressesT.update(with:.v6(NetworkV6(address:AddressV6(curAdd.address!)!, subnetPrefix:curAdd.prefix_length)))
					}
					if curAdd.interfaceIndex == hostedInterface.interfaceIndex {
						existingAddressesH.update(with:.v6(NetworkV6(address:AddressV6(curAdd.address!)!, subnetPrefix:curAdd.prefix_length)))
					}
				}
			}

			var expectingAddressesH = Set<Network>()
			var expectingAddressesT = Set<Network>()
			for curHostedNet in configuration.hostedNetworks {
				expectingAddressesH.update(with:curHostedNet)
			}
			for (curTrustNetInternal, _) in configuration.trustedNodes {
				expectingAddressesT.update(with:.v6(curTrustNetInternal))
			}

			let hostInterfaceDelta = Delta(start:existingAddressesH, end:expectingAddressesH)
			let trustInterfaceDelta = Delta(start:existingAddressesT, end:expectingAddressesT)

			// assign trust interface peers based on the configuration
			for (_, curNodes) in configuration.trustedNodes {
				for curNode in curNodes {
					let newPeer = Device.Peer(publicKey:curNode.publicKey, presharedKey:curNode.presharedKey)
					switch curNode.endpoint.address {
					case .v4(let asV4):
						newPeer.endpoint = .v4(asV4, curNode.endpoint.port)
					case .v6(let asV6):
						newPeer.endpoint = .v6(asV6, curNode.endpoint.port)
					}
					newPeer.update(with:Device.Peer.AllowedIPsEntry(NetworkV6(address:curNode.allowedIP, subnetPrefix:128)))
					trustInterface.update(with:newPeer)
				}
			}
			
			try modifyInterface([Int32(trustInterface.interfaceIndex):trustInterfaceDelta, Int32(hostedInterface.interfaceIndex):hostInterfaceDelta], logger:logger)
			try await Task.sleep(nanoseconds:1000000000*5)
		} while true
	}
}
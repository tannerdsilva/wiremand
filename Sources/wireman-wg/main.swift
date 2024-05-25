import CWireguardTools
import ArgumentParser

// @main
// struct RunThing:AsyncParsableCommand {
	// func run() {
		var wgd:UnsafeMutablePointer<wg_device>? = nil
		let interface = wg_get_device(&wgd, "wg0")
		if interface != 0 {
			print("Interface not found")
			exit(1)
		} else {
			print("Interface found \(wgd!.pointee.name)")
		}
// 	}
// }
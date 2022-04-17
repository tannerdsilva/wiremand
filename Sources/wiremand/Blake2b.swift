import Foundation
import cblake2b
import CLMDB

public struct Blake2bHasher {
    static func hash(data:Data, length:size_t) throws -> Data {
        var newHasher = Blake2bHasher(outputLength:length)
        try newHasher.update(data:data)
        return newHasher.export()
    }
    enum Error:Swift.Error {
        case blake2bError
    }

    fileprivate var state = blake2b_state()
    
    let outputLength:size_t

    /// Initialize a new blake2s hasher
    public init(outputLength:size_t) {
        guard blake2b_init(&state, outputLength) == 0 else {
            fatalError("error initializing blake2s")
        }
        self.outputLength = outputLength
    }
    
    public mutating func update(data input:Data) throws {
        try input.withUnsafeBytes { unsafeBuffer in
            try self.update(unsafeBuffer)
        }
    }
    
    public mutating func update(_ value:MDB_val) throws {
        guard blake2b_update(&state, value.mv_data, value.mv_size) == 0 else {
            throw Error.blake2bError
        }
    }
    
    /// Update the hasher with new data
    public mutating func update(_ input:UnsafeRawBufferPointer) throws {
        guard blake2b_update(&state, UnsafeRawPointer(input.baseAddress!), input.count) == 0 else {
            throw Error.blake2bError
        }
    }

    /// Finish the hashing
    public mutating func export() -> Data {
        let finalHash = UnsafeMutableBufferPointer<UInt8>.allocate(capacity:outputLength)
        defer {
            finalHash.deallocate()
        }
        guard blake2b_final(&state, finalHash.baseAddress!, outputLength) == 0 else {
            fatalError("error finalizing blake2s")
        }
        return Data(buffer:finalHash)
    }
    
    mutating func reset() throws {
        guard blake2b_init(&state, outputLength) == 0 else {
            throw Error.blake2bError
        }
    }
}

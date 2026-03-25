internal import OpenSSL

@frozen public enum CryptographyHashType: Sendable {
    /// The standard 256-bit algorithm from the SHA-2 family.
    case sha256
    /// The 384-bit algorithm from the SHA-2 family.
    case sha384
    /// The 512-bit algorithm from the SHA-2 family.
    case sha512
    /// The 256-bit algorithm from the modern SHA-3 family.
    case sha3_256
    /// The 384-bit algorithm from the modern SHA-3 family.
    case sha3_384
    /// The 512-bit algorithm from the modern SHA-3 family.
    case sha3_512
}

extension CryptographyHashType {
    // Maps the Swift enum to the OpenSSL EVP_MD pointer
    var id: OpaquePointer? {
        switch self {
        case .sha256: EVP_sha256()
        case .sha384: EVP_sha384()
        case .sha512: EVP_sha512()
        case .sha3_256: EVP_sha3_256()
        case .sha3_384: EVP_sha3_384()
        case .sha3_512: EVP_sha3_512()
        }
    }
}

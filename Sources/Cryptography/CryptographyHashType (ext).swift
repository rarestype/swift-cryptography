#if canImport(OpenSSL)
internal import OpenSSL

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
#endif

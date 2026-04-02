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

internal import OpenSSL

extension RSA {
    @frozen public enum SignaturePaddingMode: Sendable {
        /// A legacy standard, mathematically fragile and should be avoided when possible.
        case pkcs1_legacy
        /// A more-modern RSA padding scheme, that adds random salt to the padding process.
        case pkcs1_pss
        case x931
    }
}
extension RSA.SignaturePaddingMode {
    /// FIXME: should not be public
    public var mode: Int32 {
        switch self {
        case .pkcs1_legacy: RSA_PKCS1_PADDING
        case .pkcs1_pss: RSA_PKCS1_PSS_PADDING
        case .x931: RSA_X931_PADDING
        }
    }
}

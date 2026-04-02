extension RSA {
    @frozen public enum SignaturePaddingMode: Sendable {
        /// A legacy standard, mathematically fragile and should be avoided when possible.
        case pkcs1_legacy
        /// A more-modern RSA padding scheme, that adds random salt to the padding process.
        case pkcs1_pss
        case x931
    }
}

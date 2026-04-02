#if canImport(OpenSSL)
internal import OpenSSL

extension RSA.SignaturePaddingMode {
    var mode: Int32 {
        switch self {
        case .pkcs1_legacy: RSA_PKCS1_PADDING
        case .pkcs1_pss: RSA_PKCS1_PSS_PADDING
        case .x931: RSA_X931_PADDING
        }
    }
}
#endif

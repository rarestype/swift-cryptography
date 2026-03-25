internal import OpenSSL

extension RSA {
    @frozen public struct PrivateKey: ~Copyable {
        private let object: OpaquePointer
        private init(consuming object: OpaquePointer) {
            self.object = object
        }
        deinit {
            EVP_PKEY_free(self.object)
        }
    }
}
// This is valid as long as we never switch pointers
extension RSA.PrivateKey: @unchecked Sendable {}
extension RSA.PrivateKey {
    /// Parses a PEM-encoded private key.
    public init(pem: borrowing String) throws(CryptographyError) {
        let unmanaged: OpaquePointer = try CryptographyError.do {
            /// we expect this to be a no-op, if the PEM string is already UTF-8
            var pem: String = copy pem
            return pem.withUTF8 {
                guard
                let bio: OpaquePointer = BIO_new_mem_buf(
                    $0.baseAddress,
                    Int32.init($0.count)
                ) else {
                    // the most common reason this fails is because the string provided was empty
                    return nil
                }

                defer {
                    BIO_free(bio)
                }

                return PEM_read_bio_PrivateKey(bio, nil, nil, nil)
            }
        }

        self.init(consuming: unmanaged)
    }

    /// Parses raw DER-encoded binary data.
    public init(der: borrowing ArraySlice<UInt8>) throws(CryptographyError) {
        let unmanaged: OpaquePointer = try CryptographyError.do {
            der.withUnsafeBufferPointer {
                guard
                let bio: OpaquePointer = BIO_new_mem_buf(
                    $0.baseAddress,
                    Int32.init($0.count)
                ) else {
                    return nil
                }

                defer {
                    BIO_free(bio)
                }

                return d2i_PrivateKey_bio(bio, nil)
            }
        }

        self.init(consuming: unmanaged)
    }
}
extension RSA.PrivateKey {
    /// Signs an UnsafeRawBufferPointer using RSA PKCS#1 v1.5 padding and SHA-256.
    public func sign(
        hashing message: String,
        padding: RSA.SignaturePaddingMode,
        algorithm: CryptographyHashType = .sha512
    ) throws -> [UInt8] {
        var message: String = message
        return try message.withUTF8 {
            try self.sign(
                hashing: UnsafeRawBufferPointer.init($0),
                padding: padding,
                algorithm: algorithm
            )
        }
    }
    public func sign(
        hashing message: UnsafeRawBufferPointer,
        padding: RSA.SignaturePaddingMode,
        algorithm: CryptographyHashType = .sha512
    ) throws -> [UInt8] {
        try CryptographyError.do {
            guard
            let context: OpaquePointer = EVP_MD_CTX_new() else {
                return nil
            }
            defer {
                EVP_MD_CTX_free(context)
            }

            /// the public key context’s life cycle is managed by the message digest context,
            /// and must not be freed separately
            var publicKey: OpaquePointer? = nil

            guard case 1 = EVP_DigestSignInit(
                context,
                &publicKey,
                algorithm.id,
                nil,
                self.object
            ),
            let publicKey: OpaquePointer else {
                return nil
            }

            // a success here is any positive return code
            guard EVP_PKEY_CTX_set_rsa_padding(publicKey, padding.mode) > 0 else {
                return nil
            }

            // most signing operations require two passes (to compute the signature length),
            // but because we know statically this is an RSA key, we can use this optimization
            var length: Int = .init(EVP_PKEY_get_size(self.object))
            let signature: [UInt8] = .init(unsafeUninitializedCapacity: length) {
                if  case 1 = EVP_DigestSign(
                    context,
                    $0.baseAddress,
                    &length,
                    message.baseAddress,
                    message.count
                ) {
                    $1 = length
                } else {
                    $1 = 0
                }
            }
            if  signature.count != length {
                return nil
            } else {
                return signature
            }
        }
    }
}
extension RSA.PrivateKey {
    public func verify(
        signature: ArraySlice<UInt8>,
        message: Substring,
        padding: RSA.SignaturePaddingMode,
        algorithm: CryptographyHashType,
    ) throws -> Bool {
        try signature.withUnsafeBytes { (signature: UnsafeRawBufferPointer) -> Bool in
            var message: Substring = message
            return try message.withUTF8 {
                try self.verify(
                    signature: signature,
                    message: UnsafeRawBufferPointer.init($0),
                    padding: padding,
                    algorithm: algorithm
                )
            }
        }
    }

    public func verify(
        signature: UnsafeRawBufferPointer,
        message: UnsafeRawBufferPointer,
        padding: RSA.SignaturePaddingMode,
        algorithm: CryptographyHashType,
    ) throws -> Bool {
        try CryptographyError.do {
            guard
            let digestContext: OpaquePointer = EVP_MD_CTX_new() else {
                return nil
            }

            defer {
                EVP_MD_CTX_free(digestContext)
            }

            var keyContext: OpaquePointer? = nil

            guard case 1 = EVP_DigestVerifyInit(
                digestContext,
                &keyContext,
                algorithm.id,
                nil,
                self.object
            ),
            let keyContext: OpaquePointer else {
                return nil
            }

            guard EVP_PKEY_CTX_set_rsa_padding(keyContext, padding.mode) > 0 else {
                return nil
            }

            return 1 == EVP_DigestVerify(
                digestContext,
                signature.baseAddress,
                signature.count,
                message.baseAddress,
                message.count
            )
        }
    }
}

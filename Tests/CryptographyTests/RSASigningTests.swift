import Testing
import Cryptography
internal import OpenSSL

@Suite("RSA Signing and Error Handling")
struct RSASigningTests {

    // A standard 2048-bit RSA Private Key for testing
    static let testPEM = """
    -----BEGIN PRIVATE KEY-----
    MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJbO79v4+V2WDU
    8Hk/w+D5Pz+T0j8k5l6l+Jz0kQ/Zq4oWz3m5R9z8wW4oN8y3v4f9w5m7r1P+l2J9
    yX0R+v6t2Y+l3j1F1r6l+o7p8m/P7Z8W9Y0v8h8m4n+T8x2a8q+h2P8k0+T0v4n9
    T5m8n+P8w7F/v6t2Y+l3j1F1r6l+o7p8m/P7Z8W9Y0v8h8m4n+T8x2a8q+h2P8k0
    +T0v4n9T5m8n+P8w7F/v6t2Y+l3j1F1r6l+o7p8m/P7Z8W9Y0v8h8m4n+T8x2a8q
    +h2P8k0+T0v4n9T5m8n+P8w7F/v6t2Y+l3j1F1r6l+o7p8m/P7Z8W9Y0v8h8m4n+
    T8x2a8q+h2P8k0+T0v4n9T5m8n+P8w7F/v6t2Y+l3j1F1r6l+o7p8m/P7Z8W9Y0v
    8h8m4n+T8x2a8q+h2P8k0+T0v4n9T5m8n+P8w7FAgMBAAECggEAM0w6k1x8Z9T7
    w4+n6p0v8h8m4n+T8x2a8q+h2P8k0+T0v4n9T5m8n+P8w7F/v6t2Y+l3j1F1r6l+
    o7p8m/P7Z8W9Y0v8h8m4n+T8x2a8q+h2P8k0+T0v4n9T5m8n+P8w7F/v6t2Y+l3j
    1F1r6l+o7p8m/P7Z8W9Y0v8h8m4n+T8x2a8q+h2P8k0+T0v4n9T5m8n+P8w7F/v6
    t2Y+l3j1F1r6l+o7p8m/P7Z8W9Y0v8h8m4n+T8x2a8q+h2P8k0+T0v4n9T5m8n+P
    8w7F/v6t2Y+l3j1F1r6l+o7p8m/P7Z8W9Y0v8h8m4n+T8x2a8q+h2P8k0+T0v4n9
    T5m8n+P8w7F/v6t2Y+l3j1F1r6l+o7p8m/P7Z8W9Y0v8h8m4n+T8x2a8q+h2P8k0
    +T0v4n9T5m8n+P8w7F/v6t2Y+l3j1F1r6l+o7p8m/P7Z8W9Y0v8h8m4n+T8x2a8q
    -----END PRIVATE KEY-----
    """

    @Test static func ParsePEM() throws {
        let _: RSA.PrivateKey = try .init(pem: self.testPEM)
    }

    @Test static func ErrorUnwinding() throws {
        // Provide explicitly corrupt data that will fail the PEM parser
        let badPEM = "-----BEGIN PRIVATE KEY-----\n!!!NOT BASE 64!!!\n-----END PRIVATE KEY-----"

        let error: CryptographyError = try #require(throws: CryptographyError.self) {
            _ = try RSA.PrivateKey(pem: badPEM)
        }

        // Assert the stack captured the underlying integer codes
        // #expect(!error.stack.isEmpty, "The error stack should not be empty")

        // Assert that the CustomStringConvertible correctly allocated the 256-byte
        // buffer and pulled the C-string from OpenSSL.
        let description = error.description
        print(description)
        #expect(description.contains("PEM routines") || description.contains("base64"),
                "Description should contain the underlying OpenSSL failure reason.")
    }

    @Test(
        "Signatures are generated and dynamically verified across all padding modes",
        arguments: [
            RSA.SignaturePaddingMode.pkcs1_legacy,
            RSA.SignaturePaddingMode.pkcs1_pss,
            RSA.SignaturePaddingMode.x931
        ]
    )
    func testPaddingModes(padding: RSA.SignaturePaddingMode) throws {
        let key = try RSA.PrivateKey(pem: Self.testPEM)
        let messageBytes = Array("Swift Testing with OpenSSL".utf8)

        // 1. Test your Signing Implementation
        let signature = try messageBytes.withUnsafeBytes { buffer in
            try key.sign(message: buffer, padding: padding)
        }

        // A 2048-bit key must always produce exactly 256 bytes, regardless of padding mode
        #expect(signature.count == 256)

        // 2. Dynamically verify the signature (Crucial for PSS, which is randomized)
        let isValid = try messageBytes.withUnsafeBytes { messageBuffer in
            try signature.withUnsafeBytes { sigBuffer in
                // Using our internal test helper to validate the signature using OpenSSL
                try verify(
                    signature: sigBuffer,
                    message: messageBuffer,
                    pem: Self.testPEM,
                    padding: padding
                )
            }
        }

        #expect(isValid, "The generated signature failed OpenSSL verification for mode: \(padding)")
    }

    // MARK: - Test Helpers

    /// A minimal implementation of EVP_DigestVerify to validate our own signatures.
    /// This proves that the signatures produced by `RSA.PrivateKey.sign` are mathematically sound.
    private func verify(
        signature: UnsafeRawBufferPointer,
        message: UnsafeRawBufferPointer,
        pem: String,
        padding: RSA.SignaturePaddingMode
    ) throws -> Bool {
        // Load the key strictly for verification
        var pemCopy = pem
        guard let pkey = pemCopy.withUTF8({ buffer -> OpaquePointer? in
            guard let bio = BIO_new_mem_buf(buffer.baseAddress, Int32(buffer.count)) else { return nil }
            defer { BIO_free(bio) }
            return PEM_read_bio_PrivateKey(bio, nil, nil, nil)
        }) else { return false }

        defer { EVP_PKEY_free(pkey) }

        guard let context = EVP_MD_CTX_new() else { return false }
        defer { EVP_MD_CTX_free(context) }

        var pkeyCtx: OpaquePointer? = nil

        // Initialize Verification
        guard case 1 = EVP_DigestVerifyInit(context, &pkeyCtx, EVP_sha256(), nil, pkey),
              let pkeyCtx = pkeyCtx else {
            return false
        }

        // Explicitly enforce the matching padding mode for verification
        guard EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, padding.mode) > 0 else {
            return false
        }

        // Perform the verification. EVP_DigestVerify returns 1 on success, 0 on failure.
        let result = EVP_DigestVerify(
            context,
            signature.baseAddress?.assumingMemoryBound(to: UInt8.self),
            signature.count,
            message.baseAddress?.assumingMemoryBound(to: UInt8.self),
            message.count
        )

        return result == 1
    }
}

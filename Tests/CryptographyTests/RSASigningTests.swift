import Testing
import Cryptography
internal import OpenSSL

@Suite("RSA Signing and Error Handling")
struct RSASigningTests {

    // A standard 2048-bit RSA Private Key for testing
    static let testPEM = """
    -----BEGIN PRIVATE KEY-----
    MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQC5Ap62HYzffzgr
    9cqGJen0yfmu0Ut9R5Ct4jDV0dkBUdHdTjQOGF/ZlyphzTbgD5YmVO9zyOjeh2oB
    ieug8/i+b2LdlX/6U6DCFiXCV460rKuvEYj1A3qj7mPZbpB2mABb7uxRO6OV0VM6
    4gJ5Z3upOXQ+k1usPZn90Jk0M6PXCZedpwzPLgRmw3DpI02YzutQqI4HcSoMFWnQ
    sGQWEsu6kOtpBWtkPNKKkAYlPym1Vg33nQ5x7N+03PckmoFkcyiik5wz/yKGfYpl
    Vf5IqbkC6EfjT9ZBSg35IrU+j5KsW3COaQAs/GgHBxxbYHHPoNoDLRvoE3KJ5sjg
    M8sP5ZLZAgMBAAECgf8VJi/+dGJTZntnP8hX9t909pK5+FEZzHZqtYdJCDQZNki/
    zvwVVR1jq75/YJRHNfllDgVCa9rJlXUIxw4/I0pEmOB/sFOeFWm8EXG4CWhsezKO
    ffKqD5YbGDvoandzj6Fr0eu5XYjkzC6v/XFpFRh+v87c3+x1NQ4Dk+uVMbtyaGzc
    3PJl9+q9ANALsDhB/ak3JeipWpZo2eN9HKqlWlZqe/uBhVKaf0mmr3XsscYqI/2s
    FVltEoDheuPtIBghFIQE/2iueM7tYQeZUfoHJBuCF+aDp2ouMPXoLAaejQQgL66K
    9DT5ioWl8u5IRZmu9/JHV4cIPhMg6h+ClFf9eW8CgYEA66Zi4e7U4P869xI27RqH
    VgShRgWcIj+IkMOofJuy0m4wBaZ93eN52e5w27mM92y650wgDuqvm25Ddhv7fYTJ
    nIaes82fgNG4DhAPWP8yRhEje0ugSjfUNkL4Q0OfIYRP3YywrEasAjUsOKLVOmnI
    jPBWWaQMxHZFiTwkAfccyL8CgYEAyPy4U0yiiYoxlPEoUYb8ZOxxvXOSA/NsIwG0
    eKWvnrKJJq5uzw2HdeWvClOyxiuB3OwwZVS5o14oPe37t0p0TsZroNmmu0mlL9rV
    jOMQ5OdDqzudpKQw8VpxA+La7nQ7kcZiyE1f3NSudaM3mIc0TXvc1Bc2XzBIV3TA
    BPNEsmcCgYEAt2l0s0dR16GwAlfh+l/YkGHgKID7SkjLAWnYPMxuvYxXwj4Y31hL
    Ig2NN+fOyVGOk7JTjWiqr759sXMMJmDxDuxUn7vedsREjmV/nJRcS97REAkHxFx5
    xpYPZ0M9mzfBdb4oUJ5dCQbb2WUbs3BcUR5LB1BBQ7SOYMc3e3Qbqj8CgYB5XVGY
    y0/iqdYi0DS+djp2XuiXs+/Z/uWvhdoKeFJCDCERgIdc9Bh2Msmt/LiZPbBfTSg0
    KCMo6TR3oPs8xPLSlrJrIMKzmVbsPMJzHrIW5ydPgOJChvse4rQX2qbFEt7duePw
    e/iFCtCGLJbnvczxdPf2AkZM2IT2eoNw+czjxQKBgBW0SAVDU4h3CwBM6LFJOAQu
    gOm8F0MdF6LfAE84g5Ue42H5tWZBM/vpOFo+zPMgLpfjdbdrlaZkidOdalPisf5n
    gQIp9hL/KG5OPeJ/KsRzdT8Z0OzLxkYdzRXNA41lDZIMClv2onIwwddx3LHjbwNb
    Iiy487Lr3g8PqhxxVLVk
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
        #expect("\(error)".contains("DECODER routines::unsupported"))
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

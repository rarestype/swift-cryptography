import Cryptography
import Testing

@Suite struct RSASigningTests {
    // A standard 2048-bit RSA Private Key for testing
    static var k: String {
        """
        -----BEGIN PRIVATE KEY-----
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCf26FUadSI7hfu
        2te9xvw2GGYmGujFPyuEYm5PxBZyQ/+p167i1dtAK8brpnY8m6dvZKIu1kNn7Zis
        f1nbR7Hl/a2czIix+meGKloZ7D1Kki+nGFBOFoX3juWE/SmXDZU5oJX38PZpWBfa
        BuWK5ccQGBE7QihFi3SFpQ7Awr1qVVz7BGIkErs84owt75SrXeKLa8oT8ytWu7W6
        1KjLjfE/XJPE2aQqz/8oXm6MkZ2cS2bpFovnDOZ4isnJr5CEUcM9p0+5fXnLo/4E
        xYwgdkKS++1+kG+asjxZhFEc8M4U0G4FG9CIKc9QfDiTMu+qGLk6+EWFgBRIEjQE
        b2y0V/+HAgMBAAECggEAAg0md9fX014CzpzeUeAg0mzjuq9ztzxFSbCdq8ZfZ136
        BOrwopaN9rfZGKMNN1/j+Sj4b9NuEAJbiDMmKwszfDkSJkX1pxsIgw8+EsEWVEOl
        +uXz+dyOIYwi497/zqFs/c1Sv1jHQLjRrYmTHoIuWMWGSxVhQOs2NpTUqKKXHasv
        iuv4a0NO+LnlPniXL99CCtG9dqSzZUYbgbuiZo/ehXdZc4k3ONB+KVNBX05vIf+P
        bFJ7caiOSLmiUJX45nUKKTK9NleCdmvz7CSYUTkHb8hGNBZqqSvsNspCQigVcCzI
        JokAd5i+P+OSmF3KB8UTnsR7+GyYcV3ZFBFowQvyMQKBgQDgeldc5I14fmcfEwSd
        2rs9TLxsskLRFhqkNlttFISSyN7Wh+xvBZBq6YeRr/HVw+sZYSfjwVkk6Kco2g+9
        lHDp6bzv7UdUEwa3nprXmIWe8tozmJ/GZbn9I3a4mGR9Yxl2dbQEVHBTFGNStg3Z
        i4pNUBv/H8Tlm6VxnWNEWi2OaQKBgQC2Tks0W+mkJDEpariJsvke+yyw+YjEzM3h
        xnw8kYNoZ+tZIBwop+wuU7dMGd4MggUovANtWvjfTsXJDMJgqA7t9F1P8bzAYIQ1
        oMIn9DNoBUfHylr5Fb5LK49BVUMUCjpeWcjmgKxxY2s+KITZ+4SP4k4zP4JM0hT0
        9Vuo+XVAbwKBgAJukN+6wiWaCPf3NseXBQxG9oue6sZlHOjGhfsKi90jO/bLBi61
        urjNyuAzLcWJF9TwjoQTJioWMyloI1+Eaiy+kYNv6KPqiNoYZ8kKJ/hu3RpN/v0h
        QQCTD8g0LnKFTlNQNyEM4SKlR+Yvfrrqnhb0VTlQWMu8AfDXKaol5/RxAoGBAJWx
        YjUjB4z9HtUISXDf4Ykb642ByFj4ZlFuPpMpVMKFGg27vQNxJxC/MvItB1Qz6vKQ
        tyuzGEmcj/FPJchiFqgzD+/V6gv49HZogyR1c0SFmXQm515CCVgF84JM9WBeKaFR
        jhIfM/mDDgsjEDtBOI9A3r9b9a0Ij6a4VURBWZLHAoGAJUogwwWmDmS8C16eAhZq
        1gVY0vdQo0bKhF3bZDHDP7F2Kfcm+PglZ4HZqawG8dZzsAA35uGqGlFbGF/cfLJV
        T8USQ1E4LHpPkVizrjE/NmsQG7ozSTtWMCCQ30vYK+nFxtIe0x0SPEI43Vngx8Bl
        ALYi8BGscTYtpjCf7Ygbkro=
        -----END PRIVATE KEY-----
        """
    }

    static var l: String {
        """
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCjDOQgxxCC6jS0
        iqKzzZveCimog7KYkn+jbd8eQrK/Y2tsyh6rIx4SfZeay1kkwdMzssTF6l7e2/T5
        I02qRcszwG+ZYa4pyVhukqX4F8lhyXIXgw0p5Wy73wZc9iFry1jPEcquYwD4v64c
        BnxrA0KnBnrqH7ftROPLE3jqkJLL0nVQp9KfrGxWML3VYbpEbt6H7zHLPM3hP2Lg
        lXHs8wdMwt4kMhHbywBYW8BMDw0i3jqZeBfaFJCiL3wCN7IMpsXSH+vtW06Lv7z/
        lAjaxj1AmNa1f36SwfTMdKUCztvuwuBE2U18z3l6Yo4b+QqNgvbB4P4/liKGEayh
        CEh1SlwrAgMBAAECggEABuSiWirwRGWwXaNqyUu7g0d8tbxFDl2oP+3gAbTcVjvu
        CYbqVqPYP1klLwFOVkuRnZdEu0a4/yIN9j2uHPb8ZiObvO8ZDwR2A0Ganby3VliJ
        OUHJW9zks0Zo7rrOi8/RPlfT8L/1HKZRgHzmzL2PLp/0JQ2Ml987QQnHbyVk/1nF
        B99L52SmVDmp0S0QWztsgyelGm3EYnOn45I2yslHYIXzEnjJ7nLDsVmAnCgIsPfK
        3elsbfeQpHbZc5qDE3eXKpe81Ka38R7T9P7y+bEp0qve1WO1Xp+vNXVjxQd5lxjn
        lIHz/O03KylJqlWlgUXc1CQViOnQE/wI00P1/xg96QKBgQDNgqE13eGHxmHMT6pJ
        2EgyAqyzQL6bJacjusSAckQnuzJ/TDKpRbZs+/VYF56BgISDnLvdecUNslRwuQHX
        qsgQ4m+KeJ1DJ6uKw+UGYQZI7N7j34rozWStMs9XECqWio7vahdbYm4kmLcfT6dv
        y/tIpMCFxU3OuPS74Lit2T/WPwKBgQDLG8kyccrVoU5J3oWHZMm4a4Ifu/rIu4pj
        n6/7ismNfvHwC5xBAFt06wKc78MptZvCvZv7vJDbFwMPXCnjRWzum+j7NAWQbt5h
        ThIuGoRi0PHpYPjXPeEfCo8bpRSrh70WrsCW7Rp4fKmEUdRg8HnaZaZxg7VkDoUm
        GqUl9On3FQKBgBQjVtTGd1EsuWyh6dfun7R22qF+GK9vUx+HL7Y+fDtAdsROnTBF
        Koknb3VAa0HZbCLRev9K7WpYLToWhv2xOIWfCrsQ8qgf/QlOBOVJIKqIu5as0xnY
        9qKaNgMcDHBQB42iYcOMs6pWZKtmzMuBu4/0xQDWwrcdHK5EaRRwE3dVAoGBAIsS
        9Jp49oV/VUcZel8yMTn5S3mFUvxeBi2fK3ZXGxmrIejXWl/b6cPOI9ToC7+kngoj
        oQonnRyXzj2XQwte/28HDOntPh4e/GCuf55YA+xR3EOMZfekZGDH7yPjzpqBcIV2
        lWMC6Yw0+DIlggH6x8U2s1io8eyYUK29svWhlQ7dAoGBAI05ups99ucwljgREIeM
        yf4I8RA1e83fM9XsWcQ4Rbnkomd/9HRgGm/3/MaaxdBk9UU9tLkmgQls2Y9rpEOM
        TD+iTR7vw/+nDUt38bEo4kTSqayrhvI2LsU7UiQXCndL6l9FaIg5l42SJpa5/iD0
        qQJSkgFr4qMTb0UMb0LPs9pf
        -----END PRIVATE KEY-----
        """
    }

    @Test static func ParsePEM() throws {
        let _: RSA.PrivateKey = try .init(pem: self.k)
    }

    @Test static func ParseErrorUnwinding() throws {
        let error: CryptographyError = try #require(throws: CryptographyError.self) {
            let _: RSA.PrivateKey = try .init(
                pem: """
                -----BEGIN PRIVATE KEY-----\n!!!NOT BASE 64!!!\n-----END PRIVATE KEY-----
                """
            )
        }

        #expect("\(error)".contains("DECODER routines::unsupported"))
    }

    @Test static func SignDeterministicPKCS1() throws {
        let key: RSA.PrivateKey = try .init(pem: self.l)
        let computed: [UInt8] = try key.sign(
            hashing: "Swift Testing with OpenSSL",
            padding: .pkcs1_legacy,
            algorithm: .sha256
        )
        let expected: [UInt8] = [
            0x42, 0xd0, 0xbc, 0x76, 0xb6, 0xb5, 0x47, 0x07, 0xc0, 0x2a, 0x52, 0x39,
            0xb3, 0x68, 0xe9, 0xb4, 0x9c, 0x3c, 0x38, 0x71, 0xcd, 0x04, 0x6f, 0xc1,
            0x28, 0x93, 0x5f, 0xb7, 0xb2, 0x00, 0x66, 0x13, 0xa8, 0x2d, 0x4e, 0x63,
            0xcd, 0xf3, 0xf1, 0x75, 0xe4, 0x94, 0xdc, 0x4a, 0x04, 0x54, 0x88, 0xff,
            0x9f, 0xd4, 0x9c, 0x8e, 0xa7, 0xc7, 0x4a, 0xad, 0xa4, 0xe8, 0x65, 0xcf,
            0x87, 0x41, 0x74, 0x77, 0x0e, 0xfd, 0x99, 0x90, 0xfb, 0xdb, 0x9d, 0xfd,
            0x1c, 0xfb, 0xcd, 0x33, 0x54, 0x02, 0xcd, 0xf2, 0x4f, 0x3a, 0xe1, 0x52,
            0xf7, 0x08, 0xba, 0xdc, 0x2a, 0xdf, 0xbe, 0xb9, 0x5c, 0x62, 0x27, 0xef,
            0x25, 0xb6, 0xbe, 0x80, 0xc5, 0x64, 0x8c, 0x2b, 0xfa, 0xf6, 0xdf, 0x9b,
            0x9c, 0x8d, 0xa4, 0x9a, 0xb1, 0x86, 0xd7, 0x75, 0x13, 0xe1, 0x5f, 0x19,
            0xc8, 0x61, 0x80, 0xd2, 0x16, 0xe9, 0x36, 0xbe, 0xae, 0xec, 0xee, 0xca,
            0x33, 0xce, 0xdd, 0xa5, 0x80, 0xcd, 0x8f, 0xbd, 0xeb, 0x70, 0x9a, 0x3a,
            0x90, 0xf0, 0x4e, 0x51, 0x75, 0xd7, 0x76, 0x92, 0xd0, 0xc8, 0x60, 0x53,
            0xa8, 0x78, 0xb7, 0x13, 0x34, 0x8a, 0xd6, 0xce, 0x1f, 0xa6, 0xfd, 0xa4,
            0xb4, 0x26, 0x52, 0x12, 0x91, 0x0d, 0x01, 0x0e, 0x1f, 0xfe, 0x9d, 0xd5,
            0xbb, 0x26, 0x0c, 0x80, 0x21, 0xb0, 0x13, 0xc7, 0x37, 0x22, 0x81, 0xb5,
            0x0c, 0x4f, 0x41, 0xba, 0xff, 0xf3, 0xe4, 0xe4, 0x6e, 0x18, 0x0f, 0xf6,
            0x2c, 0xb5, 0xda, 0xe0, 0xa4, 0xee, 0x4c, 0xae, 0xa0, 0x96, 0x9f, 0xaa,
            0x0e, 0x81, 0x86, 0x1b, 0x2c, 0x9e, 0xfd, 0xe6, 0xc5, 0x07, 0x03, 0x7b,
            0xf9, 0x5f, 0x8d, 0x3e, 0xff, 0xa9, 0xf2, 0xdb, 0xbd, 0x3c, 0x66, 0x6d,
            0xc7, 0x85, 0x78, 0xe3, 0xcf, 0x25, 0x2a, 0x10, 0x8a, 0x55, 0xf3, 0x09,
            0x2a, 0x36, 0xb5, 0x1f
            ]
        #expect(computed == expected)
    }


    @Test(
        arguments: [
            .pkcs1_legacy,
            .pkcs1_pss,
            .x931
        ] as [RSA.SignaturePaddingMode]
    ) static func SignWithVerify(_ mode: RSA.SignaturePaddingMode) throws {
        let k: RSA.PrivateKey = try .init(pem: Self.k)
        let l: RSA.PrivateKey = try .init(pem: Self.l)
        let message: String = "Swift Testing with OpenSSL"

        let signature: [UInt8] = try k.sign(
            hashing: message,
            padding: mode,
            algorithm: .sha256
        )

        #expect(signature.count == 256)

        // Dynamically verify the signature (Crucial for PSS, which is randomized)
        #expect(
            try k.verify(
                signature: signature[...],
                message: message[...],
                padding: mode,
                algorithm: .sha256
            )
        )
        #expect(
            try !l.verify(
                signature: signature[...],
                message: message[...],
                padding: mode,
                algorithm: .sha256
            )
        )
    }
}

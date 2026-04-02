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
        MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8/LFgrG0Doa6f
        w8vLEu1PoYy069uc7/1LdEjvLNhSAMxVx4B9ThfEJZ3QICaysS4VF6UefguOGv4I
        xYrrwyuSUaUIhFWvRpJdxzfF0fzupQ8MUmNSdIaMG3A+u1Kxr9QxIaI0C+0LVI3c
        sJeGzRCHdvxA2qVK3esC06xNiS47jwdbj1CLjItjynWYBDSXZHEfuus5vRa/PM/k
        e2jMnkwEcxFRB1iB3Kr7zwWsEIP1nYkHNImCZjvcbshHl+BGbuRpLLwkLDEop+cC
        0gj1eLtPgIET91vWn7864cT+GHhenU8xwN+cmuyO8UAEWbZH248xPQC2EvXBHtHN
        yYTspRwZAgMBAAECggEAMdWKan0dQ/tjAkMNnq+Pf1OQuHaHUyNfjgGMZ/FR25HV
        T/tLEP/COZlXu3V27uDUz4AMLPW800yf1y1MHC47c5pu48eNlqoL14m8VcAxK7a/
        uJaTFT+f6RslJo2b2ToNwKTnUkUgzT+PJvY0BrpVVPtVuj5NnufU3Ep34Xw+gjqZ
        CazMuhggJC2s6AxVmC+4fSVuBzibaS7KO5M4plDbc+ErwIUsQZbf0VWNFvy7xHqd
        ciwC2WjRCrQea6Zo3JoLt8DVqp3/s+VDdFdyjBNhhbC4LK10QpO9cqXEVERhkKa2
        h/9x72QaK5hsT2YEW7ViNndX4hSoeXDPoulKGA8uFwKBgQDxi4rCYonjNV5TFuJ/
        usDflxoXEC9Qhw+WxYTotRMV7HPPMPSPfM90ae+H+4Z1FXCBQeJkuvGhPBtr7khe
        bSCbpdTxD9W32UcQVaSAeWI0msoNNrmpdcdibchtfYO3YveRtzw156/LWSrQ33W+
        BR2nV3q7iizggT5UUMe2OqBHMwKBgQDIS/cKF3z4Acbyp0XfIcioslZBPzWM5OoL
        huNMd11w4LJFO7lUY5FBQxi7SKAAJdxIbXZkXgwf+jRPS06Q/togafrD+DvsXGR4
        WYrJNGYj2qs2DIQ3r04V0uUy0s7Pf/Fj4DakHBCEpn1pijIEuRN8DgcPHjfFein2
        0pfj/fifgwKBgGRlg79YBcgSnqoakPpWPWSyAX4klAX8nVYlsyCmYtBx/5DW4E/j
        qLbScWUr/q8bwi93mwoTSeuieCNcX2ggI7WOL/wigMpx3T/E2SMtUMxcqi7j2De/
        ZKhcyTn5OY437H78kmI1crQq08kNmHrq1XCAw9q/i/ekwKt7CAeORqBRAoGAUKg+
        kALLYTed/OMdQPBi1IQUNewVTWp1UTT9XTKIH0dsonKde/0oZiZ11B03yTd10Hi7
        /0jcCxh/bhr+RWdLQVhMEhRpVRITp18vgzylkPSik35Q0/e1MxadE21OuMJl23lT
        p5xhjnlY8WIkKEC7Nu6TKyRZAx3hvjIp1jbUoq8CgYEAiSnyweB1uYzwpdxLANsL
        GpVI4euCZpEbqaK04egEFWQbfQKrmv2/mkfpvx+JaTaUhYbyLxWvHw7WFugGUIER
        MB1zvDs4Q72LNXEztivciR7wfhYbFDolEXxEyrxQiM5NrDnFJ8UWnYWvsuwCfLVa
        4IwYX3BKD0yF6rwWHfhKimA=
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
            hashing: "Oh how I love being a Barbie!",
            padding: .pkcs1_legacy,
            algorithm: .sha256
        )
        let expected: [UInt8] = [
            0x56, 0x5a, 0x84, 0x4b, 0xf3, 0xba, 0xd3, 0x50, 0x82, 0x2c, 0x95, 0x92,
            0x55, 0xb1, 0x8b, 0x10, 0x1e, 0x31, 0x19, 0xbc, 0xea, 0xee, 0xf0, 0x3d,
            0xf0, 0x4c, 0xc0, 0xdf, 0x8b, 0x4e, 0x3d, 0x24, 0xcb, 0x2d, 0x3a, 0x69,
            0x0b, 0x0c, 0x76, 0x06, 0x01, 0x32, 0xb1, 0x6b, 0xf7, 0x07, 0xde, 0x26,
            0x67, 0x8b, 0xd0, 0x90, 0x0f, 0x19, 0xbb, 0x21, 0x5b, 0x84, 0xa0, 0x9a,
            0xfb, 0x1f, 0x28, 0xc5, 0xde, 0x15, 0x99, 0x8c, 0xef, 0x1b, 0x15, 0x89,
            0x6c, 0xcc, 0xbe, 0x4d, 0x6e, 0x27, 0xbc, 0x83, 0x03, 0x2e, 0x2c, 0x76,
            0xa9, 0x08, 0xc0, 0x9d, 0x32, 0x3f, 0xdb, 0xe6, 0xbf, 0x0b, 0x31, 0xb0,
            0x9d, 0xf8, 0xcf, 0x1f, 0x9a, 0xb0, 0xe7, 0x44, 0x07, 0x0e, 0xc0, 0xeb,
            0xa7, 0x4d, 0xe0, 0x6e, 0x40, 0xda, 0x90, 0x95, 0xdb, 0xfc, 0xea, 0x59,
            0xd6, 0x48, 0x18, 0xe3, 0x17, 0xbb, 0xbc, 0x5e, 0x30, 0x85, 0x3f, 0xa1,
            0x55, 0xa0, 0x39, 0xf5, 0x05, 0x13, 0x7e, 0x9b, 0xc9, 0x85, 0x17, 0xf4,
            0x6a, 0xbc, 0xf5, 0x4a, 0x19, 0x76, 0x18, 0xdf, 0x12, 0x31, 0x1a, 0x79,
            0x75, 0x68, 0x1e, 0x58, 0x58, 0xe5, 0x6e, 0x23, 0xf3, 0x52, 0xe1, 0xaf,
            0xfa, 0xb4, 0xa5, 0xd8, 0x4b, 0xf8, 0x1c, 0xbf, 0xe5, 0x86, 0xd2, 0x3f,
            0x9a, 0x5a, 0xf7, 0x28, 0xd3, 0x27, 0x05, 0x68, 0x88, 0x20, 0xd9, 0xa2,
            0x2b, 0x3f, 0x02, 0xbf, 0x9f, 0x1b, 0x0d, 0x79, 0x50, 0xb3, 0xe4, 0xfa,
            0xd8, 0x0d, 0x3e, 0x91, 0xb4, 0xd2, 0xfc, 0x62, 0x64, 0x6d, 0x28, 0x62,
            0xa1, 0x87, 0xd5, 0x97, 0xf1, 0x95, 0xf1, 0x97, 0x5a, 0x9b, 0x0f, 0xe4,
            0xcf, 0xf8, 0x6a, 0xfc, 0xef, 0x31, 0x59, 0x01, 0xab, 0x73, 0x4b, 0x7b,
            0x65, 0xa2, 0x01, 0x9b, 0x85, 0xe4, 0x7c, 0xc3, 0xec, 0x6f, 0xad, 0xfe,
            0x13, 0x27, 0xd9, 0xc8
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
        let message: String = "Oh how I love being a Barbie!"

        let signature: [UInt8] = try k.sign(
            hashing: message[...],
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

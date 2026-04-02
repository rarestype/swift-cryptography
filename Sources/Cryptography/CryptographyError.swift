@frozen public struct CryptographyError: Error {
    let stack: [UInt]
}

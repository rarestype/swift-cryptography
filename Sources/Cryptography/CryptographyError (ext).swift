#if canImport(OpenSSL)
internal import OpenSSL

extension CryptographyError {
    static func `do`<T>(_ operations: () -> T?) throws(Self) -> T {
        // make sure we are not carrying over any errors from a previous operation
        ERR_clear_error()

        if  let success: T = operations() {
            return success
        }

        var stack: [UInt] = []
        unwinding: do {
            let code: UInt = ERR_get_error()
            if  code != 0 {
                stack.append(code)
                continue unwinding
            }
        }

        throw .init(stack: stack)
    }
}
extension CryptographyError: CustomStringConvertible {
    public var description: String {
        var lines: String = ""
        for code: UInt in self.stack {
            // OpenSSL guarantees 256 bytes is large enough for all error strings
            let string: String = .init(unsafeUninitializedCapacity: 256) {
                ERR_error_string_n(code, $0.baseAddress, $0.count)
                for i: Int in $0.indices where $0[i] == 0 {
                    return $0.distance(from: $0.startIndex, to: i)
                }
                return $0.count
            }
            if !lines.isEmpty {
                lines.append("\n")
                lines += string
            } else {
                lines = string
            }
        }
        return lines
    }
}
#endif

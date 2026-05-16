public enum PQCB {
    public static let version = "0.1.0"

    public static func createSecureSession() throws -> Never {
        throw PQCBError.backendUnavailable
    }
}

public enum PQCBError: Error {
    case backendUnavailable
}

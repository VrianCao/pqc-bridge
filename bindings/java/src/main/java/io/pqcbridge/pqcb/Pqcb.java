package io.pqcbridge.pqcb;

public final class Pqcb {
    public static final String VERSION = "0.2.0";

    private Pqcb() {
    }

    public static void createSecureSession() {
        throw new IllegalStateException(
            "SecureSession backend is not configured in the v0.1 scaffold"
        );
    }
}

package it.auties.leap.socket;

public final class SocketException extends RuntimeException {
    public SocketException(String message) {
        super(message);
    }

    public SocketException(String message, Throwable cause) {
        super(message, cause);
    }

    public static SocketException closed() {
        return new SocketException("Closed");
    }
}

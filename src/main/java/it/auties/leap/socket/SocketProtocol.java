package it.auties.leap.socket;

public sealed interface SocketProtocol {
    static SocketProtocol tcp() {
        return TCP.INSTANCE;
    }

    static SocketProtocol udp() {
        return UDP.INSTANCE;
    }

    final class TCP implements SocketProtocol {
        private static final TCP INSTANCE = new TCP();

        private TCP() {

        }
    }

    final class UDP implements SocketProtocol {
        private static final UDP INSTANCE = new UDP();

        private UDP() {

        }
    }
}

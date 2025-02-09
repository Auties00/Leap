package it.auties.leap.socket.blocking.client;

import it.auties.leap.socket.SocketClient;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.blocking.BlockingSocketImplementation;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public non-sealed interface BlockingSocketClient extends SocketClient {
    void connect(InetSocketAddress address);

    void write(ByteBuffer buffer);

    void read(ByteBuffer buffer);

    void readFully(ByteBuffer buffer);

    default void write(byte[] data) {
        write(data, 0, data.length);
    }

    default void write(byte[] data, int offset, int length) {
        write(ByteBuffer.wrap(data, offset, length));
    }

    @Override
    BlockingSocketImplementation implementation();

    static BlockingSocketClientBuilder newBuilder(SocketProtocol protocol) {
        return new BlockingSocketClientBuilder(protocol);
    }
}

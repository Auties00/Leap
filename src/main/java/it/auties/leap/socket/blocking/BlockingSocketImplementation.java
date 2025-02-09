package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketImplementation;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public non-sealed interface BlockingSocketImplementation extends SocketImplementation {
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
}

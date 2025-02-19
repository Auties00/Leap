package it.auties.leap.socket.blocking;

import it.auties.leap.socket.SocketIOProvider;
import it.auties.leap.socket.blocking.applicationLayer.BlockingSocketApplicationLayer;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayer;

import java.nio.ByteBuffer;

public sealed interface BlockingSocketIO extends SocketIOProvider permits BlockingSocketApplicationLayer, BlockingSocketClient, BlockingSocketTransportLayer {
    default void write(byte[] data) {
        write(data, 0, data.length);
    }

    default void write(byte[] data, int offset, int length) {
        write(ByteBuffer.wrap(data, offset, length));
    }

    void write(ByteBuffer buffer);

    void read(ByteBuffer buffer);

    void readFully(ByteBuffer buffer);
}

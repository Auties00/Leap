package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketIO;
import it.auties.leap.socket.blocking.BlockingSocketIO;

import java.io.IOException;

public sealed interface SocketIOProvider permits AsyncSocketIO, BlockingSocketIO {
    <V> V getOption(SocketOption<V> option);
    void close() throws IOException;
}

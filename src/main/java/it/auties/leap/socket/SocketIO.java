package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketIO;
import it.auties.leap.socket.blocking.BlockingSocketIO;

public sealed interface SocketIO permits AsyncSocketIO, BlockingSocketIO {
    <V> V getOption(SocketOption<V> option);
}

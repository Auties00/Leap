package it.auties.leap.socket;

import it.auties.leap.socket.async.AsyncSocketIO;
import it.auties.leap.socket.blocking.BlockingSocketIO;

public sealed interface SocketIOProvider permits AsyncSocketIO, BlockingSocketIO {

}

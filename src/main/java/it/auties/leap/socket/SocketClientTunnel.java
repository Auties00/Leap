package it.auties.leap.socket;

import it.auties.leap.socket.async.client.AsyncSocketClientTunnel;
import it.auties.leap.socket.blocking.client.BlockingSocketClientTunnel;

public sealed interface SocketClientTunnel permits AsyncSocketClientTunnel, BlockingSocketClientTunnel {

}

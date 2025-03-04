package it.auties.leap.socket.blocking.transportLayer.implementation;

import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.blocking.transportLayer.BlockingSocketTransportLayerFactory;
import it.auties.leap.socket.implementation.win.WSAData;
import it.auties.leap.socket.implementation.win.WindowsKernel;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

// Completion Ports
public final class BlockingWinTransportSocketLayer extends BlockingNativeTransportSocketLayer<Long> {
    private static final BlockingSocketTransportLayerFactory FACTORY = BlockingWinTransportSocketLayer::new;

    public static BlockingSocketTransportLayerFactory factory() {
        return FACTORY;
    }

    static {
        System.loadLibrary("ws2_32");
        System.loadLibrary("Kernel32");

        var data = Arena.global().allocate(WSAData.layout());
        var startupResult = WindowsKernel.WSAStartup(
                makeWord(2, 2),
                data
        );
        if (startupResult != 0) {
            WindowsKernel.WSACleanup();
            throw new RuntimeException("Cannot initialize Windows Sockets: bootstrap failed");
        }

        var version = WSAData.wVersion(data);
        var lowVersion = (byte) version;
        var highVersion = version >> 8;
        if (lowVersion != 2 || highVersion != 2) {
            WindowsKernel.WSACleanup();
            throw new RuntimeException("Cannot initialize Windows Sockets: unsupported platform");
        }
    }

    public BlockingWinTransportSocketLayer(SocketProtocol protocol) {
        super(protocol);
    }

    @SuppressWarnings("SameParameterValue")
    private static short makeWord(int a, int b) {
        return (short) ((a & 0xff) | ((b & 0xff) << 8));
    }

    @Override
    protected Long createNativeHandle() {
        return -1L;
    }

    @Override
    protected void connectNative(InetSocketAddress address) {

    }

    @Override
    protected void writeNative(ByteBuffer input) {

    }

    @Override
    protected void readNative(ByteBuffer output, boolean lastRead) {

    }

    @Override
    public void close() throws IOException {

    }
}

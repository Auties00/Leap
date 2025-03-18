package it.auties.leap.socket.async.transportLayer.implementation;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayerFactory;
import it.auties.leap.socket.implementation.win.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.*;

// Completion Ports
public final class AsyncWinTransportSocketLayer extends AsyncNativeTransportSocketLayer<Long> {
    private static final AsyncSocketTransportLayerFactory FACTORY = AsyncWinTransportSocketLayer::new;

    public static AsyncSocketTransportLayerFactory factory() {
        return FACTORY;
    }

    private static final MemorySegment CONNECT_EX_FUNCTION;

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

        var socket = WindowsKernel.socket(WindowsKernel.AF_INET(), WindowsKernel.SOCK_STREAM(), 0);
        if (socket == WindowsKernel.INVALID_SOCKET()) {
            WindowsKernel.WSACleanup();
            throw new RuntimeException("Cannot create bootstrap socket");
        }

        var connectExOpCode = getConnectEx();
        var connectEx = Arena.global().allocate(ValueLayout.ADDRESS, 8);
        var connectExBytes = Arena.global().allocate(WindowsKernel.LPDWORD);
        var connectExResult = WindowsKernel.WSAIoctl(
                socket,
                WindowsKernel.SIO_GET_EXTENSION_FUNCTION_POINTER(),
                connectExOpCode,
                (int) connectExOpCode.byteSize(),
                connectEx,
                (int) connectEx.byteSize(),
                connectExBytes,
                MemorySegment.NULL,
                MemorySegment.NULL
        );
        if (connectExResult != 0) {
            var error = WindowsKernel.WSAGetLastError();
            WindowsKernel.WSACleanup();
            WindowsKernel.closesocket(socket);
            throw new RuntimeException("Cannot get ConnectEx pointer, error code " + error);
        }

        WindowsKernel.closesocket(socket);
        CONNECT_EX_FUNCTION = connectEx.get(ValueLayout.ADDRESS, 0);
    }

    @SuppressWarnings("SameParameterValue")
    private static short makeWord(int a, int b) {
        return (short) ((a & 0xff) | ((b & 0xff) << 8));
    }

    // #define WSAID_CONNECTEX {0x25a207b9,0xddf3,0x4660,{0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}}
    private static MemorySegment getConnectEx() {
        var connectExGuid = Arena.global().allocate(_GUID.layout());
        _GUID.Data1(connectExGuid, 0x25a207b9);
        _GUID.Data2(connectExGuid, (short) 0xddf3);
        _GUID.Data3(connectExGuid, (short) 0x4660);
        var data4 = Arena.global().allocate(WindowsKernel.C_CHAR, 8);
        _GUID.Data4(data4, 0, (byte) 0x8e);
        _GUID.Data4(data4, 1, (byte) 0xe9);
        _GUID.Data4(data4, 2, (byte) 0x76);
        _GUID.Data4(data4, 3, (byte) 0xe5);
        _GUID.Data4(data4, 4, (byte) 0x8c);
        _GUID.Data4(data4, 5, (byte) 0x74);
        _GUID.Data4(data4, 6, (byte) 0x06);
        _GUID.Data4(data4, 7, (byte) 0x3e);
        _GUID.Data4(connectExGuid, data4);
        return connectExGuid;
    }

    private CompletionPort completionPort;

    public AsyncWinTransportSocketLayer(SocketProtocol protocol) {
        super(protocol);
    }

    @Override
    protected Long createNativeHandle() {
        var handle = WindowsKernel.WSASocketA(
                WindowsKernel.AF_INET(),
                WindowsKernel.SOCK_STREAM(),
                WindowsKernel.IPPROTO_TCP(),
                MemorySegment.NULL,
                0,
                WindowsKernel.WSA_FLAG_OVERLAPPED()
        );
        if (handle == WindowsKernel.INVALID_SOCKET()) {
            throw new SocketException("Cannot create socket");
        }
        return handle;
    }

    @Override
    public CompletableFuture<Void> connectNative(InetSocketAddress address) {
        var localAddress = createLocalAddress();
        var bindResult = WindowsKernel.bind(handle, localAddress, (int) localAddress.byteSize());
        if (bindResult == WindowsKernel.SOCKET_ERROR()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: local bind failed"));
        }

        var remoteAddress = createRemoteAddress(address);
        if (remoteAddress.isEmpty()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName())));
        }

        initIOBuffers();

        this.completionPort = CompletionPort.shared();
        completionPort.registerHandle(handle);

        var future = completionPort.getOrAllocateFuture(handle);
        var overlapped = arena.allocate(_OVERLAPPED.layout());
        var connectResult = LPFN_CONNECTEX.invoke(
                CONNECT_EX_FUNCTION,
                handle,
                remoteAddress.get(),
                (int) remoteAddress.get().byteSize(),
                MemorySegment.NULL,
                0,
                MemorySegment.NULL,
                overlapped
        );
        if (connectResult != 1) {
            var errorCode = WindowsKernel.WSAGetLastError();
            if (errorCode != 0 && errorCode != WindowsKernel.WSA_IO_PENDING()) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: remote connection failure (error code %s)".formatted(errorCode)));
            }
        }

        return future.thenComposeAsync(_ -> {
            var updateOptions = WindowsKernel.setsockopt(
                    handle,
                    WindowsKernel.SOL_SOCKET(),
                    WindowsKernel.SO_UPDATE_CONNECT_CONTEXT(),
                    MemorySegment.NULL,
                    0
            );
            if (updateOptions != 0) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: cannot set socket options (error code %s)".formatted(updateOptions)));
            }

            connected.set(true);
            return NO_RESULT;
        });
    }

    private MemorySegment createLocalAddress() {
        var remoteAddress = arena.allocate(sockaddr_in.layout());
        sockaddr_in.sin_family(remoteAddress, (short) WindowsKernel.AF_INET());
        sockaddr_in.sin_port(remoteAddress, (short) 0);
        var inAddr = arena.allocate(in_addr.layout());
        in_addr.S_un(inAddr, arena.allocateFrom(WindowsKernel.ULONG, WindowsKernel.INADDR_ANY()));
        sockaddr_in.sin_addr(remoteAddress, inAddr);
        return remoteAddress;
    }

    private Optional<MemorySegment> createRemoteAddress(InetSocketAddress address) {
        var remoteAddress = arena.allocate(sockaddr_in.layout());
        sockaddr_in.sin_family(remoteAddress, (short) WindowsKernel.AF_INET());
        sockaddr_in.sin_port(remoteAddress, Short.reverseBytes((short) address.getPort()));
        var inAddr = arena.allocate(in_addr.layout());
        var ipv4Host = getLittleEndianIPV4Host(address);
        if (ipv4Host.isEmpty()) {
            return Optional.empty();
        }

        in_addr.S_un(inAddr, arena.allocateFrom(WindowsKernel.C_INT, ipv4Host.getAsInt()));
        sockaddr_in.sin_addr(remoteAddress, inAddr);
        return Optional.of(remoteAddress);
    }

    @Override
    protected CompletableFuture<Void> writeNative(ByteBuffer input) {
        var length = Math.min(input.remaining(), writeBufferSize);
        writeToIOBuffer(input, length);

        var message = arena.allocate(_WSABUF.layout());
        message.set(_WSABUF.len$layout(), _WSABUF.len$offset(), length);
        message.set(_WSABUF.buf$layout(), _WSABUF.buf$offset(), writeBuffer);
        var overlapped = arena.allocate(_OVERLAPPED.layout());
        var future = completionPort.getOrAllocateFuture(handle);
        var result = WindowsKernel.WSASend(
                handle,
                message,
                1,
                MemorySegment.NULL,
                0,
                overlapped,
                MemorySegment.NULL
        );
        if (result == WindowsKernel.SOCKET_ERROR()) {
            var error = WindowsKernel.WSAGetLastError();
            if (error != WindowsKernel.WSA_IO_PENDING()) {
                return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (error code %s)".formatted(error)));
            }
        }

        return future.thenCompose(writeValue -> {
            if (writeValue == 0) {
                close();
                return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket closed)"));
            }

            if (input.hasRemaining()) {
                return writeNative(input);
            }

            return NO_RESULT;
        });
    }

    @Override
    protected CompletableFuture<Void> readNative(ByteBuffer output, boolean lastRead) {
        var buffer = arena.allocate(_WSABUF.layout());
        _WSABUF.len(buffer, Math.min(output.remaining(), readBufferSize));
        _WSABUF.buf(buffer, this.readBuffer);
        var lpFlags = arena.allocate(ValueLayout.JAVA_INT);
        var overlapped = arena.allocate(_OVERLAPPED.layout());
        var future = completionPort.getOrAllocateFuture(handle);
        var result = WindowsKernel.WSARecv(
                handle,
                buffer,
                1,
                MemorySegment.NULL,
                lpFlags,
                overlapped,
                MemorySegment.NULL
        );
        if (result == WindowsKernel.SOCKET_ERROR()) {
            var error = WindowsKernel.WSAGetLastError();
            if (error != WindowsKernel.WSA_IO_PENDING()) {
                return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (error code %s)".formatted(error)));
            }
        }

        return future.thenCompose(readLength -> {
            if (readLength == 0) {
                close();
                return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socket closed)"));
            }

            readFromIOBuffer(output, readLength, lastRead);
            return NO_RESULT;
        });
    }

    @Override
    public <V> void setOption(SocketOption<V> option, V optionValue) {
        Objects.requireNonNull(optionValue, "Invalid option value");
        var value = arena.allocate(
                WindowsKernel.DWORD,
                option.accept(optionValue)
        );
        var result = WindowsKernel.setsockopt(
                handle,
                WindowsKernel.SOL_SOCKET(),
                WindowsKernel.SO_KEEPALIVE(),
                value,
                (int) value.byteSize()
        );
        if (result != 0) {
            throw new SocketException("Cannot set option %s to %s: error code %s".formatted(option.name(), optionValue, result));
        }

        super.setOption(option, optionValue);
    }

    @Override
    public void close() {
        if (!connected.get()) {
            return;
        }

        this.address = null;
        connected.set(false);
        WindowsKernel.closesocket(handle);
        if (completionPort != null) {
            completionPort.unregisterHandle(handle);
        }
    }

    private static final class CompletionPort implements Runnable {
        private static final MemorySegment INVALID_HANDLE_VALUE = MemorySegment.ofAddress(-1);
        private static final int OVERLAPPED_CHUNK_SIZE = 8192;

        private static CompletionPort instance;
        private static final Object lock = new Object();

        public static CompletionPort shared() {
            if (instance != null) {
                return instance;
            }

            synchronized (lock) {
                return Objects.requireNonNullElseGet(instance, () -> instance = new CompletionPort());
            }
        }

        private final Arena arena;
        private final Set<Long> handles;
        private final ConcurrentMap<Long, CompletableFuture<Integer>> futures;
        private MemorySegment completionPort;
        private Thread portTask;

        private CompletionPort() {
            this.arena = Arena.ofAuto();
            this.handles = ConcurrentHashMap.newKeySet();
            this.futures = new ConcurrentHashMap<>();
        }

        private void initPort() {
            if (completionPort != null) {
                return;
            }

            synchronized (this) {
                if (completionPort != null) {
                    return;
                }

                var completionPort = WindowsKernel.CreateIoCompletionPort(
                        INVALID_HANDLE_VALUE,
                        MemorySegment.NULL,
                        0,
                        0
                );
                if (completionPort == MemorySegment.NULL) {
                    throw new IllegalStateException("Cannot create socket completion port");
                }
                this.completionPort = completionPort;
                this.portTask = Thread.ofPlatform().start(this);
            }
        }

        public void registerHandle(long handle) {
            initPort();
            var completionPort = WindowsKernel.CreateIoCompletionPort(
                    MemorySegment.ofAddress(handle),
                    this.completionPort,
                    handle,
                    0
            );
            if (completionPort == MemorySegment.NULL) {
                throw new IllegalStateException("Cannot register file handle %s with completion port".formatted(handle));
            }
            handles.add(handle);
        }

        public void unregisterHandle(long handle) {
            handles.remove(handle);
            futures.remove(handle);
            if (!handles.isEmpty()) {
                return;
            }

            close();
        }

        private void close() {
            var completionPort = this.completionPort;
            this.completionPort = null;
            if (completionPort != null) {
                WindowsKernel.CloseHandle(completionPort);
            }

            if (portTask != null) {
                portTask.interrupt();
                portTask = null;
            }
        }

        public CompletableFuture<Integer> getOrAllocateFuture(long handle) {
            return futures.compute(handle, (_, value) -> Objects.requireNonNullElseGet(value, CompletableFuture::new));
        }

        @Override
        public void run() {
            var overlappedEntries = arena.allocate(OVERLAPPED_ENTRY.layout(), OVERLAPPED_CHUNK_SIZE);
            var overlappedEntriesCount = arena.allocate(ValueLayout.JAVA_INT);
            while (!Thread.interrupted()) {
                var result = WindowsKernel.GetQueuedCompletionStatusEx(
                        completionPort,
                        overlappedEntries,
                        OVERLAPPED_CHUNK_SIZE,
                        overlappedEntriesCount,
                        WindowsKernel.INFINITE(),
                        1
                );
                if (result == 0) {
                    break;
                }

                var count = overlappedEntriesCount.get(ValueLayout.JAVA_INT, 0);
                for (var i = 0; i < count; i++) {
                    var overlappedEntry = OVERLAPPED_ENTRY.asSlice(overlappedEntries, i);
                    var key = OVERLAPPED_ENTRY.lpCompletionKey(overlappedEntry);
                    var bytesTransferred = OVERLAPPED_ENTRY.dwNumberOfBytesTransferred(overlappedEntry);
                    var requestedOperation = futures.remove(key);
                    if (requestedOperation != null) {
                        requestedOperation.complete(bytesTransferred);
                    }
                }
            }
        }
    }
}

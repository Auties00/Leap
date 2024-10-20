package it.auties.leap;

import it.auties.leap.impl.linux.*;
import it.auties.leap.impl.shared.*;
import it.auties.leap.impl.win.*;

import javax.net.ssl.*;
import javax.net.ssl.SSLEngineResult.Status;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.InvalidMarkException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

@SuppressWarnings("unused")
public final class SocketClient implements AutoCloseable {
    private static final int DEFAULT_CONNECTION_TIMEOUT = 300;

    public static SocketClient ofPlain(URI proxy) throws IOException {
        var transmissionLayer = createPlatformTransmissionLayer();
        var layerSupport = new SecurityLayer.Plain(transmissionLayer);
        var proxySupport = TunnelLayer.of(transmissionLayer, layerSupport, proxy);
        return new SocketClient(transmissionLayer, proxySupport, layerSupport);
    }

    public static SocketClient ofSecure(SSLContext sslContext, SSLParameters sslParameters, URI proxy) throws IOException {
        var transmissionLayer = createPlatformTransmissionLayer();
        var layerSupport = new SecurityLayer.Secure(transmissionLayer, sslContext, sslParameters);
        var proxySupport = TunnelLayer.of(transmissionLayer, layerSupport, proxy);
        return new SocketClient(transmissionLayer, proxySupport, layerSupport);
    }

    private static TransmissionLayer<?> createPlatformTransmissionLayer() throws SocketException {
        var os = System.getProperty("os.name").toLowerCase();
        if(os.contains("win")) {
            return new TransmissionLayer.Windows();
        }else if(os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            return new TransmissionLayer.Linux();
        }else {
            throw new IllegalArgumentException("Unsupported os: " + os);
        }
    }

    final TransmissionLayer<?> transmissionLayer;
    final TunnelLayer tunnelLayer;
    SecurityLayer securityLayer;
    private SocketClient(TransmissionLayer<?> transmissionLayer, TunnelLayer tunnelLayer, SecurityLayer securityLayer) {
        this.transmissionLayer = transmissionLayer;
        this.tunnelLayer = tunnelLayer;
        this.securityLayer = securityLayer;
    }

    public CompletableFuture<Void> connectAsync(InetSocketAddress address) {
        return connectAsync(address, DEFAULT_CONNECTION_TIMEOUT);
    }

    public CompletableFuture<Void> connectAsync(InetSocketAddress address, int timeout) {
        return tunnelLayer.connectAsync(address, timeout)
                .thenComposeAsync(ignored -> securityLayer.handshake(address.getHostName(), address.getPort()))
                .exceptionallyComposeAsync(error -> {
                    try {
                        close();
                    }catch (Throwable ignored) {

                    }

                    return CompletableFuture.failedFuture(error);
                });
    }

    public CompletableFuture<Void> upgrade(SSLContext sslContext, SSLParameters sslParameters) {
        if(!isConnected()) {
            throw new IllegalArgumentException("The socket is not connected");
        }

        if(securityLayer.isSecure()) {
            throw new IllegalStateException("This socket is already using a secure connection");
        }

        this.securityLayer = new SecurityLayer.Secure(transmissionLayer, sslContext, sslParameters);
        var address = getRemoteSocketAddress();
        return securityLayer.handshake(address.getHostName(), address.getPort());
    }

    @Override
    public void close() throws IOException {
        transmissionLayer.close();
    }

    public boolean isConnected() {
        return transmissionLayer.isConnected();
    }

    public InetSocketAddress getRemoteSocketAddress() {
        return tunnelLayer.address()
                .orElse(null);
    }

    public void setKeepAlive(boolean on) {
        transmissionLayer.setKeepAlive(on);
    }

    public boolean keepAlive() {
        return transmissionLayer.keepAlive();
    }

    public int sendBufferSize() {
        return transmissionLayer.sendBufferSize();
    }

    public int receiveBufferSize() {
        return transmissionLayer.receiveBufferSize();
    }

    public CompletableFuture<Void> writeAsync(byte[] data) {
        return writeAsync(data, 0, data.length);
    }

    public CompletableFuture<Void> writeAsync(byte[] data, int offset, int length) {
        return writeAsync(ByteBuffer.wrap(data, offset, length));
    }

    public CompletableFuture<Void> writeAsync(ByteBuffer buffer) {
        return securityLayer.write(buffer);
    }

    public CompletableFuture<ByteBuffer> readFullyAsync(int length) {
        if (length < 0) {
            return CompletableFuture.failedFuture(new IllegalArgumentException("Cannot read %s bytes from socket".formatted(length)));
        }

        var buffer = ByteBuffer.allocate(length);
        return securityLayer.readFully(buffer);
    }

    public CompletableFuture<ByteBuffer> readAsync(ByteBuffer buffer) {
        return securityLayer.read(buffer, true);
    }

    private static sealed abstract class TransmissionLayer<HANDLE> implements AutoCloseable {
        private static final int IO_BUFFER_SIZE = 8192;

        final Arena arena;
        final HANDLE handle;
        final ReentrantLock ioLock;
        final AtomicBoolean connected;
        MemorySegment ioBuffer;
        boolean keepAlive;
        private TransmissionLayer(Arena arena, HANDLE handle) {
            this.arena = arena;
            this.handle = handle;
            this.ioLock = new ReentrantLock(true);
            this.connected = new AtomicBoolean(false);
        }

        abstract CompletableFuture<Void> connect(InetSocketAddress address);
        abstract CompletableFuture<Void> write(ByteBuffer data);
        abstract CompletableFuture<ByteBuffer> read(ByteBuffer buffer);
        abstract int sendBufferSize();
        abstract int receiveBufferSize();
        abstract boolean keepAlive();
        abstract void setKeepAlive(boolean keepAlive);
        @Override
        public abstract void close() throws IOException;

        CompletableFuture<ByteBuffer> read(int length) {
            var buffer = ByteBuffer.allocate(length);
            return read(buffer)
                    .thenApply(_ -> buffer);
        }

        boolean isConnected() {
            return connected.get();
        }

        Optional<MemorySegment> createRemoteAddress(InetSocketAddress address) {
            var remoteAddress = arena.allocate(sockaddr_in.layout());
            sockaddr_in.sin_family(remoteAddress, (short) WindowsSockets.AF_INET());
            sockaddr_in.sin_port(remoteAddress, Short.reverseBytes((short) address.getPort()));
            var inAddr = arena.allocate(in_addr.layout());
            var ipv4Host = getLittleEndianIPV4Host(address);
            if(ipv4Host.isEmpty()) {
                return Optional.empty();
            }

            in_addr.S_un(inAddr, arena.allocateFrom(WindowsSockets.ULONG, ipv4Host.getAsInt()));
            sockaddr_in.sin_addr(remoteAddress, inAddr);
            return Optional.of(remoteAddress);
        }

        private OptionalInt getLittleEndianIPV4Host(InetSocketAddress address) {
            var inetAddress = address.getAddress();
            if(inetAddress == null) {
                return OptionalInt.empty();
            }

            var result = ByteBuffer.wrap(inetAddress.getAddress())
                    .order(ByteOrder.LITTLE_ENDIAN)
                    .getInt();
            return OptionalInt.of(result);
        }

        void writeToIOBuffer(ByteBuffer input, int length) {
            for (int i = 0; i < length; i++) {
                ioBuffer.setAtIndex(ValueLayout.JAVA_BYTE, i, input.get());
            }
        }

        void readFromIOBuffer(ByteBuffer output, int readLength) {
            for (int i = 0; i < readLength; i++) {
                output.put(ioBuffer.getAtIndex(ValueLayout.JAVA_BYTE, i));
            }
        }

        // Completion Ports
        private static final class Windows extends TransmissionLayer<Long> {
            private static final MemorySegment CONNECT_EX_FUNCTION;
            static {
                System.loadLibrary("ws2_32");
                System.loadLibrary("Kernel32");

                var data = Arena.global().allocate(WSAData.layout());
                var startupResult = WindowsSockets.WSAStartup(
                        makeWord(2, 2),
                        data
                );
                if(startupResult != 0) {
                    WindowsSockets.WSACleanup();
                    throw new RuntimeException("Cannot initialize Windows Sockets: bootstrap failed");
                }

                var version = WSAData.wVersion(data);
                var lowVersion = (byte) version;
                var highVersion = version >> 8;
                if(lowVersion != 2 || highVersion != 2) {
                    WindowsSockets.WSACleanup();
                    throw new RuntimeException("Cannot initialize Windows Sockets: unsupported platform");
                }

                var socket = WindowsSockets.socket(WindowsSockets.AF_INET(), WindowsSockets.SOCK_STREAM(), 0);
                if(socket == WindowsSockets.INVALID_SOCKET()) {
                    WindowsSockets.WSACleanup();
                    throw new RuntimeException("Cannot create bootstrap socket");
                }

                var connectExOpCode = getConnectEx();
                var connectEx = Arena.global().allocate(ValueLayout.ADDRESS, 8);
                var connectExBytes = Arena.global().allocate(WindowsSockets.LPDWORD);
                var connectExResult = WindowsSockets.WSAIoctl(
                        socket,
                        WindowsSockets.SIO_GET_EXTENSION_FUNCTION_POINTER(),
                        connectExOpCode,
                        (int) connectExOpCode.byteSize(),
                        connectEx,
                        (int) connectEx.byteSize(),
                        connectExBytes,
                        MemorySegment.NULL,
                        MemorySegment.NULL
                );
                if(connectExResult != 0) {
                    var error = WindowsSockets.WSAGetLastError();
                    WindowsSockets.WSACleanup();
                    WindowsSockets.closesocket(socket);
                    throw new RuntimeException("Cannot get ConnectEx pointer, error code " + error);
                }

                WindowsSockets.closesocket(socket);
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
                var data4 = Arena.global().allocate(WindowsSockets.C_CHAR, 8);
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
            private Windows() throws SocketException {
                super(Arena.ofAuto(), createSocketHandle());
            }

            private static long createSocketHandle() throws SocketException {
                var handle = WindowsSockets.WSASocketA(
                        WindowsSockets.AF_INET(),
                        WindowsSockets.SOCK_STREAM(),
                        WindowsSockets.IPPROTO_TCP(),
                        MemorySegment.NULL,
                        0,
                        WindowsSockets.WSA_FLAG_OVERLAPPED()
                );
                if(handle == WindowsSockets.INVALID_SOCKET()) {
                    throw new SocketException("Cannot create socket");
                }
                return handle;
            }

            @Override
            public CompletableFuture<Void> connect(InetSocketAddress address) {
                if(connected.getAndSet(true)) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: already connected"));
                }

                var localAddress = createLocalAddress();
                var bindResult = WindowsSockets.bind(handle, localAddress, (int) localAddress.byteSize());
                if(bindResult == WindowsSockets.SOCKET_ERROR()) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: local bind failed"));
                }

                var remoteAddress = createRemoteAddress(address);
                if(remoteAddress.isEmpty()) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName())));
                }

                this.ioBuffer = arena.allocate(ValueLayout.JAVA_BYTE, IO_BUFFER_SIZE);
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
                if(connectResult != 1) {
                    var errorCode = WindowsSockets.WSAGetLastError();
                    if(errorCode != 0 && errorCode != WindowsSockets.WSA_IO_PENDING()) {
                        close();
                        return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: remote connection failure (error code %s)".formatted(errorCode)));
                    }
                }

                return future.thenComposeAsync(_ -> {
                    var updateOptions = WindowsSockets.setsockopt(
                            handle,
                            WindowsSockets.SOL_SOCKET(),
                            WindowsSockets.SO_UPDATE_CONNECT_CONTEXT(),
                            MemorySegment.NULL,
                            0
                    );
                    if(updateOptions != 0) {
                        close();
                        return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: cannot set socket options (error code %s)".formatted(updateOptions)));
                    }

                    if(keepAlive) {
                        enableKeepAlive(true);
                    }

                    return CompletableFuture.completedFuture(null);
                });
            }

            private MemorySegment createLocalAddress() {
                var remoteAddress = arena.allocate(sockaddr_in.layout());
                sockaddr_in.sin_family(remoteAddress, (short) WindowsSockets.AF_INET());
                sockaddr_in.sin_port(remoteAddress, (short) 0);
                var inAddr = arena.allocate(in_addr.layout());
                in_addr.S_un(inAddr, arena.allocateFrom(WindowsSockets.ULONG, WindowsSockets.INADDR_ANY()));
                sockaddr_in.sin_addr(remoteAddress, inAddr);
                return remoteAddress;
            }


            @Override
            public CompletableFuture<Void> write(ByteBuffer input) {
                if(!connected.get()) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket not connected)"));
                }

                if(!input.hasRemaining()) {
                    return CompletableFuture.completedFuture(null);
                }

                ioLock.lock();
                try {
                    return writeUnchecked(input);
                }finally {
                    ioLock.unlock();
                }
            }

            private CompletableFuture<Void> writeUnchecked(ByteBuffer input) {
                var length = Math.min(input.remaining(), IO_BUFFER_SIZE);
                writeToIOBuffer(input, length);

                var message = arena.allocate(_WSABUF.layout());
                message.set(_WSABUF.len$layout(), _WSABUF.len$offset(), length);
                message.set(_WSABUF.buf$layout(), _WSABUF.buf$offset(), ioBuffer);
                var overlapped = arena.allocate(_OVERLAPPED.layout());
                var future = completionPort.getOrAllocateFuture(handle);
                var result = WindowsSockets.WSASend(
                        handle,
                        message,
                        1,
                        MemorySegment.NULL,
                        0,
                        overlapped,
                        MemorySegment.NULL
                );
                if (result == WindowsSockets.SOCKET_ERROR()) {
                    var error = WindowsSockets.WSAGetLastError();
                    if(error != WindowsSockets.WSA_IO_PENDING()) {
                        return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (error code %s)".formatted(error)));
                    }
                }

                return future.thenCompose(writeValue -> {
                    if(writeValue == 0) {
                        close();
                        return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socked closed)"));
                    }

                    if (input.hasRemaining()) {
                        return writeUnchecked(input);
                    }

                    return CompletableFuture.completedFuture(null);
                });
            }

            @Override
            public CompletableFuture<ByteBuffer> read(ByteBuffer output) {
                if(!connected.get()) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot read message from socket (socket not connected)"));
                }

                if(!output.hasRemaining()) {
                    return CompletableFuture.completedFuture(output);
                }

                ioLock.lock();
                try {
                    return readUnchecked(output);
                }finally {
                    ioLock.unlock();
                }
            }

            private CompletableFuture<ByteBuffer> readUnchecked(ByteBuffer output) {
                var buffer = arena.allocate(_WSABUF.layout());
                _WSABUF.len(buffer, Math.min(output.remaining(), IO_BUFFER_SIZE));
                _WSABUF.buf(buffer, this.ioBuffer);
                var lpFlags = arena.allocate(ValueLayout.JAVA_INT);
                var overlapped = arena.allocate(_OVERLAPPED.layout());
                var future = completionPort.getOrAllocateFuture(handle);
                var result = WindowsSockets.WSARecv(
                        handle,
                        buffer,
                        1,
                        MemorySegment.NULL,
                        lpFlags,
                        overlapped,
                        MemorySegment.NULL
                );
                if (result == WindowsSockets.SOCKET_ERROR()) {
                    var error = WindowsSockets.WSAGetLastError();
                    if (error != WindowsSockets.WSA_IO_PENDING()) {
                        return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (error code %s)".formatted(error)));
                    }
                }

                return future.thenCompose(readLength -> {
                    if (readLength == 0) {
                        close();
                        return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socked closed)"));
                    }

                    readFromIOBuffer(output, readLength);
                    return CompletableFuture.completedFuture(output);
                });
            }

            @Override
            boolean keepAlive() {
                return keepAlive;
            }

            @Override
            void setKeepAlive(boolean keepAlive) {
                if(!isConnected()) {
                    this.keepAlive = keepAlive;
                    return;
                }

                enableKeepAlive(keepAlive);
            }

            private void enableKeepAlive(boolean keepAlive) {
                var value = arena.allocate(WindowsSockets.DWORD, keepAlive ? 1 : 0);
                var keepAliveResult = WindowsSockets.setsockopt(
                        handle,
                        WindowsSockets.SOL_SOCKET(),
                        WindowsSockets.SO_KEEPALIVE(),
                        value,
                        (int) value.byteSize()
                );
                if(keepAliveResult != 0) {
                    throw new IllegalStateException("Cannot enable keep alive, error code: " + keepAliveResult);
                }

                this.keepAlive = keepAlive;
            }

            @Override
            int sendBufferSize() {
                return IO_BUFFER_SIZE;
            }

            @Override
            int receiveBufferSize() {
                return IO_BUFFER_SIZE;
            }

            @Override
            public void close() {
                if(!connected.get()) {
                    return;
                }

                connected.set(false);
                var closeResult = WindowsSockets.closesocket(handle);
                if(completionPort != null) {
                    completionPort.unregisterHandle(handle);
                }
            }

            private static class CompletionPort implements Runnable {
                private static final MemorySegment INVALID_HANDLE_VALUE = MemorySegment.ofAddress(-1);
                private static final int OVERLAPPED_CHUNK_SIZE = 8192;

                private static CompletionPort instance;
                private static final Object lock = new Object();

                public static CompletionPort shared() {
                    if(instance != null) {
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
                private ExecutorService executor;
                private CompletionPort() {
                    this.arena = Arena.ofAuto();
                    this.handles = ConcurrentHashMap.newKeySet();
                    this.futures = new ConcurrentHashMap<>();
                }

                private void initPort() {
                    if(completionPort != null) {
                        return;
                    }

                    synchronized (this) {
                        if(completionPort != null) {
                            return;
                        }

                        var completionPort = WindowsSockets.CreateIoCompletionPort(
                                INVALID_HANDLE_VALUE,
                                MemorySegment.NULL,
                                0,
                                0
                        );
                        if(completionPort == MemorySegment.NULL) {
                            throw new IllegalStateException("Cannot create socket completion port");
                        }
                        this.completionPort = completionPort;
                        if (executor != null && !executor.isShutdown()) {
                            return;
                        }

                        this.executor = Executors.newSingleThreadExecutor();
                        executor.submit(this);
                    }
                }

                public void registerHandle(long handle) {
                    initPort();
                    var completionPort = WindowsSockets.CreateIoCompletionPort(
                            MemorySegment.ofAddress(handle),
                            this.completionPort,
                            handle,
                            0
                    );
                    if(completionPort == MemorySegment.NULL) {
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
                        WindowsSockets.CloseHandle(completionPort);
                    }

                    if (executor != null && !executor.isShutdown()) {
                        executor.shutdownNow();
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
                        var result = WindowsSockets.GetQueuedCompletionStatusEx(
                                completionPort,
                                overlappedEntries,
                                OVERLAPPED_CHUNK_SIZE,
                                overlappedEntriesCount,
                                WindowsSockets.INFINITE(),
                                1
                        );
                        if (result == 0) {
                            break;
                        }

                        var count = overlappedEntriesCount.get(ValueLayout.JAVA_INT, 0);
                        for(var i = 0; i < count; i++) {
                            var overlappedEntry = OVERLAPPED_ENTRY.asSlice(overlappedEntries, i);
                            var key = OVERLAPPED_ENTRY.lpCompletionKey(overlappedEntry);
                            var bytesTransferred = OVERLAPPED_ENTRY.dwNumberOfBytesTransferred(overlappedEntry);
                            var requestedOperation = futures.remove(key);
                            if(requestedOperation != null) {
                                requestedOperation.complete(bytesTransferred);
                            }
                        }
                    }
                }
            }
        }

        // Io_uring
        private static final class Linux extends TransmissionLayer<Integer> {
            private IOUring ioUring;
            private Linux() throws SocketException {
                super(Arena.ofAuto(), createSocketHandle());
            }

            private static int createSocketHandle() throws SocketException {
                var handle = LinuxSockets.socket(
                        LinuxSockets.AF_INET(),
                        LinuxSockets.SOCK_STREAM() | LinuxSockets.SOCK_NONBLOCK(),
                        0
                );
                if(handle == -1) {
                    throw new SocketException("Cannot create socket");
                }
                return handle;
            }

            @Override
            CompletableFuture<Void> connect(InetSocketAddress address) {
                if(connected.getAndSet(true)) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: already connected"));
                }

                var remoteAddress = createRemoteAddress(address);
                if(remoteAddress.isEmpty()) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName())));
                }

                this.ioBuffer = arena.allocate(ValueLayout.JAVA_BYTE, IO_BUFFER_SIZE);
                this.ioUring = IOUring.shared();
                ioUring.registerHandle(handle);

                return ioUring.prepareAsyncOperation(handle, sqe -> {
                    io_uring_sqe.opcode(sqe, (byte) LinuxSockets.IORING_OP_CONNECT());
                    io_uring_sqe.fd(sqe, handle);
                    io_uring_sqe.addr(sqe, remoteAddress.get().address());
                    io_uring_sqe.off(sqe, remoteAddress.get().byteSize());
                    io_uring_sqe.user_data(sqe, handle);
                }).thenCompose(result -> {
                    if(result != 0) {
                        return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: operation failed"));
                    }

                    return CompletableFuture.completedFuture(null);
                });
            }

            @Override
            CompletableFuture<Void> write(ByteBuffer input) {
                if(!connected.get()) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket not connected)"));
                }

                if(!input.hasRemaining()) {
                    return CompletableFuture.completedFuture(null);
                }

                ioLock.lock();
                try {
                    return writeUnchecked(input);
                }finally {
                    ioLock.unlock();
                }
            }

            private CompletableFuture<Void> writeUnchecked(ByteBuffer data) {
                return ioUring.prepareAsyncOperation(handle, sqe -> {
                    var length = Math.min(data.remaining(), IO_BUFFER_SIZE);
                    writeToIOBuffer(data, length);
                    io_uring_sqe.fd(sqe, handle);
                    io_uring_sqe.opcode(sqe, (byte) LinuxSockets.IORING_OP_WRITE());
                    io_uring_sqe.addr(sqe, ioBuffer.address());
                    io_uring_sqe.len(sqe, length);
                    io_uring_sqe.user_data(sqe, handle);
                }).thenCompose(result -> {
                    if(result < 0) {
                        return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (error code: %s)".formatted(result)));
                    }

                    if(!data.hasRemaining()) {
                        return CompletableFuture.completedFuture(null);
                    }

                    return writeUnchecked(data);
                });
            }

            @Override
            CompletableFuture<ByteBuffer> read(ByteBuffer output) {
                if(!connected.get()) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot read message from socket (socket not connected)"));
                }

                if(!output.hasRemaining()) {
                    return CompletableFuture.completedFuture(output);
                }

                ioLock.lock();
                try {
                    return readUnchecked(output);
                }finally {
                    ioLock.unlock();
                }
            }

            private CompletableFuture<ByteBuffer> readUnchecked(ByteBuffer data) {
                return ioUring.prepareAsyncOperation(handle, sqe -> {
                    var length = Math.min(data.remaining(), IO_BUFFER_SIZE);
                    io_uring_sqe.opcode(sqe, (byte) LinuxSockets.IORING_OP_READ());
                    io_uring_sqe.fd(sqe, handle);
                    io_uring_sqe.addr(sqe, ioBuffer.address());
                    io_uring_sqe.len(sqe, length);
                    io_uring_sqe.off(sqe, 0);
                    io_uring_sqe.user_data(sqe, handle);
                }).thenCompose(readLength -> {
                    if (readLength == 0) {
                        close();
                        return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socked closed)"));
                    }

                    readFromIOBuffer(data, readLength);
                    return CompletableFuture.completedFuture(data);
                });
            }

            @Override
            int sendBufferSize() {
                return DEFAULT_CONNECTION_TIMEOUT;
            }

            @Override
            int receiveBufferSize() {
                return DEFAULT_CONNECTION_TIMEOUT;
            }

            @Override
            boolean keepAlive() {
                return false;
            }

            @Override
            void setKeepAlive(boolean keepAlive) {

            }

            @Override
            public void close() {
                if(ioUring != null) {
                    ioUring.unregisterHandle(handle);
                }

                if(handle != null) {
                    LinuxSockets.shutdown(handle, LinuxSockets.SHUT_RDWR());
                    LinuxSockets.close(handle);
                }
            }

            private static class IOUring implements Runnable {
                private static final int QUEUE_SIZE = 20_000;

                private static IOUring instance;
                private static final Object lock = new Object();

                public static IOUring shared() {
                    if(instance != null) {
                        return instance;
                    }

                    synchronized (lock) {
                        return Objects.requireNonNullElseGet(instance, () -> instance = new IOUring());
                    }
                }

                private final Arena arena;
                private final ConcurrentMap<Integer, CompletableFuture<Integer>> futures;
                private final Set<Integer> handles;
                private final ReentrantLock queueLock;
                private Integer ringHandle;
                private MemorySegment ringSq;
                private MemorySegment ringSqEntries;
                private MemorySegment ringCq;
                private MemorySegment ringCqEntries;
                private MemorySegment ringParams;
                private ExecutorService executor;
                private IOUring() {
                    this.arena = Arena.ofAuto();
                    this.futures = new ConcurrentHashMap<>();
                    this.handles = new CopyOnWriteArraySet<>();
                    this.queueLock = new ReentrantLock(true);
                }
                
                private void initRing() {
                    if(ringHandle != null) {
                        return;
                    }

                    synchronized (this) {
                        if(ringHandle != null) {
                            return;
                        }

                        ringParams = arena.allocate(io_uring_params.layout());
                        this.ringHandle = setupRing();
                        if(ringHandle < 0) {
                            throw new RuntimeException("Io_uring bootstrap failed: invalid ring file descriptor");
                        }

                        var sqRingSize = io_sqring_offsets.array(io_uring_params.sq_off(ringParams)) + io_uring_params.sq_entries(ringParams) * ValueLayout.JAVA_INT.byteSize();
                        var cqRingSize = io_cqring_offsets.cqes(io_uring_params.cq_off(ringParams)) + io_uring_params.cq_entries(ringParams) * io_uring_cqe.sizeof();
                        var singleMap = (io_uring_params.features(ringParams) & LinuxSockets.IORING_FEAT_SINGLE_MMAP()) == 0;
                        if(singleMap) {
                            if(cqRingSize > sqRingSize) {
                                sqRingSize = cqRingSize;
                            }

                            cqRingSize = sqRingSize;
                        }

                        ringSq = LinuxSockets.mmap(
                                MemorySegment.NULL,
                                sqRingSize,
                                LinuxSockets.PROT_READ() | LinuxSockets.PROT_WRITE(),
                                LinuxSockets.MAP_SHARED() | LinuxSockets.MAP_POPULATE(),
                                ringHandle,
                                LinuxSockets.IORING_OFF_SQ_RING()
                        );
                        if(ringSq == LinuxSockets.MAP_FAILED()) {
                            throw new RuntimeException("Io_uring bootstrap failed: invalid ringSq mmap result");
                        }
                        if(singleMap) {
                            ringCq = ringCqEntries;
                        }else {
                            ringCq = LinuxSockets.mmap(
                                    MemorySegment.NULL,
                                    cqRingSize,
                                    LinuxSockets.PROT_READ() | LinuxSockets.PROT_WRITE(),
                                    LinuxSockets.MAP_SHARED() | LinuxSockets.MAP_POPULATE(),
                                    ringHandle,
                                    LinuxSockets.IORING_OFF_CQ_RING()
                            );
                            if(ringCq == LinuxSockets.MAP_FAILED()) {
                                throw new RuntimeException("Io_uring bootstrap failed: invalid ringCq mmap result");
                            }
                        }

                        ringSqEntries = LinuxSockets.mmap(
                                MemorySegment.NULL,
                                io_uring_params.sq_entries(ringParams) * io_uring_sqe.sizeof(),
                                LinuxSockets.PROT_READ() | LinuxSockets.PROT_WRITE(),
                                LinuxSockets.MAP_SHARED() | LinuxSockets.MAP_POPULATE(),
                                ringHandle,
                                LinuxSockets.IORING_OFF_SQES()
                        );
                        if(ringSqEntries == LinuxSockets.MAP_FAILED()) {
                            throw new RuntimeException("Io_uring bootstrap failed: invalid ringSqEntries mmap result");
                        }

                        ringCqEntries = ringCq.asSlice(
                                io_cqring_offsets.cqes(io_uring_params.cq_off(ringParams)),
                                io_uring_params.cq_entries(ringParams) * io_uring_cqe.sizeof(),
                                io_uring_cqe.layout().byteAlignment()
                        );

                        this.executor = Executors.newSingleThreadExecutor();
                        executor.submit(this);
                    }
                }

                public void registerHandle(int handle) {
                    initRing();
                    handles.add(handle);
                }

                public void unregisterHandle(int handle) {
                    handles.remove(handle);
                    futures.remove(handle);
                    if (!handles.isEmpty()) {
                        return;
                    }

                    close();
                }

                private void close() {
                    if(ringHandle == null) {
                        return;
                    }

                    try {
                        queueLock.lock();
                        int ringHandle = this.ringHandle;
                        this.ringHandle = null;
                        LinuxSockets.close(ringHandle);
                        if (executor != null && !executor.isShutdown()) {
                            executor.shutdownNow();
                        }
                    }finally {
                        queueLock.unlock();
                    }
                }

                public CompletableFuture<Integer> prepareAsyncOperation(int handle, Consumer<MemorySegment> configurator) {
                    try {
                        queueLock.lock();
                        var sqOffset = io_uring_params.sq_off(ringParams);
                        var head = atomicRead(ringSq, io_sqring_offsets.head(sqOffset));
                        var tail = atomicRead(ringSq, io_sqring_offsets.tail(sqOffset));
                        var size = atomicRead(ringSq, io_sqring_offsets.ring_entries(sqOffset));
                        if(tail + 1 > size) {
                            // TODO: How to handle this?
                            throw new RuntimeException("Queue is full");
                        }

                        var mask = atomicRead(ringSq, io_sqring_offsets.ring_mask(sqOffset));
                        var index = tail & mask;
                        var entry = io_uring_sqe.asSlice(ringSqEntries, index);
                        configurator.accept(entry);
                        atomicWrite(
                                ringSq,
                                io_sqring_offsets.array(io_uring_params.sq_off(ringParams)) + (index * ValueLayout.JAVA_INT.byteSize()),
                                index
                        );

                        atomicWrite(
                                ringSq,
                                io_sqring_offsets.tail(sqOffset),
                                tail + 1
                        );
                        var future = new CompletableFuture<Integer>();
                        futures.put(handle, future);
                        enterRing(1, 0, 0);
                        return future;
                    }finally {
                        queueLock.unlock();
                    }
                }

                @Override
                public void run() {
                    while (!Thread.interrupted()) {
                        var result = enterRing(0, 1, LinuxSockets.IORING_ENTER_GETEVENTS());
                        if(!result) {
                            break;
                        }

                        var cqOffset = io_uring_params.cq_off(ringParams);
                        var head = atomicRead(ringCq, io_cqring_offsets.head(cqOffset));
                        var tail = atomicRead(ringCq, io_cqring_offsets.tail(cqOffset));
                        var mask = atomicRead(ringCq, io_cqring_offsets.ring_mask(cqOffset));
                        while (head != tail) {
                            var index = head & mask;
                            var cqe = io_uring_cqe.asSlice(ringCqEntries, index);
                            var identifier = (int) io_uring_cqe.user_data(cqe);
                            var future = futures.remove(identifier);
                            if(future != null) {
                                future.complete(io_uring_cqe.res(cqe));
                            }

                            head++;
                        }
                        atomicWrite(
                                ringCq,
                                io_cqring_offsets.head(cqOffset),
                                head
                        );
                    }
                }

                private int atomicRead(MemorySegment segment, int offset) {
                    return (int) ValueLayout.JAVA_INT.varHandle()
                            .getVolatile(segment, offset);
                }

                private void atomicWrite(MemorySegment segment, long offset, int value) {
                    ValueLayout.JAVA_INT.varHandle()
                            .setVolatile(segment, offset, value);
                }

                private int setupRing() {
                    return (int) LinuxSockets.syscall
                            .makeInvoker(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS.withTargetLayout(io_uring_params.layout())
                            )
                            .apply(
                                    LinuxSockets.__NR_io_uring_setup(),
                                    QUEUE_SIZE,
                                    ringParams
                            );
                }

                private boolean enterRing(int in, int out, int flags) {
                    try {
                        var result = LinuxSockets.syscall
                                .makeInvoker(
                                        ValueLayout.JAVA_INT,
                                        ValueLayout.JAVA_INT,
                                        ValueLayout.JAVA_INT,
                                        ValueLayout.JAVA_INT,
                                        ValueLayout.ADDRESS,
                                        ValueLayout.JAVA_INT
                                )
                                .apply(
                                        LinuxSockets.__NR_io_uring_enter(),
                                        ringHandle,
                                        in,
                                        out,
                                        flags,
                                        MemorySegment.NULL,
                                        0
                                );
                        return result == 0;
                    }catch (Throwable throwable) {
                        return false;
                    }
                }
            }
        }
    }

    static sealed abstract class SecurityLayer {
        final TransmissionLayer<?> channel;
        private SecurityLayer(TransmissionLayer<?> channel) {
            this.channel = channel;
        }

        abstract CompletableFuture<Void> handshake(String hostname, int port);

        abstract boolean isSecure();

        abstract CompletableFuture<Void> write(ByteBuffer buffer);

        abstract CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead);

        CompletableFuture<ByteBuffer> readPlain(ByteBuffer buffer, boolean lastRead) {
            return channel.read(buffer).thenApply(result -> {
                if(lastRead) {
                    buffer.flip();
                }

                return buffer;
            });
        }

        CompletableFuture<Void> writePlain(ByteBuffer buffer) {
            return channel.write(buffer);
        }

        CompletableFuture<ByteBuffer> read() {
            return read(ByteBuffer.allocate(channel.receiveBufferSize()), true);
        }

        CompletableFuture<ByteBuffer> readFully(int length) {
            return readFully(ByteBuffer.allocate(length));
        }

        CompletableFuture<ByteBuffer> readFully(ByteBuffer buffer) {
            return read(buffer, false).thenCompose(_ -> {
                if(buffer.hasRemaining()) {
                    return readFully(buffer);
                }

                buffer.flip();
                return CompletableFuture.completedFuture(buffer);
            });
        }

        private static final class Plain extends SecurityLayer {
            private Plain(TransmissionLayer<?> channel) {
                super(channel);
            }

            @Override
            boolean isSecure() {
                return false;
            }

            @Override
            CompletableFuture<Void> write(ByteBuffer buffer) {
                return writePlain(buffer);
            }

            @Override
            CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead) {
                return readPlain(buffer, lastRead);
            }

            @Override
            CompletableFuture<Void> handshake(String hostname, int port) {
                return CompletableFuture.completedFuture(null);
            }
        }

        private static final class Secure extends SecurityLayer {
            private final AtomicBoolean sslHandshakeCompleted;
            private final Object sslHandshakeLock;
            private final SSLContext sslContext;
            private final SSLParameters sslParameters;
            private SSLEngine sslEngine;
            private ByteBuffer sslReadBuffer, sslWriteBuffer, sslOutputBuffer;
            private CompletableFuture<Void> sslHandshake;
            private Secure(TransmissionLayer<?> channel, SSLContext sslContext, SSLParameters sslParameters) {
                super(channel);
                this.sslHandshakeCompleted = new AtomicBoolean();
                this.sslHandshakeLock = new Object();
                this.sslContext = sslContext;
                this.sslParameters = sslParameters;
            }

            @Override
            boolean isSecure() {
                return true;
            }

            @Override
            CompletableFuture<Void> handshake(String hostname, int port) {
                try {
                    if(sslHandshakeCompleted.get()) {
                        return CompletableFuture.completedFuture(null);
                    }

                    if(sslHandshake != null) {
                        return sslHandshake;
                    }

                    synchronized (sslHandshakeLock) {
                        if(sslHandshake != null) {
                            return sslHandshake;
                        }

                        this.sslEngine = sslContext.createSSLEngine(hostname, port == -1 ? 443 : port);
                        sslEngine.setUseClientMode(true);
                        sslEngine.setSSLParameters(sslParameters);
                        var bufferSize = sslEngine.getSession().getPacketBufferSize();
                        this.sslReadBuffer = ByteBuffer.allocate(bufferSize);
                        this.sslWriteBuffer = ByteBuffer.allocate(bufferSize);
                        this.sslOutputBuffer = ByteBuffer.allocate(bufferSize);
                        sslEngine.beginHandshake();
                        sslReadBuffer.position(sslReadBuffer.limit());
                        return this.sslHandshake = handleSslHandshakeStatus(null);
                    }
                } catch (Throwable throwable) {
                    return CompletableFuture.failedFuture(throwable);
                }
            }

            private CompletableFuture<Void> handleSslHandshakeStatus(Status status){
                return switch (sslEngine.getHandshakeStatus()) {
                    case NEED_WRAP -> doSslHandshakeWrap();
                    case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> doSslHandshakeUnwrap(status == Status.BUFFER_UNDERFLOW);
                    case NEED_TASK -> doSslHandshakeTasks();
                    case FINISHED -> finishSslHandshake();
                    case NOT_HANDSHAKING -> CompletableFuture.failedFuture(new IOException("Cannot complete handshake"));
                };
            }

            private CompletableFuture<Void> finishSslHandshake() {
                sslHandshakeCompleted.set(true);
                sslOutputBuffer.clear();
                return CompletableFuture.completedFuture(null);
            }

            private CompletableFuture<Void> doSslHandshakeTasks() {
                Runnable runnable;
                while ((runnable = sslEngine.getDelegatedTask()) != null) {
                    runnable.run();
                }

                return handleSslHandshakeStatus(null);
            }

            private CompletableFuture<Void> doSslHandshakeUnwrap(boolean forceRead) {
                sslReadBuffer.compact();
                if (!forceRead && sslReadBuffer.position() != 0) {
                    sslReadBuffer.flip();
                    return doSSlHandshakeUnwrapOperation();
                }

                return readPlain(sslReadBuffer, true)
                        .thenComposeAsync(_ -> doSSlHandshakeUnwrapOperation());
            }

            private CompletableFuture<Void> doSSlHandshakeUnwrapOperation() {
                try {
                    var result = sslEngine.unwrap(sslReadBuffer, sslOutputBuffer);
                    if(isHandshakeFinished(result, false)) {
                        return finishSslHandshake();
                    }else {
                        return handleSslHandshakeStatus(result.getStatus());
                    }
                }catch(Throwable throwable) {
                    return CompletableFuture.failedFuture(throwable);
                }
            }

            private CompletableFuture<Void> doSslHandshakeWrap() {
                try {
                    sslWriteBuffer.clear();
                    var result = sslEngine.wrap(sslOutputBuffer, sslWriteBuffer);
                    var isHandshakeFinished = isHandshakeFinished(result, true);
                    sslWriteBuffer.flip();
                    return writePlain(sslWriteBuffer).thenComposeAsync(_ -> {
                        if(isHandshakeFinished) {
                            return finishSslHandshake();
                        }else {
                            return handleSslHandshakeStatus(null);
                        }
                    });
                }catch (Throwable throwable) {
                    return CompletableFuture.failedFuture(throwable);
                }
            }

            private boolean isHandshakeFinished(SSLEngineResult result, boolean wrap) {
                var sslEngineStatus = result.getStatus();
                if (sslEngineStatus != Status.OK && (wrap || sslEngineStatus != Status.BUFFER_UNDERFLOW)) {
                    throw new IllegalStateException("SSL handshake operation failed with status: " + sslEngineStatus);
                }

                if (wrap && result.bytesConsumed() != 0) {
                    throw new IllegalStateException("SSL handshake operation failed with status: no bytes consumed");
                }

                if (!wrap && result.bytesProduced() != 0) {
                    throw new IllegalStateException("SSL handshake operation failed with status: no bytes produced");
                }

                var sslHandshakeStatus = result.getHandshakeStatus();
                return sslHandshakeStatus == SSLEngineResult.HandshakeStatus.FINISHED;
            }

            @Override
            CompletableFuture<ByteBuffer> read(ByteBuffer buffer, boolean lastRead) {
                try {
                    if(!sslHandshakeCompleted.get()) {
                        return readPlain(buffer, lastRead);
                    }

                    var bytesCopied = readFromBufferedOutput(buffer, lastRead);
                    if(bytesCopied != 0) {
                        return CompletableFuture.completedFuture(buffer);
                    }else if (sslReadBuffer.hasRemaining()) {
                        return decodeSslBuffer(buffer, lastRead);
                    }else {
                        return fillSslBuffer(buffer, lastRead);
                    }
                }catch (Throwable throwable) {
                    return CompletableFuture.failedFuture(throwable);
                }
            }

            private CompletableFuture<ByteBuffer> fillSslBuffer(ByteBuffer buffer, boolean lastRead) {
                sslReadBuffer.compact();
                return readPlain(sslReadBuffer, true)
                        .thenComposeAsync(_ -> decodeSslBuffer(buffer, lastRead));
            }

            private CompletableFuture<ByteBuffer> decodeSslBuffer(ByteBuffer buffer, boolean lastRead) {
                try {
                    var unwrapResult = sslEngine.unwrap(sslReadBuffer, sslOutputBuffer);
                    return switch (unwrapResult.getStatus()) {
                        case OK -> {
                            if (unwrapResult.bytesProduced() == 0) {
                                sslOutputBuffer.mark();
                                yield read(buffer, lastRead);
                            } else {
                                var bytesCopied = readFromBufferedOutput(buffer, lastRead);
                                yield CompletableFuture.completedFuture(buffer);
                            }
                        }
                        case BUFFER_UNDERFLOW -> fillSslBuffer(buffer, lastRead);
                        case BUFFER_OVERFLOW -> CompletableFuture.failedFuture(new IllegalStateException("SSL output buffer overflow"));
                        case CLOSED -> CompletableFuture.failedFuture(new EOFException());
                    };
                }catch (Throwable throwable) {
                    return CompletableFuture.failedFuture(throwable);
                }
            }

            private int readFromBufferedOutput(ByteBuffer buffer, boolean lastRead) {
                var writePosition = sslOutputBuffer.position();
                if(writePosition == 0) {
                    return 0;
                }

                var bytesRead = 0;
                var writeLimit = sslOutputBuffer.limit();
                sslOutputBuffer.limit(writePosition);
                try {
                    sslOutputBuffer.reset(); // Go back to last read position
                }catch (InvalidMarkException exception) {
                    sslOutputBuffer.flip(); // This can happen if unwrapResult.bytesProduced() != 0 on the first call
                }
                while (buffer.hasRemaining() && sslOutputBuffer.hasRemaining()) {
                    buffer.put(sslOutputBuffer.get());
                    bytesRead++;
                }

                if(!sslOutputBuffer.hasRemaining()) {
                    sslOutputBuffer.clear();
                    sslOutputBuffer.mark();
                }else {
                    sslOutputBuffer.limit(writeLimit);
                    sslOutputBuffer.mark();
                    sslOutputBuffer.position(writePosition);
                }

                if(lastRead) {
                    buffer.flip();
                }

                return bytesRead;
            }

            @Override
            CompletableFuture<Void> write(ByteBuffer buffer) {
                if(!sslHandshakeCompleted.get()) {
                    return writePlain(buffer);
                }

                return writeSecure(buffer);
            }

            private CompletableFuture<Void> writeSecure(ByteBuffer buffer) {
                if(!buffer.hasRemaining()) {
                    return CompletableFuture.completedFuture(null);
                }

                try {
                    sslWriteBuffer.clear();
                    var wrapResult = sslEngine.wrap(buffer, sslWriteBuffer);
                    var status = wrapResult.getStatus();
                    if (status != Status.OK && status != Status.BUFFER_OVERFLOW) {
                        throw new IllegalStateException("SSL wrap failed with status: " + status);
                    }

                    sslWriteBuffer.flip();
                    return writePlain(sslWriteBuffer)
                            .thenComposeAsync(_ -> writeSecure(buffer));
                }catch (SSLException exception) {
                    return CompletableFuture.failedFuture(exception);
                }
            }
        }
    }

    private sealed static abstract class TunnelLayer {
        final TransmissionLayer<?> channel;
        final SecurityLayer securityLayer;
        final URI proxy;
        InetSocketAddress address;
        private TunnelLayer(TransmissionLayer<?> channel, SecurityLayer securityLayer, URI proxy) {
            this.channel = channel;
            this.securityLayer = securityLayer;
            this.proxy = proxy;
        }

        private static TunnelLayer of(TransmissionLayer<?> channel, SecurityLayer securityLayer, URI proxy) {
            return switch (toProxy(proxy).type()) {
                case DIRECT -> new Direct(channel);
                case HTTP -> new HttpProxy(channel, securityLayer, proxy);
                case SOCKS -> new SocksProxy(channel, securityLayer, proxy);
            };
        }

        private static Proxy toProxy(URI uri) {
            if (uri == null) {
                return Proxy.NO_PROXY;
            }

            var scheme = Objects.requireNonNull(uri.getScheme(), "Invalid proxy, expected a scheme: %s".formatted(uri));
            var host = Objects.requireNonNull(uri.getHost(), "Invalid proxy, expected a host: %s".formatted(uri));
            var port = getDefaultPort(scheme, uri.getPort()).orElseThrow(() -> new NullPointerException("Invalid proxy, expected a port: %s".formatted(uri)));
            return switch (scheme.toLowerCase()) {
                case "http", "https" -> new Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(host, port));
                case "socks5", "socks5h" -> new Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(host, port));
                default -> throw new IllegalStateException("Unexpected scheme: " + scheme);
            };
        }

        private static OptionalInt getDefaultPort(String scheme, int port) {
            return port != -1 ? OptionalInt.of(port) : switch (scheme.toLowerCase()) {
                case "http" -> OptionalInt.of(80);
                case "https" -> OptionalInt.of(443);
                default -> OptionalInt.empty();
            };
        }

        CompletableFuture<Void> connectAsync(InetSocketAddress address, int timeout) {
            return channel.connect(address)
                    .orTimeout(timeout > 0 ? timeout : DEFAULT_CONNECTION_TIMEOUT, TimeUnit.SECONDS)
                    .exceptionallyComposeAsync(error -> {
                        try {
                            channel.close();
                        }catch (IOException _) {

                        }
                        return CompletableFuture.failedFuture(error);
                    });
        }

        public Optional<InetSocketAddress> address() {
            return Optional.ofNullable(address);
        }

        private static final class Direct extends TunnelLayer {
            private Direct(TransmissionLayer<?> channel) {
                super(channel, null, null);
            }

            @Override
            public CompletableFuture<Void> connectAsync(InetSocketAddress address, int timeout) {
                return super.connectAsync(address, timeout);
            }
        }

        private static final class HttpProxy extends TunnelLayer {
            private static final int DEFAULT_RCV_BUF = 8192;
            private static final int OK_STATUS_CODE = 200;

            private HttpProxy(TransmissionLayer<?> channel, SecurityLayer securityLayer, URI proxy) {
                super(channel, securityLayer, proxy);
            }

            @Override
            public CompletableFuture<Void> connectAsync(InetSocketAddress address, int timeout) {
                return super.connectAsync(new InetSocketAddress(proxy.getHost(), proxy.getPort()), timeout)
                        .thenComposeAsync(openResult -> sendAuthentication(address))
                        .thenComposeAsync(connectionResult -> readAuthenticationResponse())
                        .thenComposeAsync(this::handleAuthentication);
            }

            private CompletableFuture<Void> handleAuthentication(String response) {
                var responseParts = response.split(" ");
                if(responseParts.length < 2) {
                    return CompletableFuture.failedFuture(new SocketException("HTTP : Cannot connect to proxy, malformed response: " + response));
                }

                var statusCodePart = responseParts[1];
                try {
                    var statusCode = statusCodePart == null ? -1 : Integer.parseUnsignedInt(statusCodePart);
                    if(statusCode != OK_STATUS_CODE) {
                        return CompletableFuture.failedFuture(new SocketException("HTTP : Cannot connect to proxy, status code " + statusCode));
                    }

                    return CompletableFuture.completedFuture(null);
                }catch (Throwable throwable) {
                    return CompletableFuture.failedFuture(new SocketException("HTTP : Cannot connect to proxy: " + response));
                }
            }

            private CompletableFuture<String> readAuthenticationResponse() {
                var decoder = new HttpDecoder(securityLayer);
                var future = new CompletableFuture<String>();
                var buffer = ByteBuffer.allocate(DEFAULT_RCV_BUF);
                return securityLayer.read(buffer, true)
                        .thenApplyAsync(result -> StandardCharsets.UTF_8.decode(result).toString())
                        .exceptionallyComposeAsync(error -> CompletableFuture.failedFuture(new SocketException("HTTP : Cannot read authentication response", error)));
            }

            private CompletableFuture<Void> sendAuthentication(InetSocketAddress endpoint) {
                var builder = new StringBuilder();
                builder.append("CONNECT ")
                        .append(endpoint.getHostName())
                        .append(":")
                        .append(endpoint.getPort())
                        .append(" HTTP/1.1\r\n");
                builder.append("host: ")
                        .append(endpoint.getHostName())
                        .append("\r\n");
                var authInfo = proxy.getUserInfo();
                if (authInfo != null) {
                    builder.append("proxy-authorization: Basic ")
                            .append(Base64.getEncoder().encodeToString(authInfo.getBytes()))
                            .append("\r\n");
                }
                builder.append("\r\n");
                return securityLayer.write(ByteBuffer.wrap(builder.toString().getBytes()));
            }
        }

        private static final class SocksProxy extends TunnelLayer {
            private static final byte VERSION_5 = 5;

            private static final int NO_AUTH = 0;
            private static final int USER_PASSW = 2;
            private static final int NO_METHODS = -1;

            private static final int CONNECT = 1;

            private static final int IPV4 = 1;
            private static final int DOMAIN_NAME = 3;
            private static final int IPV6 = 4;

            private static final int REQUEST_OK = 0;
            private static final int GENERAL_FAILURE = 1;
            private static final int NOT_ALLOWED = 2;
            private static final int NET_UNREACHABLE = 3;
            private static final int HOST_UNREACHABLE = 4;
            private static final int CONN_REFUSED = 5;
            private static final int TTL_EXPIRED = 6;
            private static final int CMD_NOT_SUPPORTED = 7;
            private static final int ADDR_TYPE_NOT_SUP = 8;

            private SocksProxy(TransmissionLayer<?> channel, SecurityLayer securityLayer, URI proxy) {
                super(channel, securityLayer, proxy);
            }


            @Override
            public CompletableFuture<Void> connectAsync(InetSocketAddress address, int timeout) {
                return super.connectAsync(new InetSocketAddress(proxy.getHost(), proxy.getPort()), timeout)
                        .thenComposeAsync(openResult -> sendAuthenticationRequest())
                        .thenComposeAsync(response -> sendAuthenticationData(address, response));
            }

            private CompletableFuture<ByteBuffer> sendAuthenticationRequest() {
                var connectionPayload = new ByteArrayOutputStream();
                connectionPayload.write(VERSION_5);
                connectionPayload.write(2);
                connectionPayload.write(NO_AUTH);
                connectionPayload.write(USER_PASSW);
                return securityLayer.write(ByteBuffer.wrap(connectionPayload.toByteArray()))
                        .thenComposeAsync(connectionResult -> readServerResponse(2, "Cannot read authentication request response"));
            }

            private CompletionStage<Void> sendAuthenticationData(InetSocketAddress address, ByteBuffer response) {
                var socksVersion = response.get();
                if (socksVersion != VERSION_5) {
                    return CompletableFuture.failedFuture(new SocketException("SOCKS : Invalid version"));
                }

                var method = response.get();
                if (method == NO_METHODS) {
                    return CompletableFuture.failedFuture(new SocketException("SOCKS : No acceptable methods"));
                }

                if (method == NO_AUTH) {
                    return sendConnectionData(address, null);
                }

                if (method != USER_PASSW) {
                    return CompletableFuture.failedFuture(new SocketException("SOCKS : authentication failed"));
                }

                var userInfo = parseUserInfo(proxy.getUserInfo());
                if (userInfo.isEmpty()) {
                    return CompletableFuture.failedFuture(new SocketException("SOCKS : invalid authentication data"));
                }

                var outputStream = new ByteArrayOutputStream();
                outputStream.write(1);
                outputStream.write(userInfo.get().username().length());
                outputStream.writeBytes(userInfo.get().username().getBytes(StandardCharsets.ISO_8859_1));
                if (userInfo.get().password() != null) {
                    outputStream.write(userInfo.get().password().length());
                    outputStream.writeBytes(userInfo.get().password().getBytes(StandardCharsets.ISO_8859_1));
                } else {
                    outputStream.write(0);
                }
                return securityLayer.write(ByteBuffer.wrap(outputStream.toByteArray()))
                        .thenComposeAsync(connectionResult -> readServerResponse(2, "Cannot read authentication data response"))
                        .thenComposeAsync(connectionResponse -> sendConnectionData(address, connectionResponse));
            }

            private CompletableFuture<Void> sendConnectionData(InetSocketAddress address, ByteBuffer connectionResponse) {
                if(connectionResponse != null && connectionResponse.get(1) != 0) {
                    return CompletableFuture.failedFuture(new SocketException("SOCKS : authentication failed"));
                }

                var outputStream = new ByteArrayOutputStream();
                outputStream.write(VERSION_5);
                outputStream.write(CONNECT);
                outputStream.write(0);
                outputStream.write(DOMAIN_NAME);
                outputStream.write(address.getHostName().length());
                outputStream.writeBytes(address.getHostName().getBytes(StandardCharsets.ISO_8859_1));
                outputStream.write((address.getPort() >> 8) & 0xff);
                outputStream.write((address.getPort()) & 0xff);
                return securityLayer.write(ByteBuffer.wrap(outputStream.toByteArray()))
                        .thenComposeAsync(authenticationResult -> readServerResponse(4, "Cannot read connection data response"))
                        .thenComposeAsync(this::onConnected);
            }

            private static Optional<UserInfo> parseUserInfo(String userInfo) {
                if(userInfo == null || userInfo.isEmpty()) {
                    return Optional.empty();
                }

                var data = userInfo.split(":", 2);
                if(data.length > 2) {
                    return Optional.empty();
                }

                return Optional.of(new UserInfo(data[0], data.length == 2 ? data[1] : null));
            }

            private record UserInfo(String username, String password) {

            }

            private CompletableFuture<Void> onConnected(ByteBuffer authenticationResponse) {
                if(authenticationResponse.limit() < 2) {
                    return CompletableFuture.failedFuture(new SocketException("SOCKS malformed response"));
                }

                return switch (authenticationResponse.get(1)) {
                    case REQUEST_OK -> onConnected(authenticationResponse.get(3));
                    case GENERAL_FAILURE -> CompletableFuture.failedFuture(new SocketException("SOCKS server general failure"));
                    case NOT_ALLOWED -> CompletableFuture.failedFuture(new SocketException("SOCKS: Connection not allowed by ruleset"));
                    case NET_UNREACHABLE -> CompletableFuture.failedFuture(new SocketException("SOCKS: Network unreachable"));
                    case HOST_UNREACHABLE -> CompletableFuture.failedFuture(new SocketException("SOCKS: Host unreachable"));
                    case CONN_REFUSED -> CompletableFuture.failedFuture(new SocketException("SOCKS: Connection refused"));
                    case TTL_EXPIRED -> CompletableFuture.failedFuture(new SocketException("SOCKS: TTL expired"));
                    case CMD_NOT_SUPPORTED -> CompletableFuture.failedFuture(new SocketException("SOCKS: Command not supported"));
                    case ADDR_TYPE_NOT_SUP -> CompletableFuture.failedFuture(new SocketException("SOCKS: address type not supported"));
                    default -> CompletableFuture.failedFuture(new SocketException("SOCKS: unhandled error"));
                };
            }

            private CompletableFuture<Void> onConnected(byte authenticationType) {
                return switch (authenticationType) {
                    case IPV4 -> readServerResponse(4, "Cannot read IPV4 address")
                            .thenComposeAsync(ipResult -> readServerResponse(2, "Cannot read IPV4 port"))
                            .thenRun(() -> {});
                    case IPV6 -> readServerResponse(16, "Cannot read IPV6 address")
                            .thenComposeAsync(ipResult -> readServerResponse(2, "Cannot read IPV6 port"))
                            .thenRun(() -> {});
                    case DOMAIN_NAME -> readServerResponse(1, "Cannot read domain name")
                            .thenComposeAsync(domainLengthBuffer -> readServerResponse(Byte.toUnsignedInt(domainLengthBuffer.get()), "Cannot read domain hostname"))
                            .thenComposeAsync(ipResult -> readServerResponse(2, "Cannot read domain port"))
                            .thenRun(() -> {});
                    default -> CompletableFuture.failedFuture(new SocketException("Reply from SOCKS server contains wrong code"));
                };
            }

            private CompletableFuture<ByteBuffer> readServerResponse(int length, String errorMessage) {
                var buffer = ByteBuffer.allocate(length);
                return securityLayer.readFully(buffer)
                        .exceptionallyCompose(error -> CompletableFuture.failedFuture(new SocketException(errorMessage, error)));
            }
        }
    }
}

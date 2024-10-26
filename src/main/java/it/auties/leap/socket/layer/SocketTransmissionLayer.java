package it.auties.leap.socket.layer;

import it.auties.leap.socket.SocketOption;
import it.auties.leap.socket.platform.in_addr;
import it.auties.leap.socket.platform.linux.*;
import it.auties.leap.socket.platform.sockaddr_in;
import it.auties.leap.socket.platform.unix.UnixSockets;
import it.auties.leap.socket.platform.unix.__Block_byref_ND;
import it.auties.leap.socket.platform.unix.dispatch_block_t;
import it.auties.leap.socket.platform.unix.dispatch_object_t;
import it.auties.leap.socket.platform.win.*;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

public sealed abstract class SocketTransmissionLayer<HANDLE> implements AutoCloseable {
    final Arena arena;
    final HANDLE handle;
    final ReentrantLock ioLock;
    final AtomicBoolean connected;
    InetSocketAddress address;
    MemorySegment readBuffer;
    int readBufferSize;
    MemorySegment writeBuffer;
    int writeBufferSize;
    boolean keepAlive;

    private SocketTransmissionLayer() throws SocketException {
        this.arena = Arena.ofAuto();
        this.handle = createHandle();
        this.ioLock = new ReentrantLock(true);
        this.connected = new AtomicBoolean(false);
        this.readBufferSize = SocketOption.readBufferSize().defaultValue();
        this.writeBufferSize = SocketOption.writeBufferSize().defaultValue();
        this.keepAlive = SocketOption.keepAlive().defaultValue();
    }

    public static SocketTransmissionLayer<?> ofPlatform() throws SocketException {
        var os = System.getProperty("os.name").toLowerCase();
        if(os.contains("win")) {
            return new Windows();
        }else if(os.contains("nix") || os.contains("nux") || os.contains("aix")) {
            return new Linux();
        }else if(os.contains("mac")) {
            return new Unix();
        }else {
            throw new IllegalArgumentException("Unsupported os: " + os);
        }
    }

    abstract HANDLE createHandle() throws SocketException;

    abstract CompletableFuture<Void> connect(InetSocketAddress address);

    CompletableFuture<Void> write(ByteBuffer input) {
        if (!connected.get()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket not connected)"));
        }

        if (!input.hasRemaining()) {
            return CompletableFuture.completedFuture(null);
        }

        ioLock.lock();
        try {
            return writeUnchecked(input);
        } finally {
            ioLock.unlock();
        }
    }

    protected abstract CompletableFuture<Void> writeUnchecked(ByteBuffer input);

    CompletableFuture<ByteBuffer> read(ByteBuffer output) {
        if (!connected.get()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot read message from socket (socket not connected)"));
        }

        if (!output.hasRemaining()) {
            return CompletableFuture.completedFuture(output);
        }

        ioLock.lock();
        try {
            return readUnchecked(output);
        } finally {
            ioLock.unlock();
        }
    }

    protected abstract CompletableFuture<ByteBuffer> readUnchecked(ByteBuffer output);

    public <V> void setOption(SocketOption<V> option, V value) throws SocketException {
        switch (option) {
            case SocketOption.KeepAlive _ -> this.keepAlive = (boolean) value;
            case SocketOption.ReadBufferSize _ -> this.readBufferSize = (int) value;
            case SocketOption.WriteBufferSize _ -> this.writeBufferSize = (int) value;
        }
    }

    public <V> V getOption(SocketOption<V> option) {
        return (V) switch (option) {
            case SocketOption.KeepAlive _ -> keepAlive;
            case SocketOption.ReadBufferSize _ -> readBufferSize;
            case SocketOption.WriteBufferSize _ -> writeBufferSize;
        };
    }

    @Override
    public abstract void close() throws IOException;

    public boolean isConnected() {
        return connected.get();
    }

    Optional<MemorySegment> createRemoteAddress(InetSocketAddress address) {
        var remoteAddress = arena.allocate(sockaddr_in.layout());
        sockaddr_in.sin_family(remoteAddress, (short) WindowsSockets.AF_INET());
        sockaddr_in.sin_port(remoteAddress, Short.reverseBytes((short) address.getPort()));
        var inAddr = arena.allocate(in_addr.layout());
        var ipv4Host = getLittleEndianIPV4Host(address);
        if (ipv4Host.isEmpty()) {
            return Optional.empty();
        }

        in_addr.S_un(inAddr, arena.allocateFrom(WindowsSockets.ULONG, ipv4Host.getAsInt()));
        sockaddr_in.sin_addr(remoteAddress, inAddr);
        return Optional.of(remoteAddress);
    }

    private OptionalInt getLittleEndianIPV4Host(InetSocketAddress address) {
        var inetAddress = address.getAddress();
        if (inetAddress == null) {
            return OptionalInt.empty();
        }

        var result = ByteBuffer.wrap(inetAddress.getAddress())
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt();
        return OptionalInt.of(result);
    }

    void writeToIOBuffer(ByteBuffer input, int length) {
        for (int i = 0; i < length; i++) {
            writeBuffer.setAtIndex(ValueLayout.JAVA_BYTE, i, input.get());
        }
    }

    void readFromIOBuffer(ByteBuffer output, int readLength) {
        for (int i = 0; i < readLength; i++) {
            output.put(readBuffer.getAtIndex(ValueLayout.JAVA_BYTE, i));
        }
    }

    void initIOBuffers() {
        this.readBuffer = arena.allocate(ValueLayout.JAVA_BYTE, getOption(SocketOption.readBufferSize()));
        this.writeBuffer = arena.allocate(ValueLayout.JAVA_BYTE, getOption(SocketOption.writeBufferSize()));
    }

    public Optional<InetSocketAddress> address() {
        return Optional.ofNullable(address);
    }

    // Completion Ports
    private static final class Windows extends SocketTransmissionLayer<Long> {
        private static final MemorySegment CONNECT_EX_FUNCTION;

        static {
            System.loadLibrary("ws2_32");
            System.loadLibrary("Kernel32");

            var data = Arena.global().allocate(WSAData.layout());
            var startupResult = WindowsSockets.WSAStartup(
                    makeWord(2, 2),
                    data
            );
            if (startupResult != 0) {
                WindowsSockets.WSACleanup();
                throw new RuntimeException("Cannot initialize Windows Sockets: bootstrap failed");
            }

            var version = WSAData.wVersion(data);
            var lowVersion = (byte) version;
            var highVersion = version >> 8;
            if (lowVersion != 2 || highVersion != 2) {
                WindowsSockets.WSACleanup();
                throw new RuntimeException("Cannot initialize Windows Sockets: unsupported platform");
            }

            var socket = WindowsSockets.socket(WindowsSockets.AF_INET(), WindowsSockets.SOCK_STREAM(), 0);
            if (socket == WindowsSockets.INVALID_SOCKET()) {
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
            if (connectExResult != 0) {
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
            super();
        }

        @Override
        Long createHandle() throws SocketException {
            var handle = WindowsSockets.WSASocketA(
                    WindowsSockets.AF_INET(),
                    WindowsSockets.SOCK_STREAM(),
                    WindowsSockets.IPPROTO_TCP(),
                    MemorySegment.NULL,
                    0,
                    WindowsSockets.WSA_FLAG_OVERLAPPED()
            );
            if (handle == WindowsSockets.INVALID_SOCKET()) {
                throw new SocketException("Cannot create socket");
            }
            return handle;
        }

        @Override
        public CompletableFuture<Void> connect(InetSocketAddress address) {
            if (connected.getAndSet(true)) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: already connected"));
            }

            this.address = address;
            var localAddress = createLocalAddress();
            var bindResult = WindowsSockets.bind(handle, localAddress, (int) localAddress.byteSize());
            if (bindResult == WindowsSockets.SOCKET_ERROR()) {
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
                var errorCode = WindowsSockets.WSAGetLastError();
                if (errorCode != 0 && errorCode != WindowsSockets.WSA_IO_PENDING()) {
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
                if (updateOptions != 0) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: cannot set socket options (error code %s)".formatted(updateOptions)));
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
        protected CompletableFuture<Void> writeUnchecked(ByteBuffer input) {
            var length = Math.min(input.remaining(), writeBufferSize);
            writeToIOBuffer(input, length);

            var message = arena.allocate(_WSABUF.layout());
            message.set(_WSABUF.len$layout(), _WSABUF.len$offset(), length);
            message.set(_WSABUF.buf$layout(), _WSABUF.buf$offset(), writeBuffer);
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
                if (error != WindowsSockets.WSA_IO_PENDING()) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (error code %s)".formatted(error)));
                }
            }

            return future.thenCompose(writeValue -> {
                if (writeValue == 0) {
                    close();
                    return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket closed)"));
                }

                if (input.hasRemaining()) {
                    return writeUnchecked(input);
                }

                return CompletableFuture.completedFuture(null);
            });
        }

        @Override
        protected CompletableFuture<ByteBuffer> readUnchecked(ByteBuffer output) {
            var buffer = arena.allocate(_WSABUF.layout());
            _WSABUF.len(buffer, Math.min(output.remaining(), readBufferSize));
            _WSABUF.buf(buffer, this.readBuffer);
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
                    return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socket closed)"));
                }

                readFromIOBuffer(output, readLength);
                return CompletableFuture.completedFuture(output);
            });
        }

        @Override
        public <V> void setOption(SocketOption<V> option, V optionValue) throws SocketException {
            Objects.requireNonNull(optionValue, "Invalid option value");
             var value = arena.allocate(
                    WindowsSockets.DWORD,
                    option.accept(optionValue)
            );
            var result = WindowsSockets.setsockopt(
                    handle,
                    WindowsSockets.SOL_SOCKET(),
                    WindowsSockets.SO_KEEPALIVE(),
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
            WindowsSockets.closesocket(handle);
            if (completionPort != null) {
                completionPort.unregisterHandle(handle);
            }
        }

        private static class CompletionPort implements Runnable {
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
            private ExecutorService executor;

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

                    var completionPort = WindowsSockets.CreateIoCompletionPort(
                            INVALID_HANDLE_VALUE,
                            MemorySegment.NULL,
                            0,
                            0
                    );
                    if (completionPort == MemorySegment.NULL) {
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

    // Io_uring
    private static final class Linux extends SocketTransmissionLayer<Integer> {
        private IOUring ioUring;

        private Linux() throws SocketException {
            super();
        }

        @Override
        Integer createHandle() throws SocketException {
            var handle = LinuxSockets.socket(
                    LinuxSockets.AF_INET(),
                    LinuxSockets.SOCK_STREAM() | LinuxSockets.SOCK_NONBLOCK(),
                    0
            );
            if (handle == -1) {
                throw new SocketException("Cannot create socket");
            }
            return handle;
        }

        @Override
        CompletableFuture<Void> connect(InetSocketAddress address) {
            if (connected.getAndSet(true)) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: already connected"));
            }

            this.address = address;
            var remoteAddress = createRemoteAddress(address);
            if (remoteAddress.isEmpty()) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName())));
            }

            initIOBuffers();

            this.ioUring = IOUring.shared();
            ioUring.registerHandle(handle);

            return ioUring.prepareAsyncOperation(handle, sqe -> {
                io_uring_sqe.opcode(sqe, (byte) LinuxSockets.IORING_OP_CONNECT());
                io_uring_sqe.fd(sqe, handle);
                io_uring_sqe.addr(sqe, remoteAddress.get().address());
                io_uring_sqe.off(sqe, remoteAddress.get().byteSize());
                io_uring_sqe.user_data(sqe, handle);
            }).thenCompose(result -> {
                if (result != 0) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: operation failed"));
                }

                return CompletableFuture.completedFuture(null);
            });
        }

        @Override
        protected CompletableFuture<Void> writeUnchecked(ByteBuffer data) {
            return ioUring.prepareAsyncOperation(handle, sqe -> {
                var length = Math.min(data.remaining(), writeBufferSize);
                writeToIOBuffer(data, length);
                io_uring_sqe.fd(sqe, handle);
                io_uring_sqe.opcode(sqe, (byte) LinuxSockets.IORING_OP_WRITE());
                io_uring_sqe.addr(sqe, writeBuffer.address());
                io_uring_sqe.len(sqe, length);
                io_uring_sqe.user_data(sqe, handle);
            }).thenCompose(result -> {
                if (result < 0) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (error code: %s)".formatted(result)));
                }

                if (!data.hasRemaining()) {
                    return CompletableFuture.completedFuture(null);
                }

                return writeUnchecked(data);
            });
        }

        @Override
        protected CompletableFuture<ByteBuffer> readUnchecked(ByteBuffer data) {
            return ioUring.prepareAsyncOperation(handle, sqe -> {
                var length = Math.min(data.remaining(), readBufferSize);
                io_uring_sqe.opcode(sqe, (byte) LinuxSockets.IORING_OP_READ());
                io_uring_sqe.fd(sqe, handle);
                io_uring_sqe.addr(sqe, readBuffer.address());
                io_uring_sqe.len(sqe, length);
                io_uring_sqe.off(sqe, 0);
                io_uring_sqe.user_data(sqe, handle);
            }).thenCompose(readLength -> {
                if (readLength == 0) {
                    close();
                    return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socket closed)"));
                }

                readFromIOBuffer(data, readLength);
                return CompletableFuture.completedFuture(data);
            });
        }

        @Override
        public void close() {
            if (!connected.get()) {
                return;
            }

            this.address = null;
            connected.set(false);
            if (ioUring != null) {
                ioUring.unregisterHandle(handle);
            }

            if (handle != null) {
                LinuxSockets.shutdown(handle, LinuxSockets.SHUT_RDWR());
                LinuxSockets.close(handle);
            }
        }

        private static class IOUring implements Runnable {
            private static final int QUEUE_SIZE = 20_000;

            private static IOUring instance;
            private static final Object lock = new Object();

            public static IOUring shared() {
                if (instance != null) {
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
                if (ringHandle != null) {
                    return;
                }

                synchronized (this) {
                    if (ringHandle != null) {
                        return;
                    }

                    ringParams = arena.allocate(io_uring_params.layout());
                    this.ringHandle = setupRing();
                    if (ringHandle < 0) {
                        throw new RuntimeException("Io_uring bootstrap failed: invalid ring file descriptor");
                    }

                    var sqRingSize = io_sqring_offsets.array(io_uring_params.sq_off(ringParams)) + io_uring_params.sq_entries(ringParams) * ValueLayout.JAVA_INT.byteSize();
                    var cqRingSize = io_cqring_offsets.cqes(io_uring_params.cq_off(ringParams)) + io_uring_params.cq_entries(ringParams) * io_uring_cqe.sizeof();
                    var singleMap = (io_uring_params.features(ringParams) & LinuxSockets.IORING_FEAT_SINGLE_MMAP()) == 0;
                    if (singleMap) {
                        if (cqRingSize > sqRingSize) {
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
                    if (ringSq == LinuxSockets.MAP_FAILED()) {
                        throw new RuntimeException("Io_uring bootstrap failed: invalid ringSq mmap result");
                    }
                    if (singleMap) {
                        ringCq = ringCqEntries;
                    } else {
                        ringCq = LinuxSockets.mmap(
                                MemorySegment.NULL,
                                cqRingSize,
                                LinuxSockets.PROT_READ() | LinuxSockets.PROT_WRITE(),
                                LinuxSockets.MAP_SHARED() | LinuxSockets.MAP_POPULATE(),
                                ringHandle,
                                LinuxSockets.IORING_OFF_CQ_RING()
                        );
                        if (ringCq == LinuxSockets.MAP_FAILED()) {
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
                    if (ringSqEntries == LinuxSockets.MAP_FAILED()) {
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
                if (ringHandle == null) {
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
                } finally {
                    queueLock.unlock();
                }
            }

            public CompletableFuture<Integer> prepareAsyncOperation(int handle, Consumer<MemorySegment> configurator) {
                try {
                    queueLock.lock();
                    var sqOffset = io_uring_params.sq_off(ringParams);
                    var tail = atomicRead(ringSq, io_sqring_offsets.tail(sqOffset));
                    var size = atomicRead(ringSq, io_sqring_offsets.ring_entries(sqOffset));
                    if (tail + 1 > size) {
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
                } finally {
                    queueLock.unlock();
                }
            }

            @Override
            public void run() {
                while (!Thread.interrupted()) {
                    var result = enterRing(0, 1, LinuxSockets.IORING_ENTER_GETEVENTS());
                    if (!result) {
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
                        if (future != null) {
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
                } catch (Throwable throwable) {
                    return false;
                }
            }
        }
    }

    // GCD (General Central Dispatch)
    private static final class Unix extends SocketTransmissionLayer<Integer> {
        private static final UnixSockets.fcntl fcntl = UnixSockets.fcntl
                .makeInvoker(ValueLayout.JAVA_INT);
        private static final MemorySegment errno = Linker.nativeLinker()
                .defaultLookup()
                .findOrThrow("errno")
                .reinterpret(ValueLayout.JAVA_INT.byteSize());

        private MemorySegment gcdQueue;

        private Unix() throws SocketException {
            super();
        }

        @Override
        Integer createHandle() throws SocketException {
            var socketHandle = UnixSockets.socket(UnixSockets.AF_INET(), UnixSockets.SOCK_STREAM(), 0);
            if (socketHandle == -1) {
                // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/socket.2.html
                throw new SocketException("Cannot create socket (socket call failed)");
            }

            var flags = fcntl.apply(socketHandle, UnixSockets.F_GETFL(), 0);
            if (flags == -1) {
                throw new SocketException("Cannot create socket (fcntl get call failed)");
            }

            var result = fcntl.apply(socketHandle, UnixSockets.F_SETFL(), flags | UnixSockets.O_NONBLOCK());
            if (result == -1) {
                throw new SocketException("Cannot create socket (fcntl set call failed)");
            }

            return socketHandle;
        }

        @Override
        CompletableFuture<Void> connect(InetSocketAddress address) {
            if (connected.getAndSet(true)) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: already connected"));
            }

            this.address = address;
            var remoteAddress = createRemoteAddress(address);
            if (remoteAddress.isEmpty()) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName())));
            }

            var response = UnixSockets.connect(
                    handle,
                    remoteAddress.get(),
                    (int) remoteAddress.get().byteSize()
            );
            if (response != -1) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket remote connection failure (async operation expected)"));
            }

            var errorCode = getErrorCode();
            if (errorCode != UnixSockets.EINPROGRESS() && errorCode != UnixSockets.ETIMEDOUT()) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: remote connection failure (error code: %s)".formatted(errorCode)));
            }

            initIOBuffers();

            this.gcdQueue = UnixSockets.dispatch_queue_create(
                    arena.allocateFrom("socket_" + handle),
                    MemorySegment.NULL
            );
            return dispatch(DispatchEvent.WRITE).thenCompose(_ -> {
                var errorSegment = arena.allocate(ValueLayout.JAVA_INT);
                var result = UnixSockets.getsockopt(
                        handle,
                        UnixSockets.SOL_SOCKET(),
                        UnixSockets.SO_ERROR(),
                        errorSegment,
                        arena.allocateFrom(ValueLayout.JAVA_INT, (int) errorSegment.byteSize())
                );
                if (result < 0) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: cannot get result (error code: %s)".formatted(result)));
                }

                var error = errorSegment.get(ValueLayout.JAVA_INT, 0);
                if (error != 0) {
                    return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: remote connection failure (error code: %s)".formatted(error)));
                }

                return CompletableFuture.completedFuture(null);
            });
        }

        @Override
        protected CompletableFuture<Void> writeUnchecked(ByteBuffer input) {
            var length = Math.min(input.remaining(), writeBufferSize);
            writeToIOBuffer(input, length);
            return dispatch(DispatchEvent.WRITE).thenCompose(_ -> {
                var result = UnixSockets.write(handle, writeBuffer, length);
                if (result == -1) {
                    close();
                    return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (socket closed)"));
                }

                if (input.hasRemaining()) {
                    return writeUnchecked(input);
                }

                return CompletableFuture.completedFuture(null);
            });
        }

        @Override
        protected CompletableFuture<ByteBuffer> readUnchecked(ByteBuffer output) {
            return dispatch(DispatchEvent.READ).thenCompose(_ -> {
                var length = Math.min(output.remaining(), readBufferSize);
                var readLength = UnixSockets.read(handle, readBuffer, length);
                if (readLength <= 0) {
                    close();
                    return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socket closed)"));
                }

                readFromIOBuffer(output, Math.toIntExact(readLength));
                return CompletableFuture.completedFuture(output);
            });
        }

        @Override
        public void close() {
            if (!connected.get()) {
                return;
            }

            this.address = null;
            connected.set(false);
            UnixSockets.close(handle);
        }

        private int getErrorCode() {
            return (int) ValueLayout.JAVA_INT
                    .varHandle()
                    .getVolatile(errno, 0);
        }

        private CompletableFuture<Void> dispatch(DispatchEvent event) {
            var source = UnixSockets.dispatch_source_create(
                    event.constant(),
                    handle,
                    0,
                    gcdQueue
            );

            var future = new CompletableFuture<Void>();
            var handler = dispatch_block_t.allocate(() -> {
                if (!future.isDone()) {
                    future.complete(null);
                }

                UnixSockets.dispatch_source_cancel(source);
            }, arena);

            var block = arena.allocate(__Block_byref_ND.layout());
            __Block_byref_ND.__isa(block, BlockType.GLOBAL.constant());
            __Block_byref_ND.__flags(block, UnixSockets.BLOCK_BYREF_LAYOUT_UNRETAINED());
            __Block_byref_ND.__reserved(block, 0);
            __Block_byref_ND.__FuncPtr(block, handler);
            UnixSockets.dispatch_source_set_event_handler(source, block);

            var obj = arena.allocate(dispatch_object_t.layout());
            dispatch_object_t._ds(obj, source);
            UnixSockets.dispatch_resume(obj);

            return future;
        }

        private enum DispatchEvent {
            READ("_dispatch_source_type_read"),
            WRITE("_dispatch_source_type_write");

            private final MemorySegment constant;

            DispatchEvent(String name) {
                this.constant = Linker.nativeLinker()
                        .defaultLookup()
                        .findOrThrow(name);
            }

            public MemorySegment constant() {
                return constant;
            }
        }

        private enum BlockType {
            GLOBAL("_NSConcreteGlobalBlock"),
            STACK("_NSConcreteStackBlock");

            private final MemorySegment constant;

            BlockType(String name) {
                this.constant = Linker.nativeLinker()
                        .defaultLookup()
                        .findOrThrow(name);
            }

            public MemorySegment constant() {
                return constant;
            }
        }
    }
}

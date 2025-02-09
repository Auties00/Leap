package it.auties.leap.socket.async.client.transportLayer;

import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.implementation.linux.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

// Io_uring
public final class AsyncLinuxSocketClient extends AsyncNativeSocketClient<Integer> {
    private IOUring ioUring;

    public AsyncLinuxSocketClient(SocketProtocol protocol) {
        super(protocol);
    }

    @Override
    protected Integer createNativeHandle() {
        var handle = LinuxKernel.socket(
                LinuxKernel.AF_INET(),
                LinuxKernel.SOCK_STREAM() | LinuxKernel.SOCK_NONBLOCK(),
                0
        );
        if (handle == -1) {
            throw new SocketException("Cannot create socket");
        }
        return handle;
    }

    @Override
    public CompletableFuture<Void> connectNative(InetSocketAddress address) {
        var remoteAddress = createRemoteAddress(address);
        if (remoteAddress.isEmpty()) {
            return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: unresolved host %s".formatted(address.getHostName())));
        }

        initIOBuffers();

        this.ioUring = IOUring.shared();
        ioUring.registerHandle(handle);

        return ioUring.prepareAsyncOperation(handle, sqe -> {
            io_uring_sqe.opcode(sqe, (byte) LinuxKernel.IORING_OP_CONNECT());
            io_uring_sqe.fd(sqe, handle);
            io_uring_sqe.addr(sqe, remoteAddress.get().address());
            io_uring_sqe.off(sqe, remoteAddress.get().byteSize());
            io_uring_sqe.user_data(sqe, handle);
        }).thenCompose(result -> {
            if (result != 0) {
                return CompletableFuture.failedFuture(new SocketException("Cannot connect to socket: operation failed with error code " + result));
            }

            connected.set(true);
            return NO_RESULT;
        });
    }

    private Optional<MemorySegment> createRemoteAddress(InetSocketAddress address) {
        var remoteAddress = arena.allocate(sockaddr_in.layout());
        sockaddr_in.sin_family(remoteAddress, (short) LinuxKernel.AF_INET());
        sockaddr_in.sin_port(remoteAddress, Short.reverseBytes((short) address.getPort()));
        var inAddr = arena.allocate(in_addr.layout());
        var ipv4Host = getLittleEndianIPV4Host(address);
        if (ipv4Host.isEmpty()) {
            return Optional.empty();
        }

        in_addr.S_un(inAddr, arena.allocateFrom(LinuxKernel.C_INT, ipv4Host.getAsInt()));
        sockaddr_in.sin_addr(remoteAddress, inAddr);
        return Optional.of(remoteAddress);
    }
    
    @Override
    protected CompletableFuture<Void> writeNative(ByteBuffer data) {
        return ioUring.prepareAsyncOperation(handle, sqe -> {
            var length = Math.min(data.remaining(), writeBufferSize);
            writeToIOBuffer(data, length);
            io_uring_sqe.fd(sqe, handle);
            io_uring_sqe.opcode(sqe, (byte) LinuxKernel.IORING_OP_WRITE());
            io_uring_sqe.addr(sqe, writeBuffer.address());
            io_uring_sqe.len(sqe, length);
            io_uring_sqe.user_data(sqe, handle);
        }).thenCompose(result -> {
            if (result < 0) {
                return CompletableFuture.failedFuture(new SocketException("Cannot send message to socket (error code: %s)".formatted(result)));
            }

            if (!data.hasRemaining()) {
                return NO_RESULT;
            }

            return writeNative(data);
        });
    }

    @Override
    protected CompletableFuture<Void> readNative(ByteBuffer data, boolean lastRead) {
        return ioUring.prepareAsyncOperation(handle, sqe -> {
            var length = Math.min(data.remaining(), readBufferSize);
            io_uring_sqe.opcode(sqe, (byte) LinuxKernel.IORING_OP_READ());
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

            readFromIOBuffer(data, readLength, lastRead);
            return NO_RESULT;
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
            LinuxKernel.shutdown(handle, LinuxKernel.SHUT_RDWR());
            LinuxKernel.close(handle);
        }
    }

    private static final class IOUring implements Runnable {
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
        private Thread ringTask;

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
                var singleMap = (io_uring_params.features(ringParams) & LinuxKernel.IORING_FEAT_SINGLE_MMAP()) == 0;
                if (singleMap) {
                    if (cqRingSize > sqRingSize) {
                        sqRingSize = cqRingSize;
                    }

                    cqRingSize = sqRingSize;
                }

                ringSq = LinuxKernel.mmap(
                        MemorySegment.NULL,
                        sqRingSize,
                        LinuxKernel.PROT_READ() | LinuxKernel.PROT_WRITE(),
                        LinuxKernel.MAP_SHARED() | LinuxKernel.MAP_POPULATE(),
                        ringHandle,
                        LinuxKernel.IORING_OFF_SQ_RING()
                );
                if (ringSq == LinuxKernel.MAP_FAILED()) {
                    throw new RuntimeException("Io_uring bootstrap failed: invalid ringSq mmap result");
                }
                if (singleMap) {
                    ringCq = ringCqEntries;
                } else {
                    ringCq = LinuxKernel.mmap(
                            MemorySegment.NULL,
                            cqRingSize,
                            LinuxKernel.PROT_READ() | LinuxKernel.PROT_WRITE(),
                            LinuxKernel.MAP_SHARED() | LinuxKernel.MAP_POPULATE(),
                            ringHandle,
                            LinuxKernel.IORING_OFF_CQ_RING()
                    );
                    if (ringCq == LinuxKernel.MAP_FAILED()) {
                        throw new RuntimeException("Io_uring bootstrap failed: invalid ringCq mmap result");
                    }
                }

                ringSqEntries = LinuxKernel.mmap(
                        MemorySegment.NULL,
                        io_uring_params.sq_entries(ringParams) * io_uring_sqe.sizeof(),
                        LinuxKernel.PROT_READ() | LinuxKernel.PROT_WRITE(),
                        LinuxKernel.MAP_SHARED() | LinuxKernel.MAP_POPULATE(),
                        ringHandle,
                        LinuxKernel.IORING_OFF_SQES()
                );
                if (ringSqEntries == LinuxKernel.MAP_FAILED()) {
                    throw new RuntimeException("Io_uring bootstrap failed: invalid ringSqEntries mmap result");
                }

                ringCqEntries = ringCq.asSlice(
                        io_cqring_offsets.cqes(io_uring_params.cq_off(ringParams)),
                        io_uring_params.cq_entries(ringParams) * io_uring_cqe.sizeof(),
                        io_uring_cqe.layout().byteAlignment()
                );

                this.ringTask = Thread.startVirtualThread(this);
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
                var ringHandle = this.ringHandle;
                this.ringHandle = null;
                LinuxKernel.close(ringHandle);
                if (ringTask != null) {
                    ringTask.interrupt();
                    this.ringTask = null;
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
                var result = enterRing(0, 1, LinuxKernel.IORING_ENTER_GETEVENTS());
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
            return (int) LinuxKernel.syscall
                    .makeInvoker(
                            ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS.withTargetLayout(io_uring_params.layout())
                    )
                    .apply(
                            LinuxKernel.__NR_io_uring_setup(),
                            QUEUE_SIZE,
                            ringParams
                    );
        }

        private boolean enterRing(int in, int out, int flags) {
            try {
                var result = LinuxKernel.syscall
                        .makeInvoker(
                                ValueLayout.JAVA_INT,
                                ValueLayout.JAVA_INT,
                                ValueLayout.JAVA_INT,
                                ValueLayout.JAVA_INT,
                                ValueLayout.ADDRESS,
                                ValueLayout.JAVA_INT
                        )
                        .apply(
                                LinuxKernel.__NR_io_uring_enter(),
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

package it.auties.leap.socket.async.transportLayer.implementation;

import it.auties.leap.StableValue;
import it.auties.leap.socket.SocketException;
import it.auties.leap.socket.SocketProtocol;
import it.auties.leap.socket.async.transportLayer.AsyncSocketTransportLayerFactory;
import it.auties.leap.socket.implementation.linux.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Consumer;

// Io_uring
public final class AsyncLinuxTransportSocketLayer extends AsyncNativeTransportSocketLayer<Integer> {
    private static final AsyncSocketTransportLayerFactory FACTORY = AsyncLinuxTransportSocketLayer::new;

    public static AsyncSocketTransportLayerFactory factory() {
        return FACTORY;
    }

    private IOUring ioUring;

    public AsyncLinuxTransportSocketLayer(SocketProtocol protocol) {
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

        return ioUring.prepareAsyncOperation(handle, true, sqe -> {
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

        in_addr.s_addr(inAddr, ipv4Host.getAsInt());
        sockaddr_in.sin_addr(remoteAddress, inAddr);
        return Optional.of(remoteAddress);
    }

    @Override
    protected CompletableFuture<Void> writeNative(ByteBuffer data) {
        return ioUring.prepareAsyncOperation(handle, true, sqe -> {
            var length = Math.min(data.remaining(), writeBufferSize);
            writeToIOBuffer(data, length);
            io_uring_sqe.fd(sqe, handle);
            io_uring_sqe.opcode(sqe, (byte) LinuxKernel.IORING_OP_WRITE());
            io_uring_sqe.addr(sqe, writeBuffer.address());
            io_uring_sqe.len(sqe, length);
            io_uring_sqe.user_data(sqe, handle);
        }).thenCompose(result -> {
            if (result < 0) {
                close();
                return CompletableFuture.failedFuture(new SocketException("Cannot receive message from socket (socket closed)"));
            }

            if (!data.hasRemaining()) {
                return NO_RESULT;
            }

            return writeNative(data);
        });
    }

    @Override
    protected CompletableFuture<Void> readNative(ByteBuffer data, boolean lastRead) {
        return ioUring.prepareAsyncOperation(handle, true, sqe -> {
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
        if (ioUring != null && handle != null && ioUring.isHandleRegistered(handle)) {
            ioUring.unregisterHandle(handle);
            LinuxKernel.shutdown(handle, LinuxKernel.SHUT_RDWR());
            LinuxKernel.close(handle);
        }

        this.address = null;
        connected.set(false);
    }

    private static final class IOUring implements Runnable {
        private static final LinuxKernel.syscall SETUP_SYS_CALL = LinuxKernel.syscall.makeInvoker(
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS.withTargetLayout(io_uring_params.layout())
        );
        private static final LinuxKernel.syscall ENTER_SYS_CALL = LinuxKernel.syscall.makeInvoker(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS,
                ValueLayout.JAVA_INT
        );
        private static final LinuxKernel.syscall RESIZE_SYS_CALL = LinuxKernel.syscall.makeInvoker(
                ValueLayout.JAVA_INT,
                ValueLayout.JAVA_INT,
                ValueLayout.ADDRESS.withTargetLayout(io_uring_params.layout()),
                ValueLayout.JAVA_INT
        );
        private static final int QUEUE_SIZE = 20_000;

        private static final StableValue<IOUring> INSTANCE = StableValue.of();
        public static IOUring shared() {
            return INSTANCE.orElseSet(IOUring::new);
        }
        
        private final Arena arena;
        private final ConcurrentMap<Integer, CompletableFuture<Integer>> futures;
        private final Set<Integer> registeredHandles;

        private volatile Integer ringHandle;
        private MemorySegment ringSq;
        private MemorySegment ringSqEntries;
        private MemorySegment ringCq;
        private MemorySegment ringCqEntries;
        private MemorySegment ringParams;
        private Long ringSqSize;
        private Long ringCqSize;
        private Thread ringTask;

        private IOUring() {
            this.arena = Arena.ofAuto();
            this.futures = new ConcurrentHashMap<>();
            this.registeredHandles = new CopyOnWriteArraySet<>();
        }

        public void registerHandle(int handle) {
            if (ringHandle == null) {
                synchronized (this) {
                    if (ringHandle == null) {
                        setupRing();
                        mapRing();
                        startTask();
                    }
                }
            }
            
            registeredHandles.add(handle);
        }

        private void setupRing() {
            this.ringParams = arena.allocate(io_uring_params.layout());
            var result = (int) SETUP_SYS_CALL.apply(
                    LinuxKernel.__NR_io_uring_setup(),
                    QUEUE_SIZE,
                    ringParams
            );
            if (result < 0) {
                throw new RuntimeException("Invalid ring file descriptor");
            }

            this.ringHandle = result;
        }


        private void mapRing() {
            this.ringSqSize = io_sqring_offsets.array(io_uring_params.sq_off(ringParams)) + io_uring_params.sq_entries(ringParams) * ValueLayout.JAVA_INT.byteSize();
            this.ringCqSize = io_cqring_offsets.cqes(io_uring_params.cq_off(ringParams)) + io_uring_params.cq_entries(ringParams) * io_uring_cqe.sizeof();
            var singleMap = (io_uring_params.features(ringParams) & LinuxKernel.IORING_FEAT_SINGLE_MMAP()) == 0;
            if (singleMap) {
                if (ringCqSize > ringSqSize) {
                    ringSqSize = ringCqSize;
                }

                ringCqSize = ringSqSize;
            }

            ringSq = LinuxKernel.mmap(
                    MemorySegment.NULL,
                    ringSqSize,
                    LinuxKernel.PROT_READ() | LinuxKernel.PROT_WRITE(),
                    LinuxKernel.MAP_SHARED() | LinuxKernel.MAP_POPULATE(),
                    ringHandle,
                    LinuxKernel.IORING_OFF_SQ_RING()
            );
            if (ringSq == LinuxKernel.MAP_FAILED()) {
                throw new RuntimeException("Invalid ringSq mmap result");
            }

            if (singleMap) {
                ringCq = ringSq;
            } else {
                ringCq = LinuxKernel.mmap(
                        MemorySegment.NULL,
                        ringCqSize,
                        LinuxKernel.PROT_READ() | LinuxKernel.PROT_WRITE(),
                        LinuxKernel.MAP_SHARED() | LinuxKernel.MAP_POPULATE(),
                        ringHandle,
                        LinuxKernel.IORING_OFF_CQ_RING()
                );
                if (ringCq == LinuxKernel.MAP_FAILED()) {
                    throw new RuntimeException("Invalid ringCq mmap result");
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
                unmapMemory();
                throw new RuntimeException("Invalid ringSqEntries mmap result");
            }

            ringCqEntries = ringCq.asSlice(
                    io_cqring_offsets.cqes(io_uring_params.cq_off(ringParams)),
                    io_uring_params.cq_entries(ringParams) * io_uring_cqe.sizeof(),
                    io_uring_cqe.layout().byteAlignment()
            );
        }

        private void startTask() {
            this.ringTask = Thread.ofPlatform().start(this);
        }

        public void unregisterHandle(int handle) {
            registeredHandles.remove(handle);
            futures.remove(handle);
            if (registeredHandles.isEmpty()) {
                close();
            }
        }

        public boolean isHandleRegistered(int handle) {
            return registeredHandles.contains(handle);
        }

        private void close() {
            if (ringTask != null) {
                ringTask.interrupt();
                this.ringTask = null;
            }

            if (ringHandle != null) {
                var ringHandle = this.ringHandle;
                this.ringHandle = null;
                LinuxKernel.close(ringHandle);
                unmapMemory();
                if (ringTask != null) {
                    ringTask.interrupt();
                    this.ringTask = null;
                }
            }
        }

        private void unmapMemory() {
            if(ringSq != null) {
                LinuxKernel.munmap(ringSq, ringSqSize);
            }
            if(ringCq != null && ringSq != ringCq) {
                LinuxKernel.munmap(ringCq, ringCqSize);
            }
            ringSq = null;
            ringSqEntries = null;
            ringCq = null;
            ringCqEntries = null;
            ringParams = null;
            ringSqSize = null;
            ringCqSize = null;
        }

        public CompletableFuture<Integer> prepareAsyncOperation(int handle, boolean allowResize, Consumer<MemorySegment> configurator) {
            var sqOffset = io_uring_params.sq_off(ringParams);
            var tail = atomicRead(ringSq, io_sqring_offsets.tail(sqOffset));
            var size = atomicRead(ringSq, io_sqring_offsets.ring_entries(sqOffset));
            if (tail + 1 > size) {
                System.err.println("Resize");
                if(!allowResize) {
                    return CompletableFuture.failedFuture(new IllegalStateException("Io_uring queue is full"));
                }
                resizeRing(sqOffset);
                return prepareAsyncOperation(handle, false, configurator);
            }

            var mask = atomicRead(ringSq, io_sqring_offsets.ring_mask(sqOffset));
            var index = tail & mask;
            var entry = io_uring_sqe.asSlice(ringSqEntries, index);
            configurator.accept(entry);
            atomicWrite(
                    ringSq,
                    io_sqring_offsets.array(sqOffset) + (index * ValueLayout.JAVA_INT.byteSize()),
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
        }

        // https://git.kernel.dk/cgit/liburing/tree/src/register.c#n458
        private void resizeRing(MemorySegment sqOffset) {
            io_uring_params.sq_off(ringParams)
                    .fill((byte) 0);
            io_uring_params.cq_off(ringParams)
                    .fill((byte) 0);

            var result = RESIZE_SYS_CALL.apply(
                    LinuxKernel.__NR_io_uring_register(),
                    ringHandle,
                    LinuxKernel.IORING_REGISTER_RESIZE_RINGS(),
                    ringParams,
                    1
            );
            if(result < 0) {
                throw new RuntimeException();
            }

            var sq_head = atomicRead(ringSq, io_sqring_offsets.head(sqOffset));
            var sq_tail = atomicRead(ringSq, io_sqring_offsets.tail(sqOffset));
            unmapMemory();
            ringSq.fill((byte) 0);
            ringCq.fill((byte) 0);
            mapRing();
            atomicWrite(ringSq, io_sqring_offsets.head(sqOffset), sq_head);
            atomicWrite(ringSq, io_sqring_offsets.head(sqOffset), sq_tail);
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

                if(!atomicWrite(ringCq, io_cqring_offsets.head(cqOffset), head)) {
                    break;
                }
            }
        }

        private boolean enterRing(int in, int out, int flags) {
            try {
                var result = ENTER_SYS_CALL.apply(
                        LinuxKernel.__NR_io_uring_enter(),
                        ringHandle,
                        in,
                        out,
                        flags,
                        MemorySegment.NULL,
                        0
                );
                return result >= 0;
            } catch (Throwable throwable) {
                return false;
            }
        }

        private int atomicRead(MemorySegment segment, int offset) {
            if(ringHandle == null) {
                return -1;
            }

            return (int) ValueLayout.JAVA_INT.varHandle()
                    .getVolatile(segment, offset);
        }

        private boolean atomicWrite(MemorySegment segment, long offset, int value) {
            if(ringHandle == null) {
                return false;
            }

            ValueLayout.JAVA_INT.varHandle()
                    .setVolatile(segment, offset, value);
            return true;
        }
    }
}

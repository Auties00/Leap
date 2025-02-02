package it.auties.leap.socket.implementation.threading;

import it.auties.leap.socket.implementation.foreign.linux.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

public class IOUring implements Runnable {
    private static final int QUEUE_SIZE = 20_000;

    private static IOUring instance;
    private static final Object lock = new Object();

    public static IOUring shared() {
        if (instance != null) {
            return instance;
        }

        synchronized (lock) {
            if (instance != null) {
                return instance;
            }

            return instance = new IOUring();
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

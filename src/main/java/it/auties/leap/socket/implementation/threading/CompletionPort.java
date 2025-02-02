package it.auties.leap.socket.implementation.threading;

import it.auties.leap.socket.implementation.foreign.win.OVERLAPPED_ENTRY;
import it.auties.leap.socket.implementation.foreign.win.WindowsKernel;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.*;

public class CompletionPort implements Runnable {
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
            if (executor != null && !executor.isShutdown()) {
                return;
            }

            this.executor = Executors.newSingleThreadExecutor();
            executor.submit(this);
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

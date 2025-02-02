package it.auties.leap.socket.implementation.threading;

import it.auties.leap.socket.implementation.foreign.unix.UnixKernel;
import it.auties.leap.socket.implementation.foreign.unix.__Block_byref_ND;
import it.auties.leap.socket.implementation.foreign.unix.dispatch_block_t;
import it.auties.leap.socket.implementation.foreign.unix.dispatch_object_t;

import java.lang.foreign.Arena;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.CompletableFuture;

public class GCD {
    private final Arena arena;
    private final long handle;
    private final MemorySegment gcdQueue;

    public GCD(long handle) {
        this.arena = Arena.ofAuto();
        this.handle = handle;
        this.gcdQueue = UnixKernel.dispatch_queue_create(
                arena.allocateFrom("socket_" + handle),
                MemorySegment.NULL
        );
    }

    public CompletableFuture<Void> dispatch(DispatchEvent event) {
        var source = UnixKernel.dispatch_source_create(
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

            UnixKernel.dispatch_source_cancel(source);
        }, arena);

        var block = arena.allocate(__Block_byref_ND.layout());
        __Block_byref_ND.__isa(block, BlockType.GLOBAL.constant());
        __Block_byref_ND.__flags(block, UnixKernel.BLOCK_BYREF_LAYOUT_UNRETAINED());
        __Block_byref_ND.__reserved(block, 0);
        __Block_byref_ND.__FuncPtr(block, handler);
        UnixKernel.dispatch_source_set_event_handler(source, block);

        var obj = arena.allocate(dispatch_object_t.layout());
        dispatch_object_t._ds(obj, source);
        UnixKernel.dispatch_resume(obj);

        return future;
    }

    public enum DispatchEvent {
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

    public enum BlockType {
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

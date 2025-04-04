package it.auties.leap;

import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

// Mirror while we wait for https://openjdk.org/jeps/502
public final class StableValue<T> {
    private final AtomicReference<T> value = new AtomicReference<>(null);

    private StableValue() {

    }

    public static <T> StableValue<T> of() {
        return new StableValue<>();
    }

    public T orElseSet(Supplier<T> newValue) {
        var current = value.getAcquire();
        if (current != null) {
            return current;
        }

        var update = newValue.get();
        if (value.compareAndSet(null, update)) {
            return update;
        }

        return value.get();
    }
}

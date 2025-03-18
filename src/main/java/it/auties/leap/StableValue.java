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
        var value = this.value.getAcquire();
        if(value == null) {
            var result = newValue.get();
            this.value.set(result);
            return result;
        }else {
            return value;
        }
    }
}

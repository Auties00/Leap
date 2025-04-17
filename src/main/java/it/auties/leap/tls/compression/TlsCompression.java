package it.auties.leap.tls.compression;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.List;
import java.util.Objects;

public final class TlsCompression implements TlsIdentifiableProperty<Byte> {
    private static final TlsCompression NONE = new TlsCompression((byte) 0, Type.NONE, TlsCompressor.none());
    private static final TlsCompression DEFLATE = new TlsCompression((byte) 1, Type.DEFLATE, TlsCompressor.deflate());
    private static final List<TlsCompression> VALUES = List.of(NONE, DEFLATE);
    private static final List<TlsCompression> RECOMMENDED = List.of(NONE);

    private final byte id;
    private final Type type;
    private final TlsCompressor compressor;

    private TlsCompression(byte id, Type type, TlsCompressor compressor) {
        this.id = id;
        this.type = type;
        this.compressor = compressor;
    }

    public static TlsCompression none() {
        return NONE;
    }

    public static TlsCompression deflate() {
        return DEFLATE;
    }

    public static TlsCompression reservedForPrivateUse(byte id) {
        return reservedForPrivateUse(id, null);
    }

    public static TlsCompression reservedForPrivateUse(byte id, TlsCompressor compressor) {
        if (id < -32 || id > -1) {
            throw new TlsAlert("Only values from 224-255 (decimal) inclusive are reserved for Private Use", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new TlsCompression(id, Type.RESERVED_FOR_PRIVATE_USE, Objects.requireNonNullElse(compressor, TlsCompressor.stub()));
    }

    public static List<TlsCompression> values() {
        return VALUES;
    }

    public static List<TlsCompression> recommended() {
        return RECOMMENDED;
    }

    @Override
    public Byte id() {
        return id;
    }

    public Type type() {
        return type;
    }

    public TlsCompressor compressor() {
        return compressor;
    }

    public enum Type {
        NONE,
        DEFLATE,
        RESERVED_FOR_PRIVATE_USE
    }
}

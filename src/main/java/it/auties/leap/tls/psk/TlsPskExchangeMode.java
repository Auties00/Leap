package it.auties.leap.tls.psk;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsIdentifiableProperty;

import java.util.Objects;

public final class TlsPskExchangeMode implements TlsIdentifiableProperty<Byte> {
    private static final TlsPskExchangeMode KE = new TlsPskExchangeMode((byte) 0, Type.KE, TlsPskExchangeModeGenerator.ke());
    private static final TlsPskExchangeMode DHE_KE = new TlsPskExchangeMode((byte) 1, Type.DHE_KE, TlsPskExchangeModeGenerator.dheKe());

    private final byte id;
    private final Type type;
    private final TlsPskExchangeModeGenerator generator;

    private TlsPskExchangeMode(byte id, Type type, TlsPskExchangeModeGenerator generator) {
        this.id = id;
        this.type = type;
        this.generator = generator;
    }

    public static TlsPskExchangeMode pskKe() {
        return KE;
    }

    public static TlsPskExchangeMode pskDheKe() {
        return DHE_KE;
    }

    public static TlsPskExchangeMode reservedForPrivateUse(byte id) {
        return reservedForPrivateUse(id, null);
    }

    public static TlsPskExchangeMode reservedForPrivateUse(byte id, TlsPskExchangeModeGenerator generator) {
        if(id != -32 && id != -31) {
            throw new TlsAlert("Only values from 224-255 (decimal) inclusive are reserved for Private Use", TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER);
        }

        return new TlsPskExchangeMode(id, Type.RESERVED_FOR_PRIVATE_USE, Objects.requireNonNullElse(generator, TlsPskExchangeModeGenerator.stub()));
    }

    @Override
    public Byte id() {
        return id;
    }

    public Type type() {
        return type;
    }

    public TlsPskExchangeModeGenerator generator() {
        return generator;
    }

    public enum Type {
        KE,
        DHE_KE,
        RESERVED_FOR_PRIVATE_USE
    }
}

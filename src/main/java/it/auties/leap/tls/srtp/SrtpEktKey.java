package it.auties.leap.tls.srtp;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;

import java.nio.ByteBuffer;
import java.util.Objects;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SrtpEktKey {
    private final byte[] ektKeyValue;
    private final byte[] srtpMasterSalt;
    private final int ektSpi;
    private final int ektTtl;

    private SrtpEktKey(byte[] ektKeyValue, byte[] srtpMasterSalt, int ektSpi, int ektTtl) {
        this.ektKeyValue = ektKeyValue;
        this.srtpMasterSalt = srtpMasterSalt;
        this.ektSpi = ektSpi;
        this.ektTtl = ektTtl;
    }

    public static SrtpEktKey of(byte[] ektKeyValue, byte[] srtpMasterSalt, int ektSpi, int ektTtl) {
        Objects.requireNonNull(ektKeyValue, "ektKeyValue must not be null");
        Objects.requireNonNull(srtpMasterSalt, "srtpMasterSalt must not be null");
        if(ektSpi < 0) {
            throw new IllegalArgumentException("ektSpi must not be negative");
        }
        if(ektTtl < 0) {
            throw new IllegalArgumentException("ektTtl must not be negative");
        }
        return new SrtpEktKey(ektKeyValue, srtpMasterSalt, ektSpi, ektTtl);
    }

    public static SrtpEktKey of(ByteBuffer buffer) {
        var ektKeyValue = readBytesBigEndian8(buffer);
        var srtpMasterSalt = readBytesBigEndian8(buffer);
        var ektSpi = readBigEndianInt16(buffer);
        if(ektSpi < 0) {
            throw new TlsAlert("ektSpi must not be negative", TlsAlertLevel.FATAL, TlsAlertType.HANDSHAKE_FAILURE);
        }
        var ektTtl = readBigEndianInt24(buffer);
        if(ektTtl < 0) {
            throw new TlsAlert("ektTtl must not be negative", TlsAlertLevel.FATAL, TlsAlertType.HANDSHAKE_FAILURE);
        }
        return new SrtpEktKey(ektKeyValue, srtpMasterSalt, ektSpi, ektTtl);
    }

    public byte[] ektKeyValue() {
        return ektKeyValue;
    }

    public byte[] srtpMasterSalt() {
        return srtpMasterSalt;
    }

    public int ektSpi() {
        return ektSpi;
    }

    public int ektTtl() {
        return ektTtl;
    }

    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian8(buffer, ektKeyValue);
        writeBytesBigEndian8(buffer, srtpMasterSalt);
        writeBigEndianInt16(buffer, ektSpi);
        writeBigEndianInt24(buffer, ektTtl);
    }

    public int length() {
        return INT8_LENGTH + ektKeyValue.length
                + INT8_LENGTH + srtpMasterSalt.length
                + INT16_LENGTH
                + INT24_LENGTH;
    }
}

package it.auties.leap.tls.srtp;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SrtpEktKey implements TlsSerializableProperty {
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

    public static SrtpEktKey newEktKey(byte[] ektKeyValue, byte[] srtpMasterSalt, int ektSpi, int ektTtl) {
        if(ektKeyValue == null) {
            throw new TlsAlert("ektKeyValue", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if(srtpMasterSalt == null) {
            throw new TlsAlert("srtpMasterSalt", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if(ektSpi < 0) {
            throw new TlsAlert("ektSpi", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if(ektTtl < 0) {
            throw new TlsAlert("ektTtl", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        return new SrtpEktKey(ektKeyValue, srtpMasterSalt, ektSpi, ektTtl);
    }

    public static SrtpEktKey of(ByteBuffer buffer) {
        var ektKeyValue = readBytesBigEndian8(buffer);
        var srtpMasterSalt = readBytesBigEndian8(buffer);
        var ektSpi = readBigEndianInt16(buffer);
        if(ektSpi < 0) {
            throw new TlsAlert("ektSpi", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        var ektTtl = readBigEndianInt24(buffer);
        if(ektTtl < 0) {
            throw new TlsAlert("ektTtl", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
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

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesBigEndian8(buffer, ektKeyValue);
        writeBytesBigEndian8(buffer, srtpMasterSalt);
        writeBigEndianInt16(buffer, ektSpi);
        writeBigEndianInt24(buffer, ektTtl);
    }

    @Override
    public int length() {
        return INT8_LENGTH + ektKeyValue.length
                + INT8_LENGTH + srtpMasterSalt.length
                + INT16_LENGTH
                + INT24_LENGTH;
    }
}

package it.auties.leap.tls.srtp;

import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsSrtpEktKey implements TlsSerializableProperty {
    private final byte[] ektKeyValue;
    private final byte[] srtpMasterSalt;
    private final int ektSpi;
    private final int ektTtl;

    private TlsSrtpEktKey(byte[] ektKeyValue, byte[] srtpMasterSalt, int ektSpi, int ektTtl) {
        this.ektKeyValue = ektKeyValue;
        this.srtpMasterSalt = srtpMasterSalt;
        this.ektSpi = ektSpi;
        this.ektTtl = ektTtl;
    }

    public static TlsSrtpEktKey newEktKey(byte[] ektKeyValue, byte[] srtpMasterSalt, int ektSpi, int ektTtl) {
        if(ektKeyValue == null) {
            throw new NullPointerException("ektKeyValue");
        }

        if(srtpMasterSalt == null) {
            throw new NullPointerException("srtpMasterSalt");
        }

        if(ektSpi < 0) {
            throw new IllegalArgumentException("ektSpi");
        }

        if(ektTtl < 0) {
            throw new IllegalArgumentException("ektTtl");
        }

        return new TlsSrtpEktKey(ektKeyValue, srtpMasterSalt, ektSpi, ektTtl);
    }

    public static TlsSrtpEktKey of(ByteBuffer buffer) {
        var ektKeyValue = readBytesBigEndian8(buffer);
        var srtpMasterSalt = readBytesBigEndian8(buffer);
        var ektSpi = readBigEndianInt16(buffer);
        if(ektSpi < 0) {
            throw new IllegalArgumentException("ektSpi");
        }

        var ektTtl = readBigEndianInt24(buffer);
        if(ektTtl < 0) {
            throw new IllegalArgumentException("ektTtl");
        }

        return new TlsSrtpEktKey(ektKeyValue, srtpMasterSalt, ektSpi, ektTtl);
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

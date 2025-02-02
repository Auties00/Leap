package it.auties.leap.tls.cipher.exchange.server.implementation;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchange;
import it.auties.leap.tls.cipher.exchange.client.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchange;
import it.auties.leap.tls.cipher.exchange.server.TlsServerKeyExchangeFactory;

import java.nio.ByteBuffer;
import java.security.PrivateKey;
import java.security.PublicKey;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SRPServerKeyExchange implements TlsServerKeyExchange {
    private static final TlsServerKeyExchangeFactory FACTORY = engine -> {
        return new SRPServerKeyExchange(new byte[0], new byte[0], new byte[0], new byte[0]);
    };

    private final byte[] srpN;
    private final byte[] srpG;
    private final byte[] srpS;
    private final byte[] srpB;

    public SRPServerKeyExchange(byte[] srpN, byte[] srpG, byte[] srpS, byte[] srpB) {
        this.srpN = srpN;
        this.srpG = srpG;
        this.srpS = srpS;
        this.srpB = srpB;
    }

    public SRPServerKeyExchange(ByteBuffer buffer) {
        this.srpN = readBytesLittleEndian16(buffer);
        this.srpG = readBytesLittleEndian16(buffer);
        this.srpS = readBytesLittleEndian8(buffer);
        this.srpB = readBytesLittleEndian16(buffer);
    }

    public static TlsServerKeyExchangeFactory factory() {
        return FACTORY;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, srpN);
        writeBytesLittleEndian16(buffer, srpG);
        writeBytesLittleEndian8(buffer, srpS);
        writeBytesLittleEndian16(buffer, srpB);
    }

    @Override
    public int length() {
        return INT16_LENGTH + srpN.length
                + INT16_LENGTH + srpG.length
                + INT8_LENGTH + srpS.length
                + INT16_LENGTH + srpB.length;
    }

    @Override
    public TlsServerKeyExchange decodeLocal(ByteBuffer buffer) {
        throw new UnsupportedOperationException();
    }

    @Override
    public TlsClientKeyExchange decodeRemote(ByteBuffer buffer) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] generatePreMasterSecret(PrivateKey localPrivateKey, PublicKey remoteCertificatePublicKey, TlsKeyExchange remoteKeyExchange) {
        throw new UnsupportedOperationException();
    }
}

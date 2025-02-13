package it.auties.leap.tls.cipher.exchange.server;

import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.cipher.exchange.TlsServerKeyExchange;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class SRPServerKeyExchange extends TlsServerKeyExchange {
    private final byte[] srpN;
    private final byte[] srpG;
    private final byte[] srpS;
    private final byte[] srpB;

    public SRPServerKeyExchange(byte[] srpN, byte[] srpG, byte[] srpS, byte[] srpB) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.srp());
        this.srpN = srpN;
        this.srpG = srpG;
        this.srpS = srpS;
        this.srpB = srpB;
    }

    public SRPServerKeyExchange(ByteBuffer buffer) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.srp());
        this.srpN = readBytesLittleEndian16(buffer);
        this.srpG = readBytesLittleEndian16(buffer);
        this.srpS = readBytesLittleEndian8(buffer);
        this.srpB = readBytesLittleEndian16(buffer);
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
}
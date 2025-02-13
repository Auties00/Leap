package it.auties.leap.tls.cipher.exchange.client;

import it.auties.leap.tls.cipher.exchange.TlsClientKeyExchange;
import it.auties.leap.tls.cipher.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.key.TlsPreMasterSecretGenerator;

import java.nio.ByteBuffer;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class KRB5ClientKeyExchange extends TlsClientKeyExchange {
    private final byte[] ticket;
    private final byte[] authenticator;
    private final byte[] encryptedPreMasterSecret;

    public KRB5ClientKeyExchange(byte[] ticket, byte[] authenticator, byte[] encryptedPreMasterSecret) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.krb5());
        this.ticket = ticket;
        this.authenticator = authenticator;
        this.encryptedPreMasterSecret = encryptedPreMasterSecret;
    }

    public KRB5ClientKeyExchange(ByteBuffer buffer) {
        super(TlsKeyExchangeType.EPHEMERAL, TlsPreMasterSecretGenerator.krb5());
        this.ticket = readBytesLittleEndian16(buffer);
        this.authenticator = readBytesLittleEndian16(buffer);
        this.encryptedPreMasterSecret = readBytesLittleEndian16(buffer);
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBytesLittleEndian16(buffer, ticket);
        writeBytesLittleEndian16(buffer, authenticator);
        writeBytesLittleEndian16(buffer, encryptedPreMasterSecret);
    }

    @Override
    public int length() {
        return INT16_LENGTH + ticket.length
                + INT16_LENGTH + authenticator.length
                + INT16_LENGTH + encryptedPreMasterSecret.length;
    }
}
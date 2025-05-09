package it.auties.leap.tls.message.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.message.*;
import it.auties.leap.tls.version.TlsVersion;

import java.net.URI;
import java.nio.ByteBuffer;

/**
 * <a href="https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.1.2">7.4.1.1.  Hello Request</a>
 * <p>
 *    When this message will be sent:
 * <p>
 *       The HelloRequest message MAY be sent by the server at any time.
 * <p>
 *    Meaning of this message:
 * <p>
 *       HelloRequest is a simple notification that the client should begin
 *       the negotiation process anew.  In response, the client should send
 *       a ClientHello message when convenient.  This message is not
 *       intended to establish which side is the client or server but
 *       merely to initiate a new negotiation.  Servers SHOULD NOT send a
 *       HelloRequest immediately upon the client's initial connection.  It
 *       is the client's job to send a ClientHello at that time.
 * <p>
 *       This message will be ignored by the client if the client is
 *       currently negotiating a session.  This message MAY be ignored by
 *       the client if it does not wish to renegotiate a session, or the
 *       client may, if it wishes, respond with a no_renegotiation alert.
 *       Since handshake messages are intended to have transmission
 *       precedence over application data, it is expected that the
 *       negotiation will begin before no more than a few records are
 *       received from the client.  If the server sends a HelloRequest but
 *       does not receive a ClientHello in response, it may close the
 *       connection with a fatal alert.
 * <p>
 *       After sending a HelloRequest, servers SHOULD NOT repeat the
 *       request until the subsequent handshake negotiation is complete.
 * <p>
 *    Structure of this message:
 * <code>
 *       struct { } HelloRequest;
 * </code>
 * <p>
 *    This message MUST NOT be included in the message hashes that are
 *    maintained throughout the handshake and used in the Finished messages
 *    and the certificate verify message.
 *
 * @param version the TLS version of this message
 * @param source the source of this message
 */
public record HelloRequestMessage(
        TlsVersion version,
        TlsSource source
) implements TlsHandshakeMessage {
    private static final byte ID = 0x00;
    private static final TlsHandshakeMessageDeserializer DESERIALIZER = new TlsHandshakeMessageDeserializer() {
        @Override
        public int id() {
            return ID;
        }

        @Override
        public TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata) {
            if(buffer.hasRemaining()) {
                throw new TlsAlert(
                        "Expected server hello request message to have an empty payload",
                        URI.create("https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.9"),
                        "7.4.1.1",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.INTERNAL_ERROR
                );
            }

            return new HelloRequestMessage(metadata.version(), metadata.source());
        }
    };

    public static TlsHandshakeMessageDeserializer deserializer() {
        return DESERIALIZER;
    }

    @Override
    public byte id() {
        return ID;
    }

    @Override
    public TlsMessageContentType contentType() {
        return TlsMessageContentType.HANDSHAKE;
    }

    @Override
    public void serializePayload(ByteBuffer buffer) {

    }

    @Override
    public int payloadLength() {
        return 0;
    }


    @Override
    public void apply(TlsContext context) {

    }

    @Override
    public boolean hashable() {
        return false;
    }

    public void validate(TlsContext context) {

    }
}

package it.auties.leap.tls.message;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.message.implementation.*;

import java.nio.ByteBuffer;

public interface TlsHandshakeMessageDeserializer {
    static TlsMessageDeserializer of() {
        return HandshakeMessageDeserializer.instance();
    }

    static TlsHandshakeMessageDeserializer certificate() {
        return CertificateMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer certificateStatus() {
        return CertificateStatusMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer certificateUrl() {
        return CertificateUrlMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer certificateVerify() {
        return CertificateVerifyMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer clientCertificateRequest() {
        return ClientCertificateRequestMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer clientHello() {
        return ClientHelloMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer clientKeyExchange() {
        return ClientKeyExchangeMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer compressedCertificate() {
        return CompressedCertificateMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer ekt() {
        return EktMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer encryptedExtensions() {
        return EncryptedExtensionsMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer endOfEarlyData() {
        return EndOfEarlyDataMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer finished() {
        return FinishedMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer helloRequest() {
        return HelloRequestMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer helloRetryRequest() {
        return HelloRetryRequestMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer helloVerifyRequest() {
        return HelloVerifyRequestMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer keyUpdateRequest() {
        return KeyUpdateRequestMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer messageHash() {
        return MessageHashMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer newConnectionId() {
        return NewConnectionIdMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer newSessionTicket() {
        return NewSessionTicketMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer serverHelloDone() {
        return ServerHelloDoneMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer serverHello() {
        return ServerHelloMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer serverKeyExchange() {
        return ServerKeyExchangeMessage.deserializer();
    }

    static TlsHandshakeMessageDeserializer supplementalData() {
        return SupplementalDataMessage.deserializer();
    }

    int id();

    TlsMessage deserialize(TlsContext context, ByteBuffer buffer, TlsMessageMetadata metadata);
}

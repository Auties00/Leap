package it.auties.leap.tls.certificate;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsCertificateUrl {
    private final IdentifierType type;
    private final List<TlsCertificateUrlAndHash> urlAndHashList;
    private final int urlAndHashListLength;

    private TlsCertificateUrl(IdentifierType type, List<TlsCertificateUrlAndHash> urlAndHashList, int urlAndHashListLength) {
        this.type = type;
        this.urlAndHashList = urlAndHashList;
        this.urlAndHashListLength = urlAndHashListLength;
    }

    public static TlsCertificateUrl of(IdentifierType type, List<TlsCertificateUrlAndHash> urlAndHashList) {
        Objects.requireNonNull(type, "Type cannot be null");
        Objects.requireNonNull(urlAndHashList, "Url and hash list cannot be null");
        var length = urlAndHashList.stream()
                .mapToInt(TlsCertificateUrlAndHash::length)
                .sum();
        return new TlsCertificateUrl(type, urlAndHashList, length);
    }

    public static TlsCertificateUrl of(ByteBuffer buffer) {
        var typeId = readBigEndianInt8(buffer);
        var type = IdentifierType.of(typeId)
                .orElseThrow(() -> new TlsAlert("Unknown certificate chain type: " + typeId, TlsAlertLevel.FATAL, TlsAlertType.ILLEGAL_PARAMETER));
        var urlAndHashListLength = buffer.remaining() >= INT16_LENGTH ? readBigEndianInt16(buffer) : 0;
        var urlAndHashList = new ArrayList<TlsCertificateUrlAndHash>();
        try(var _ = scopedRead(buffer, urlAndHashListLength)) {
            while (buffer.hasRemaining()) {
                var urlAndHash = TlsCertificateUrlAndHash.of(buffer);
                urlAndHashList.add(urlAndHash);
            }
        }
        return new TlsCertificateUrl(type, urlAndHashList, urlAndHashListLength);
    }

    public IdentifierType type() {
        return type;
    }

    public List<TlsCertificateUrlAndHash> urlAndHashList() {
        return urlAndHashList;
    }

    public void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, type().id());
        if(urlAndHashListLength > 0) {
            writeBigEndianInt16(buffer, urlAndHashListLength);
            for (var urlAndHash : urlAndHashList) {
                urlAndHash.serialize(buffer);
            }
        }
    }

    public int length() {
        if(urlAndHashListLength > 0) {
            return INT8_LENGTH
                    + INT16_LENGTH + urlAndHashListLength;
        }else {
            return INT8_LENGTH;
        }
    }

    public enum IdentifierType {
        INDIVIDUAL_CERTS((byte) 0),
        PKIPATH((byte) 1);

        private final byte id;
        IdentifierType(byte id) {
            this.id = id;
        }

        private static final Map<Byte, IdentifierType> VALUES = Arrays.stream(values())
                .collect(Collectors.toUnmodifiableMap(IdentifierType::id, Function.identity()));

        public static Optional<IdentifierType> of(byte value) {
            return Optional.ofNullable(VALUES.get(value));
        }

        public byte id() {
            return id;
        }
    }
}

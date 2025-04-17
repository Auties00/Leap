package it.auties.leap.tls.certificate.url;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.property.TlsSerializableProperty;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

public final class TlsCertificateUrl implements TlsSerializableProperty {
    private final TlsCertificateChainType type;
    private final List<TlsCertificateUrlAndHash> urlAndHashList;
    private final int urlAndHashListLength;

    private TlsCertificateUrl(TlsCertificateChainType type, List<TlsCertificateUrlAndHash> urlAndHashList, int urlAndHashListLength) {
        this.type = type;
        this.urlAndHashList = urlAndHashList;
        this.urlAndHashListLength = urlAndHashListLength;
    }

    public static TlsCertificateUrl of(TlsCertificateChainType type, List<TlsCertificateUrlAndHash> urlAndHashList) {
        if (type == null) {
            throw new TlsAlert("Type cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        if (urlAndHashList == null) {
            throw new TlsAlert("Url and hash list cannot be null", TlsAlertLevel.FATAL, TlsAlertType.INTERNAL_ERROR);
        }

        var length = urlAndHashList.stream()
                .mapToInt(TlsCertificateUrlAndHash::length)
                .sum();
        return new TlsCertificateUrl(type, urlAndHashList, length);
    }

    public static TlsCertificateUrl of(ByteBuffer buffer) {
        var typeId = readBigEndianInt8(buffer);
        var type = TlsCertificateChainType.of(typeId)
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

    public TlsCertificateChainType type() {
        return type;
    }

    public List<TlsCertificateUrlAndHash> urlAndHashList() {
        return urlAndHashList;
    }

    @Override
    public void serialize(ByteBuffer buffer) {
        writeBigEndianInt8(buffer, type().id());
        if(urlAndHashListLength > 0) {
            writeBigEndianInt16(buffer, urlAndHashListLength);
            for (var urlAndHash : urlAndHashList) {
                urlAndHash.serialize(buffer);
            }
        }
    }

    @Override
    public int length() {
        if(urlAndHashListLength > 0) {
            return INT8_LENGTH
                    + INT16_LENGTH + urlAndHashListLength;
        }else {
            return INT8_LENGTH;
        }
    }
}

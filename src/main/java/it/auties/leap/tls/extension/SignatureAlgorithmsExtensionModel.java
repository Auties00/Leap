package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.readLittleEndianInt16;

final class SignatureAlgorithmsExtensionModel implements TlsExtension.Model {
    @Override
    public Optional<? extends Implementation> newInstance(Context context) {
        return Optional.empty();
    }

    @Override
    public Optional<? extends Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        var algorithmsSize = readLittleEndianInt16(buffer);
        var algorithms = new ArrayList<Integer>(algorithmsSize);
        for (var i = 0; i < algorithmsSize; i++) {
            var algorithmId = readLittleEndianInt16(buffer);
            algorithms.add(algorithmId);
        }
        var extension = new SignatureAlgorithmsExtension(algorithms);
        return Optional.of(extension);
    }

    @Override
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return SignatureAlgorithmsExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.none();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.SIGNATURE_ALGORITHMS_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.SIGNATURE_ALGORITHMS_VERSIONS;
    }
}

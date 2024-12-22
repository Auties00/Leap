package it.auties.leap.tls.extension;

import it.auties.leap.tls.config.TlsMode;
import it.auties.leap.tls.config.TlsVersion;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static it.auties.leap.tls.util.BufferHelper.*;

final class ServerNameIndiciationExtensionModel implements TlsExtension.Model {
    static final ServerNameIndiciationExtensionModel INSTANCE = new ServerNameIndiciationExtensionModel();
    private ServerNameIndiciationExtensionModel() {

    }

    @Override
    public Optional<? extends TlsExtension.Implementation> newInstance(Context context) {
        var hostname = context.address().getHostName();
        var type = ServerNameIndicationExtension.NameType.HOST_NAME;
        if(!type.isValid(hostname)) {
            return Optional.empty();
        }

        var result = new ServerNameIndicationExtension(hostname.getBytes(StandardCharsets.US_ASCII), type);
        return Optional.of(result);
    }

    @Override
    public Optional<? extends TlsExtension.Implementation> decode(ByteBuffer buffer, int type, TlsMode mode) {
        var listLength = readLittleEndianInt16(buffer);
        if(listLength == 0) {
            return Optional.empty();
        }

        try(var _ = scopedRead(buffer, listLength)) {
            var nameTypeId = readLittleEndianInt8(buffer);
            var nameType = ServerNameIndicationExtension.NameType.of(nameTypeId)
                    .orElseThrow(() -> new IllegalArgumentException("Unknown name type: " + nameTypeId));
            var nameBytes = readBytesLittleEndian16(buffer);
            var extension = new ServerNameIndicationExtension(nameBytes, nameType);
            return Optional.of(extension);
        }
    }
    
    @Override
    public Class<? extends Implementation> toConcreteType(TlsMode mode) {
        return ServerNameIndicationExtension.class;
    }

    @Override
    public Dependencies dependencies() {
        return Dependencies.none();
    }

    @Override
    public int extensionType() {
        return TlsExtensions.SERVER_NAME_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return TlsExtensions.SERVER_NAME_VERSIONS;
    }
}

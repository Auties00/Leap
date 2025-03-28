package it.auties.leap.tls.extension.implementation.sni;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsSource;
import it.auties.leap.tls.extension.TlsConfiguredClientExtension;
import it.auties.leap.tls.extension.TlsConfiguredServerExtension;
import it.auties.leap.tls.extension.TlsExtensionDependencies;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.name.TlsNameType;
import it.auties.leap.tls.version.TlsVersion;

import java.nio.ByteBuffer;
import java.util.List;

import static it.auties.leap.tls.util.BufferUtils.*;

record SNIExtension(
        byte[] name,
        TlsNameType nameType
) implements TlsConfiguredClientExtension, TlsConfiguredServerExtension {
    @Override
    public void serializePayload(ByteBuffer buffer) {
        writeBigEndianInt16(buffer, INT8_LENGTH + INT16_LENGTH + name.length);
        writeBigEndianInt8(buffer, nameType.id());
        writeBytesBigEndian16(buffer, name);
    }

    @Override
    public int payloadLength() {
        return INT16_LENGTH + INT8_LENGTH + INT16_LENGTH + name.length;
    }

    @Override
    public void apply(TlsContext context, TlsSource source) {

    }

    @Override
    public int extensionType() {
        return SERVER_NAME_TYPE;
    }

    @Override
    public List<TlsVersion> versions() {
        return SERVER_NAME_VERSIONS;
    }

    @Override
    public TlsExtensionDeserializer deserializer() {
        return SNIExtensionDeserializer.INSTANCE;
    }

    @Override
    public TlsExtensionDependencies dependencies() {
        return TlsExtensionDependencies.none();
    }
}

package it.auties.leap.tls.extension.implementation.signatureAlgorithms;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextMode;
import it.auties.leap.tls.extension.TlsExtension;
import it.auties.leap.tls.extension.TlsExtensionDeserializer;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.property.TlsProperty;
import it.auties.leap.tls.signature.TlsSignature;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static it.auties.leap.tls.util.BufferUtils.readBigEndianInt16;

final class SignatureAlgorithmsExtensionDeserializer implements TlsExtensionDeserializer {
    static final TlsExtensionDeserializer INSTANCE = new SignatureAlgorithmsExtensionDeserializer();

    private SignatureAlgorithmsExtensionDeserializer() {

    }

    @Override
    public Optional<? extends TlsExtension> deserialize(TlsContext context, int type, ByteBuffer buffer) {
        var algorithmsSize = readBigEndianInt16(buffer);
        var algorithms = new ArrayList<TlsSignature>(algorithmsSize);
        var knownAlgorithms = context.getNegotiableValue(TlsProperty.signatureAlgorithms())
                .orElseThrow(() -> TlsAlert.noNegotiableProperty(TlsProperty.signatureAlgorithms()))
                .stream()
                .collect(Collectors.toUnmodifiableMap(TlsIdentifiableProperty::id, Function.identity()));
        var mode = context.selectedMode()
                .orElseThrow(TlsAlert::noModeSelected);
        for (var i = 0; i < algorithmsSize; i++) {
            var algorithmId = readBigEndianInt16(buffer);
            var algorithm = knownAlgorithms.get(algorithmId);
            if(algorithm != null) {
                algorithms.add(algorithm);
            }else if(mode == TlsContextMode.CLIENT) {
                throw new TlsAlert("Remote tried to negotiate a signature algorithm that wasn't advertised");
            }
        }
        var extension = new SignatureAlgorithmsExtension(algorithms);
        return Optional.of(extension);
    }
}

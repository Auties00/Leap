package it.auties.leap.tls.group;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.property.TlsIdentifiable;

import java.security.KeyPair;

// Includes ECCurveType
// https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
public sealed interface TlsSupportedGroup extends TlsIdentifiable<Integer> permits TlsSupportedCurve, TlsSupportedFiniteField {
    boolean dtls();
    KeyPair generateLocalKeyPair(TlsContext context);;
    byte[] computeSharedSecret(TlsContext context);
    byte[] dumpPublicKey(KeyPair keyPair);
}

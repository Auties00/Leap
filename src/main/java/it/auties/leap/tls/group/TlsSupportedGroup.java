package it.auties.leap.tls.group;

import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.property.TlsIdentifiableProperty;
import it.auties.leap.tls.secret.TlsSecret;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

// Includes ECCurveType
// https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
public sealed interface TlsSupportedGroup extends TlsIdentifiableProperty<Integer> permits TlsSupportedEllipticCurve, TlsSupportedFiniteField {
    boolean dtls();
    KeyPair generateKeyPair(TlsContext context);;
    TlsSecret computeSharedSecret(TlsContext context);
    byte[] dumpPublicKey(PublicKey keyPair);
    PublicKey parsePublicKey(byte[] rawPublicKey);
}

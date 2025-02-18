package it.auties.leap.tls.key;

import it.auties.leap.tls.TlsContext;

import java.security.KeyPair;

// Includes ECCurveType
// https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv
public sealed interface TlsSupportedGroup permits TlsSupportedCurve, TlsSupportedFiniteField {
    int id();
    boolean dtls();
    KeyPair generateLocalKeyPair(TlsContext context);;
    byte[] computeSharedSecret(TlsContext context);
}

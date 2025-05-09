package it.auties.leap.tls.group.implementation;

import it.auties.leap.tls.alert.TlsAlert;
import it.auties.leap.tls.alert.TlsAlertLevel;
import it.auties.leap.tls.alert.TlsAlertType;
import it.auties.leap.tls.ciphersuite.exchange.TlsKeyExchangeType;
import it.auties.leap.tls.connection.TlsConnectionSecret;
import it.auties.leap.tls.context.TlsContext;
import it.auties.leap.tls.context.TlsContextualProperty;
import it.auties.leap.tls.version.TlsVersion;

import javax.crypto.KeyAgreement;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;

final class JcaSharedSecret {
    static TlsConnectionSecret compute(TlsContext context, String algorithm, AlgorithmParameterSpec spec) {
        var privateKey = context.localConnectionState()
                .ephemeralKeyPair()
                .orElseThrow(() -> new TlsAlert(
                        "Cannot compute shared secret: no local ephemeral key pair was selected",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.HANDSHAKE_FAILURE
                ))
                .privateKey()
                .orElseThrow(() -> new TlsAlert(
                        "Cannot compute shared secret: local selected ephemeral key pair doesn't provide a private key",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.HANDSHAKE_FAILURE
                ));
        var keyExchangeType = getTlsKeyExchangeType(context);
        var remoteConnectionState = context.remoteConnectionState().orElseThrow(() -> new TlsAlert(
                "Cannot compute shared secret: no remote server connection state was created",
                TlsAlertLevel.FATAL,
                TlsAlertType.HANDSHAKE_FAILURE
        ));
        var publicKey = switch (keyExchangeType) {
            case STATIC -> remoteConnectionState.staticCertificate()
                    .orElseThrow(() -> new TlsAlert(
                            "Cannot compute shared secret: no remote static certificate was selected",
                            TlsAlertLevel.FATAL,
                            TlsAlertType.HANDSHAKE_FAILURE
                    ))
                    .value()
                    .getPublicKey();
            case EPHEMERAL -> remoteConnectionState.ephemeralKeyPair()
                    .orElseThrow(() -> new TlsAlert(
                            "Cannot compute shared secret: no remote ephemeral key pair was selected",
                            TlsAlertLevel.FATAL,
                            TlsAlertType.HANDSHAKE_FAILURE
                    ))
                    .publicKey();
        };
        try {
            var keyAgreement = KeyAgreement.getInstance(algorithm);
            keyAgreement.init(privateKey, spec);
            keyAgreement.doPhase(publicKey, true);
            var result = keyAgreement.generateSecret();
            return TlsConnectionSecret.of(result);
        }catch (GeneralSecurityException exception) {
            throw new TlsAlert(
                    "Cannot compute shared secret: " + exception.getMessage(),
                    exception,
                    TlsAlertLevel.FATAL,
                    TlsAlertType.HANDSHAKE_FAILURE
            );
        }
    }

    private static TlsKeyExchangeType getTlsKeyExchangeType(TlsContext context) {
        var version = context.getNegotiatedValue(TlsContextualProperty.version()).orElseThrow(() -> new TlsAlert(
                "Cannot compute shared secret: no version was negotiated yet",
                TlsAlertLevel.FATAL,
                TlsAlertType.HANDSHAKE_FAILURE
        ));
        var cipher = context.getNegotiatedValue(TlsContextualProperty.cipher()).orElseThrow(() -> new TlsAlert(
                "Cannot compute shared secret: no cipher was negotiated yet",
                TlsAlertLevel.FATAL,
                TlsAlertType.HANDSHAKE_FAILURE
        ));
        var keyExchangeFactory = cipher
                .keyExchangeFactory()
                .orElse(null);
        if(version == TlsVersion.TLS13 || version == TlsVersion.DTLS13) {
            if(keyExchangeFactory != null) {
                throw new TlsAlert(
                        "Cannot compute shared secret: expected no key exchange for (D)TLS1.3",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.HANDSHAKE_FAILURE
                );
            }

            return TlsKeyExchangeType.EPHEMERAL;
        } else {
            if(keyExchangeFactory == null) {
                throw new TlsAlert(
                        "Cannot compute shared secret: expected a valid key exchange for <=(D)TLS1.2",
                        TlsAlertLevel.FATAL,
                        TlsAlertType.HANDSHAKE_FAILURE
                );
            }

            return keyExchangeFactory.type();
        }
    }
}

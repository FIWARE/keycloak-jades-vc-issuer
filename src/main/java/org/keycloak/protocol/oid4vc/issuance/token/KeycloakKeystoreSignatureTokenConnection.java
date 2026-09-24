package org.keycloak.protocol.oid4vc.issuance.token;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import org.keycloak.crypto.KeyWrapper;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * DSS signature token backed by a Keycloak realm key.
 * <p>
 * DSS signs through a {@link KeyStore}, while Keycloak hands out a {@link KeyWrapper}. This connection
 * bridges the two by holding the realm key and its certificate chain in a transient, in-memory keystore
 * that never reaches the disk.
 *
 * @author <a href="https://github.com/wistefan">Stefan Wiedemann</a>
 */
public class KeycloakKeystoreSignatureTokenConnection extends AbstractKeyStoreTokenConnection {

    /**
     * Alias the realm key is stored under. The keystore holds exactly one entry and is never shared, so
     * the value only has to be stable between writing and reading it.
     */
    public static final String KEY_ALIAS = "alias";

    /**
     * Protection password of the in-memory keystore. The keystore is transient and process-local, so this
     * is not a secret - it only satisfies the {@link KeyStore} API, which requires one.
     */
    private static final char[] KEYSTORE_PASSWORD = "pwd".toCharArray();

    private final KeyStore keyStore;
    private final KeyStore.PasswordProtection passwordProtection;

    public KeycloakKeystoreSignatureTokenConnection(KeyWrapper keyWrapper) {
        try {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            passwordProtection = new KeyStore.PasswordProtection(KEYSTORE_PASSWORD);
            keyStore.load(null);
            keyStore.setKeyEntry(KEY_ALIAS, keyWrapper.getPrivateKey(), KEYSTORE_PASSWORD,
                    keyWrapper.getCertificateChain().toArray(new Certificate[0]));
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new DSSException(e);
        }
    }

    @Override
    protected KeyStore getKeyStore() {
        return keyStore;
    }

    @Override
    protected KeyStore.PasswordProtection getKeyProtectionParameter() {
        return passwordProtection;
    }

    @Override
    public void close() {
        // the keystore is in-memory only, nothing to release
    }
}
